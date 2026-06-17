// http_server.m - 解密助手 本地 HTTP 服务
//
// 设计:
//   - 一个 socket 监听端口, 一个 accept 队列, 每个连接 dispatch 到处理队列
//   - 每个连接一次性读 header (限 64KB), 没有 keep-alive 也没有 chunked
//   - JSON 用 NSJSONSerialization
//   - HTML 来自 web_index_html.h
//
// 安全声明: 本服务无认证, 把 key/iv/明文都暴露给任何能连接的人.
// 仅供调试时在可信网络上使用.

#import <Foundation/Foundation.h>
#import <sys/socket.h>
#import <sys/types.h>
#import <sys/ioctl.h>
#import <netinet/in.h>
#import <netinet/tcp.h>
#import <arpa/inet.h>
#import <ifaddrs.h>
#import <net/if.h>
#import <unistd.h>
#import <fcntl.h>
#import <errno.h>
#import <string.h>
#import "http_server.h"
#import "log_store.h"
#import "web_index_html.h"

#define DH_HTTP_PORT_FIRST  8088
#define DH_HTTP_PORT_LAST   8108
#define DH_HTTP_BACKLOG     16
#define DH_HTTP_MAX_HEADER  (64 * 1024)
#define DH_HTTP_VERSION     "1.1.0"

static int        gListenFD = -1;
static uint16_t   gPort     = 0;
static NSString  *gURL      = nil;
static dispatch_queue_t gAcceptQ = NULL;
static dispatch_queue_t gWorkerQ = NULL;
static dispatch_semaphore_t gConcurrency = NULL;  // 限制同时处理的连接数, 防 slow-client 耗尽 fd

#define DH_HTTP_MAX_CONCURRENCY 8

// ============================================================
// 工具
// ============================================================
static NSString *get_local_ip(void) {
    struct ifaddrs *ifa = NULL, *p = NULL;
    NSString *best = nil;
    NSString *fallback = nil;
    if (getifaddrs(&ifa) == 0) {
        for (p = ifa; p; p = p->ifa_next) {
            if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
            if (!(p->ifa_flags & IFF_UP) || (p->ifa_flags & IFF_LOOPBACK)) continue;
            char buf[INET_ADDRSTRLEN];
            struct sockaddr_in *sin = (struct sockaddr_in *)p->ifa_addr;
            inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
            NSString *ifn = [NSString stringWithUTF8String:p->ifa_name];
            NSString *ip  = [NSString stringWithUTF8String:buf];
            // 优先 Wi-Fi (en0) → 蜂窝 (pdp_ip0) → 其它
            if ([ifn isEqualToString:@"en0"]) { best = ip; break; }
            if ([ifn hasPrefix:@"en"] && !best) best = ip;
            if (!fallback) fallback = ip;
        }
        freeifaddrs(ifa);
    }
    return best ?: fallback ?: @"127.0.0.1";
}

static NSString *url_decode(NSString *s) {
    return [s stringByRemovingPercentEncoding] ?: s;
}

static NSDictionary *parse_query(NSString *qs) {
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    if (qs.length == 0) return out;
    for (NSString *kv in [qs componentsSeparatedByString:@"&"]) {
        NSRange eq = [kv rangeOfString:@"="];
        if (eq.location == NSNotFound) {
            out[url_decode(kv)] = @"";
        } else {
            NSString *k = [kv substringToIndex:eq.location];
            NSString *v = [kv substringFromIndex:eq.location + 1];
            out[url_decode(k)] = url_decode(v);
        }
    }
    return out;
}

static const char *category_name(NSInteger c) {
    switch (c) {
        case DHCategoryDigest:     return "digest";
        case DHCategoryHMAC:       return "hmac";
        case DHCategorySymmetric:  return "sym";
        case DHCategoryAsymmetric: return "asym";
        default: return "other";
    }
}

// ============================================================
// I/O helpers
// ============================================================
static BOOL write_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    size_t left = len;
    while (left > 0) {
        ssize_t n = send(fd, p, left, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return NO;
        }
        if (n == 0) return NO;
        p += n; left -= (size_t)n;
    }
    return YES;
}

static void send_response(int fd, int status, NSString *statusMsg, NSString *contentType, NSData *body) {
    NSMutableString *headers = [NSMutableString string];
    [headers appendFormat:@"HTTP/1.1 %d %@\r\n", status, statusMsg];
    [headers appendFormat:@"Content-Type: %@\r\n", contentType];
    [headers appendFormat:@"Content-Length: %lu\r\n", (unsigned long)body.length];
    [headers appendString:@"Cache-Control: no-store\r\n"];
    [headers appendString:@"Access-Control-Allow-Origin: *\r\n"];
    [headers appendString:@"Connection: close\r\n\r\n"];
    NSData *hd = [headers dataUsingEncoding:NSUTF8StringEncoding];
    write_all(fd, hd.bytes, hd.length);
    if (body.length) write_all(fd, body.bytes, body.length);
}

static void send_json(int fd, int status, id obj) {
    NSData *body = [NSJSONSerialization dataWithJSONObject:obj ?: @{}
                                                   options:0 error:nil] ?: [NSData data];
    send_response(fd, status, status == 200 ? @"OK" : @"Error", @"application/json; charset=utf-8", body);
}

static void send_text(int fd, int status, NSString *msg) {
    NSData *body = [(msg ?: @"") dataUsingEncoding:NSUTF8StringEncoding];
    send_response(fd, status, status == 200 ? @"OK" : @"Error", @"text/plain; charset=utf-8", body);
}

// ============================================================
// 路由 handlers
// ============================================================
static NSDictionary *entry_summary(DHLogEntry *e) {
    NSString *preview = nil;
    if (e.input.length) {
        NSData *d = e.input.length > 32 ? [e.input subdataWithRange:NSMakeRange(0, 32)] : e.input;
        NSString *u = DHUTF8FromData(d);
        if (![u isEqualToString:@"(非UTF-8)"]) {
            preview = u.length > 80 ? [[u substringToIndex:80] stringByAppendingString:@"…"] : u;
        } else {
            preview = DHHexFromData(d);
        }
    }
    return @{
        @"seq":        @(e.seq),
        @"category":   @(e.category),
        @"categoryName": @(category_name(e.category)),
        @"algorithm":  e.algorithm ?: @"",
        @"operation":  e.operation ?: @"",
        @"timestamp":  e.timestamp ?: @"",
        @"inLen":      @(e.input.length),
        @"outLen":     @(e.output.length),
        @"preview":    preview ?: @"",
    };
}

static NSDictionary *entry_detail(DHLogEntry *e) {
    NSMutableDictionary *m = [entry_summary(e) mutableCopy] ?: [NSMutableDictionary dictionary];
    if (e.key)    { m[@"key"]    = @(e.key.length);    m[@"keyHex"]    = DHHexFromData(e.key); }
    if (e.iv)     { m[@"iv"]     = @(e.iv.length);     m[@"ivHex"]     = DHHexFromData(e.iv); }
    if (e.input)  {
        m[@"input"]    = @(e.input.length);
        m[@"inputHex"] = DHHexFromData(e.input);
        NSString *u = DHUTF8FromData(e.input);
        if (![u isEqualToString:@"(非UTF-8)"]) m[@"inputUtf8"] = u;
        m[@"inputDump"] = DHHexDumpFromData(e.input);
    }
    if (e.output) {
        m[@"output"]    = @(e.output.length);
        m[@"outputHex"] = DHHexFromData(e.output);
        NSString *u = DHUTF8FromData(e.output);
        if (![u isEqualToString:@"(非UTF-8)"]) m[@"outputUtf8"] = u;
        m[@"outputDump"] = DHHexDumpFromData(e.output);
    }
    if (e.publicKeyInfo) m[@"publicKeyInfo"] = e.publicKeyInfo;
    if (e.callStack)     m[@"callStack"] = e.callStack;
    return m;
}

static void handle_stats(int fd) {
    DHLogStore *s = [DHLogStore shared];
    NSArray *byCat = @[
        @([s countForCategory:DHCategoryDigest]),
        @([s countForCategory:DHCategoryHMAC]),
        @([s countForCategory:DHCategorySymmetric]),
        @([s countForCategory:DHCategoryAsymmetric]),
        @([s countForCategory:DHCategoryOther]),
    ];
    send_json(fd, 200, @{
        @"total":       @(s.totalCount),
        @"paused":      @(s.paused),
        @"byCategory":  byCat,
        @"port":        @(gPort),
        @"version":     @DH_HTTP_VERSION,
    });
}

static void handle_logs_list(int fd, NSDictionary *q) {
    NSInteger cat   = q[@"cat"]   ? [q[@"cat"] integerValue] : -1;
    NSString *kw    = q[@"q"]     ?: @"";
    uint64_t  since = q[@"since"] ? (uint64_t)[q[@"since"] longLongValue] : 0;
    NSInteger lim   = q[@"limit"] ? [q[@"limit"] integerValue] : 500;
    if (lim <= 0 || lim > 5000) lim = 500;

    NSArray *src = [[DHLogStore shared] snapshotMatching:kw category:cat];
    // 最新在前
    NSMutableArray *out = [NSMutableArray array];
    for (NSInteger i = (NSInteger)src.count - 1; i >= 0 && (NSInteger)out.count < lim; i--) {
        DHLogEntry *e = src[i];
        if (since && e.seq <= since) continue;
        [out addObject:entry_summary(e)];
    }
    send_json(fd, 200, out);
}

static void handle_log_detail(int fd, NSString *seqStr) {
    uint64_t seq = (uint64_t)[seqStr longLongValue];
    DHLogEntry *e = [[DHLogStore shared] entryWithSeq:seq];
    if (!e) { send_json(fd, 404, @{@"error": @"not found"}); return; }
    send_json(fd, 200, entry_detail(e));
}

static void handle_clear(int fd) {
    [[DHLogStore shared] clearAll];
    send_json(fd, 200, @{@"ok": @YES});
}

static void handle_pause(int fd, NSDictionary *q) {
    BOOL p = [(q[@"paused"] ?: @"1") isEqualToString:@"1"];
    [DHLogStore shared].paused = p;
    send_json(fd, 200, @{@"paused": @(p)});
}

static void handle_download(int fd) {
    NSString *path = [[DHLogStore shared] logFilePath];
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    if (!attrs) {
        send_text(fd, 404, @"log file not present yet");
        return;
    }
    unsigned long long total = [(NSNumber *)attrs[NSFileSize] unsignedLongLongValue];

    NSMutableString *headers = [NSMutableString string];
    [headers appendString:@"HTTP/1.1 200 OK\r\n"];
    [headers appendString:@"Content-Type: text/plain; charset=utf-8\r\n"];
    [headers appendFormat:@"Content-Length: %llu\r\n", total];
    [headers appendString:@"Content-Disposition: attachment; filename=decrypt_helper.log\r\n"];
    [headers appendString:@"Cache-Control: no-store\r\n"];
    [headers appendString:@"Connection: close\r\n\r\n"];
    NSData *hd = [headers dataUsingEncoding:NSUTF8StringEncoding];
    if (!write_all(fd, hd.bytes, hd.length)) return;

    // 64KB 分块, 避免一次性把整个日志文件吃进内存
    NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!fh) return;
    @try {
        while (1) {
            NSData *chunk = [fh readDataOfLength:64 * 1024];
            if (chunk.length == 0) break;
            if (!write_all(fd, chunk.bytes, chunk.length)) break;
        }
    } @catch (__unused NSException *e) {}
    [fh closeFile];
}

static void handle_index(int fd) {
    NSData *body = [NSData dataWithBytes:kDHIndexHTML length:strlen(kDHIndexHTML)];
    send_response(fd, 200, @"OK", @"text/html; charset=utf-8", body);
}

// ============================================================
// 请求 dispatch
// ============================================================
static void handle_connection(int fd) {
    // 设置读超时, 防止恶意连接卡死
    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    NSMutableData *buf = [NSMutableData data];
    char tmp[4096];
    BOOL gotHeader = NO;
    while (buf.length < DH_HTTP_MAX_HEADER) {
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n < 0) { if (errno == EINTR) continue; break; }
        if (n == 0) break;
        [buf appendBytes:tmp length:(NSUInteger)n];
        if (memmem(buf.bytes, buf.length, "\r\n\r\n", 4)) { gotHeader = YES; break; }
    }
    if (!gotHeader) { close(fd); return; }

    NSString *req = [[NSString alloc] initWithData:buf encoding:NSUTF8StringEncoding];
    if (!req) { close(fd); return; }
    NSArray *lines = [req componentsSeparatedByString:@"\r\n"];
    if (lines.count == 0) { close(fd); return; }
    NSArray *parts = [lines[0] componentsSeparatedByString:@" "];
    if (parts.count < 3) { send_text(fd, 400, @"bad request"); close(fd); return; }
    NSString *method = parts[0];
    NSString *target = parts[1];

    NSString *path; NSString *qs;
    NSRange qrange = [target rangeOfString:@"?"];
    if (qrange.location == NSNotFound) { path = target; qs = @""; }
    else { path = [target substringToIndex:qrange.location]; qs = [target substringFromIndex:qrange.location + 1]; }
    NSDictionary *q = parse_query(qs);

    @try {
        if ([method isEqualToString:@"GET"]) {
            if ([path isEqualToString:@"/"] || [path isEqualToString:@"/index.html"]) {
                handle_index(fd);
            } else if ([path isEqualToString:@"/api/stats"]) {
                handle_stats(fd);
            } else if ([path isEqualToString:@"/api/logs"]) {
                handle_logs_list(fd, q);
            } else if ([path hasPrefix:@"/api/logs/"]) {
                handle_log_detail(fd, [path substringFromIndex:[@"/api/logs/" length]]);
            } else if ([path isEqualToString:@"/download"]) {
                handle_download(fd);
            } else if ([path isEqualToString:@"/favicon.ico"]) {
                send_response(fd, 204, @"No Content", @"image/x-icon", [NSData data]);
            } else {
                send_text(fd, 404, @"not found");
            }
        } else if ([method isEqualToString:@"POST"]) {
            if ([path isEqualToString:@"/api/clear"]) {
                handle_clear(fd);
            } else if ([path isEqualToString:@"/api/pause"]) {
                handle_pause(fd, q);
            } else {
                send_text(fd, 404, @"not found");
            }
        } else if ([method isEqualToString:@"OPTIONS"]) {
            NSMutableString *h = [NSMutableString string];
            [h appendString:@"HTTP/1.1 204 No Content\r\n"];
            [h appendString:@"Access-Control-Allow-Origin: *\r\n"];
            [h appendString:@"Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"];
            [h appendString:@"Access-Control-Allow-Headers: *\r\n"];
            [h appendString:@"Connection: close\r\n\r\n"];
            NSData *hd = [h dataUsingEncoding:NSUTF8StringEncoding];
            write_all(fd, hd.bytes, hd.length);
        } else {
            send_text(fd, 405, @"method not allowed");
        }
    } @catch (NSException *ex) {
        send_text(fd, 500, [NSString stringWithFormat:@"server error: %@", ex.reason]);
    }
    close(fd);
}

// ============================================================
// listen + accept loop
// ============================================================
static int try_bind(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { close(fd); return -1; }
    if (listen(fd, DH_HTTP_BACKLOG) != 0) { close(fd); return -1; }
    return fd;
}

static void accept_loop(void) {
    useconds_t backoff = 0;
    while (gListenFD >= 0) {
        struct sockaddr_in client = {0};
        socklen_t clen = sizeof(client);
        int cfd = accept(gListenFD, (struct sockaddr *)&client, &clen);
        if (cfd < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            if (gListenFD < 0) break;
            // EMFILE/ENFILE: fd 耗尽, 指数退避避免 100% CPU
            if (errno == EMFILE || errno == ENFILE) {
                backoff = backoff ? MIN(backoff * 2, (useconds_t)500 * 1000) : 50 * 1000;
                usleep(backoff);
            } else {
                usleep(50 * 1000);
            }
            continue;
        }
        backoff = 0;
        int yes = 1;
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
        // 拿信号量, 超出并发上限就在 accept 线程上等; 这反向给客户端施加压力
        dispatch_semaphore_wait(gConcurrency, DISPATCH_TIME_FOREVER);
        dispatch_async(gWorkerQ, ^{
            handle_connection(cfd);
            dispatch_semaphore_signal(gConcurrency);
        });
    }
}

void dh_http_start(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        for (uint16_t p = DH_HTTP_PORT_FIRST; p <= DH_HTTP_PORT_LAST; p++) {
            int fd = try_bind(p);
            if (fd >= 0) { gListenFD = fd; gPort = p; break; }
        }
        if (gListenFD < 0) {
            NSLog(@"[解密助手] HTTP 服务启动失败: %s..%s 端口都被占用",
                  "8088", "8108");
            return;
        }
        NSString *ip = get_local_ip();
        gURL = [NSString stringWithFormat:@"http://%@:%u", ip, (unsigned)gPort];
        gAcceptQ = dispatch_queue_create("com.decrypthelper.http.accept", DISPATCH_QUEUE_SERIAL);
        gWorkerQ = dispatch_queue_create("com.decrypthelper.http.worker", DISPATCH_QUEUE_CONCURRENT);
        gConcurrency = dispatch_semaphore_create(DH_HTTP_MAX_CONCURRENCY);
        dispatch_async(gAcceptQ, ^{ accept_loop(); });
        NSLog(@"[解密助手] HTTP 服务已启动: %@", gURL);
    });
}

uint16_t  dh_http_port(void) { return gPort; }
NSString *dh_http_url(void)  { return gURL ?: @"(not running)"; }
