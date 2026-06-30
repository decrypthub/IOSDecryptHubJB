// http_server.m - IOSDecryptHub 本地 HTTP 服务
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
#import "dh_health.h"
#import "dh_capture.h"
#import "ui_float.h"
#import "dump_manager.h"
#import "dh_symtab.h"

#define DH_HTTP_PORT_FIRST  8088
#define DH_HTTP_PORT_LAST   8108
#define DH_HTTP_BACKLOG     16
#define DH_HTTP_MAX_HEADER  (64 * 1024)
#define DH_HTTP_VERSION     "1.8.0"

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
            // 优先 Wi-Fi (en0) -> 蜂窝 (pdp_ip0) -> 其它
            if ([ifn isEqualToString:@"en0"]) { best = ip; break; }
            if ([ifn hasPrefix:@"en"] && !best) best = ip;
            if (!fallback) fallback = ip;
        }
        freeifaddrs(ifa);
    }
    if (best) return best;
    if (fallback) return fallback;
    // fail-loud(info): 没有任何非回环 IP, 服务只能本地访问 —— 明示而非假装一切正常.
    dh_health_note_localonly();
    return @"127.0.0.1";
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
        case DHCategoryNetwork:    return "net";
        case DHCategoryFile:       return "file";
        case DHCategorySystem:     return "sys";
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
    NSError *jerr = nil;
    NSData *body = [NSJSONSerialization dataWithJSONObject:obj ?: @{} options:0 error:&jerr];
    if (!body) {
        // fail-loud: 序列化失败返回 500 + 明确错误, 而不是静默回空让客户端以为「无数据」.
        DH_ERR(@"JSON 序列化失败: %@", jerr.localizedDescription);
        NSData *eb = [@"{\"error\":\"json encode failed\"}" dataUsingEncoding:NSUTF8StringEncoding];
        send_response(fd, 500, @"Error", @"application/json; charset=utf-8", eb);
        return;
    }
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
        @"detail":     e.detail ?: @"",
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
        @([s countForCategory:DHCategoryNetwork]),
        @([s countForCategory:DHCategoryFile]),
        @([s countForCategory:DHCategorySystem]),
        @([s countForCategory:DHCategoryOther]),
    ];
    NSMutableDictionary *capture = [NSMutableDictionary dictionary];
    for (int i = 0; i < DH_CAP_SUB_COUNT; i++)
        capture[[NSString stringWithUTF8String:dh_capture_sub_name((dh_cap_sub)i)]] = @(dh_capture_sub_enabled((dh_cap_sub)i));
    NSArray *pausedByCat = @[
        @([s isPausedForCategory:DHCategoryDigest]),
        @([s isPausedForCategory:DHCategoryHMAC]),
        @([s isPausedForCategory:DHCategorySymmetric]),
        @([s isPausedForCategory:DHCategoryAsymmetric]),
        @([s isPausedForCategory:DHCategoryNetwork]),
        @([s isPausedForCategory:DHCategoryFile]),
        @([s isPausedForCategory:DHCategorySystem]),
        @([s isPausedForCategory:DHCategoryOther]),
    ];
    const char *hsum = dh_health_summary();
    send_json(fd, 200, @{
        @"total":       @(s.totalCount),
        @"paused":      @(s.paused),
        @"byCategory":  byCat,
        @"pausedByCat": pausedByCat,
        @"capture":     capture,
        @"port":        @(gPort),
        @"version":     @DH_HTTP_VERSION,
        @"process":     [s processInfo],
        @"health":      @{
            @"hookFails":     @(dh_health_hook_fail_count()),
            @"persistFailed": dh_health_persist_failed() ? @YES : @NO,
            @"httpFailed":    dh_health_http_failed() ? @YES : @NO,
            @"localOnly":     dh_health_local_only() ? @YES : @NO,
            @"summary":       (hsum && hsum[0]) ? [NSString stringWithUTF8String:hsum] : @"",
        },
    });
}

static void handle_logs_list(int fd, NSDictionary *q) {
    NSInteger cat   = q[@"cat"]   ? [q[@"cat"] integerValue] : -1;
    NSString *kw    = q[@"q"]     ?: @"";
    uint64_t  since = q[@"since"] ? (uint64_t)[q[@"since"] longLongValue] : 0;
    NSInteger lim   = q[@"limit"] ? [q[@"limit"] integerValue] : 500;
    if (lim <= 0 || lim > 5000) lim = 500;
    NSUInteger minSize = q[@"minSize"] ? (NSUInteger)[q[@"minSize"] integerValue] : 0;

    NSArray *src = [[DHLogStore shared] snapshotMatching:kw category:cat minSize:minSize];
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

static void handle_clear(int fd, NSDictionary *q) {
    if (q[@"cat"]) [[DHLogStore shared] clearCategory:[q[@"cat"] integerValue]];   // 清空本类
    else           [[DHLogStore shared] clearAll];                                 // 清空全部(含落盘)
    send_json(fd, 200, @{@"ok": @YES});
}

static void handle_pause(int fd, NSDictionary *q) {
    BOOL p = [(q[@"paused"] ?: @"1") isEqualToString:@"1"];
    DHLogStore *s = [DHLogStore shared];
    if (q[@"cat"]) {
        NSInteger cat = [q[@"cat"] integerValue];
        if (cat == -2) {                                // 加密组(摘要/HMAC/对称/非对称)
            for (int c = DHCategoryDigest; c <= DHCategoryAsymmetric; c++) [s setPaused:p forCategory:(DHCategory)c];
        } else {                                        // 单类(网络/文件/系统等)
            [s setPaused:p forCategory:(DHCategory)cat];
        }
        send_json(fd, 200, @{@"paused": @(p), @"cat": @(cat)});
    } else {                                            // 全局总开关
        s.paused = p;
        send_json(fd, 200, @{@"paused": @(p)});
    }
}

// 捕获开关 —— 哪些子类型被记录(持久化在沙箱)。
static void handle_capture_get(int fd) {
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    for (int i = 0; i < DH_CAP_SUB_COUNT; i++)
        d[[NSString stringWithUTF8String:dh_capture_sub_name((dh_cap_sub)i)]] = @(dh_capture_sub_enabled((dh_cap_sub)i));
    send_json(fd, 200, d);
}
static void handle_capture_set(int fd, NSDictionary *q) {
    NSString *sub = q[@"sub"];
    if (!sub) { send_json(fd, 400, @{@"error": @"missing sub"}); return; }
    int idx = -1;
    for (int i = 0; i < DH_CAP_SUB_COUNT; i++)
        if ([sub isEqualToString:[NSString stringWithUTF8String:dh_capture_sub_name((dh_cap_sub)i)]]) { idx = i; break; }
    if (idx < 0) { send_json(fd, 400, @{@"error": @"unknown sub"}); return; }
    BOOL on = [(q[@"on"] ?: @"1") isEqualToString:@"1"];
    dh_capture_set_sub((dh_cap_sub)idx, on ? 1 : 0);
    send_json(fd, 200, @{@"sub": sub, @"on": @(on)});
}

// 按板块下载: 把某分类(或 -2 加密组)的内存日志导出为纯文本附件。
static void handle_logs_download(int fd, NSDictionary *q) {
    NSInteger cat = q[@"cat"] ? [q[@"cat"] integerValue] : -1;
    NSString *text = [[DHLogStore shared] exportTextForCategory:cat];
    NSData *body = [text dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
    NSMutableString *headers = [NSMutableString string];
    [headers appendString:@"HTTP/1.1 200 OK\r\n"];
    [headers appendString:@"Content-Type: text/plain; charset=utf-8\r\n"];
    [headers appendFormat:@"Content-Length: %lu\r\n", (unsigned long)body.length];
    [headers appendFormat:@"Content-Disposition: attachment; filename=iosdecrypthub-cat%ld.log\r\n", (long)cat];
    [headers appendString:@"Cache-Control: no-store\r\n"];
    [headers appendString:@"Connection: close\r\n\r\n"];
    NSData *hd = [headers dataUsingEncoding:NSUTF8StringEncoding];
    if (!write_all(fd, hd.bytes, hd.length)) return;
    write_all(fd, body.bytes, body.length);
}

// 审查日志(诊断): 进程信息 + hook 安装结果 + 按板块的错误事件时间线。board<0=全部板块。
// 注意: NSString 的 %s 按系统默认 C 编码解释 UTF-8 会乱码, 含中文的 C 串先 stringWithUTF8String 再 %@。
static NSString *diag_text(NSInteger board) {
    DHLogStore *s = [DHLogStore shared];
    NSDictionary *pi = [s processInfo];
    NSMutableString *t = [NSMutableString string];
    [t appendString:@"==== IOSDecryptHub 审查日志 (diagnostic) ====\n"];
    [t appendFormat:@"版本: %s\n", DH_HTTP_VERSION];
    [t appendFormat:@"应用: %@ (%@)  PID %@\n", pi[@"appName"] ?: @"", pi[@"bundleId"] ?: @"", pi[@"pid"] ?: @"?"];
    [t appendFormat:@"系统: %@   设备: %@   物理内存: %@ MB\n",
        pi[@"systemVersion"] ?: @"", pi[@"deviceModel"] ?: @"", pi[@"physicalMemoryMB"] ?: @"?"];
    [t appendFormat:@"服务端口: %d   监听: %@\n", gPort, gURL ?: @""];
    const char *unh = dh_health_hook_unhooked();
    if (unh && unh[0])
        [t appendFormat:@"未挂上的符号(多为该 App 未调用此 API, 属正常): %s\n", unh];   // 符号名为 ASCII
    const char *hsum = dh_health_summary();
    NSString *hs = (hsum && hsum[0]) ? [NSString stringWithUTF8String:hsum] : nil;
    [t appendFormat:@"健康摘要: %@\n", hs ?: @"正常"];
    [t appendFormat:@"---- 事件时间线 (%@) ----\n", board < 0 ? @"全部板块" : @"本板块"];
    NSString *timeline = [NSString stringWithUTF8String:dh_diag_dump((int)board)];
    [t appendString:timeline ?: @""];
    [t appendString:@"==== END ====\n"];
    return t;
}
static void handle_diag(int fd, NSDictionary *q) {
    NSInteger board = q[@"board"] ? [q[@"board"] integerValue] : -1;
    send_text(fd, 200, diag_text(board));
}
static void handle_diag_download(int fd, NSDictionary *q) {
    NSInteger board = q[@"board"] ? [q[@"board"] integerValue] : -1;
    NSData *body = [diag_text(board) dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
    NSMutableString *headers = [NSMutableString string];
    [headers appendString:@"HTTP/1.1 200 OK\r\n"];
    [headers appendString:@"Content-Type: text/plain; charset=utf-8\r\n"];
    [headers appendFormat:@"Content-Length: %lu\r\n", (unsigned long)body.length];
    [headers appendFormat:@"Content-Disposition: attachment; filename=iosdecrypthub-diag-%ld.log\r\n", (long)board];
    [headers appendString:@"Cache-Control: no-store\r\n"];
    [headers appendString:@"Connection: close\r\n\r\n"];
    NSData *hd = [headers dataUsingEncoding:NSUTF8StringEncoding];
    if (!write_all(fd, hd.bytes, hd.length)) return;
    write_all(fd, body.bytes, body.length);
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
    if (!fh) {
        // fail-loud: header(含 Content-Length) 已发出但打不开文件, 连接会被中断而非静默补 0.
        DH_ERR(@"下载: 无法读取日志文件 %@, 连接将中断", path);
        return;
    }
    @try {
        while (1) {
            NSData *chunk = [fh readDataOfLength:64 * 1024];
            if (chunk.length == 0) break;
            if (!write_all(fd, chunk.bytes, chunk.length)) {
                DH_ERR(@"下载: 发送数据块失败(客户端可能已断开), 连接中断");
                break;
            }
        }
    } @catch (NSException *e) {
        DH_ERR(@"下载: 读取日志文件异常: %@", e.reason);
    }
    [fh closeFile];
}

static void handle_appicon(int fd) {
    NSData *png = dh_host_app_icon_png();
    if (!png) { send_text(fd, 404, @"no app icon"); return; }
    send_response(fd, 200, @"OK", @"image/png", png);
}

// ---- 砸壳 (dump / 脱壳) ----
static void handle_dump_images(int fd) {
    send_json(fd, 200, [[DHDumpManager shared] listImagesDict]);
}

static void handle_dump_start(int fd, NSDictionary *q) {
    NSString *mode = q[@"mode"] ?: @"ipa";
    BOOL ok = [[DHDumpManager shared] startDump:mode];
    if (!ok) { send_json(fd, 409, @{@"started": @NO, @"error": @"已有任务在进行或 mode 非法"}); return; }
    send_json(fd, 200, @{@"started": @YES, @"mode": mode});
}

static void handle_dump_status(int fd) {
    send_json(fd, 200, [[DHDumpManager shared] statusDict]);
}

static void handle_dump_download(int fd, NSDictionary *q) {
    NSString *kind = [q[@"kind"] isEqualToString:@"bin"] ? @"bin" : @"ipa";
    NSString *path = [[DHDumpManager shared] artifactPathForKind:kind];
    if (!path) { send_text(fd, 404, @"砸壳产物尚未就绪"); return; }
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    if (!attrs) { send_text(fd, 404, @"产物文件丢失"); return; }
    unsigned long long total = [(NSNumber *)attrs[NSFileSize] unsignedLongLongValue];

    // 复用 handle_download 的分块流式写法, 仅换 Content-Type / 文件名
    NSMutableString *headers = [NSMutableString string];
    [headers appendString:@"HTTP/1.1 200 OK\r\n"];
    [headers appendString:@"Content-Type: application/octet-stream\r\n"];
    [headers appendFormat:@"Content-Length: %llu\r\n", total];
    [headers appendFormat:@"Content-Disposition: attachment; filename=%@\r\n", [path lastPathComponent]];
    [headers appendString:@"Cache-Control: no-store\r\n"];
    [headers appendString:@"Connection: close\r\n\r\n"];
    NSData *hd = [headers dataUsingEncoding:NSUTF8StringEncoding];
    if (!write_all(fd, hd.bytes, hd.length)) return;

    NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!fh) { DH_ERR(@"砸壳下载: 无法读取产物 %@, 连接将中断", path); return; }
    @try {
        while (1) {
            NSData *chunk = [fh readDataOfLength:64 * 1024];
            if (chunk.length == 0) break;
            if (!write_all(fd, chunk.bytes, chunk.length)) {
                DH_ERR(@"砸壳下载: 发送数据块失败(客户端可能已断开)");
                break;
            }
        }
    } @catch (NSException *e) {
        DH_ERR(@"砸壳下载: 读取产物异常: %@", e.reason);
    }
    [fh closeFile];
}

// ---- 符号导入表(可 hook 观测) ----
// fishhook 只能改导入符号表 —— 这几个端点把各 image 的导入(undefined)符号暴露给面板, 让使用者
// 当场看清「哪些可被 fishhook 拦截」, 尤其 TLS 明文接口是否在导入表里(不在=多半静态链接)。
static NSArray *dh_hooked_net_syms(void) {
    return @[@"connect", @"SSL_write", @"SSL_read", @"SSL_write_ex", @"SSL_read_ex", @"SSLWrite", @"SSLRead"];
}

// C 回调把 image 短名收进 NSMutableArray(去重)。
static void sym_image_collect_cb(const char *name, void *ctx) {
    NSMutableArray *a = (__bridge NSMutableArray *)ctx;
    NSString *s = name ? [NSString stringWithUTF8String:name] : nil;
    if (s && ![a containsObject:s]) [a addObject:s];
}
// C 回调把符号名收进 NSMutableArray。
static void sym_name_collect_cb(const char *name, void *ctx) {
    NSMutableArray *a = (__bridge NSMutableArray *)ctx;
    if (name) [a addObject:[NSString stringWithUTF8String:name] ?: @"?"];
}

// GET /api/symbols/tls —— 探测 r0capture 关心的 TLS 明文接口在本进程导入表里是否存在 + 是否已被我们 hook。
static void handle_symbols_tls(int fd) {
    NSArray *curated = dh_hooked_net_syms();   // 这几个正好都是我们接入 hook 的
    NSMutableArray *arr = [NSMutableArray array];
    for (NSString *nm in curated) {
        NSMutableArray *imgs = [NSMutableArray array];
        int cnt = dh_symtab_find_import(nm.UTF8String, sym_image_collect_cb, (__bridge void *)imgs);
        [arr addObject:@{
            @"name":    nm,
            @"present": @(cnt > 0),
            @"hooked":  @YES,
            @"images":  imgs,
        }];
    }
    send_json(fd, 200, @{@"symbols": arr});
}

// GET /api/symbols/images —— 列出有导入符号的 image(主程序优先), 给「符号」页下拉用。
static void handle_symbols_images(int fd) {
    int n = dh_symtab_image_count();
    NSMutableArray *arr = [NSMutableArray array];
    for (int i = 0; i < n; i++) {
        char nm[256]; int isMain = 0;
        dh_symtab_image_name(i, nm, sizeof(nm), &isMain);
        int imports = dh_symtab_imports(i, NULL, 0, NULL, NULL);   // 只计数
        if (imports <= 0) continue;
        [arr addObject:@{
            @"idx":     @(i),
            @"name":    [NSString stringWithUTF8String:nm] ?: @"?",
            @"main":    isMain ? @YES : @NO,
            @"imports": @(imports),
        }];
    }
    [arr sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        BOOL am = [a[@"main"] boolValue], bm = [b[@"main"] boolValue];
        if (am != bm) return am ? NSOrderedAscending : NSOrderedDescending;   // 主程序排最前
        return [a[@"name"] caseInsensitiveCompare:b[@"name"]];
    }];
    send_json(fd, 200, @{@"images": arr});
}

// GET /api/symbols?img=N&q=&limit= —— 某 image 的导入符号列表(可子串过滤), hooked 集给前端高亮。
static void handle_symbols(int fd, NSDictionary *q) {
    int n = dh_symtab_image_count();
    int idx = q[@"img"] ? [q[@"img"] intValue] : 0;
    if (idx < 0 || idx >= n) { send_json(fd, 400, @{@"error": @"bad img index"}); return; }
    NSString *kw = q[@"q"] ?: @"";
    int limit = q[@"limit"] ? [q[@"limit"] intValue] : 300;
    if (limit <= 0 || limit > 2000) limit = 300;

    char nm[256]; int isMain = 0;
    dh_symtab_image_name(idx, nm, sizeof(nm), &isMain);
    NSMutableArray *syms = [NSMutableArray array];
    const char *qc = kw.length ? kw.UTF8String : NULL;
    int total = dh_symtab_imports(idx, qc, limit, sym_name_collect_cb, (__bridge void *)syms);
    send_json(fd, 200, @{
        @"idx":     @(idx),
        @"name":    [NSString stringWithUTF8String:nm] ?: @"?",
        @"main":    isMain ? @YES : @NO,
        @"total":   @(total),
        @"shown":   @(syms.count),
        @"symbols": syms,
        @"hooked":  dh_hooked_net_syms(),
    });
}

static void handle_index(int fd) {
    NSData *body = [NSData dataWithBytes:kDHIndexHTML length:kDHIndexHTML_len];   // 字节数组, 非 NUL 结尾
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
            } else if ([path isEqualToString:@"/api/logs/download"]) {
                handle_logs_download(fd, q);
            } else if ([path isEqualToString:@"/api/capture"]) {
                handle_capture_get(fd);
            } else if ([path hasPrefix:@"/api/logs/"]) {
                handle_log_detail(fd, [path substringFromIndex:[@"/api/logs/" length]]);
            } else if ([path isEqualToString:@"/download"]) {
                handle_download(fd);
            } else if ([path isEqualToString:@"/api/dump/images"]) {
                handle_dump_images(fd);
            } else if ([path isEqualToString:@"/api/dump/status"]) {
                handle_dump_status(fd);
            } else if ([path isEqualToString:@"/api/dump/download"]) {
                handle_dump_download(fd, q);
            } else if ([path isEqualToString:@"/api/appicon"]) {
                handle_appicon(fd);
            } else if ([path isEqualToString:@"/api/diag"]) {
                handle_diag(fd, q);
            } else if ([path isEqualToString:@"/api/diag/download"]) {
                handle_diag_download(fd, q);
            } else if ([path isEqualToString:@"/api/symbols/tls"]) {
                handle_symbols_tls(fd);
            } else if ([path isEqualToString:@"/api/symbols/images"]) {
                handle_symbols_images(fd);
            } else if ([path isEqualToString:@"/api/symbols"]) {
                handle_symbols(fd, q);
            } else if ([path isEqualToString:@"/favicon.ico"]) {
                send_response(fd, 204, @"No Content", @"image/x-icon", [NSData data]);
            } else {
                send_text(fd, 404, @"not found");
            }
        } else if ([method isEqualToString:@"POST"]) {
            if ([path isEqualToString:@"/api/clear"]) {
                handle_clear(fd, q);
            } else if ([path isEqualToString:@"/api/pause"]) {
                handle_pause(fd, q);
            } else if ([path isEqualToString:@"/api/capture"]) {
                handle_capture_set(fd, q);
            } else if ([path isEqualToString:@"/api/dump"]) {
                handle_dump_start(fd, q);
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
            NSLog(@"[IOSDecryptHub] HTTP 服务启动失败: %s..%s 端口都被占用", "8088", "8108");
            dh_health_http_fail("端口 8088..8108 全被占用, 本地服务不可用");
            return;
        }
        NSString *ip = get_local_ip();
        gURL = [NSString stringWithFormat:@"http://%@:%u", ip, (unsigned)gPort];
        gAcceptQ = dispatch_queue_create("com.decrypthelper.http.accept", DISPATCH_QUEUE_SERIAL);
        gWorkerQ = dispatch_queue_create("com.decrypthelper.http.worker", DISPATCH_QUEUE_CONCURRENT);
        gConcurrency = dispatch_semaphore_create(DH_HTTP_MAX_CONCURRENCY);
        dispatch_async(gAcceptQ, ^{ accept_loop(); });
        dh_health_http_ok();
        NSLog(@"[IOSDecryptHub] HTTP 服务已启动: %@", gURL);
    });
}

uint16_t  dh_http_port(void) { return gPort; }
NSString *dh_http_url(void)  { return gURL ?: @"(not running)"; }
