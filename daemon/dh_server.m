// dh_server.m — IOSDecryptHub root daemon
// 监听 127.0.0.1:29817, 提供注入管理 API (枚举 App / 读写偏好)
// 以 root 身份运行 (LaunchDaemon), 绕过 App 沙盒限制。
//
// API:
//   GET  /api/apps        → JSON 数组 [{bundleId, name, isSystem}]
//   GET  /api/prefs       → JSON {enabled, targetBundleId}
//   POST /api/prefs       → body: {enabled, targetBundleId} → 写入偏好 plist
//   GET  /api/status      → {version, running}

#import <Foundation/Foundation.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>
#import <mach-o/dyld.h>
#import <spawn.h>
#import <sys/wait.h>
#import <libgen.h>

// ---- 路径推导: 从 daemon 自身位置推导 jbroot (不依赖 /var/jb symlink) ----
// daemon 装在 <jbroot>/usr/bin/dh_server, 所以 jbroot = dirname(dirname(exe))
static NSString *g_jbroot = nil;

static NSString *dh_jbroot(void) {
    if (g_jbroot) return g_jbroot;
    char exe[PATH_MAX] = {0};
    uint32_t sz = PATH_MAX;
    _NSGetExecutablePath(exe, &sz);
    // realpath 解析 symlink 得到真实路径
    char real[PATH_MAX] = {0};
    if (realpath(exe, real)) {
        // /xxx/usr/bin/dh_server → /xxx
        NSString *p = [[NSString stringWithUTF8String:real] stringByDeletingLastPathComponent]; // .../usr/bin
        p = [p stringByDeletingLastPathComponent]; // .../usr
        p = [p stringByDeletingLastPathComponent]; // jbroot
        g_jbroot = p;
    } else {
        g_jbroot = @"/var/jb"; // fallback
    }
    NSLog(@"[dh_server] jbroot = %@", g_jbroot);
    return g_jbroot;
}

static NSString *dh_path(NSString *relative) {
    return [dh_jbroot() stringByAppendingPathComponent:relative];
}

#define DH_SERVER_PORT 29817
#define PREFS_PATH @"/var/jb/var/mobile/Library/Preferences/com.dh.decrypthelper.plist"
#define PREFS_PATH_ROOTFUL @"/var/mobile/Library/Preferences/com.dh.decrypthelper.plist"

// ---- 偏好读写 ----
static NSString *dh_prefs_path(void) {
    return dh_path(@"tmp/com.dh.decrypthelper.plist");
}

static NSDictionary *dh_read_prefs(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:dh_prefs_path()];
    if (!d) d = @{};
    return @{
        @"enabled": @([d[@"DHEnabled"] boolValue]),
        @"targetBundleId": d[@"DHTargetBundleId"] ?: @"",
    };
}

static void dh_write_prefs(BOOL enabled, NSString *targetBid) {
    NSDictionary *d = @{@"DHEnabled": @(enabled), @"DHTargetBundleId": targetBid ?: @""};
    // 写 daemon 推导的真实路径
    [d writeToFile:dh_prefs_path() atomically:YES];
    // 也尝试写 dylib 读取的标准路径 (roothide 下可能失败)
    [d writeToFile:PREFS_PATH atomically:YES];
    [d writeToFile:PREFS_PATH_ROOTFUL atomically:YES];
}

// ---- App 列表: 读 JSON 缓存 (由 LaunchDaemon 启动时的 helper 脚本生成) ----
static NSString *dh_applist_path(void) {
    return dh_path(@"tmp/com.dh.applist.json");
}

static NSArray *dh_list_apps(void) {
    NSString *path = dh_applist_path();
    NSLog(@"[dh_server] 读取 app 列表: %@", path);
    NSLog(@"[dh_server] 文件存在: %d", [[NSFileManager defaultManager] fileExistsAtPath:path]);
    NSData *data = [NSData dataWithContentsOfFile:path];
    NSLog(@"[dh_server] data length: %lu", (unsigned long)data.length);
    if (!data) {
        // fallback: 尝试另一个路径
        NSString *alt = @"/var/mobile/Library/Preferences/com.dh.applist.json";
        data = [NSData dataWithContentsOfFile:alt];
        NSLog(@"[dh_server] fallback %@ length: %lu", alt, (unsigned long)data.length);
    }
    if (!data) return @[];
    NSError *err = nil;
    NSArray *arr = [NSJSONSerialization JSONObjectWithData:data options:0 error:&err];
    if (err) NSLog(@"[dh_server] JSON 解析错误: %@", err);
    NSLog(@"[dh_server] 解析到 %lu 个 app", (unsigned long)arr.count);
    return arr ?: @[];
}

// ---- JSON 序列化 ----
static NSData *dh_json(id obj) {
    return [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
}

// ---- HTTP 响应 ----
static void dh_send_response(int fd, int code, NSString *contentType, NSData *body) {
    NSString *status = code == 200 ? @"OK" : (code == 404 ? @"Not Found" : @"Bad Request");
    NSString *header = [NSString stringWithFormat:
        @"HTTP/1.1 %d %@\r\nContent-Type: %@\r\nContent-Length: %lu\r\n"
        @"Access-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
        code, status, contentType, (unsigned long)body.length];
    write(fd, header.UTF8String, header.length);
    if (body.length) write(fd, body.bytes, body.length);
}

// ---- 请求处理 ----
static void dh_handle_request(int fd) {
    char buf[8192] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) { close(fd); return; }

    NSString *req = [[NSString alloc] initWithBytes:buf length:n encoding:NSUTF8StringEncoding];
    if (!req) { close(fd); return; }

    // 解析方法和路径
    NSString *firstLine = [req componentsSeparatedByString:@"\r\n"].firstObject;
    NSArray *parts = [firstLine componentsSeparatedByString:@" "];
    if (parts.count < 2) { close(fd); return; }
    NSString *method = parts[0];
    NSString *path = parts[1];

    if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/apps"]) {
        NSArray *apps = dh_list_apps();
        dh_send_response(fd, 200, @"application/json", dh_json(apps));
    }
    else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/prefs"]) {
        dh_send_response(fd, 200, @"application/json", dh_json(dh_read_prefs()));
    }
    else if ([method isEqualToString:@"POST"] && [path isEqualToString:@"/api/prefs"]) {
        // 解析 body JSON
        NSRange bodyRange = [req rangeOfString:@"\r\n\r\n"];
        if (bodyRange.location != NSNotFound) {
            NSString *bodyStr = [req substringFromIndex:bodyRange.location + 4];
            NSData *bodyData = [bodyStr dataUsingEncoding:NSUTF8StringEncoding];
            NSDictionary *j = [NSJSONSerialization JSONObjectWithData:bodyData options:0 error:nil];
            if (j) {
                BOOL en = [j[@"enabled"] boolValue];
                NSString *bid = j[@"targetBundleId"] ?: @"";
                dh_write_prefs(en, bid);
                dh_send_response(fd, 200, @"application/json", dh_json(@{@"ok": @YES}));
            } else {
                dh_send_response(fd, 400, @"application/json", dh_json(@{@"error": @"invalid json"}));
            }
        } else {
            dh_send_response(fd, 400, @"application/json", dh_json(@{@"error": @"no body"}));
        }
    }
    else if ([method isEqualToString:@"GET"] && [path isEqualToString:@"/api/status"]) {
        dh_send_response(fd, 200, @"application/json",
            dh_json(@{@"version": @"1.23.0", @"running": @YES, @"port": @(DH_SERVER_PORT)}));
    }
    else {
        dh_send_response(fd, 404, @"application/json", dh_json(@{@"error": @"not found"}));
    }
    close(fd);
}

// ---- main ----
int main(int argc, char *argv[]) {
    @autoreleasepool {
        NSLog(@"[dh_server] IOSDecryptHub daemon 启动, 监听 127.0.0.1:%d", DH_SERVER_PORT);

        int srv = socket(AF_INET, SOCK_STREAM, 0);
        if (srv < 0) { perror("socket"); return 1; }
        int opt = 1;
        setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(DH_SERVER_PORT),
            .sin_addr.s_addr = inet_addr("127.0.0.1"),
        };
        if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind"); return 1;
        }
        listen(srv, 16);
        NSLog(@"[dh_server] 就绪");

        // 启动时调用 helper 脚本刷新 app 列表缓存
        NSString *helper = dh_path(@"usr/bin/dh_listapps");
        if ([[NSFileManager defaultManager] isExecutableFileAtPath:helper]) {
            pid_t pid;
            char *argv[] = {(char *)helper.fileSystemRepresentation, NULL};
            extern char **environ;
            if (posix_spawn(&pid, helper.fileSystemRepresentation, NULL, NULL, argv, environ) == 0) {
                int status;
                waitpid(pid, &status, 0);
                NSLog(@"[dh_server] app 列表已刷新");
            }
        }

        // GCD 并发处理连接
        dispatch_queue_t q = dispatch_queue_create("dh.server", DISPATCH_QUEUE_CONCURRENT);
        dispatch_source_t src = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, srv, 0, q);
        dispatch_source_set_event_handler(src, ^{
            int cli = accept(srv, NULL, NULL);
            if (cli >= 0) {
                dispatch_async(q, ^{ dh_handle_request(cli); });
            }
        });
        dispatch_resume(src);
        dispatch_main();
    }
    return 0;
}
