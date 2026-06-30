// hook_network.m
// 网络抓包(r0capture 式 TLS 明文点): connect(目标 IP:port) + 一组 TLS 读写接口的明文:
//   OpenSSL/BoringSSL: SSL_write / SSL_read / SSL_write_ex / SSL_read_ex
//   Apple SecureTransport: SSLWrite / SSLRead
// 写类共用「捕获:SSL_write」开关, 读类共用「捕获:SSL_read」开关; algorithm 字段保留各自真名,
// 便于看出走的是哪条 TLS 路径.
//
// 刻意不 hook send/recv: 一是会被本地 HTTP 服务自身的响应 send 污染, 二是 TLS 之上的
// send/recv 是密文, 价值低于明文.
//
// fishhook 天花板(务必知道): 它只能改「导入符号表」—— 即本 image 调用其它 dylib 导出的符号.
// 若目标把 BoringSSL/OpenSSL 静态链接进主二进制(大厂 App 常见), 这些符号是 image 内部直接
// 跳转, 不在导入表里, fishhook 抓不到 —— 加了也会是空, 属机制硬边界而非 bug. 因此装好后把
// 每个符号「已挂载/未导入」写进网络板块审查日志, 让使用者当场判断: 全是「未导入」基本就证明
// 目标静态链接了 TLS, 该换 inline hook 了. 「符号」页(/api/symbols)可进一步看完整导入表.
//
// dh_in_hook: 记录路径会用 Foundation(NSDateFormatter/backtrace), 其内部可能再触发 connect/
// open/dlopen 等被 hook 的调用 → 递归. 置标志期间放行同类 hook.

#import <Foundation/Foundation.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import "fishhook.h"
#import "log_store.h"
#define DH_BOARD DH_DIAG_NET
#import "dh_health.h"
#import "dh_capture.h"

#define DH_NET_MAX 8192

static int (*orig_connect)(int, const struct sockaddr *, socklen_t);
static int hooked_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    int r = orig_connect(fd, addr, len);
    if (!dh_in_hook && addr && addr->sa_family == AF_INET && dh_capture_sub_enabled(DH_CAP_NET_CONNECT)) {
        dh_in_hook = 1;
        const struct sockaddr_in *s = (const struct sockaddr_in *)addr;
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip));
        DHLogEntry *e = [DHLogEntry new];
        e.category  = DHCategoryNetwork;
        e.algorithm = @"connect";
        e.operation = @"tcp";
        e.detail    = [NSString stringWithFormat:@"%s:%u", ip, ntohs(s->sin_port)];
        e.timestamp = DHTimestampNow();
        e.callStack = DHCallStackFiltered();
        [[DHLogStore shared] append:e];
        dh_in_hook = 0;
    }
    return r;
}

static int (*orig_SSL_write)(void *, const void *, int);
static int hooked_SSL_write(void *ssl, const void *buf, int num) {
    int r = orig_SSL_write(ssl, buf, num);
    if (!dh_in_hook && buf && num > 0 && dh_capture_sub_enabled(DH_CAP_NET_SSL_WRITE)) {
        dh_in_hook = 1;
        int n = num > DH_NET_MAX ? DH_NET_MAX : num;
        DHLogEntry *e = [DHLogEntry new];
        e.category  = DHCategoryNetwork;
        e.algorithm = @"SSL_write";
        e.operation = @"send (明文)";
        e.input     = [NSData dataWithBytes:buf length:n];
        e.detail    = [NSString stringWithFormat:@"%d bytes", num];
        e.timestamp = DHTimestampNow();
        e.callStack = DHCallStackFiltered();
        [[DHLogStore shared] append:e];
        dh_in_hook = 0;
    }
    return r;
}

static int (*orig_SSL_read)(void *, void *, int);
static int hooked_SSL_read(void *ssl, void *buf, int num) {
    int r = orig_SSL_read(ssl, buf, num);
    if (!dh_in_hook && buf && r > 0 && dh_capture_sub_enabled(DH_CAP_NET_SSL_READ)) {
        dh_in_hook = 1;
        int n = r > DH_NET_MAX ? DH_NET_MAX : r;
        DHLogEntry *e = [DHLogEntry new];
        e.category  = DHCategoryNetwork;
        e.algorithm = @"SSL_read";
        e.operation = @"recv (明文)";
        e.output    = [NSData dataWithBytes:buf length:n];
        e.detail    = [NSString stringWithFormat:@"%d bytes", r];
        e.timestamp = DHTimestampNow();
        e.callStack = DHCallStackFiltered();
        [[DHLogStore shared] append:e];
        dh_in_hook = 0;
    }
    return r;
}

// ---- 新版 OpenSSL/BoringSSL: SSL_write_ex / SSL_read_ex ----
// int SSL_write_ex(SSL*, const void *buf, size_t num, size_t *written);  成功返回 1, *written=实际写出
static int (*orig_SSL_write_ex)(void *, const void *, size_t, size_t *);
static int hooked_SSL_write_ex(void *ssl, const void *buf, size_t num, size_t *written) {
    int r = orig_SSL_write_ex(ssl, buf, num, written);
    if (!dh_in_hook && r == 1 && buf && written && *written > 0 && dh_capture_sub_enabled(DH_CAP_NET_SSL_WRITE)) {
        dh_in_hook = 1;
        size_t w = *written; int n = w > DH_NET_MAX ? DH_NET_MAX : (int)w;
        DHLogEntry *e = [DHLogEntry new];
        e.category  = DHCategoryNetwork;
        e.algorithm = @"SSL_write_ex";
        e.operation = @"send (明文)";
        e.input     = [NSData dataWithBytes:buf length:n];
        e.detail    = [NSString stringWithFormat:@"%zu bytes", w];
        e.timestamp = DHTimestampNow();
        e.callStack = DHCallStackFiltered();
        [[DHLogStore shared] append:e];
        dh_in_hook = 0;
    }
    return r;
}

// int SSL_read_ex(SSL*, void *buf, size_t num, size_t *readbytes);  成功返回 1, *readbytes=实际读入
static int (*orig_SSL_read_ex)(void *, void *, size_t, size_t *);
static int hooked_SSL_read_ex(void *ssl, void *buf, size_t num, size_t *readbytes) {
    int r = orig_SSL_read_ex(ssl, buf, num, readbytes);
    if (!dh_in_hook && r == 1 && buf && readbytes && *readbytes > 0 && dh_capture_sub_enabled(DH_CAP_NET_SSL_READ)) {
        dh_in_hook = 1;
        size_t rb = *readbytes; int n = rb > DH_NET_MAX ? DH_NET_MAX : (int)rb;
        DHLogEntry *e = [DHLogEntry new];
        e.category  = DHCategoryNetwork;
        e.algorithm = @"SSL_read_ex";
        e.operation = @"recv (明文)";
        e.output    = [NSData dataWithBytes:buf length:n];
        e.detail    = [NSString stringWithFormat:@"%zu bytes", rb];
        e.timestamp = DHTimestampNow();
        e.callStack = DHCallStackFiltered();
        [[DHLogStore shared] append:e];
        dh_in_hook = 0;
    }
    return r;
}

// ---- Apple SecureTransport(老接口, iOS 13 起弃用但仍在 Security.framework): SSLWrite / SSLRead ----
// 用 void* 代替 SSLContextRef, 仅取明文缓冲, 不引 SecureTransport 头. *processed=已处理字节(可能在
// errSSLWouldBlock 时部分写出), 故按 *processed>0 捕获, 不强求返回 errSecSuccess.
static int (*orig_SSLWrite)(void *, const void *, size_t, size_t *);
static int hooked_SSLWrite(void *ctx, const void *data, size_t len, size_t *processed) {
    int r = orig_SSLWrite(ctx, data, len, processed);
    if (!dh_in_hook && data && processed && *processed > 0 && dh_capture_sub_enabled(DH_CAP_NET_SSL_WRITE)) {
        dh_in_hook = 1;
        size_t w = *processed; int n = w > DH_NET_MAX ? DH_NET_MAX : (int)w;
        DHLogEntry *e = [DHLogEntry new];
        e.category  = DHCategoryNetwork;
        e.algorithm = @"SSLWrite";
        e.operation = @"send (明文)";
        e.input     = [NSData dataWithBytes:data length:n];
        e.detail    = [NSString stringWithFormat:@"%zu bytes", w];
        e.timestamp = DHTimestampNow();
        e.callStack = DHCallStackFiltered();
        [[DHLogStore shared] append:e];
        dh_in_hook = 0;
    }
    return r;
}

static int (*orig_SSLRead)(void *, void *, size_t, size_t *);
static int hooked_SSLRead(void *ctx, void *data, size_t len, size_t *processed) {
    int r = orig_SSLRead(ctx, data, len, processed);
    if (!dh_in_hook && data && processed && *processed > 0 && dh_capture_sub_enabled(DH_CAP_NET_SSL_READ)) {
        dh_in_hook = 1;
        size_t rb = *processed; int n = rb > DH_NET_MAX ? DH_NET_MAX : (int)rb;
        DHLogEntry *e = [DHLogEntry new];
        e.category  = DHCategoryNetwork;
        e.algorithm = @"SSLRead";
        e.operation = @"recv (明文)";
        e.output    = [NSData dataWithBytes:data length:n];
        e.detail    = [NSString stringWithFormat:@"%zu bytes", rb];
        e.timestamp = DHTimestampNow();
        e.callStack = DHCallStackFiltered();
        [[DHLogStore shared] append:e];
        dh_in_hook = 0;
    }
    return r;
}

void dh_install_network_hooks(void) {
    struct rebinding r[] = {
        {"connect",      hooked_connect,      (void **)&orig_connect},
        {"SSL_write",    hooked_SSL_write,    (void **)&orig_SSL_write},
        {"SSL_read",     hooked_SSL_read,     (void **)&orig_SSL_read},
        {"SSL_write_ex", hooked_SSL_write_ex, (void **)&orig_SSL_write_ex},
        {"SSL_read_ex",  hooked_SSL_read_ex,  (void **)&orig_SSL_read_ex},
        {"SSLWrite",     hooked_SSLWrite,     (void **)&orig_SSLWrite},
        {"SSLRead",      hooked_SSLRead,      (void **)&orig_SSLRead},
    };
    rebind_symbols(r, sizeof(r)/sizeof(r[0]));
    // 自检: connect 属 libSystem 必有, 缺失才告警; TLS 一族是 best-effort(导入表无则不存在).
    if (r[0].replaced && *(void **)r[0].replaced == NULL) dh_health_hook_fail(DH_DIAG_NET, r[0].name);

    // 把每个 TLS 符号「已挂载/未导入」记入网络板块审查日志 —— 装 hook 时各 TLS 库通常已加载,
    // 这是一份启动期快照, 便于判断本 App 哪些 TLS 接口可被 fishhook 拦截(全未导入≈静态链接)。
    int tlsBound = 0;
    for (size_t k = 1; k < sizeof(r)/sizeof(r[0]); k++) {   // 跳过 connect
        int bound = (r[k].replaced && *(void **)r[k].replaced != NULL);
        if (bound) tlsBound++;
        char msg[120];
        snprintf(msg, sizeof(msg), "TLS hook %s: %s", r[k].name,
                 bound ? "已挂载(导入表存在)" : "未导入(本 App 未动态链接此 TLS 接口)");
        dh_diag_append(DH_DIAG_NET, "INFO", msg);
    }
    if (tlsBound == 0) {
        dh_diag_append(DH_DIAG_NET, "INFO",
            "6 个 TLS 明文接口均未在导入表 —— 该 App 很可能静态链接了 BoringSSL/OpenSSL, "
            "fishhook 无法拦截明文; 如需抓包需改用 inline hook。可在「符号」页查看完整导入表佐证。");
    }
}
