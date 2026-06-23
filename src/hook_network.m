// hook_network.m
// 网络抓包: connect(目标 IP:port) + SSL_write/SSL_read(TLS 明文).
// 刻意不 hook send/recv: 一是会被本地 HTTP 服务自身的响应 send 污染, 二是 TLS 之上的
// send/recv 是密文, 价值低于 SSL_* 明文. SSL_write/SSL_read 是 App 自带 BoringSSL/OpenSSL
// 的符号, 系统 TLS(Network.framework) 不走它们 —— 没有则属 best-effort, 自检不告警.
//
// dh_in_hook: 记录路径会用 Foundation(NSDateFormatter/backtrace), 其内部可能再触发 connect/
// open/dlopen 等被 hook 的调用 → 递归. 置标志期间放行同类 hook.

#import <Foundation/Foundation.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import "fishhook.h"
#import "log_store.h"
#import "dh_health.h"

#define DH_NET_MAX 8192

static int (*orig_connect)(int, const struct sockaddr *, socklen_t);
static int hooked_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    int r = orig_connect(fd, addr, len);
    if (!dh_in_hook && addr && addr->sa_family == AF_INET) {
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
    if (!dh_in_hook && buf && num > 0) {
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
    if (!dh_in_hook && buf && r > 0) {
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

void dh_install_network_hooks(void) {
    struct rebinding r[] = {
        {"connect",   hooked_connect,   (void **)&orig_connect},
        {"SSL_write", hooked_SSL_write, (void **)&orig_SSL_write},
        {"SSL_read",  hooked_SSL_read,  (void **)&orig_SSL_read},
    };
    rebind_symbols(r, sizeof(r)/sizeof(r[0]));
    // 自检: connect 属 libSystem 必有; SSL_* 是 best-effort(App 无 BoringSSL 则不存在), 不告警.
    for (size_t k = 0; k < sizeof(r)/sizeof(r[0]); k++) {
        if (strstr(r[k].name, "SSL_")) continue;
        if (r[k].replaced && *(void **)r[k].replaced == NULL) dh_health_hook_fail(r[k].name);
    }
}
