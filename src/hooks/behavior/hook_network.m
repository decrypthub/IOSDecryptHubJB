// hook_network.m — 网络抓包 (进程内, TLS 之上, 无需代理/证书/绕 pinning)
//
// 两条路径 (同 CommonCrypto + OpenSSL EVP 的双抓思路):
//   1) swizzle -[NSURLSessionTask resume]  —— 抓系统网络栈的请求 (URL/method/header/body),
//      这是 iOS App 最常见的 HTTP 通道。发生在 URL loading 层, 在 TLS 与证书绑定之上。
//   2) fishhook SSL_write / SSL_read        —— 抓 App 自带 TLS 栈 (bundle 了 OpenSSL/BoringSSL、
//      走 import slot) 的明文收发。系统 TLS 栈不经 App import, 故对系统流量多不命中(属正常)。
//
// 全部受 dh_capture_sub_enabled(DH_CAP_NETWORK) 开关控制, 记入 DHCategoryNetwork。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import "fishhook.h"
#import "log_store.h"
#define DH_BOARD DH_DIAG_SYS
#import "dh_health.h"
#import "dh_capture.h"
#import "dh_dlsym_redirect.h"

// ============================================================
// 统一记录
// ============================================================
static void net_log(NSString *algo, NSString *op, NSString *detail, NSData *body) {
    if (!dh_capture_sub_enabled(DH_CAP_NETWORK)) return;
    DHLogEntry *e = [DHLogEntry new];
    e.category  = DHCategoryNetwork;
    e.algorithm = algo;
    e.operation = op;
    e.detail    = detail ?: @"";
    e.input     = body;
    e.timestamp = DHTimestampNow();
    e.callStack = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
}

// ============================================================
// 1) NSURLSession 请求 (ObjC swizzle)
// ============================================================
static void (*orig_task_resume)(id, SEL) = NULL;

static void swz_task_resume(id self, SEL _cmd) {
    @try {
        if (dh_capture_sub_enabled(DH_CAP_NETWORK)) {
            NSURLSessionTask *task = (NSURLSessionTask *)self;
            NSURLRequest *req = task.currentRequest ?: task.originalRequest;
            if (req && req.URL) {
                NSMutableString *d = [NSMutableString stringWithString:req.URL.absoluteString ?: @""];
                NSDictionary *hdrs = req.allHTTPHeaderFields;
                if (hdrs.count) {
                    [d appendString:@"\n-- Headers --\n"];
                    for (NSString *k in hdrs) [d appendFormat:@"%@: %@\n", k, hdrs[k]];
                }
                net_log(@"HTTP", req.HTTPMethod ?: @"GET", d, req.HTTPBody);
            }
        }
    } @catch (__unused NSException *ex) { /* 抓包尽力而为, 绝不因异常影响宿主网络 */ }
    if (orig_task_resume) orig_task_resume(self, _cmd);
}

static void install_urlsession_hook(void) {
    // resume 定义在基类 NSURLSessionTask 上; 具体任务为其私有子类, 通常继承基类实现。
    Class cls = NSClassFromString(@"NSURLSessionTask");
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, @selector(resume));
    if (!m) { dh_health_hook_fail(DH_DIAG_SYS, "-[NSURLSessionTask resume]"); return; }
    orig_task_resume = (void (*)(id, SEL))method_getImplementation(m);
    method_setImplementation(m, (IMP)swz_task_resume);
}

// ============================================================
// 2) SSL_write / SSL_read 明文 (fishhook, best-effort)
//    用 void* 占位 SSL 类型, 免依赖 openssl 头; ABI 兼容。
// ============================================================
static int (*orig_SSL_write)(void *ssl, const void *buf, int num) = NULL;
static int (*orig_SSL_read)(void *ssl, void *buf, int num) = NULL;

static int hooked_SSL_write(void *ssl, const void *buf, int num) {
    if (num > 0 && buf && dh_capture_sub_enabled(DH_CAP_NETWORK)) {
        net_log(@"TLS", @"send",
                [NSString stringWithFormat:@"SSL=%p len=%d", ssl, num],
                [NSData dataWithBytes:buf length:(NSUInteger)num]);
    }
    return orig_SSL_write ? orig_SSL_write(ssl, buf, num) : 0;
}

static int hooked_SSL_read(void *ssl, void *buf, int num) {
    int r = orig_SSL_read ? orig_SSL_read(ssl, buf, num) : 0;
    if (r > 0 && buf && dh_capture_sub_enabled(DH_CAP_NETWORK)) {
        net_log(@"TLS", @"recv",
                [NSString stringWithFormat:@"SSL=%p len=%d", ssl, r],
                [NSData dataWithBytes:buf length:(NSUInteger)r]);
    }
    return r;
}

static void install_ssl_hooks(void) {
    struct rebinding r[] = {
        {"SSL_write", hooked_SSL_write, (void **)&orig_SSL_write},
        {"SSL_read",  hooked_SSL_read,  (void **)&orig_SSL_read},
    };
    rebind_symbols(r, sizeof(r) / sizeof(r[0]));
    dh_dlsym_register_rebindings(r, sizeof(r) / sizeof(r[0]));
    // 未命中不告警: 系统 TLS 不经 App import, 多为正常 (见文件头说明)。
}

// ============================================================
// 安装入口
// ============================================================
void dh_install_network_hooks(void) {
    install_urlsession_hook();
    install_ssl_hooks();
}
