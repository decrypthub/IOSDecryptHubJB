// hook_network.m — 网络抓包 (进程内, TLS 之上, 无需代理/证书/绕 pinning)
//
// 三条路径:
//   1) swizzle 三个 completion-handler 建任务方法  —— 请求↔响应【配对】成一条完整记录
//      (input=请求体, output=响应体, detail=URL+状态码+头), 用 task 身份天然关联。
//      覆盖用 completionHandler 的 NSURLSession 调用 (绝大多数 App)。
//   2) swizzle -[NSURLSessionTask resume]           —— delegate 型任务(无 completion)的请求兜底,
//      已被 (1) 配对捕获的 task 会跳过, 不重复记。
//   3) fishhook SSL_write / SSL_read                —— App 自带 TLS 栈(bundle OpenSSL/BoringSSL、
//      走 import slot)的明文收发。系统 TLS 不经 App import, 多不命中属正常。
//
// 全部受 dh_capture_sub_enabled(DH_CAP_NETWORK) 开关控制, 记入 DHCategoryNetwork。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <sys/time.h>
#import <pthread.h>
#import "fishhook.h"
#import "log_store.h"
#define DH_BOARD DH_DIAG_SYS
#import "dh_health.h"
#import "dh_capture.h"
#import "dh_dlsym_redirect.h"

// 标记「此 task 的响应会由 completion 配对捕获」, 供 resume 兜底去重。
static const void *kDHNetHandled = &kDHNetHandled;

// 请求时刻的 ms/tid —— 配对事件用它做锚点(而非响应到达时刻), 否则慢请求会跳出关联时间窗。
static uint64_t dh_now_ms(void) { struct timeval tv; gettimeofday(&tv, NULL); return (uint64_t)tv.tv_sec * 1000ULL + tv.tv_usec / 1000; }
static uint64_t dh_cur_tid(void) { uint64_t t = 0; pthread_threadid_np(NULL, &t); return t; }

// ============================================================
// 记录
// ============================================================

// 单向记录 (SSL send/recv 用)
static void net_log(NSString *algo, NSString *op, NSString *detail, NSData *body) {
    if (!dh_capture_sub_enabled(DH_CAP_NETWORK)) return;
    DHLogEntry *e = [DHLogEntry new];
    e.category = DHCategoryNetwork; e.algorithm = algo; e.operation = op;
    e.detail = detail ?: @""; e.input = body;
    e.timestamp = DHTimestampNow(); e.callStack = DHCallStackFiltered();
    [[DHLogStore shared] append:e];
}

static void net_append_headers(NSMutableString *d, NSString *title, NSDictionary *hdrs) {
    if (!hdrs.count) return;
    [d appendFormat:@"-- %@ --\n", title];
    for (id k in hdrs) [d appendFormat:@"%@: %@\n", k, hdrs[k]];
}

// 请求↔响应配对记录: 一条 entry 里 input=请求体 / output=响应体 / detail=URL+状态+头。
// tsMs/tid 为「请求构建时刻」的值(不是响应到达时刻), 保证与算 Header 的 crypto 落在同一时间窗/线程。
// detail 只记实际捕获到的字段(方法、URL、请求头、状态、响应头), 不加 curl 风格 >/<, 也不拼 HTTP/1.1 报文。
static void net_log_pair(NSString *method, NSString *urlStr, NSDictionary *reqHdrs, NSData *reqBody,
                         NSData *respData, NSURLResponse *resp, NSError *err, NSString *callStack,
                         uint64_t tsMs, uint64_t tid) {
    if (!dh_capture_sub_enabled(DH_CAP_NETWORK)) return;
    NSMutableString *d = [NSMutableString stringWithFormat:@"%@ %@\n", method ?: @"GET", urlStr ?: @"?"];
    net_append_headers(d, @"Request Headers", reqHdrs);
    if ([resp isKindOfClass:[NSHTTPURLResponse class]]) {
        NSHTTPURLResponse *http = (NSHTTPURLResponse *)resp;
        [d appendFormat:@"-- Status: %ld  (resp %llu bytes) --\n", (long)http.statusCode,
                        (unsigned long long)respData.length];
        net_append_headers(d, @"Response Headers", http.allHeaderFields);
    } else if (respData) {
        [d appendFormat:@"-- resp %llu bytes --\n", (unsigned long long)respData.length];
    }
    if (err) [d appendFormat:@"-- Error: %@\n", err.localizedDescription];

    DHLogEntry *e = [DHLogEntry new];
    e.category  = DHCategoryNetwork;
    e.algorithm = @"HTTP";
    e.operation = method ?: @"GET";
    e.detail    = d;
    e.input       = reqBody;      // 请求体
    e.output      = respData;     // 响应体
    e.timestamp   = DHTimestampNow();
    e.timestampMs = tsMs;         // 请求时刻 (供 correlate_request 锚点)
    e.threadId    = tid;          // 请求线程
    e.callStack   = callStack ?: DHCallStackFiltered();
    [[DHLogStore shared] append:e];
}

// ============================================================
// 1) completion-handler 建任务 (请求↔响应配对)
// ============================================================
typedef void (^DHDataCH)(NSData *, NSURLResponse *, NSError *);

static id (*orig_dtReqCH)(id, SEL, NSURLRequest *, DHDataCH) = NULL;
static id (*orig_dtURLCH)(id, SEL, NSURL *, DHDataCH) = NULL;
static id (*orig_upReqCH)(id, SEL, NSURLRequest *, NSData *, DHDataCH) = NULL;

static id mark_handled(id task) {
    if (task) objc_setAssociatedObject(task, kDHNetHandled, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    return task;
}

// -[NSURLSession dataTaskWithRequest:completionHandler:]
static id swz_dtReqCH(id self, SEL _cmd, NSURLRequest *req, DHDataCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_dtReqCH(self, _cmd, req, ch);
    NSURLRequest *rc = req;
    NSString *cs = DHCallStackFiltered();
    uint64_t reqMs = dh_now_ms(), reqTid = dh_cur_tid();
    DHDataCH wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        @try { net_log_pair(rc.HTTPMethod, rc.URL.absoluteString, rc.allHTTPHeaderFields, rc.HTTPBody, data, resp, err, cs, reqMs, reqTid); }
        @catch (__unused NSException *e) {}
        ch(data, resp, err);
    };
    return mark_handled(orig_dtReqCH(self, _cmd, req, wrapped));
}

// -[NSURLSession dataTaskWithURL:completionHandler:]
static id swz_dtURLCH(id self, SEL _cmd, NSURL *url, DHDataCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_dtURLCH(self, _cmd, url, ch);
    NSURL *uc = url;
    NSString *cs = DHCallStackFiltered();
    uint64_t reqMs = dh_now_ms(), reqTid = dh_cur_tid();
    DHDataCH wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        @try { net_log_pair(@"GET", uc.absoluteString, nil, nil, data, resp, err, cs, reqMs, reqTid); }
        @catch (__unused NSException *e) {}
        ch(data, resp, err);
    };
    return mark_handled(orig_dtURLCH(self, _cmd, url, wrapped));
}

// -[NSURLSession uploadTaskWithRequest:fromData:completionHandler:]
static id swz_upReqCH(id self, SEL _cmd, NSURLRequest *req, NSData *bodyData, DHDataCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_upReqCH(self, _cmd, req, bodyData, ch);
    NSURLRequest *rc = req; NSData *bc = bodyData ?: req.HTTPBody;
    NSString *cs = DHCallStackFiltered();
    uint64_t reqMs = dh_now_ms(), reqTid = dh_cur_tid();
    DHDataCH wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        @try { net_log_pair(rc.HTTPMethod, rc.URL.absoluteString, rc.allHTTPHeaderFields, bc, data, resp, err, cs, reqMs, reqTid); }
        @catch (__unused NSException *e) {}
        ch(data, resp, err);
    };
    return mark_handled(orig_upReqCH(self, _cmd, req, bodyData, wrapped));
}

static BOOL swz_instance(Class cls, SEL sel, IMP newImp, IMP *origOut) {
    if (!cls) return NO;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;
    *origOut = method_getImplementation(m);
    method_setImplementation(m, newImp);
    return YES;
}

// ============================================================
// 2) resume 兜底 (仅记未被 completion 配对的请求)
// ============================================================
static void (*orig_task_resume)(id, SEL) = NULL;
static void swz_task_resume(id self, SEL _cmd) {
    @try {
        if (dh_capture_sub_enabled(DH_CAP_NETWORK) &&
            !objc_getAssociatedObject(self, kDHNetHandled)) {   // 已配对捕获则不重复记请求
            NSURLSessionTask *task = (NSURLSessionTask *)self;
            NSURLRequest *req = task.currentRequest ?: task.originalRequest;
            if (req && req.URL) {
                NSMutableString *d = [NSMutableString stringWithFormat:@"%@ %@\n",
                                      req.HTTPMethod ?: @"GET", req.URL.absoluteString ?: @""];
                net_append_headers(d, @"Request Headers", req.allHTTPHeaderFields);
                net_log(@"HTTP", req.HTTPMethod ?: @"GET", d, req.HTTPBody);
            }
        }
    } @catch (__unused NSException *ex) {}
    if (orig_task_resume) orig_task_resume(self, _cmd);
}

static void install_urlsession_hook(void) {
    // 配对: 在「shared session 的真实类」上换 completion 建任务方法 (custom session 同为该私有类)
    Class sc = object_getClass([NSURLSession sharedSession]) ?: NSClassFromString(@"NSURLSession");
    swz_instance(sc, @selector(dataTaskWithRequest:completionHandler:),          (IMP)swz_dtReqCH, (IMP *)&orig_dtReqCH);
    swz_instance(sc, @selector(dataTaskWithURL:completionHandler:),              (IMP)swz_dtURLCH, (IMP *)&orig_dtURLCH);
    swz_instance(sc, @selector(uploadTaskWithRequest:fromData:completionHandler:),(IMP)swz_upReqCH, (IMP *)&orig_upReqCH);

    // 兜底: resume (delegate 型任务的请求)
    Class taskCls = NSClassFromString(@"NSURLSessionTask");
    Method m = taskCls ? class_getInstanceMethod(taskCls, @selector(resume)) : NULL;
    if (m) { orig_task_resume = (void (*)(id, SEL))method_getImplementation(m);
             method_setImplementation(m, (IMP)swz_task_resume); }
    else   { dh_health_hook_fail(DH_DIAG_SYS, "-[NSURLSessionTask resume]"); }
}

// ============================================================
// 3) SSL_write / SSL_read 明文 (fishhook, best-effort; void* 占位 SSL 免依赖)
// ============================================================
static int (*orig_SSL_write)(void *, const void *, int) = NULL;
static int (*orig_SSL_read)(void *, void *, int) = NULL;

static int hooked_SSL_write(void *ssl, const void *buf, int num) {
    if (num > 0 && buf && dh_capture_sub_enabled(DH_CAP_NETWORK))
        net_log(@"TLS", @"send", [NSString stringWithFormat:@"SSL=%p len=%d", ssl, num],
                [NSData dataWithBytes:buf length:(NSUInteger)num]);
    return orig_SSL_write ? orig_SSL_write(ssl, buf, num) : 0;
}
static int hooked_SSL_read(void *ssl, void *buf, int num) {
    int r = orig_SSL_read ? orig_SSL_read(ssl, buf, num) : 0;
    if (r > 0 && buf && dh_capture_sub_enabled(DH_CAP_NETWORK))
        net_log(@"TLS", @"recv", [NSString stringWithFormat:@"SSL=%p len=%d", ssl, r],
                [NSData dataWithBytes:buf length:(NSUInteger)r]);
    return r;
}
static void install_ssl_hooks(void) {
    struct rebinding r[] = {
        {"SSL_write", hooked_SSL_write, (void **)&orig_SSL_write},
        {"SSL_read",  hooked_SSL_read,  (void **)&orig_SSL_read},
    };
    rebind_symbols(r, sizeof(r) / sizeof(r[0]));
    dh_dlsym_register_rebindings(r, sizeof(r) / sizeof(r[0]));
}

// ============================================================
void dh_install_network_hooks(void) {
    install_urlsession_hook();
    install_ssl_hooks();
}
