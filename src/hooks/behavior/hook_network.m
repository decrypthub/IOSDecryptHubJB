// hook_network.m — 网络抓包 (进程内, TLS 之上, 无需代理/证书/绕 pinning)
//
// 核心原则: 请求一发出就先落一条日志, 有没有响应都不丢包 —— 响应/错误到了再原子替换补全。
//
// 四条路径:
//   1) swizzle -[<真实任务类> resume]                —— 所有 NSURLSession 任务的请求「先记」入口。
//      每个 task 首个 resume 立刻记一条【只有请求】的完整日志并挂到 task 上, 此刻已落库/落盘。
//      真实 resume 实现在私有具体子类上, 故运行时探测该类再换实现 (打基类会漏)。这一步保证
//      即便请求超时无响应、进程被杀、或走 delegate 无回调, 请求也永远留档。
//   2) swizzle completion-handler 建任务方法  —— 响应/错误到达时, 用【请求+响应】完整条目原子
//      替换 (1) 先记的那条 (保持 seq/位置), 而非新增, 因此不重复、也不丢。覆盖 data /
//      upload(fromData/fromFile) / download 的 completionHandler 调用 (绝大多数 App)。
//      HTTPBody 必须在建任务时快照: 发出请求后原对象上的 body 经常变 nil。download 响应落地为
//      文件(不读内容, 只补响应头/状态码); fromFile 上传体读文件前缀作快照。
//   3) swizzle NSURLConnection 便捷方法              —— 老 API (async/sync 便捷方法)的请求↔响应配对。
//   4) fishhook SSL_write(_ex) / SSL_read(_ex)       —— App 自带 TLS 栈(bundle OpenSSL/BoringSSL、
//      走 import slot)的明文收发。系统 TLS 不经 App import, 多不命中属正常。
//
// 替换靠 DHLogStore replaceNetworkEntry:with: (串行队列内换整条不可变对象引用, 读侧零竞态)。
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

// 挂在 task 上的「先记的请求条目」(eager entry): resume 一发出请求就记一条只有请求的日志并挂这里,
// 响应/错误到达时用完整条目原子替换它。既保证「无响应也留档」, 又不重复记。既是去重标志也是替换句柄。
static const void *kDHNetEntry = &kDHNetEntry;
// 建任务时快照的请求字段, 挂在 task 上。completion 时 HTTPBody 往往已被 URLSession 转成 stream 清掉。
static const void *kDHNetSnap = &kDHNetSnap;
// -[NSMutableURLRequest setHTTPBody:] 当时的副本, 防止 getter 随后返回 nil。
static const void *kDHSetHTTPBody = &kDHSetHTTPBody;

// 请求时刻的 ms/tid —— 配对事件用它做锚点(而非响应到达时刻), 否则慢请求会跳出关联时间窗。
static uint64_t dh_now_ms(void) { struct timeval tv; gettimeofday(&tv, NULL); return (uint64_t)tv.tv_sec * 1000ULL + tv.tv_usec / 1000; }
static uint64_t dh_cur_tid(void) { uint64_t t = 0; pthread_threadid_np(NULL, &t); return t; }

// 建任务瞬间的请求快照。必须在调用 orig 之前取 HTTPBody, 发出去之后原对象上的 body 经常变 nil。
@interface DHNetSnap : NSObject
@property (copy)   NSString *method;
@property (copy)   NSString *url;
@property (copy)   NSDictionary *headers;
@property (strong) NSData *body;
// 请求体缺失时的诚实注记 (如 HTTPBodyStream 未快照), 拼在请求段末尾, 避免被误读成「空 body」。
@property (copy)   NSString *bodyNote;
// 响应段注记 (如下载落地文件名/大小), 拼在响应段末尾。
@property (copy)   NSString *respNote;
// 下载落地文件前缀预览 (走 output 通道, 与请求体 body 槽位无关)。
@property (strong) NSData *dlPreview;
@property (copy)   NSString *callStack;
@property (assign) uint64_t tsMs;
@property (assign) uint64_t tid;
@end
@implementation DHNetSnap
@end

static NSDictionary *dh_merge_headers(NSDictionary *base, NSDictionary *extra) {
    if (!base.count) return extra.count ? [extra copy] : nil;
    if (!extra.count) return [base copy];
    NSMutableDictionary *h = [base mutableCopy];
    [h addEntriesFromDictionary:extra];
    return h;
}

static DHNetSnap *dh_snap_from_request(NSURLRequest *req, id session) {
    DHNetSnap *s = [DHNetSnap new];
    s.method = req.HTTPMethod ?: @"GET";
    s.url = req.URL.absoluteString ?: @"";
    NSMutableDictionary *h = [NSMutableDictionary dictionary];
    if ([session isKindOfClass:[NSURLSession class]]) {
        NSDictionary *add = ((NSURLSession *)session).configuration.HTTPAdditionalHeaders;
        if (add.count) [h addEntriesFromDictionary:add];
    }
    if (req.allHTTPHeaderFields.count) [h addEntriesFromDictionary:req.allHTTPHeaderFields];
    s.headers = h;
    NSData *body = req.HTTPBody;
    if (!body.length) body = objc_getAssociatedObject(req, kDHSetHTTPBody);
    s.body = body;
    // HTTPBodyStream 的字节读出来就会消耗原流 (系统随后还要用它发包), 且超长流无法无损重建,
    // 故只做诚实标注、不读内容。AFNetworking multipart 等上传走的正是这条路。
    if (!body.length && req.HTTPBodyStream)
        s.bodyNote = @"[request body carried by HTTPBodyStream — not captured]";
    s.callStack = DHCallStackFiltered();
    s.tsMs = dh_now_ms();
    s.tid = dh_cur_tid();
    return s;
}

static void dh_attach_snap(id task, DHNetSnap *snap) {
    if (task && snap) objc_setAssociatedObject(task, kDHNetSnap, snap, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

static void (*orig_setHTTPBody)(id, SEL, NSData *) = NULL;
static void swz_setHTTPBody(id self, SEL _cmd, NSData *body) {
    if (body) objc_setAssociatedObject(self, kDHSetHTTPBody, body, OBJC_ASSOCIATION_COPY_NONATOMIC);
    if (orig_setHTTPBody) orig_setHTTPBody(self, _cmd, body);
}

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

static void net_append_headers(NSMutableString *d, NSDictionary *hdrs) {
    if (!hdrs.count) return;
    for (id k in hdrs) [d appendFormat:@"%@: %@\n", k, hdrs[k]];
}

// 构造一条网络 entry (不落库): input=请求体 / output=响应体。
// tsMs/tid 为「请求构建时刻」的值(不是响应到达时刻), 保证与算 Header 的 crypto 落在同一时间窗/线程。
// detail 用 \x1e 分成「纯请求 / 纯响应 / 错误」三段, 请求段只有 METHOD URL + Header: value, 不加任何标签。
// 响应三元(respData/resp/err)全 nil 时即「只有请求」的条目 —— 无响应也照样成条, 绝不因此丢弃。
static DHLogEntry *dh_net_make_entry(NSString *method, NSString *urlStr, NSDictionary *reqHdrs, NSData *reqBody,
                                     NSString *bodyNote, NSData *respData, NSURLResponse *resp, NSString *respNote,
                                     NSError *err, NSString *callStack,
                                     uint64_t tsMs, uint64_t tid) {
    NSMutableString *req = [NSMutableString stringWithFormat:@"%@ %@\n", method ?: @"GET", urlStr ?: @"?"];
    net_append_headers(req, reqHdrs);
    if (bodyNote.length) [req appendFormat:@"%@\n", bodyNote];
    NSMutableString *respPart = [NSMutableString string];
    if ([resp isKindOfClass:[NSHTTPURLResponse class]]) {
        NSHTTPURLResponse *http = (NSHTTPURLResponse *)resp;
        [respPart appendFormat:@"%ld\n", (long)http.statusCode];
        net_append_headers(respPart, http.allHeaderFields);
    }
    if (respNote.length) [respPart appendFormat:@"%@\n", respNote];
    NSString *errPart = err.localizedDescription ?: @"";
    NSString *d = [NSString stringWithFormat:@"%@\x1e%@\x1e%@", req, respPart, errPart];

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
    return e;
}

// 一次性追加一条完整配对记录 (无 task 身份可挂时用: NSURLConnection 便捷方法等)。
static void net_log_pair(NSString *method, NSString *urlStr, NSDictionary *reqHdrs, NSData *reqBody,
                         NSData *respData, NSURLResponse *resp, NSError *err, NSString *callStack,
                         uint64_t tsMs, uint64_t tid) {
    if (!dh_capture_sub_enabled(DH_CAP_NETWORK)) return;
    [[DHLogStore shared] append:dh_net_make_entry(method, urlStr, reqHdrs, reqBody, nil,
                                                  respData, resp, nil, err, callStack, tsMs, tid)];
}

// ============================================================
// 1) completion-handler 建任务 (请求↔响应配对)
// ============================================================
typedef void (^DHDataCH)(NSData *, NSURLResponse *, NSError *);

static id (*orig_dtReqCH)(id, SEL, NSURLRequest *, DHDataCH) = NULL;
static id (*orig_dtURLCH)(id, SEL, NSURL *, DHDataCH) = NULL;
static id (*orig_upReqCH)(id, SEL, NSURLRequest *, NSData *, DHDataCH) = NULL;
static id (*orig_dtReq)(id, SEL, NSURLRequest *) = NULL;
static id (*orig_upReq)(id, SEL, NSURLRequest *, NSData *) = NULL;

// 下载任务 completion 块签名: (下载落地临时文件 URL, 响应, 错误)。响应体是磁盘文件, 不读内容,
// 只配对 URL+状态码+响应头(请求仍完整), 把「请求-only」升级成「请求↔响应」记录。
typedef void (^DHDownloadCH)(NSURL *, NSURLResponse *, NSError *);
static id (*orig_dlReqCH)(id, SEL, NSURLRequest *, DHDownloadCH) = NULL;
static id (*orig_dlURLCH)(id, SEL, NSURL *, DHDownloadCH) = NULL;
// 断点续传下载: 入参是 resume data(二进制 blob), 此刻拿不到 URLRequest。
static id (*orig_dlResumeCH)(id, SEL, NSData *, DHDownloadCH) = NULL;
// 文件上传: body 是磁盘文件, 建任务时读一段前缀当请求体快照 (完整文件可能是大视频, 必须限长)。
static id (*orig_upFileCH)(id, SEL, NSURLRequest *, NSURL *, DHDataCH) = NULL;
static id (*orig_upFile)(id, SEL, NSURLRequest *, NSURL *) = NULL;

// fromFile 上传体前缀上限: 只取头部足够分析(magic/头部结构), 避免把整段大文件塞进日志内存。
#define DH_NET_MAX_FILE_BODY (1 * 1024 * 1024)

// 读文件 URL 前缀作请求体快照。用 NSFileHandle readDataOfLength: 只读头部, 不映射整文件;
// 全程 @try/@catch, 任何异常静默降级返回 nil (不崩宿主)。
static NSData *dh_body_from_fileurl(NSURL *fileURL) {
    if (![fileURL isKindOfClass:[NSURL class]] || !fileURL.isFileURL) return nil;
    NSData *out = nil;
    @try {
        NSFileHandle *fh = [NSFileHandle fileHandleForReadingFromURL:fileURL error:NULL];
        if (fh) {
            out = [fh readDataOfLength:DH_NET_MAX_FILE_BODY];
            @try { [fh closeFile]; } @catch (__unused NSException *e) {}
        }
    } @catch (__unused NSException *e) { out = nil; }
    return out.length ? out : nil;
}

// dataTaskWithURL:/downloadTaskWithURL: 没有 NSURLRequest, 用 URL 直接造快照, 让 resume 与
// completion 共用同一份请求锚点(时刻/调用栈/URL), 保证「请求先记、响应后配」两步落到同一条。
static DHNetSnap *dh_snap_from_url(NSURL *url, NSString *method) {
    DHNetSnap *s = [DHNetSnap new];
    s.method = method ?: @"GET";
    s.url = url.absoluteString ?: @"";
    s.headers = nil;
    s.body = nil;
    s.callStack = DHCallStackFiltered();
    s.tsMs = dh_now_ms();
    s.tid = dh_cur_tid();
    return s;
}

// 响应/错误到达: 构造「请求+响应」完整条目, 原子替换 resume 时先记的「只有请求」条目 (kDHNetEntry)。
// 若该 task 没有先记条目(极少数: resume 没命中), 退化为直接追加一条完整记录, 绝不丢包。
static void dh_net_enrich(id task, DHNetSnap *snap, NSData *respData, NSURLResponse *resp, NSError *err) {
    if (!dh_capture_sub_enabled(DH_CAP_NETWORK)) return;
    NSURLRequest *cur = [task isKindOfClass:[NSURLSessionTask class]] ? [(NSURLSessionTask *)task currentRequest] : nil;
    NSDictionary *hdrs = dh_merge_headers(snap.headers, cur.allHTTPHeaderFields);
    NSData *body = snap.body ?: cur.HTTPBody;
    if (!body.length) body = objc_getAssociatedObject(cur, kDHSetHTTPBody);
    DHLogEntry *full = dh_net_make_entry(snap.method, snap.url, hdrs, body, snap.bodyNote,
                                         respData, resp, snap.respNote, err, snap.callStack, snap.tsMs, snap.tid);
    DHLogEntry *eager = task ? objc_getAssociatedObject(task, kDHNetEntry) : nil;
    if (eager) {
        [[DHLogStore shared] replaceNetworkEntry:eager with:full];
        objc_setAssociatedObject(task, kDHNetEntry, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    } else {
        [[DHLogStore shared] append:full];
    }
}

// -[NSURLSession dataTaskWithRequest:completionHandler:]
// 建任务时挂快照; resume 会先记「只有请求」的条目; 这里响应到达时原子替换成完整条目。
static id swz_dtReqCH(id self, SEL _cmd, NSURLRequest *req, DHDataCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_dtReqCH(self, _cmd, req, ch);
    DHNetSnap *snap = dh_snap_from_request(req, self);
    __block __weak id weakTask = nil;
    DHDataCH wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        @try { dh_net_enrich(weakTask, snap, data, resp, err); }
        @catch (__unused NSException *e) {}
        ch(data, resp, err);
    };
    id task = orig_dtReqCH(self, _cmd, req, wrapped);
    weakTask = task;
    dh_attach_snap(task, snap);
    return task;
}

// -[NSURLSession dataTaskWithURL:completionHandler:]
static id swz_dtURLCH(id self, SEL _cmd, NSURL *url, DHDataCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_dtURLCH(self, _cmd, url, ch);
    DHNetSnap *snap = dh_snap_from_url(url, @"GET");
    __block __weak id weakTask = nil;
    DHDataCH wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        @try { dh_net_enrich(weakTask, snap, data, resp, err); }
        @catch (__unused NSException *e) {}
        ch(data, resp, err);
    };
    id task = orig_dtURLCH(self, _cmd, url, wrapped);
    weakTask = task;
    dh_attach_snap(task, snap);
    return task;
}

// -[NSURLSession uploadTaskWithRequest:fromData:completionHandler:]
static id swz_upReqCH(id self, SEL _cmd, NSURLRequest *req, NSData *bodyData, DHDataCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_upReqCH(self, _cmd, req, bodyData, ch);
    DHNetSnap *snap = dh_snap_from_request(req, self);
    if (bodyData.length) snap.body = bodyData;
    __block __weak id weakTask = nil;
    DHDataCH wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        @try { dh_net_enrich(weakTask, snap, data, resp, err); }
        @catch (__unused NSException *e) {}
        ch(data, resp, err);
    };
    id task = orig_upReqCH(self, _cmd, req, bodyData, wrapped);
    weakTask = task;
    dh_attach_snap(task, snap);
    return task;
}

// 无 completion 的建任务: 只快照 body/头, 响应仍走 resume 兜底(只有请求)。
static id swz_dtReq(id self, SEL _cmd, NSURLRequest *req) {
    if (!orig_dtReq) return nil;
    id task = orig_dtReq(self, _cmd, req);
    if (dh_capture_sub_enabled(DH_CAP_NETWORK) && !objc_getAssociatedObject(task, kDHNetSnap))
        dh_attach_snap(task, dh_snap_from_request(req, self));
    return task;
}

static id swz_upReq(id self, SEL _cmd, NSURLRequest *req, NSData *bodyData) {
    if (!orig_upReq) return nil;
    id task = orig_upReq(self, _cmd, req, bodyData);
    if (dh_capture_sub_enabled(DH_CAP_NETWORK) && !objc_getAssociatedObject(task, kDHNetSnap)) {
        DHNetSnap *snap = dh_snap_from_request(req, self);
        if (bodyData.length) snap.body = bodyData;
        dh_attach_snap(task, snap);
    }
    return task;
}

// 下载落地文件预览上限: 只读头部作 output 预览(magic/文本头), 不把整文件塞进日志内存。
// 落盘 blob 另有 64KB 上限, 这里取同样量级。
#define DH_NET_MAX_DOWNLOAD_PREVIEW (64 * 1024)

// 下载完成: 读落地文件前缀作响应体预览 + 文件名/大小注记。必须在原 ch 被调用前同步读完,
// 系统随后可能删除该临时文件。全程 @try/@catch, 失败降级为原来的 nil(只配对状态码)。
static void dh_snap_download_preview(DHNetSnap *snap, NSURL *location, NSURLResponse *resp) {
    if (!snap || !location.isFileURL) return;
    @try {
        NSString *name = resp.suggestedFilename ?: location.lastPathComponent ?: @"?";
        unsigned long long size = 0;
        NSNumber *sz = nil;
        if ([location getResourceValue:&sz forKey:NSURLFileSizeKey error:NULL] && sz)
            size = sz.unsignedLongLongValue;
        NSData *head = dh_body_from_fileurl(location);
        if (head.length > DH_NET_MAX_DOWNLOAD_PREVIEW)
            head = [head subdataWithRange:NSMakeRange(0, DH_NET_MAX_DOWNLOAD_PREVIEW)];
        // dh_body_from_fileurl 上限 1MB, 这里再压到 64KB 预览。
        snap.dlPreview = head.length ? head : nil;
        snap.respNote = [NSString stringWithFormat:@"[download] %@ (%llu bytes%@)", name, size,
                         head.length ? @", head preview captured" : @""];
    } @catch (__unused NSException *e) {}
}

// -[NSURLSession downloadTaskWithRequest:completionHandler:] —— 响应落地为文件, 取 64KB 前缀
// 作响应体预览, 仍把 resume 先记的「只有请求」条目原子替换成完整条目。
static id swz_dlReqCH(id self, SEL _cmd, NSURLRequest *req, DHDownloadCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_dlReqCH(self, _cmd, req, ch);
    DHNetSnap *snap = dh_snap_from_request(req, self);
    __block __weak id weakTask = nil;
    DHDownloadCH wrapped = ^(NSURL *location, NSURLResponse *resp, NSError *err) {
        @try {
            dh_snap_download_preview(snap, location, resp);
            dh_net_enrich(weakTask, snap, snap.dlPreview, resp, err);
        }
        @catch (__unused NSException *e) {}
        ch(location, resp, err);
    };
    id task = orig_dlReqCH(self, _cmd, req, wrapped);
    weakTask = task;
    dh_attach_snap(task, snap);
    return task;
}

// -[NSURLSession downloadTaskWithURL:completionHandler:]
static id swz_dlURLCH(id self, SEL _cmd, NSURL *url, DHDownloadCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_dlURLCH(self, _cmd, url, ch);
    DHNetSnap *snap = dh_snap_from_url(url, @"GET");
    __block __weak id weakTask = nil;
    DHDownloadCH wrapped = ^(NSURL *location, NSURLResponse *resp, NSError *err) {
        @try {
            dh_snap_download_preview(snap, location, resp);
            dh_net_enrich(weakTask, snap, snap.dlPreview, resp, err);
        }
        @catch (__unused NSException *e) {}
        ch(location, resp, err);
    };
    id task = orig_dlURLCH(self, _cmd, url, wrapped);
    weakTask = task;
    dh_attach_snap(task, snap);
    return task;
}

// -[NSURLSession downloadTaskWithResumeData:completionHandler:] —— 断点续传下载。
// 建任务时请求对象还没解析出来（入参是 resume data），所以只挂空快照 + 说明，
// 真正的 METHOD/URL/Header 由 resume 时的兜底路径补上；响应照常配对为完整条目。
static id swz_dlResumeCH(id self, SEL _cmd, NSData *resumeData, DHDownloadCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_dlResumeCH(self, _cmd, resumeData, ch);
    DHNetSnap *snap = dh_snap_from_request(nil, self);
    snap.bodyNote = @"[resume] 断点续传下载，请求体不适用";
    __block __weak id weakTask = nil;
    DHDownloadCH wrapped = ^(NSURL *location, NSURLResponse *resp, NSError *err) {
        @try {
            dh_snap_download_preview(snap, location, resp);
            dh_net_enrich(weakTask, snap, snap.dlPreview, resp, err);
        }
        @catch (__unused NSException *e) {}
        ch(location, resp, err);
    };
    id task = orig_dlResumeCH(self, _cmd, resumeData, wrapped);
    weakTask = task;
    dh_attach_snap(task, snap);
    return task;
}

// -[NSURLSession uploadTaskWithRequest:fromFile:completionHandler:] —— 请求体取自磁盘文件前缀。
static id swz_upFileCH(id self, SEL _cmd, NSURLRequest *req, NSURL *fileURL, DHDataCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_upFileCH(self, _cmd, req, fileURL, ch);
    DHNetSnap *snap = dh_snap_from_request(req, self);
    if (!snap.body.length) { NSData *fb = dh_body_from_fileurl(fileURL); if (fb.length) snap.body = fb; }
    __block __weak id weakTask = nil;
    DHDataCH wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        @try { dh_net_enrich(weakTask, snap, data, resp, err); }
        @catch (__unused NSException *e) {}
        ch(data, resp, err);
    };
    id task = orig_upFileCH(self, _cmd, req, fileURL, wrapped);
    weakTask = task;
    dh_attach_snap(task, snap);
    return task;
}

// 无 completion 的 fromFile 上传: 只快照请求(含文件前缀 body), 响应走 resume 兜底(只有请求)。
static id swz_upFile(id self, SEL _cmd, NSURLRequest *req, NSURL *fileURL) {
    if (!orig_upFile) return nil;
    id task = orig_upFile(self, _cmd, req, fileURL);
    if (dh_capture_sub_enabled(DH_CAP_NETWORK) && !objc_getAssociatedObject(task, kDHNetSnap)) {
        DHNetSnap *snap = dh_snap_from_request(req, self);
        if (!snap.body.length) { NSData *fb = dh_body_from_fileurl(fileURL); if (fb.length) snap.body = fb; }
        dh_attach_snap(task, snap);
    }
    return task;
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
// 2) resume: 请求一发出就先记一条「只有请求」的条目 (无响应也留档)
// ============================================================
// 每个 task 首次 resume 时立刻记录请求并把该条目挂到 task(kDHNetEntry)。这条日志此刻已完整落库/落盘,
// 即使随后请求超时无响应、宿主进程被杀、或走 delegate 无回调, 请求都不会丢。响应/错误到达时(见
// dh_net_enrich)再用完整条目原子替换本条 —— 有响应则补全, 没有就永远保留为「只有请求」。
static void (*orig_task_resume)(id, SEL) = NULL;
static void swz_task_resume(id self, SEL _cmd) {
    @try {
        if (dh_capture_sub_enabled(DH_CAP_NETWORK) &&
            !objc_getAssociatedObject(self, kDHNetEntry)) {   // 每个 task 只在首个 resume 记一次
            NSURLSessionTask *task = (NSURLSessionTask *)self;
            NSURLRequest *req = task.currentRequest ?: task.originalRequest;
            DHNetSnap *snap = objc_getAssociatedObject(self, kDHNetSnap);
            NSString *urlStr = snap.url.length ? snap.url : req.URL.absoluteString;
            if (urlStr.length) {
                NSString *method = snap.method ?: (req.HTTPMethod ?: @"GET");
                NSDictionary *hdrs = dh_merge_headers(snap.headers, req.allHTTPHeaderFields);
                NSData *body = snap.body ?: req.HTTPBody;
                if (!body.length) body = objc_getAssociatedObject(req, kDHSetHTTPBody);
                // WebSocket 任务不走 data/upload 建任务 swizzle、无 completion 配对, resume 兜底是
                // 唯一记录点: 握手请求能留档, 但 101 之后的消息帧不在覆盖内, 诚实标注。
                NSString *note = snap.bodyNote;
                if (!note.length && [self respondsToSelector:@selector(sendMessage:completionHandler:)])
                    note = @"[websocket handshake — message frames not captured]";
                // 只记请求段(响应/错误留空); 保留请求时刻/线程/调用栈, 便于与 crypto 关联。
                DHLogEntry *eager = dh_net_make_entry(method, urlStr, hdrs, body, note,
                                                      nil, nil, nil, nil,
                                                      snap.callStack ?: DHCallStackFiltered(),
                                                      snap.tsMs ? snap.tsMs : dh_now_ms(),
                                                      snap.tid ? snap.tid : dh_cur_tid());
                objc_setAssociatedObject(self, kDHNetEntry, eager, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
                [[DHLogStore shared] append:eager];
            }
        }
    } @catch (__unused NSException *ex) {}
    if (orig_task_resume) orig_task_resume(self, _cmd);
}

// resume 兜底装载: -[NSURLSessionTask resume] 的真实实现常落在私有具体子类
// (__NSCFURLSessionTask / __NSCFLocalDownloadTask ...)上, 直接 swizzle 基类会打空 → delegate
// 型任务的请求全部漏抓。这里造一个不 resume 的探针任务, 沿其类继承链向上找「自身真正实现 resume」
// 的那个类再换实现, 与 FLEX/AFNetworking 同法。全程 @try/@catch, 失败回退基类。
static void install_resume_hook(void) {
    Class baseCls = NSClassFromString(@"NSURLSessionTask");
    Class implCls = baseCls;
    @try {
        NSURLSession *sess = [NSURLSession sharedSession];
        // 用 dataTaskWithURL: (未被本模块 swizzle、绝不 resume)造探针, 只为读它的具体类。
        id probe = [sess dataTaskWithURL:[NSURL URLWithString:@"http://127.0.0.1/"]];
        if (probe) {
            Class c = object_getClass(probe);
            while (c && c != [NSObject class]) {
                unsigned int n = 0;
                Method *ms = class_copyMethodList(c, &n);
                BOOL found = NO;
                for (unsigned int i = 0; i < n; i++)
                    if (method_getName(ms[i]) == @selector(resume)) { found = YES; break; }
                if (ms) free(ms);
                if (found) { implCls = c; break; }
                c = class_getSuperclass(c);
            }
            @try { [probe cancel]; } @catch (__unused NSException *e) {}
        }
    } @catch (__unused NSException *e) { implCls = baseCls; }
    if (!implCls) implCls = baseCls;

    Method m = implCls ? class_getInstanceMethod(implCls, @selector(resume)) : NULL;
    if (m) {
        orig_task_resume = (void (*)(id, SEL))method_getImplementation(m);
        method_setImplementation(m, (IMP)swz_task_resume);
    } else {
        dh_health_hook_fail(DH_DIAG_SYS, "-[NSURLSessionTask resume]");
    }
}

static void install_urlsession_hook(void) {
    // 配对: 在「shared session 的真实类」上换 completion 建任务方法 (custom session 同为该私有类)
    Class sc = object_getClass([NSURLSession sharedSession]) ?: NSClassFromString(@"NSURLSession");
    swz_instance(sc, @selector(dataTaskWithRequest:completionHandler:),          (IMP)swz_dtReqCH, (IMP *)&orig_dtReqCH);
    swz_instance(sc, @selector(dataTaskWithURL:completionHandler:),              (IMP)swz_dtURLCH, (IMP *)&orig_dtURLCH);
    swz_instance(sc, @selector(uploadTaskWithRequest:fromData:completionHandler:),(IMP)swz_upReqCH, (IMP *)&orig_upReqCH);
    swz_instance(sc, @selector(dataTaskWithRequest:),                         (IMP)swz_dtReq, (IMP *)&orig_dtReq);
    swz_instance(sc, @selector(uploadTaskWithRequest:fromData:),            (IMP)swz_upReq, (IMP *)&orig_upReq);
    // 下载 / 文件上传 completion 建任务 (响应配对 + fromFile 请求体快照)
    swz_instance(sc, @selector(downloadTaskWithRequest:completionHandler:),      (IMP)swz_dlReqCH, (IMP *)&orig_dlReqCH);
    swz_instance(sc, @selector(downloadTaskWithURL:completionHandler:),          (IMP)swz_dlURLCH, (IMP *)&orig_dlURLCH);
    swz_instance(sc, @selector(downloadTaskWithResumeData:completionHandler:),   (IMP)swz_dlResumeCH, (IMP *)&orig_dlResumeCH);
    swz_instance(sc, @selector(uploadTaskWithRequest:fromFile:completionHandler:),(IMP)swz_upFileCH, (IMP *)&orig_upFileCH);
    swz_instance(sc, @selector(uploadTaskWithRequest:fromFile:),                 (IMP)swz_upFile, (IMP *)&orig_upFile);

    Class mreq = NSClassFromString(@"NSMutableURLRequest");
    if (!swz_instance(mreq, @selector(setHTTPBody:), (IMP)swz_setHTTPBody, (IMP *)&orig_setHTTPBody))
        dh_health_hook_fail(DH_DIAG_SYS, "-[NSMutableURLRequest setHTTPBody:]");

    // 兜底: resume (delegate 型任务的请求) —— 定位真实实现类, 避免打空基类
    install_resume_hook();
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

// OpenSSL 1.1.1+ 的 *_ex 变体: 成功返回 1, 实际收发字节写入出参。BoringSSL/新 OpenSSL 常走这两个,
// 只 hook SSL_write/read 会漏。未被 App 导入时 fishhook 不会绑定, orig 保持 NULL, hook 亦不触发。
static int (*orig_SSL_write_ex)(void *, const void *, size_t, size_t *) = NULL;
static int (*orig_SSL_read_ex)(void *, void *, size_t, size_t *) = NULL;

static int hooked_SSL_write_ex(void *ssl, const void *buf, size_t num, size_t *written) {
    int r = orig_SSL_write_ex ? orig_SSL_write_ex(ssl, buf, num, written) : 0;
    if (r == 1 && buf && written && *written > 0 && dh_capture_sub_enabled(DH_CAP_NETWORK))
        net_log(@"TLS", @"send", [NSString stringWithFormat:@"SSL=%p len=%zu", ssl, *written],
                [NSData dataWithBytes:buf length:*written]);
    return r;
}
static int hooked_SSL_read_ex(void *ssl, void *buf, size_t num, size_t *readbytes) {
    int r = orig_SSL_read_ex ? orig_SSL_read_ex(ssl, buf, num, readbytes) : 0;
    if (r == 1 && buf && readbytes && *readbytes > 0 && dh_capture_sub_enabled(DH_CAP_NETWORK))
        net_log(@"TLS", @"recv", [NSString stringWithFormat:@"SSL=%p len=%zu", ssl, *readbytes],
                [NSData dataWithBytes:buf length:*readbytes]);
    return r;
}
static void install_ssl_hooks(void) {
    struct rebinding r[] = {
        {"SSL_write",    hooked_SSL_write,    (void **)&orig_SSL_write},
        {"SSL_read",     hooked_SSL_read,     (void **)&orig_SSL_read},
        {"SSL_write_ex", hooked_SSL_write_ex, (void **)&orig_SSL_write_ex},
        {"SSL_read_ex",  hooked_SSL_read_ex,  (void **)&orig_SSL_read_ex},
    };
    rebind_symbols(r, sizeof(r) / sizeof(r[0]));
    dh_dlsym_register_rebindings(r, sizeof(r) / sizeof(r[0]));
}

// ============================================================
// 4) NSURLConnection 兜底 (老 API, 部分 SDK 仍用; 只覆盖两个便捷方法, 不碰 delegate 型以免与
//    便捷方法内部连接双记)。注意块参数顺序是 (response, data, error), 与 NSURLSession 相反。
// ============================================================
typedef void (^DHConnCH)(NSURLResponse *, NSData *, NSError *);

static BOOL swz_class_method(Class cls, SEL sel, IMP newImp, IMP *origOut) {
    if (!cls) return NO;
    Method m = class_getClassMethod(cls, sel);
    if (!m) return NO;
    *origOut = method_getImplementation(m);
    method_setImplementation(m, newImp);
    return YES;
}

// +[NSURLConnection sendAsynchronousRequest:queue:completionHandler:]
static void (*orig_conn_async)(id, SEL, NSURLRequest *, id, DHConnCH) = NULL;
static void swz_conn_async(id self, SEL _cmd, NSURLRequest *req, id queue, DHConnCH ch) {
    if (!ch || !dh_capture_sub_enabled(DH_CAP_NETWORK)) {
        if (orig_conn_async) orig_conn_async(self, _cmd, req, queue, ch);
        return;
    }
    DHNetSnap *snap = dh_snap_from_request(req, nil);
    DHConnCH wrapped = ^(NSURLResponse *resp, NSData *data, NSError *err) {
        @try {
            net_log_pair(snap.method, snap.url, snap.headers, snap.body,
                         data, resp, err, snap.callStack, snap.tsMs, snap.tid);
        } @catch (__unused NSException *e) {}
        ch(resp, data, err);
    };
    if (orig_conn_async) orig_conn_async(self, _cmd, req, queue, wrapped);
}

// +[NSURLConnection sendSynchronousRequest:returningResponse:error:]
static NSData *(*orig_conn_sync)(id, SEL, NSURLRequest *, NSURLResponse **, NSError **) = NULL;
static NSData *swz_conn_sync(id self, SEL _cmd, NSURLRequest *req, NSURLResponse **respOut, NSError **errOut) {
    if (!orig_conn_sync) return nil;
    if (!dh_capture_sub_enabled(DH_CAP_NETWORK)) return orig_conn_sync(self, _cmd, req, respOut, errOut);
    DHNetSnap *snap = dh_snap_from_request(req, nil);
    NSData *data = orig_conn_sync(self, _cmd, req, respOut, errOut);
    @try {
        NSURLResponse *resp = respOut ? *respOut : nil;
        NSError *err = errOut ? *errOut : nil;
        net_log_pair(snap.method, snap.url, snap.headers, snap.body,
                     data, resp, err, snap.callStack, snap.tsMs, snap.tid);
    } @catch (__unused NSException *e) {}
    return data;
}

static void install_nsurlconnection_hook(void) {
    Class conn = NSClassFromString(@"NSURLConnection");
    if (!conn) return;   // 系统可能已下线该类
    swz_class_method(conn, @selector(sendAsynchronousRequest:queue:completionHandler:),
                     (IMP)swz_conn_async, (IMP *)&orig_conn_async);
    swz_class_method(conn, @selector(sendSynchronousRequest:returningResponse:error:),
                     (IMP)swz_conn_sync, (IMP *)&orig_conn_sync);
}

// ============================================================
void dh_install_network_hooks(void) {
    install_urlsession_hook();
    install_nsurlconnection_hook();
    install_ssl_hooks();
}
