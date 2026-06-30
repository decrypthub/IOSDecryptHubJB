// log_store.m
#import "log_store.h"
#import "dh_health.h"
#import "dh_capture.h"
#import <sys/sysctl.h>
#import <errno.h>

@implementation DHLogEntry
@end

@interface DHLogStore () {
    NSMutableArray<DHLogEntry *> *_buckets[DHCategoryOther + 1];   // 每类独立环形缓冲, 互不挤占
    dispatch_queue_t              _queue;       // 写入串行队列
    NSUInteger                    _categoryCounts[DHCategoryOther + 1];
    uint64_t                      _seqCounter;
    NSString                     *_filePath;
}
@end

@implementation DHLogStore

static const NSUInteger kMaxPerCategory = 2000;          // 每个分类最多保留 2000 条 (各自独立)
static const NSUInteger kMaxBlobLogged  = 64 * 1024;     // 单段 blob 落盘上限 64KB

+ (instancetype)shared {
    static DHLogStore *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[DHLogStore alloc] init]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        for (int c = 0; c <= DHCategoryOther; c++) _buckets[c] = [NSMutableArray array];
        _queue = dispatch_queue_create("com.decrypthelper.logstore", DISPATCH_QUEUE_SERIAL);
        _seqCounter = 0;
        memset(_categoryCounts, 0, sizeof(_categoryCounts));
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        _filePath = [[paths firstObject] stringByAppendingPathComponent:@"decrypt_helper.log"];
    }
    return self;
}

- (NSString *)logFilePath { return _filePath; }

- (void)append:(DHLogEntry *)entry {
    if (self.paused || entry == nil) return;
    NSInteger ci = (entry.category >= 0 && entry.category <= DHCategoryOther) ? entry.category : DHCategoryOther;
    if (dh_capture_cat_paused((int)ci)) return;            // 该分类已暂停(单一真相源在 dh_capture, 已持久化)
    dispatch_async(_queue, ^{
        entry.seq = ++self->_seqCounter;
        NSMutableArray *b = self->_buckets[ci];
        [b addObject:entry];
        if (b.count > kMaxPerCategory)
            [b removeObjectsInRange:NSMakeRange(0, b.count - kMaxPerCategory)];
        self->_categoryCounts[ci]++;
        [self _persist:entry];
    });
}

- (void)setPaused:(BOOL)paused forCategory:(DHCategory)cat {
    if (cat < 0 || cat > DHCategoryOther) return;
    dh_capture_set_cat_paused((int)cat, paused ? 1 : 0);   // 写入 dh_capture 并持久化
}
- (BOOL)isPausedForCategory:(DHCategory)cat {
    if (cat < 0 || cat > DHCategoryOther) return NO;
    return dh_capture_cat_paused((int)cat) ? YES : NO;
}

// 合并所有桶并按 seq 升序 (供「全部」视图 / 落盘快照)。须在 _queue 内调用。
- (NSArray<DHLogEntry *> *)_mergedAllLocked {
    NSMutableArray *all = [NSMutableArray array];
    for (int c = 0; c <= DHCategoryOther; c++) [all addObjectsFromArray:_buckets[c]];
    [all sortUsingComparator:^NSComparisonResult(DHLogEntry *a, DHLogEntry *b) {
        return a.seq < b.seq ? NSOrderedAscending : (a.seq > b.seq ? NSOrderedDescending : NSOrderedSame);
    }];
    return all;
}

// 取某分类切片: -2=加密组(0..3) 合并排序; 0..Other=单桶(本就 seq 升序); 其它=全部。须在 _queue 内调用。
- (NSArray<DHLogEntry *> *)_categorySliceLocked:(NSInteger)cat {
    if (cat == -2) {
        NSMutableArray *m = [NSMutableArray array];
        for (int c = DHCategoryDigest; c <= DHCategoryAsymmetric; c++) [m addObjectsFromArray:_buckets[c]];
        [m sortUsingComparator:^NSComparisonResult(DHLogEntry *a, DHLogEntry *b) {
            return a.seq < b.seq ? NSOrderedAscending : (a.seq > b.seq ? NSOrderedDescending : NSOrderedSame);
        }];
        return m;
    }
    if (cat >= 0 && cat <= DHCategoryOther) return [_buckets[cat] copy];
    return [self _mergedAllLocked];
}

// 把一条日志格式化成可读文本块(落盘与「按板块下载」共用同一格式)。
static NSMutableString *dh_entry_block(DHLogEntry *e) {
    NSMutableString *s = [NSMutableString string];
    [s appendString:@"========================================\n"];
    [s appendFormat:@"#%llu  [%@]  %@  %@\n",
        (unsigned long long)e.seq, e.timestamp, e.algorithm ?: @"?", e.operation ?: @""];
    if (e.key) {
        [s appendFormat:@"-- KEY (%lu bytes) hex:\n%@\n", (unsigned long)e.key.length,
            DHHexFromData([e.key subdataWithRange:NSMakeRange(0, MIN(e.key.length, kMaxBlobLogged))])];
    }
    if (e.iv) {
        [s appendFormat:@"-- IV (%lu bytes) hex:\n%@\n", (unsigned long)e.iv.length,
            DHHexFromData([e.iv subdataWithRange:NSMakeRange(0, MIN(e.iv.length, kMaxBlobLogged))])];
    }
    if (e.publicKeyInfo) {
        [s appendFormat:@"-- KeyInfo: %@\n", e.publicKeyInfo];
    }
    if (e.detail) {
        [s appendFormat:@"-- Detail: %@\n", e.detail];
    }
    if (e.input) {
        NSData *d = e.input.length > kMaxBlobLogged
            ? [e.input subdataWithRange:NSMakeRange(0, kMaxBlobLogged)] : e.input;
        [s appendFormat:@"-- INPUT (%lu bytes)\nUTF-8: %@\nHex: %@\nDump:\n%@\n",
            (unsigned long)e.input.length, DHUTF8FromData(d), DHHexFromData(d), DHHexDumpFromData(d)];
    }
    if (e.output) {
        NSData *d = e.output.length > kMaxBlobLogged
            ? [e.output subdataWithRange:NSMakeRange(0, kMaxBlobLogged)] : e.output;
        [s appendFormat:@"-- OUTPUT (%lu bytes)\nHex: %@\n", (unsigned long)e.output.length, DHHexFromData(d)];
    }
    if (e.callStack.length) {
        [s appendFormat:@"-- CallStack:\n%@\n", e.callStack];
    }
    [s appendString:@"\n"];
    return s;
}

- (void)_persist:(DHLogEntry *)e {
    NSMutableString *s = dh_entry_block(e);
    NSData *bytes = [s dataUsingEncoding:NSUTF8StringEncoding];
    if (!bytes) { DH_ERR(@"日志 UTF-8 编码失败, 丢弃 #%llu", (unsigned long long)e.seq); return; }
    // 关键: 落盘自身的 open/write(写 decrypt_helper.log) 不能被 file hook 再记录, 否则
    // write -> 记录 -> append -> _persist -> write 无限自我循环. 落盘期间置 dh_in_hook.
    dh_in_hook = 1;
    @try {
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:_filePath]) {
            NSError *werr = nil;
            if (![bytes writeToFile:_filePath options:NSDataWritingAtomic error:&werr]) {
                dh_health_persist_fail((int)werr.code);
                DH_ERR(@"日志落盘失败(创建 %@): %@", _filePath, werr.localizedDescription);
            }
        } else {
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:_filePath];
            if (!fh) {
                dh_health_persist_fail(errno);
                DH_ERR(@"日志落盘失败: 无法打开 %@ (errno=%d)", _filePath, errno);
            } else {
                @try {
                    [fh seekToEndOfFile];
                    [fh writeData:bytes];
                    [fh closeFile];
                } @catch (NSException *ex) {
                    dh_health_persist_fail(errno);
                    DH_ERR(@"日志落盘失败(追加): %@", ex.reason);
                }
            }
        }
    } @finally {
        dh_in_hook = 0;
    }
}

- (NSArray<DHLogEntry *> *)snapshot {
    __block NSArray *r = nil;
    dispatch_sync(_queue, ^{ r = [self _mergedAllLocked]; });
    return r;
}

- (NSArray<DHLogEntry *> *)snapshotMatching:(NSString *)keyword
                                    category:(NSInteger)categoryOrMinusOne {
    __block NSArray *src = nil;
    dispatch_sync(_queue, ^{ src = [self _categorySliceLocked:categoryOrMinusOne]; });
    if (!keyword || keyword.length == 0) return src;

    NSMutableArray *out = [NSMutableArray array];
    NSString *kw = [keyword lowercaseString];
    for (DHLogEntry *e in src) {
        BOOL hit = NO;
        if ([[e.algorithm lowercaseString] containsString:kw]) hit = YES;
        else if ([[e.operation lowercaseString] containsString:kw]) hit = YES;
        else if (e.detail && [[e.detail lowercaseString] containsString:kw]) hit = YES;   // 网络/文件/系统按地址/路径搜
        else if (e.input && [[DHUTF8FromData(e.input) lowercaseString] containsString:kw]) hit = YES;
        else if (e.input && [[DHHexFromData(e.input) lowercaseString] containsString:kw]) hit = YES;
        else if (e.output && [[DHHexFromData(e.output) lowercaseString] containsString:kw]) hit = YES;
        if (hit) [out addObject:e];
    }
    return out;
}

- (DHLogEntry *)entryWithSeq:(uint64_t)seq {
    __block DHLogEntry *r = nil;
    dispatch_sync(_queue, ^{
        // 各桶倒着找, 命中率高 (用户多看最新)
        for (int c = 0; c <= DHCategoryOther && !r; c++) {
            NSMutableArray *b = self->_buckets[c];
            for (NSInteger i = (NSInteger)b.count - 1; i >= 0; i--) {
                DHLogEntry *e = b[i];
                if (e.seq == seq) { r = e; break; }
            }
        }
    });
    return r;
}

- (NSUInteger)totalCount {
    __block NSUInteger n;
    dispatch_sync(_queue, ^{ n = (NSUInteger)self->_seqCounter; });
    return n;
}

- (NSUInteger)countForCategory:(DHCategory)cat {
    if (cat < 0 || cat > DHCategoryOther) return 0;
    __block NSUInteger n;
    dispatch_sync(_queue, ^{ n = self->_categoryCounts[cat]; });
    return n;
}

- (void)clearAll {
    dispatch_async(_queue, ^{
        for (int c = 0; c <= DHCategoryOther; c++) [self->_buckets[c] removeAllObjects];
        self->_seqCounter = 0;
        memset(self->_categoryCounts, 0, sizeof(self->_categoryCounts));
        NSFileManager *fm = [NSFileManager defaultManager];
        if ([fm fileExistsAtPath:self->_filePath]) {
            [fm removeItemAtPath:self->_filePath error:nil];
        }
    });
}

- (void)clearCategory:(NSInteger)cat {
    dispatch_async(_queue, ^{
        if (cat == -2) {            // 加密组
            for (int c = DHCategoryDigest; c <= DHCategoryAsymmetric; c++) {
                [self->_buckets[c] removeAllObjects]; self->_categoryCounts[c] = 0;
            }
        } else if (cat >= 0 && cat <= DHCategoryOther) {
            [self->_buckets[cat] removeAllObjects]; self->_categoryCounts[cat] = 0;
        }
        // 仅清该类内存(落盘文件混所有类, 不动; 整体清空走 clearAll)
    });
}

- (NSDictionary *)processInfo {
    static NSDictionary *info = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSProcessInfo *pi = [NSProcessInfo processInfo];
        NSBundle *mb = [NSBundle mainBundle];
        char model[256] = {0}; size_t sz = sizeof(model);
        sysctlbyname("hw.machine", model, &sz, NULL, 0);
        NSString *appName = [mb objectForInfoDictionaryKey:@"CFBundleDisplayName"]
                          ?: [mb objectForInfoDictionaryKey:@"CFBundleName"] ?: @"";
        info = @{
            @"pid":             @(pi.processIdentifier),
            @"processName":     pi.processName ?: @"",
            @"bundleId":        mb.bundleIdentifier ?: @"",
            @"appName":         appName,
            @"systemVersion":   pi.operatingSystemVersionString ?: @"",
            @"deviceModel":     model[0] ? [NSString stringWithUTF8String:model] : @"",
            @"physicalMemoryMB":@(pi.physicalMemory / (1024 * 1024)),
        };
    });
    return info;
}

- (NSArray<DHLogEntry *> *)snapshotMatching:(NSString *)keyword
                                   category:(NSInteger)categoryOrMinusOne
                                    minSize:(NSUInteger)minBytes {
    NSArray<DHLogEntry *> *base = [self snapshotMatching:keyword category:categoryOrMinusOne];
    if (minBytes == 0) return base;
    NSMutableArray *out = [NSMutableArray array];
    for (DHLogEntry *e in base) {
        NSUInteger maxLen = MAX(e.input.length, e.output.length);
        if (maxLen >= minBytes) [out addObject:e];
    }
    return out;
}

- (NSString *)exportTextForCategory:(NSInteger)cat {
    NSArray<DHLogEntry *> *entries = [self snapshotMatching:nil category:cat];   // 该类(或 -2 加密组)切片
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"# IOSDecryptHub 日志导出  cat=%ld  共 %lu 条\n\n",
        (long)cat, (unsigned long)entries.count];
    for (DHLogEntry *e in entries) [out appendString:dh_entry_block(e)];
    return out;
}

@end

// =================== 工具函数 ===================
NSString *DHHexFromData(NSData *d) {
    if (!d || d.length == 0) return @"";
    NSMutableString *s = [NSMutableString stringWithCapacity:d.length * 2];
    const unsigned char *b = d.bytes;
    for (NSUInteger i = 0; i < d.length; i++) [s appendFormat:@"%02x", b[i]];
    return s;
}

NSString *DHHexDumpFromData(NSData *d) {
    if (!d || d.length == 0) return @"";
    NSMutableString *s = [NSMutableString string];
    const unsigned char *b = d.bytes;
    NSUInteger len = d.length;
    for (NSUInteger off = 0; off < len; off += 16) {
        [s appendFormat:@"%06lx: ", (unsigned long)off];
        for (NSUInteger i = 0; i < 16; i++) {
            if (off + i < len) [s appendFormat:@"%02x ", b[off + i]];
            else               [s appendString:@"   "];
            if (i == 7) [s appendString:@" "];
        }
        [s appendString:@" |"];
        for (NSUInteger i = 0; i < 16; i++) {
            if (off + i < len) {
                unsigned char c = b[off + i];
                [s appendFormat:@"%c", (c >= 32 && c < 127) ? c : '.'];
            }
        }
        [s appendString:@"|\n"];
    }
    return s;
}

NSString *DHUTF8FromData(NSData *d) {
    if (!d || d.length == 0) return @"";
    NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    return s ?: @"(非UTF-8)";
}

NSString *DHCallStackFiltered(void) {
    NSArray *symbols = [NSThread callStackSymbols];
    NSMutableString *cs = [NSMutableString string];
    NSArray *filterOut = @[
        @"fishhook", @"decrypt_helper", @"DHLogStore",
        @"CoreFoundation", @"libsystem", @"libdispatch",
        @"UIKitCore", @"Foundation`",
    ];
    int kept = 0;
    for (NSUInteger i = 0; i < symbols.count; i++) {
        NSString *sym = symbols[i];
        BOOL skip = NO;
        for (NSString *bad in filterOut) {
            if ([sym containsString:bad]) { skip = YES; break; }
        }
        if (skip) continue;
        [cs appendFormat:@"  [%2d] %@\n", kept++, sym];
        if (kept >= 20) break;
    }
    if (kept == 0) [cs appendString:@"  (无应用相关栈帧)\n"];
    return cs;
}

NSString *DHTimestampNow(void) {
    static NSDateFormatter *fmt = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        fmt = [[NSDateFormatter alloc] init];
        fmt.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
    });
    return [fmt stringFromDate:[NSDate date]];
}
