// log_store.m
#import "log_store.h"
#import "dh_health.h"
#import "dh_capture.h"
#import "dh_capability.h"
#import "dh_noise.h"
#import "dh_log_json.h"
#import <sys/sysctl.h>
#import <sys/time.h>
#import <stdatomic.h>
#import <mach/mach.h>
#import <execinfo.h>
#import <dlfcn.h>
#import <pthread.h>
#import <errno.h>

@implementation DHLogEntry
@end

@interface DHLogStore () {
    NSMutableArray<DHLogEntry *> *_buckets[DHCategoryOther + 1];   // 每类独立环形缓冲, 互不挤占
    NSMutableArray<DHLogEntry *> *_noiseBuckets[DHNoiseBoardCount];  // 各板块独立噪声桶
    NSUInteger                    _noiseCount[DHNoiseBoardCount];
    dispatch_queue_t              _queue;       // 写入串行队列
    NSUInteger                    _categoryCounts[DHCategoryOther + 1];
    uint64_t                      _seqCounter;
    NSString                     *_filePath;
    NSString                     *_cfgPath;     // .dh_logcfg.conf
    NSFileHandle                 *_logFH;       // 常开 append 句柄 (避免每条 open/close); 仅 _queue 内访问
    unsigned long long            _logBytes;    // 当前段已写字节 (用于滚动判断); 仅 _queue 内访问
    NSUInteger                    _maxPerCategory;   // 仅 _queue 内写, append 内读
    unsigned long long            _maxLogFileBytes;  // 仅 _queue 内写, _persist 内读
    _Atomic int64_t               _pendingEvents;    // 已派发但尚未处理的日志条数
    _Atomic uint64_t              _droppedEvents;    // 因积压主动丢弃的总条数
    _Atomic uint64_t              _droppedByCategory[DHCategoryOther + 1];
    NSMutableData                *_writeBuf;         // 落盘批量缓冲 (仅 _queue 内访问)
    BOOL                          _flushScheduled;   // 仅 _queue 内访问
}
@end

@implementation DHLogStore

static const NSUInteger kMaxBlobLogged    = 64 * 1024;     // 单段 blob 落盘上限 64KB
static const int        kMaxRotatedBackups = 3;            // 滚动归档最多保留 .1/.2/.3 (总占用 ≤ 单文件上限 ×4)
static const NSUInteger kDefaultMaxPerCategory = 2000;     // 每类内存保留默认值
static const unsigned long long kDefaultMaxLogFileBytes = 50ULL * 1024 * 1024;  // 单文件默认 50MB
// 事件管线背压: 高价值事件(加解密/网络/Keychain)到 hard 才丢; 系统/文件类低价值事件到 soft 就开始丢。
// 丢弃只计数、不阻塞宿主线程, 指标在 /api/stats.pipeline 与 get_stats.pipeline 暴露。
static const int64_t  kSoftPendingLimit  = 1024;
static const int64_t  kHardPendingLimit  = 4096;
static const NSUInteger kFlushBufferBytes = 64 * 1024;     // 落盘批量阈值
static const int64_t  kFlushIntervalMs   = 150;             // 最长 150ms 落盘一次, 兼顾崩溃取证

+ (instancetype)shared {
    static DHLogStore *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[DHLogStore alloc] init]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        for (int c = 0; c <= DHCategoryOther; c++) _buckets[c] = [NSMutableArray array];
        for (int b = 0; b < DHNoiseBoardCount; b++) {
            _noiseBuckets[b] = [NSMutableArray array];
            _noiseCount[b] = 0;
        }
        _queue = dispatch_queue_create("com.decrypthelper.logstore", DISPATCH_QUEUE_SERIAL);
        _seqCounter = 0;
        memset(_categoryCounts, 0, sizeof(_categoryCounts));
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        _filePath = [[paths firstObject] stringByAppendingPathComponent:@"decrypt_helper.log"];
        _cfgPath  = [[paths firstObject] stringByAppendingPathComponent:@".dh_logcfg.conf"];
        _maxPerCategory  = kDefaultMaxPerCategory;
        _maxLogFileBytes = kDefaultMaxLogFileBytes;
        atomic_init(&_pendingEvents, 0);
        atomic_init(&_droppedEvents, 0);
        for (int c = 0; c <= DHCategoryOther; c++) atomic_init(&_droppedByCategory[c], 0);
        _writeBuf = [NSMutableData dataWithCapacity:kFlushBufferBytes];
        [self _loadCfg];
    }
    return self;
}

- (NSString *)logFilePath { return _filePath; }

// 第 i(1..3) 个滚动备份段路径; 0 = 当前段。
- (NSString *)_segPath:(int)i { return i == 0 ? _filePath : [_filePath stringByAppendingFormat:@".%d", i]; }

// ===== 配置加载/存盘 (格式: "maxPerCategory maxLogFileBytes" 一行) =====
- (void)_loadCfg {
    int saved = dh_in_hook; dh_in_hook = 1;   // 读配置文件不应被 file hook 记录
    NSString *txt = [NSString stringWithContentsOfFile:_cfgPath encoding:NSUTF8StringEncoding error:nil];
    dh_in_hook = saved;
    if (!txt) return;
    NSArray *parts = [[txt stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]
                      componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSMutableArray *nums = [NSMutableArray array];
    for (NSString *p in parts) if (p.length) [nums addObject:p];
    if (nums.count >= 2) {
        NSInteger mpc = [nums[0] integerValue];
        long long  mfb = [nums[1] longLongValue];
        if (mpc > 0)  _maxPerCategory  = (NSUInteger)mpc;
        if (mfb >= 0) _maxLogFileBytes = (unsigned long long)mfb;   // 0=不限
    }
}
- (void)_saveCfg {   // 须在 _queue 内调用
    NSString *txt = [NSString stringWithFormat:@"%lu %llu", (unsigned long)_maxPerCategory, _maxLogFileBytes];
    int saved = dh_in_hook; dh_in_hook = 1;
    [txt writeToFile:_cfgPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    dh_in_hook = saved;
}

- (NSUInteger)maxPerCategory {
    __block NSUInteger n; dispatch_sync(_queue, ^{ n = self->_maxPerCategory; }); return n;
}
- (void)setMaxPerCategory:(NSUInteger)n {
    if (n == 0) return;
    dispatch_async(_queue, ^{
        self->_maxPerCategory = n;
        for (int c = 0; c <= DHCategoryOther; c++) {   // 立即按新上限裁剪各桶
            NSMutableArray *b = self->_buckets[c];
            if (b.count > n) [b removeObjectsInRange:NSMakeRange(0, b.count - n)];
        }
        [self _saveCfg];
    });
}
- (unsigned long long)maxLogFileBytes {
    __block unsigned long long n; dispatch_sync(_queue, ^{ n = self->_maxLogFileBytes; }); return n;
}
- (void)setMaxLogFileBytes:(unsigned long long)bytes {
    dispatch_async(_queue, ^{ self->_maxLogFileBytes = bytes; [self _saveCfg]; });
}
- (unsigned long long)totalLogBytes {
    unsigned long long total = 0;
    NSFileManager *fm = [NSFileManager defaultManager];
    for (int i = 0; i <= kMaxRotatedBackups; i++) {
        NSDictionary *a = [fm attributesOfItemAtPath:[self _segPath:i] error:nil];
        if (a) total += [(NSNumber *)a[NSFileSize] unsignedLongLongValue];
    }
    return total;
}

- (NSDictionary<NSString *, id> *)pipelineStats {
    NSMutableDictionary *byCat = [NSMutableDictionary dictionary];
    for (NSInteger c = 0; c <= DHCategoryOther; c++) {
        uint64_t n = atomic_load_explicit(&_droppedByCategory[c], memory_order_relaxed);
        if (n > 0) byCat[@(dh_log_category_name((int)c))] = @(n);
    }
    unsigned long long rss = 0;
    mach_task_basic_info_data_t info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &count) == KERN_SUCCESS)
        rss = info.resident_size;
    return @{
        @"pending":           @(atomic_load_explicit(&_pendingEvents, memory_order_relaxed)),
        @"dropped":           @(atomic_load_explicit(&_droppedEvents, memory_order_relaxed)),
        @"droppedByCategory": byCat,
        @"rss":               @(rss),
        @"softLimit":         @(kSoftPendingLimit),
        @"hardLimit":         @(kHardPendingLimit),
    };
}

// 噪点判定: 仅对该条目所属板块的特征串做匹配。
static BOOL dh_noise_entry_matches_board(DHLogEntry *entry, DHNoiseBoard board) {
    if (dh_noise_matches_for_board(board, DHUTF8FromData(entry.input))) return YES;
    if (dh_noise_matches_for_board(board, entry.detail)) return YES;
    return NO;
}

- (void)append:(DHLogEntry *)entry {
    if (self.paused || entry == nil) return;
    // tid/tsMs 必须在调用(被 hook)线程上取, 即 dispatch_async 之前 —— 否则线程号会变成串行队列的。
    if (entry.timestampMs == 0) {
        struct timeval tv; gettimeofday(&tv, NULL);
        entry.timestampMs = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000);
    }
    if (entry.threadId == 0) { uint64_t t = 0; pthread_threadid_np(NULL, &t); entry.threadId = t; }
    NSInteger ci = (entry.category >= 0 && entry.category <= DHCategoryOther) ? entry.category : DHCategoryOther;
    if (dh_capture_cat_paused((int)ci)) return;            // 该分类已暂停(单一真相源在 dh_capture, 已持久化)

    // 背压: 低价值分类(系统/文件/其它)在 soft 水位开始丢弃; 所有分类到 hard 水位都丢弃。
    // 高价值事件(加解密/网络/Keychain)在 hard 之前全部保留, 不改变正常使用体验。
    BOOL lowPriority = (ci == DHCategorySystem || ci == DHCategoryFile || ci == DHCategoryOther);
    int64_t pending = atomic_fetch_add_explicit(&_pendingEvents, 1, memory_order_relaxed) + 1;
    if (pending > kHardPendingLimit || (pending > kSoftPendingLimit && lowPriority)) {
        atomic_fetch_sub_explicit(&_pendingEvents, 1, memory_order_relaxed);
        [self _noteDroppedForCategory:ci pending:pending];
        return;
    }

    DHNoiseBoard board = dh_noise_board_for_category(ci);
    dispatch_async(_queue, ^{
        @try {
            entry.seq = ++self->_seqCounter;
            // 噪点判定移到串行队列, 宿主线程只做捕获; 匹配失败也只是少一次降噪, 不影响正确性。
            BOOL noisy = dh_noise_enabled_for_board(board) && dh_noise_entry_matches_board(entry, board);
            NSMutableArray *b = noisy ? self->_noiseBuckets[board] : self->_buckets[ci];
            [b addObject:entry];
            if (b.count > self->_maxPerCategory)
                [b removeObjectsInRange:NSMakeRange(0, b.count - self->_maxPerCategory)];
            if (noisy) self->_noiseCount[board]++;
            else       self->_categoryCounts[ci]++;
            [self _persist:entry];   // 噪点条目仍照常落盘, 保持「崩溃可闭环取证」承诺
        } @finally {
            atomic_fetch_sub_explicit(&self->_pendingEvents, 1, memory_order_relaxed);
        }
    });
}

// 累计被背压丢弃的事件并低频写诊断。热路径只做原子加法, 每 1000 条才格式化一次。
- (void)_noteDroppedForCategory:(NSInteger)ci pending:(int64_t)pending {
    uint64_t d = atomic_fetch_add_explicit(&_droppedEvents, 1, memory_order_relaxed) + 1;
    atomic_fetch_add_explicit(&_droppedByCategory[ci], 1, memory_order_relaxed);
    if (d == 1 || (d % 1000) == 0) {
        dh_diag_append(DH_DIAG_GENERAL, "WARN",
            [[NSString stringWithFormat:
              @"log pipeline overload: pending=%lld dropped=%llu category=%s (soft=%lld hard=%lld)",
              (long long)pending, (unsigned long long)d, dh_log_category_name((int)ci),
              (long long)kSoftPendingLimit, (long long)kHardPendingLimit] UTF8String]);
    }
}

// 网络请求先记「只有请求」的条目, 响应到达后用「请求+响应」的完整条目原位替换。
// 为什么不原地改旧条目: 序列化读者在队列外读取 e.detail/e.output, 若在另一线程释放旧值会竞态崩溃。
// 换整条对象引用 (旧对象不可变) 则读者要么拿到旧完整对象、要么拿到新完整对象, 永不撕裂。
- (void)replaceNetworkEntry:(DHLogEntry *)oldEntry with:(DHLogEntry *)newEntry {
    if (newEntry == nil) return;
    if (oldEntry == nil) { [self append:newEntry]; return; }
    // tid/tsMs 与 append 同理: 必须在调用(被 hook)线程取, 即 dispatch 之前。
    if (newEntry.timestampMs == 0) {
        struct timeval tv; gettimeofday(&tv, NULL);
        newEntry.timestampMs = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000);
    }
    if (newEntry.threadId == 0) { uint64_t t = 0; pthread_threadid_np(NULL, &t); newEntry.threadId = t; }
    // 网络响应是高价值事件: 只在 hard 水位丢弃; 低于 hard 时无条件排队。
    int64_t pending = atomic_fetch_add_explicit(&_pendingEvents, 1, memory_order_relaxed) + 1;
    if (pending > kHardPendingLimit) {
        atomic_fetch_sub_explicit(&_pendingEvents, 1, memory_order_relaxed);
        [self _noteDroppedForCategory:DHCategoryNetwork pending:pending];
        return;
    }
    dispatch_async(_queue, ^{
        @try {
            NSMutableArray *nb = self->_buckets[DHCategoryNetwork];
            NSUInteger idx = [nb indexOfObjectIdenticalTo:oldEntry];   // 指针身份, 不用 isEqual
            if (idx != NSNotFound) {
                newEntry.seq = oldEntry.seq;
                nb[idx] = newEntry;
                [self _persist:newEntry];
                return;
            }
            for (int b = 0; b < DHNoiseBoardCount; b++) {   // 也可能被路由进噪声桶
                NSUInteger ni = [self->_noiseBuckets[b] indexOfObjectIdenticalTo:oldEntry];
                if (ni != NSNotFound) {
                    newEntry.seq = oldEntry.seq;
                    self->_noiseBuckets[b][ni] = newEntry;
                    [self _persist:newEntry];
                    return;
                }
            }
            // 旧条目已被裁剪淘汰: 退化为追加一条完整记录。
            newEntry.seq = ++self->_seqCounter;
            [nb addObject:newEntry];
            if (nb.count > self->_maxPerCategory)
                [nb removeObjectsInRange:NSMakeRange(0, nb.count - self->_maxPerCategory)];
            self->_categoryCounts[DHCategoryNetwork]++;
            [self _persist:newEntry];
        } @finally {
            atomic_fetch_sub_explicit(&self->_pendingEvents, 1, memory_order_relaxed);
        }
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

// 取某分类切片: -2=加密组(0..3); -3=系统组(文件+模块); 0..Other=单桶; 其它=全部。须在 _queue 内调用。
- (NSArray<DHLogEntry *> *)_categorySliceLocked:(NSInteger)cat {
    if (cat == -2) {
        NSMutableArray *m = [NSMutableArray array];
        for (int c = DHCategoryDigest; c <= DHCategoryAsymmetric; c++) [m addObjectsFromArray:_buckets[c]];
        [m sortUsingComparator:^NSComparisonResult(DHLogEntry *a, DHLogEntry *b) {
            return a.seq < b.seq ? NSOrderedAscending : (a.seq > b.seq ? NSOrderedDescending : NSOrderedSame);
        }];
        return m;
    }
    if (cat == -3) {
        NSMutableArray *m = [NSMutableArray array];
        [m addObjectsFromArray:_buckets[DHCategoryFile]];
        [m addObjectsFromArray:_buckets[DHCategorySystem]];
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

// 建立/恢复常开 append 句柄 (须在 _queue 内 + dh_in_hook 已置位)。文件不存在则创建。
- (void)_openLogHandleLocked {
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:_filePath]) {
        [fm createFileAtPath:_filePath contents:nil attributes:nil];
        _logBytes = 0;
    } else {
        NSDictionary *a = [fm attributesOfItemAtPath:_filePath error:nil];
        _logBytes = a ? [(NSNumber *)a[NSFileSize] unsignedLongLongValue] : 0;
    }
    _logFH = [NSFileHandle fileHandleForWritingAtPath:_filePath];
    [_logFH seekToEndOfFile];
}

// 滚动归档 (须在 _queue 内 + dh_in_hook 已置位): 删最旧 .3, 依次 .2→.3 / .1→.2 / 当前→.1, 下次写入重建当前段。
- (void)_rotateLocked {
    [_logFH closeFile]; _logFH = nil;
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:[self _segPath:kMaxRotatedBackups] error:nil];
    for (int i = kMaxRotatedBackups - 1; i >= 0; i--) {
        NSString *from = [self _segPath:i], *to = [self _segPath:i + 1];
        if ([fm fileExistsAtPath:from]) [fm moveItemAtPath:from toPath:to error:nil];
    }
    _logBytes = 0;
}

- (void)_flushLocked {
    if (_writeBuf.length == 0) return;
    // 关键: 落盘自身的 open/write(写 decrypt_helper.log) 不能被 file hook 再记录, 否则
    // write -> 记录 -> append -> _persist -> write 无限自我循环. 落盘期间置 dh_in_hook。
    int saved = dh_in_hook; dh_in_hook = 1;
    @try {
        if (!_logFH) [self _openLogHandleLocked];
        if (!_logFH) {
            dh_health_persist_fail(errno);
            DH_ERR(@"日志落盘失败: 无法打开 %@ (errno=%d)", _filePath, errno);
            [_writeBuf setLength:0];   // 打不开就丢弃本批, 绝不让缓冲无限涨
            return;
        }
        @try {
            NSUInteger n = _writeBuf.length;
            [_logFH writeData:_writeBuf];
            _logBytes += n;
        } @catch (NSException *ex) {
            dh_health_persist_fail(errno);
            DH_ERR(@"日志落盘失败(批量): %@", ex.reason);
            [_logFH closeFile]; _logFH = nil;   // 句柄可能已坏, 下批重开
        }
        [_writeBuf setLength:0];
        if (_maxLogFileBytes > 0 && _logBytes >= _maxLogFileBytes) [self _rotateLocked];
    } @finally {
        dh_in_hook = saved;
    }
}

- (void)_persist:(DHLogEntry *)e {
    NSMutableString *s = dh_entry_block(e);
    NSData *bytes = [s dataUsingEncoding:NSUTF8StringEncoding];
    if (!bytes) { DH_ERR(@"日志 UTF-8 编码失败, 丢弃 #%llu", (unsigned long long)e.seq); return; }
    // 批量落盘: 先进 64KB 缓冲, 满缓冲或 150ms 到点再 write 一次。
    // 相比旧的「每条 write 一次」, syscall 数量降两个数量级; 崩溃时最多丢 150ms 日志,
    // 仍然满足「被检测杀掉后重启可取全量」的取证语义。
    if (!_writeBuf) _writeBuf = [NSMutableData dataWithCapacity:kFlushBufferBytes];
    [_writeBuf appendData:bytes];
    if (_writeBuf.length >= kFlushBufferBytes) {
        [self _flushLocked];
    } else if (!_flushScheduled) {
        _flushScheduled = YES;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kFlushIntervalMs * NSEC_PER_MSEC)), _queue, ^{
            self->_flushScheduled = NO;
            [self _flushLocked];
        });
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
        else if (e.detail && [[e.detail lowercaseString] containsString:kw]) hit = YES;   // 文件/系统按路径搜
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
        if (!r) {
            for (int b = 0; b < DHNoiseBoardCount && !r; b++) {
                NSMutableArray *bucket = self->_noiseBuckets[b];
                for (NSInteger i = (NSInteger)bucket.count - 1; i >= 0; i--) {
                    DHLogEntry *e = bucket[i];
                    if (e.seq == seq) { r = e; break; }
                }
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
        int saved = dh_in_hook; dh_in_hook = 1;
        [self->_writeBuf setLength:0];   // 清空时丢弃尚未落盘的旧数据
        [self->_logFH closeFile]; self->_logFH = nil; self->_logBytes = 0;
        NSFileManager *fm = [NSFileManager defaultManager];
        for (int i = 0; i <= kMaxRotatedBackups; i++)   // 当前段 + 所有滚动备份段
            [fm removeItemAtPath:[self _segPath:i] error:nil];
        dh_in_hook = saved;
    });
}

- (void)clearCategory:(NSInteger)cat {
    dispatch_async(_queue, ^{
        if (cat == -2) {            // 加密组
            for (int c = DHCategoryDigest; c <= DHCategoryAsymmetric; c++) {
                [self->_buckets[c] removeAllObjects]; self->_categoryCounts[c] = 0;
            }
        } else if (cat == -3) {     // 系统组(文件+模块)
            [self->_buckets[DHCategoryFile] removeAllObjects];
            [self->_buckets[DHCategorySystem] removeAllObjects];
            self->_categoryCounts[DHCategoryFile] = 0;
            self->_categoryCounts[DHCategorySystem] = 0;
        } else if (cat >= 0 && cat <= DHCategoryOther) {
            [self->_buckets[cat] removeAllObjects]; self->_categoryCounts[cat] = 0;
        }
        // 仅清该类内存(落盘文件混所有类, 不动; 整体清空走 clearAll)
    });
}

- (NSArray<DHLogEntry *> *)snapshotNoiseMatching:(NSString *)keyword board:(NSInteger)board {
    if (board < 0 || board >= DHNoiseBoardCount) board = DHNoiseBoardCrypto;
    __block NSArray *src = nil;
    dispatch_sync(_queue, ^{ src = [self->_noiseBuckets[board] copy]; });
    if (!keyword || keyword.length == 0) return src;

    NSMutableArray *out = [NSMutableArray array];
    NSString *kw = [keyword lowercaseString];
    for (DHLogEntry *e in src) {
        BOOL hit = NO;
        if ([[e.algorithm lowercaseString] containsString:kw]) hit = YES;
        else if ([[e.operation lowercaseString] containsString:kw]) hit = YES;
        else if (e.detail && [[e.detail lowercaseString] containsString:kw]) hit = YES;
        else if (e.input && [[DHUTF8FromData(e.input) lowercaseString] containsString:kw]) hit = YES;
        else if (e.input && [[DHHexFromData(e.input) lowercaseString] containsString:kw]) hit = YES;
        else if (e.output && [[DHHexFromData(e.output) lowercaseString] containsString:kw]) hit = YES;
        if (hit) [out addObject:e];
    }
    return out;
}

- (NSUInteger)noiseCountForBoard:(NSInteger)board {
    if (board < 0 || board >= DHNoiseBoardCount) board = DHNoiseBoardCrypto;
    __block NSUInteger n;
    dispatch_sync(_queue, ^{ n = self->_noiseCount[board]; });
    return n;
}

- (void)clearNoiseForBoard:(NSInteger)board {
    if (board < 0 || board >= DHNoiseBoardCount) board = DHNoiseBoardCrypto;
    dispatch_async(_queue, ^{
        [self->_noiseBuckets[board] removeAllObjects];
        self->_noiseCount[board] = 0;
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
            @"arch":            @(dh_cpu_arch()),
            @"physicalMemoryMB":@(pi.physicalMemory / (1024 * 1024)),
        };
    });
    return info;
}

- (NSArray<DHLogEntry *> *)snapshotMatching:(NSString *)keyword
                                   category:(NSInteger)categoryOrMinusOne
                               minInputSize:(NSUInteger)minBytes
                               maxInputSize:(NSUInteger)maxBytes {
    NSArray<DHLogEntry *> *base = [self snapshotMatching:keyword category:categoryOrMinusOne];
    if (minBytes == 0 && maxBytes == 0) return base;
    NSMutableArray *out = [NSMutableArray array];
    for (DHLogEntry *e in base) {
        NSUInteger inLen = e.input.length;
        if (minBytes > 0 && inLen < minBytes) continue;
        if (maxBytes > 0 && inLen > maxBytes) continue;
        [out addObject:e];
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

NSData *DHDataFromHex(NSString *hex) {
    NSMutableData *d = [NSMutableData data];
    const char *s = hex.UTF8String;
    if (!s) return d;
    int hi = -1;
    for (; *s; s++) {
        int v;
        char c = *s;
        if      (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else continue;   // 跳过 0x / 空格 / 分隔符
        if (hi < 0) hi = v;
        else { uint8_t byte = (uint8_t)((hi << 4) | v); [d appendBytes:&byte length:1]; hi = -1; }
    }
    return d;
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

// ---- 调用栈采集: backtrace() + PC 级符号缓存 ----
// 旧实现每条事件调用 [NSThread callStackSymbols], 内部对每一帧做 backtrace_symbols/dladdr;
// 高频 App 上这是最大的 CPU / 分配来源。新实现只 unwind 一次, 每个 PC 的 dladdr 结果缓存复用,
// 输出格式仍与 parse_callstack_frames 兼容: "  [ 0] 0   image   0xaddr symbol + offset"。
#define DH_STACK_CACHE_SIZE  1024
#define DH_STACK_CACHE_PROBES 8
#define DH_STACK_MAX_FRAMES  48
#define DH_STACK_MAX_KEEP    20

typedef struct {
    uintptr_t pc;
    uint64_t  offset;
    char      image[64];
    char      symbol[160];
} DHStackCacheEntry;

static DHStackCacheEntry g_stackCache[DH_STACK_CACHE_SIZE];
static pthread_mutex_t g_stackCacheLock = PTHREAD_MUTEX_INITIALIZER;

static NSUInteger dh_stack_slot(uintptr_t pc) {
    return (NSUInteger)((pc >> 4) & (DH_STACK_CACHE_SIZE - 1));
}

static BOOL dh_stack_cache_get(uintptr_t pc, DHStackCacheEntry *out) {
    BOOL found = NO;
    pthread_mutex_lock(&g_stackCacheLock);
    NSUInteger slot = dh_stack_slot(pc);
    for (int i = 0; i < DH_STACK_CACHE_PROBES; i++) {
        NSUInteger idx = (slot + i) & (DH_STACK_CACHE_SIZE - 1);
        if (g_stackCache[idx].pc == 0) break;
        if (g_stackCache[idx].pc == pc) { *out = g_stackCache[idx]; found = YES; break; }
    }
    pthread_mutex_unlock(&g_stackCacheLock);
    return found;
}

static void dh_stack_cache_put(const DHStackCacheEntry *e) {
    pthread_mutex_lock(&g_stackCacheLock);
    NSUInteger slot = dh_stack_slot(e->pc);
    for (int i = 0; i < DH_STACK_CACHE_PROBES; i++) {
        NSUInteger idx = (slot + i) & (DH_STACK_CACHE_SIZE - 1);
        if (g_stackCache[idx].pc == 0 || g_stackCache[idx].pc == e->pc) {
            g_stackCache[idx] = *e;
            pthread_mutex_unlock(&g_stackCacheLock);
            return;
        }
    }
    g_stackCache[slot] = *e;   // 缓存满时覆盖首槽, 保证内存有界
    pthread_mutex_unlock(&g_stackCacheLock);
}

static BOOL dh_stack_image_skipped(const char *nameOrPath) {
    if (!nameOrPath || !nameOrPath[0]) return YES;
    const char *base = strrchr(nameOrPath, '/');
    base = base ? base + 1 : nameOrPath;
    static const char *skip[] = {
        "decrypt_helper", "fishhook", "libsystem", "libdispatch",
        "CoreFoundation", "Foundation", "UIKitCore", NULL
    };
    for (int i = 0; skip[i]; i++) if (strstr(base, skip[i])) return YES;
    return NO;
}

NSString *DHCallStackFiltered(void) {
    void *frames[DH_STACK_MAX_FRAMES];
    int n = backtrace(frames, DH_STACK_MAX_FRAMES);
    NSMutableString *cs = [NSMutableString string];
    int kept = 0;
    for (int i = 0; i < n && kept < DH_STACK_MAX_KEEP; i++) {
        uintptr_t pc = (uintptr_t)frames[i];
        if (!pc) continue;
        DHStackCacheEntry e;
        if (!dh_stack_cache_get(pc, &e)) {
            Dl_info info = {0};
            if (dladdr((const void *)pc, &info) == 0 || !info.dli_fname) continue;
            const char *base = strrchr(info.dli_fname, '/');
            base = base ? base + 1 : info.dli_fname;
            memset(&e, 0, sizeof(e));
            e.pc = pc;
            snprintf(e.image, sizeof(e.image), "%s", base);
            if (info.dli_sname && info.dli_saddr) {
                snprintf(e.symbol, sizeof(e.symbol), "%s", info.dli_sname);
                e.offset = (uint64_t)(pc - (uintptr_t)info.dli_saddr);
            } else {
                snprintf(e.symbol, sizeof(e.symbol), "%s", base);
                e.offset = (uint64_t)(pc - (uintptr_t)info.dli_fbase);
            }
            dh_stack_cache_put(&e);
        }
        if (dh_stack_image_skipped(e.image)) continue;
        [cs appendFormat:@"  [%2d] 0   %s   0x%llx %s + %llu\n",
         kept++, e.image, (unsigned long long)pc, e.symbol, (unsigned long long)e.offset];
    }
    if (kept == 0) [cs appendString:@"  (无应用相关栈帧)\n"];
    return cs;
}

NSString *DHTimestampNow(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tmv;
    if (!localtime_r(&tv.tv_sec, &tmv)) return @"";
    char buf[40];
    int n = snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                     tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                     tmv.tm_hour, tmv.tm_min, tmv.tm_sec, (int)(tv.tv_usec / 1000));
    if (n <= 0) return @"";
    return [[NSString alloc] initWithBytes:buf length:(NSUInteger)MIN(n, (int)sizeof(buf) - 1)
                                  encoding:NSUTF8StringEncoding] ?: @"";
}
