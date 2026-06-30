// dump_manager.m — 见 dump_manager.h
#import "dump_manager.h"
#import "macho_dump.h"
#import "zip_writer.h"
#import "dh_health.h"

@implementation DHDumpManager {
    dispatch_queue_t _q;
    NSLock          *_lock;
    // 以下状态字段受 _lock 保护
    NSString *_state;     // idle / running / done / error
    NSString *_mode;      // bin / ipa
    int       _progress;  // 0..100
    NSString *_stage;     // 当前阶段文本
    NSString *_error;     // 错误信息
    NSString *_binPath;   // 裸二进制 zip 产物
    NSString *_ipaPath;   // IPA 产物
}

+ (instancetype)shared {
    static DHDumpManager *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [DHDumpManager new]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        _q = dispatch_queue_create("com.decrypthelper.dump", DISPATCH_QUEUE_SERIAL);
        _lock = [NSLock new];
        _state = @"idle";
        _stage = @"";
        _progress = 0;
    }
    return self;
}

// ============================================================
// 工具
// ============================================================
static NSString *docs_dir(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
}

- (NSString *)appBaseName {
    NSString *bp = [[NSBundle mainBundle] bundlePath];
    NSString *base = [[bp lastPathComponent] stringByDeletingPathExtension];   // X.app -> X
    return base.length ? base : @"app";
}

- (void)progress:(int)p stage:(NSString *)stage {
    [_lock lock];
    _progress = p;
    if (stage) _stage = stage;
    [_lock unlock];
}

- (void)failWith:(NSString *)msg {
    DH_ERR(@"砸壳失败: %@", msg);
    [_lock lock];
    _state = @"error"; _error = msg ?: @"未知错误"; _stage = @"失败";
    [_lock unlock];
}

// ============================================================
// 镜像清单
// ============================================================
- (NSDictionary *)listImagesDict {
    NSArray<DHDumpImage *> *imgs = dh_dump_list_images();
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray *arr = [NSMutableArray array];
    NSUInteger encCount = 0;
    for (DHDumpImage *im in imgs) {
        if (im.cryptid != 0) encCount++;
        NSDictionary *attrs = [fm attributesOfItemAtPath:im.path error:nil];
        unsigned long long sz = attrs ? [attrs[NSFileSize] unsignedLongLongValue] : 0;
        [arr addObject:@{
            @"name":      im.name ?: @"",
            @"kind":      im.kind ?: @"",
            @"cryptid":   @(im.cryptid),
            @"encrypted": (im.cryptid != 0) ? @YES : @NO,
            @"size":      @(sz),
        }];
    }
    return @{ @"images": arr, @"encryptedCount": @(encCount), @"total": @(imgs.count) };
}

// ============================================================
// 发起任务
// ============================================================
- (BOOL)startDump:(NSString *)mode {
    if (![mode isEqualToString:@"bin"] && ![mode isEqualToString:@"ipa"]) return NO;

    [_lock lock];
    if ([_state isEqualToString:@"running"]) { [_lock unlock]; return NO; }
    _state = @"running"; _mode = mode; _progress = 0; _stage = @"准备中"; _error = nil;
    if ([mode isEqualToString:@"bin"]) _binPath = nil; else _ipaPath = nil;
    [_lock unlock];

    dispatch_async(_q, ^{
        // 整个砸壳 + 打包过程会大量 open/read/write, 在 dh_in_hook=1 下执行,
        // 让 file/system hook 放行不记录, 同时防递归。
        int saved = dh_in_hook;
        dh_in_hook = 1;
        @try {
            if ([mode isEqualToString:@"bin"]) [self runBinDump];
            else                               [self runIpaDump];
        } @catch (NSException *ex) {
            [self failWith:[NSString stringWithFormat:@"异常: %@", ex.reason]];
        } @finally {
            dh_in_hook = saved;
        }
    });
    return YES;
}

// ============================================================
// bin: 裸解密二进制 -> zip
// ============================================================
- (void)runBinDump {
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    NSArray<DHDumpImage *> *imgs = dh_dump_list_images();

    NSMutableArray<DHDumpImage *> *targets = [NSMutableArray array];
    for (DHDumpImage *im in imgs) if (im.cryptid != 0) [targets addObject:im];
    // 没有加密镜像时, 退化为导出主程序(已是明文), 让用户仍能取到二进制。
    if (targets.count == 0) {
        for (DHDumpImage *im in imgs) if ([im.kind isEqualToString:@"main"]) { [targets addObject:im]; break; }
    }
    if (targets.count == 0) { [self failWith:@"没有可导出的镜像"]; return; }

    NSString *outPath = [docs_dir() stringByAppendingPathComponent:
                         [NSString stringWithFormat:@"%@-decrypted.zip", [self appBaseName]]];
    [[NSFileManager defaultManager] removeItemAtPath:outPath error:nil];

    dh_zip_writer *zw = zw_open(outPath.fileSystemRepresentation);
    if (!zw) { [self failWith:@"无法创建输出 zip"]; return; }

    NSUInteger n = targets.count;
    for (NSUInteger i = 0; i < n; i++) {
        DHDumpImage *im = targets[i];
        [self progress:(int)(i * 90 / n) stage:[NSString stringWithFormat:@"砸壳 %@", im.name]];

        NSError *err = nil;
        NSData *dec = dh_dump_decrypt_image(im, &err);
        if (!dec) { zw_abort(zw); [self failWith:[NSString stringWithFormat:@"%@: %@", im.name, err.localizedDescription]]; return; }

        // zip 内用相对 bundle 的路径, 保证唯一且有结构
        NSString *rel = ([im.path hasPrefix:bundlePath] && im.path.length > bundlePath.length + 1)
                      ? [im.path substringFromIndex:bundlePath.length + 1] : im.name;
        NSString *entry = [rel stringByAppendingString:@".decrypted"];
        if (zw_add_data(zw, entry.UTF8String, dec.bytes, dec.length, 0755) != 0) {
            zw_abort(zw); [self failWith:@"写入 zip 失败"]; return;
        }
    }

    [self progress:95 stage:@"收尾打包"];
    if (zw_close(zw) != 0) { [self failWith:@"zip 收尾失败"]; return; }

    [_lock lock]; _binPath = outPath; _state = @"done"; _progress = 100; _stage = @"完成"; [_lock unlock];
    NSLog(@"[IOSDecryptHub] 砸壳(bin)完成: %@", outPath);
}

// ============================================================
// ipa: 脱壳后塞回 .app -> 打包 Payload/*.app -> .ipa
// ============================================================
- (void)runIpaDump {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    NSString *appDirName = [bundlePath lastPathComponent];   // X.app
    if (bundlePath.length == 0) { [self failWith:@"无法取得 bundle 路径"]; return; }

    NSString *outPath = [docs_dir() stringByAppendingPathComponent:
                         [NSString stringWithFormat:@"%@-decrypted.ipa", [self appBaseName]]];
    [fm removeItemAtPath:outPath error:nil];

    // 1. 砸壳所有加密镜像, 建 path -> 解密data 映射
    [self progress:5 stage:@"砸壳镜像"];
    NSArray<DHDumpImage *> *imgs = dh_dump_list_images();
    NSUInteger encN = 0;
    for (DHDumpImage *im in imgs) if (im.cryptid != 0) encN++;

    NSMutableDictionary<NSString *, NSData *> *decMap = [NSMutableDictionary dictionary];
    NSUInteger done = 0;
    for (DHDumpImage *im in imgs) {
        if (im.cryptid == 0) continue;
        NSError *err = nil;
        NSData *dec = dh_dump_decrypt_image(im, &err);
        if (!dec) { [self failWith:[NSString stringWithFormat:@"%@: %@", im.name, err.localizedDescription]]; return; }
        decMap[im.path] = dec;
        done++;
        [self progress:(int)(5 + done * 35 / MAX(encN, (NSUInteger)1))
                  stage:[NSString stringWithFormat:@"砸壳 %@", im.name]];
    }

    // 2. 流式遍历 bundle 目录写 zip
    [self progress:45 stage:@"打包 IPA"];
    dh_zip_writer *zw = zw_open(outPath.fileSystemRepresentation);
    if (!zw) { [self failWith:@"无法创建输出 ipa"]; return; }

    NSDirectoryEnumerator *en = [fm enumeratorAtPath:bundlePath];
    NSString *sub;
    NSUInteger fileCount = 0;
    while ((sub = [en nextObject])) {
        NSString *full = [bundlePath stringByAppendingPathComponent:sub];
        BOOL isDir = NO;
        if (![fm fileExistsAtPath:full isDirectory:&isDir]) continue;
        if (isDir) continue;   // zip 不需显式目录项, unzip 会自动建

        NSString *zipPath = [NSString stringWithFormat:@"Payload/%@/%@", appDirName, sub];
        NSData *dec = decMap[full];
        int rc;
        if (dec) {
            rc = zw_add_data(zw, zipPath.UTF8String, dec.bytes, dec.length, 0755);   // 脱壳后的可执行
        } else {
            NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
            unsigned perm = attrs ? (unsigned)[attrs[NSFilePosixPermissions] unsignedShortValue] : 0644;
            if (perm == 0) perm = 0644;
            rc = zw_add_file(zw, zipPath.UTF8String, full.fileSystemRepresentation, perm);
        }
        if (rc != 0) { zw_abort(zw); [self failWith:[NSString stringWithFormat:@"打包失败: %@", sub]]; return; }

        if ((++fileCount & 0x3F) == 0) {
            int p = 45 + MIN(50, (int)(fileCount / 20));
            [self progress:p stage:[NSString stringWithFormat:@"打包 %@", sub.lastPathComponent]];
        }
    }

    [self progress:97 stage:@"收尾打包"];
    if (zw_close(zw) != 0) { [self failWith:@"ipa 收尾失败"]; return; }

    [_lock lock]; _ipaPath = outPath; _state = @"done"; _progress = 100; _stage = @"完成"; [_lock unlock];
    NSLog(@"[IOSDecryptHub] 砸壳(ipa)完成: %@", outPath);
}

// ============================================================
// 状态 / 产物
// ============================================================
- (NSDictionary *)statusDict {
    [_lock lock];
    NSString *state = _state, *mode = _mode, *stage = _stage, *err = _error, *bp = _binPath, *ip = _ipaPath;
    int prog = _progress;
    [_lock unlock];

    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL binReady = bp && [fm fileExistsAtPath:bp];
    BOOL ipaReady = ip && [fm fileExistsAtPath:ip];
    return @{
        @"state":    state ?: @"idle",
        @"mode":     mode ?: @"",
        @"progress": @(prog),
        @"stage":    stage ?: @"",
        @"error":    err ?: @"",
        @"binReady": binReady ? @YES : @NO,
        @"ipaReady": ipaReady ? @YES : @NO,
        @"binName":  binReady ? [bp lastPathComponent] : @"",
        @"ipaName":  ipaReady ? [ip lastPathComponent] : @"",
    };
}

- (NSString *)artifactPathForKind:(NSString *)kind {
    [_lock lock];
    NSString *p = [kind isEqualToString:@"ipa"] ? _ipaPath : _binPath;
    [_lock unlock];
    if (p && [[NSFileManager defaultManager] fileExistsAtPath:p]) return p;
    return nil;
}

@end
