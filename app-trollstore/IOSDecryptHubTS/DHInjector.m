// DHInjector.m — TrollStore 注入引擎实现
//
// 注入流程 (参考 TrollFools InjectorV3):
//   1. kill 目标 App 进程
//   2. 备份主二进制 → <binary>.dh.bak
//   3. 复制 decrypt_helper.dylib → 目标 App 的 .app/ 目录
//   4. macho_patch: 插入 LC_LOAD_DYLIB (@executable_path/decrypt_helper.dylib)
//   5. ldid -S 伪签名
//   6. ct_bypass -r -i <binary> -t <teamId> 重签名 (CoreTrust bypass)
//   7. chown 33:33 (installd 属主, 否则 iOS 拒绝启动)
//
// 卸载流程:
//   1. kill 目标 App 进程
//   2. macho_patch: 移除 LC_LOAD_DYLIB
//   3. 恢复备份 (或直接移除 load command 即可, 备份是双保险)
//   4. 删除 dylib
//   5. 重签名 + chown
//
// ⚠️ 本文件属于 TrollStore 变体, 不得引用 daemon/plist/Substrate。

#import "DHInjector.h"
#import "LSApplicationWorkspace.h"
#import "macho_patch.h"
#import <spawn.h>
#import <signal.h>

// dylib 在目标 App bundle 内的文件名
static NSString *const kDylibFileName = @"decrypt_helper.dylib";
// LC_LOAD_DYLIB 路径
static NSString *const kDylibLoadPath = @"@executable_path/decrypt_helper.dylib";
// 备份后缀
static NSString *const kBackupSuffix = @".dh.bak";
// installd 的 uid/gid
static const uid_t kInstalldUID = 33;
static const gid_t kInstalldGID = 33;

// ---------- DHAppInfo ----------

@implementation DHAppInfo
@end

// ---------- DHInjector ----------

@implementation DHInjector

+ (instancetype)shared {
    static DHInjector *inst;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ inst = [[DHInjector alloc] init]; });
    return inst;
}

- (NSString *)dylibPath {
    return [[NSBundle mainBundle] pathForResource:@"decrypt_helper" ofType:@"dylib"];
}

- (NSString *)ctBypassPath {
    return [[NSBundle mainBundle] pathForResource:@"ct_bypass" ofType:nil];
}

- (NSString *)ldidPath {
    return [[NSBundle mainBundle] pathForResource:@"ldid" ofType:nil];
}

// ---------- App 枚举 ----------

- (NSArray<DHAppInfo *> *)listApps {
    NSMutableArray<DHAppInfo *> *result = [NSMutableArray array];

    Class wsClass = NSClassFromString(@"LSApplicationWorkspace");
    if (!wsClass) {
        NSLog(@"[DHInjector] ❌ LSApplicationWorkspace 不可用");
        return result;
    }
    id workspace = [wsClass performSelector:@selector(defaultWorkspace)];
    NSArray *apps = [workspace performSelector:@selector(allInstalledApplications)];

    for (id proxy in apps) {
        NSString *bid = [proxy performSelector:@selector(applicationIdentifier)];
        NSString *name = [proxy performSelector:@selector(localizedName)];
        NSString *type = [proxy performSelector:@selector(applicationType)];
        NSURL *bundleURL = [proxy performSelector:@selector(bundleURL)];
        NSString *teamId = [proxy performSelector:@selector(teamID)];
        NSString *ver = [proxy performSelector:@selector(shortVersionString)];

        if (!bid || !bundleURL) continue;
        // 跳过自己
        if ([bid isEqualToString:[[NSBundle mainBundle] bundleIdentifier]]) continue;

        DHAppInfo *info = [[DHAppInfo alloc] init];
        info.bundleId = bid;
        info.name = name ?: bid;
        info.version = ver ?: @"";
        info.teamId = teamId ?: @"";
        info.bundleURL = bundleURL;
        // System 类型 = 系统 App
        info.isSystem = [type isEqualToString:@"System"];
        info.injected = NO;

        [self refreshInjectionStatus:info];
        [result addObject:info];
    }

    // 按名称排序
    [result sortUsingComparator:^NSComparisonResult(DHAppInfo *a, DHAppInfo *b) {
        return [a.name localizedCaseInsensitiveCompare:b.name];
    }];

    NSLog(@"[DHInjector] 枚举到 %lu 个 App", (unsigned long)result.count);
    return result;
}

// ---------- 状态查询 ----------

- (NSString *)mainExecutablePath:(NSURL *)bundleURL {
    NSString *infoPlist = [bundleURL.path stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:infoPlist];
    NSString *exeName = plist[@"CFBundleExecutable"];
    if (!exeName) return nil;
    return [bundleURL.path stringByAppendingPathComponent:exeName];
}

- (NSString *)backupPath:(NSString *)exePath {
    return [exePath stringByAppendingString:kBackupSuffix];
}

- (void)refreshInjectionStatus:(DHAppInfo *)app {
    NSString *exePath = [self mainExecutablePath:app.bundleURL];
    if (!exePath) { app.injected = NO; return; }

    // 方法 1: 检查备份文件存在
    NSString *bakPath = [self backupPath:exePath];
    if ([[NSFileManager defaultManager] fileExistsAtPath:bakPath]) {
        app.injected = YES;
        return;
    }

    // 方法 2: 检查 Mach-O 中是否有我们的 dylib
    int has = dh_macho_has_dylib(exePath.fileSystemRepresentation, kDylibFileName.UTF8String);
    app.injected = (has == 1);
}

// ---------- 进程管理 ----------

- (void)killApp:(NSString *)exePath {
    // 从可执行文件路径推导进程名
    NSString *procName = exePath.lastPathComponent;
    // 用 killall 杀进程 (TrollStore App 有权限)
    [self spawn:@"/usr/bin/killall" args:@[@"-9", procName]];
    // 等一下让进程完全退出
    usleep(300000); // 300ms
}

// ---------- 注入 ----------

- (BOOL)injectApp:(DHAppInfo *)app error:(NSError **)error {
    NSString *exePath = [self mainExecutablePath:app.bundleURL];
    if (!exePath) {
        return [self fail:error msg:@"无法定位主可执行文件"];
    }

    NSString *dylibSrc = self.dylibPath;
    if (!dylibSrc || ![[NSFileManager defaultManager] fileExistsAtPath:dylibSrc]) {
        return [self fail:error msg:@"App bundle 中未找到 decrypt_helper.dylib"];
    }

    NSString *dylibDst = [app.bundleURL.path stringByAppendingPathComponent:kDylibFileName];
    NSString *bakPath = [self backupPath:exePath];
    NSFileManager *fm = [NSFileManager defaultManager];

    NSLog(@"[DHInjector] 注入: %@ → %@", app.name, exePath);

    // 1. kill 目标 App
    [self killApp:exePath];

    // 2. 备份原始二进制
    if (![fm fileExistsAtPath:bakPath]) {
        if (![fm copyItemAtPath:exePath toPath:bakPath error:error]) {
            return [self fail:error msg:@"备份原始二进制失败"];
        }
        NSLog(@"[DHInjector] 备份: %@", bakPath);
    }

    // 3. 复制 dylib 到目标 App bundle
    if ([fm fileExistsAtPath:dylibDst]) {
        [fm removeItemAtPath:dylibDst error:nil];
    }
    if (![fm copyItemAtPath:dylibSrc toPath:dylibDst error:error]) {
        [self restoreBackup:exePath bakPath:bakPath];
        return [self fail:error msg:@"复制 dylib 失败"];
    }
    NSLog(@"[DHInjector] dylib 已复制: %@", dylibDst);

    // 4. 插入 LC_LOAD_DYLIB
    int ret = dh_macho_insert_dylib(exePath.fileSystemRepresentation, kDylibLoadPath.UTF8String);
    if (ret == DH_MACHO_ERR_EXISTS) {
        NSLog(@"[DHInjector] LC_LOAD_DYLIB 已存在, 跳过");
    } else if (ret != DH_MACHO_OK) {
        [fm removeItemAtPath:dylibDst error:nil];
        [self restoreBackup:exePath bakPath:bakPath];
        return [self fail:error msg:[NSString stringWithFormat:@"Mach-O patch 失败 (code=%d)", ret]];
    }
    NSLog(@"[DHInjector] LC_LOAD_DYLIB 已插入");

    // 5. 对 dylib 也做签名
    [self pseudoSign:dylibDst teamId:app.teamId];

    // 6. 重签名主二进制 (ldid + ct_bypass)
    [self pseudoSign:exePath teamId:app.teamId];

    // 7. chown → installd (uid=33, gid=33)
    [self chownToInstalld:dylibDst recursive:NO];
    [self chownToInstalld:exePath recursive:NO];

    NSLog(@"[DHInjector] ✅ 注入完成: %@", app.name);
    app.injected = YES;
    return YES;
}

// ---------- 卸载 ----------

- (BOOL)ejectApp:(DHAppInfo *)app error:(NSError **)error {
    NSString *exePath = [self mainExecutablePath:app.bundleURL];
    if (!exePath) {
        return [self fail:error msg:@"无法定位主可执行文件"];
    }

    NSString *dylibDst = [app.bundleURL.path stringByAppendingPathComponent:kDylibFileName];
    NSString *bakPath = [self backupPath:exePath];
    NSFileManager *fm = [NSFileManager defaultManager];

    NSLog(@"[DHInjector] 卸载: %@", app.name);

    // 1. kill 目标 App
    [self killApp:exePath];

    // 2. 优先恢复备份 (最干净)
    if ([fm fileExistsAtPath:bakPath]) {
        [fm removeItemAtPath:exePath error:nil];
        if (![fm moveItemAtPath:bakPath toPath:exePath error:error]) {
            return [self fail:error msg:@"恢复备份失败"];
        }
        NSLog(@"[DHInjector] 已从备份恢复");
    } else {
        // 无备份, 用 macho_patch 移除 load command
        int ret = dh_macho_remove_dylib(exePath.fileSystemRepresentation, kDylibFileName.UTF8String);
        if (ret != DH_MACHO_OK && ret != DH_MACHO_ERR_NOTFOUND) {
            return [self fail:error msg:[NSString stringWithFormat:@"移除 LC_LOAD_DYLIB 失败 (code=%d)", ret]];
        }
        NSLog(@"[DHInjector] LC_LOAD_DYLIB 已移除");
    }

    // 3. 删除 dylib
    if ([fm fileExistsAtPath:dylibDst]) {
        [fm removeItemAtPath:dylibDst error:nil];
        NSLog(@"[DHInjector] dylib 已删除");
    }

    // 4. 重签名
    [self pseudoSign:exePath teamId:app.teamId];

    // 5. chown
    [self chownToInstalld:exePath recursive:NO];

    NSLog(@"[DHInjector] ✅ 卸载完成: %@", app.name);
    app.injected = NO;
    return YES;
}

// ---------- 签名 ----------

- (void)pseudoSign:(NSString *)path teamId:(NSString *)teamId {
    // ldid -S (伪签名, 生成 code signature)
    if (self.ldidPath) {
        [self spawn:self.ldidPath args:@[@"-S", path]];
    }
    // ct_bypass -r -i <path> -t <teamId> (CoreTrust bypass)
    if (self.ctBypassPath) {
        NSMutableArray *args = [NSMutableArray arrayWithArray:@[@"-r", @"-i", path]];
        if (teamId.length > 0) {
            [args addObject:@"-t"];
            [args addObject:teamId];
        }
        [self spawn:self.ctBypassPath args:args];
    }
}

// ---------- 文件属主 ----------

- (void)chownToInstalld:(NSString *)path recursive:(BOOL)recursive {
    // TrollStore App 有权限直接 chown
    if (geteuid() == 0) {
        // root 权限, 直接调用
        chown(path.fileSystemRepresentation, kInstalldUID, kInstalldGID);
        if (recursive) {
            NSDirectoryEnumerator *e = [[NSFileManager defaultManager] enumeratorAtPath:path];
            for (NSString *sub in e) {
                NSString *full = [path stringByAppendingPathComponent:sub];
                chown(full.fileSystemRepresentation, kInstalldUID, kInstalldGID);
            }
        }
    } else {
        // 非 root, 用 chown 命令 (TrollStore 的 rootSpawn 机制)
        NSMutableArray *args = [NSMutableArray array];
        if (recursive) [args addObject:@"-R"];
        [args addObject:[NSString stringWithFormat:@"%d:%d", kInstalldUID, kInstalldGID]];
        [args addObject:path];
        [self spawn:@"/usr/sbin/chown" args:args];
    }
}

// ---------- 备份恢复 ----------

- (void)restoreBackup:(NSString *)exePath bakPath:(NSString *)bakPath {
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:bakPath]) {
        [fm removeItemAtPath:exePath error:nil];
        [fm moveItemAtPath:bakPath toPath:exePath error:nil];
    }
}

// ---------- 进程 spawn ----------

- (int)spawn:(NSString *)binary args:(NSArray<NSString *> *)args {
    if (![[NSFileManager defaultManager] isExecutableFileAtPath:binary]) {
        NSLog(@"[DHInjector] ⚠️ 工具不存在: %@", binary);
        return -1;
    }

    // 构造 argv
    NSMutableArray *argv = [NSMutableArray arrayWithObject:binary];
    [argv addObjectsFromArray:args];

    const char **cargv = calloc(argv.count + 1, sizeof(char *));
    for (NSUInteger i = 0; i < argv.count; i++) {
        cargv[i] = [argv[i] fileSystemRepresentation];
    }
    cargv[argv.count] = NULL;

    pid_t pid;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    // 设置 POSIX_SPAWN_CLOEXEC_DEFAULT 避免 fd 泄漏
    short flags = 0;
    posix_spawnattr_getflags(&attr, &flags);
    flags |= 0x0040; // POSIX_SPAWN_CLOEXEC_DEFAULT (macOS/iOS 扩展)
    posix_spawnattr_setflags(&attr, flags);

    int ret = posix_spawn(&pid, cargv[0], NULL, &attr, (char *const *)cargv, NULL);
    posix_spawnattr_destroy(&attr);
    free(cargv);

    if (ret != 0) {
        NSLog(@"[DHInjector] spawn 失败: %@ (errno=%d)", binary, ret);
        return -1;
    }

    int status;
    waitpid(pid, &status, 0);
    int exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    if (exitCode != 0) {
        NSLog(@"[DHInjector] ⚠️ %@ 退出码: %d", binary.lastPathComponent, exitCode);
    }
    return exitCode;
}

// ---------- 错误辅助 ----------

- (BOOL)fail:(NSError **)error msg:(NSString *)msg {
    NSLog(@"[DHInjector] ❌ %@", msg);
    if (error) {
        *error = [NSError errorWithDomain:@"com.dh.trollstore"
                                     code:-1
                                 userInfo:@{NSLocalizedDescriptionKey: msg}];
    }
    return NO;
}

@end
