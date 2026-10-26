// main.m — 一次性管理 daemon，由 launchd 按请求或周期启动。
// 检查规范 APT 源、目标启停、同步启用名单和状态；安装/回退交给包管理器。
// 旧 install / rollback 请求明确失败，不能替换 dpkg 管理的引擎。
// 常驻分析服务属于后续版本；此进程仍在完成请求后退出。

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <syslog.h>
#import <signal.h>
#import <unistd.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/file.h>
#import <fcntl.h>
#import <errno.h>
#import <string.h>
#import <limits.h>
#import "dh_shared.h"
#import "dh_package_update.h"

#define DH_TAG "[IOSDecryptHubUpdated]"
#define DH_CHECK_INTERVAL (12 * 3600.0)

static NSString *g_engine_dir = nil;
static BOOL g_engine_writable = NO;
static NSMutableDictionary *g_state = nil;

#pragma mark - log / plist

static void dh_log(const char *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *nsfmt = [NSString stringWithUTF8String:format] ?: @"";
    NSString *msg = [[NSString alloc] initWithFormat:nsfmt arguments:args];
    va_end(args);
    syslog(LOG_INFO, DH_TAG " %s", msg.UTF8String ?: "");
    // 同时写 stderr：launchd 会按 StandardErrorPath 落到 /var/log/iosdecrypthub-updated.log。
    // 只走 syslog 的话那个日志文件永远是空的，出问题时无从下手。
    fputs((msg.UTF8String ?: ""), stderr);
    fputc('\n', stderr);
    fflush(stderr);
}

static NSDictionary *_Nullable dh_read_plist(NSString *path) {
    @try {
        id obj = [NSDictionary dictionaryWithContentsOfFile:path];
        if ([obj isKindOfClass:[NSDictionary class]]) return obj;
    } @catch (__unused NSException *e) {
    }
    return nil;
}

static BOOL dh_write_plist(NSDictionary *dict, NSString *path) {
    @try {
        return [dict writeToFile:path atomically:YES];
    } @catch (__unused NSException *e) {
        return NO;
    }
}

#pragma mark - 路径

static NSString *_Nullable dh_bootstrap_root(void) {
    Dl_info info = {0};
    if (dladdr((const void *)&dh_bootstrap_root, &info) == 0 || !info.dli_fname) {
        return nil;
    }
    // daemon 布局: <bootstrap>/usr/lib/IOSDecryptHub/IOSDecryptHubUpdated，向上四级
    NSString *root = [NSString stringWithUTF8String:info.dli_fname];
    for (int i = 0; i < 4; i++) root = [root stringByDeletingLastPathComponent];
    // "/" 是合法 jbroot（rootHide 的 SSH 视角）
    if (root.length == 0) return nil;
    return root;
}

static BOOL dh_dir_is_writable(NSString *dir) {
    // 不用 NSFileManager：rootHide 下 fileExists 对短路径撒谎，.jbroot 前缀 open 又 EPERM。
    NSString *probe = [dir stringByAppendingPathComponent:@".updated.lock"];
    int fd = open(probe.fileSystemRepresentation, O_CREAT | O_RDWR | O_CLOEXEC, 0644);
    if (fd < 0) return NO;
    close(fd);
    return YES;
}

static BOOL dh_dylib_readable(NSString *dir) {
    NSString *path = [dir stringByAppendingPathComponent:DH_ENGINE_NAME];
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NO;
    close(fd);
    return YES;
}

static BOOL dh_ensure_dir(NSString *dir) {
    if (dir.length == 0) return NO;
    if (mkdir(dir.fileSystemRepresentation, 0755) != 0 && errno != EEXIST) return NO;
    return dh_dir_is_writable(dir);
}

static NSString *_Nullable dh_jbroot_from_engine(void) {
    if (!g_engine_dir.length) return nil;
    NSString *root = g_engine_dir;
    for (int i = 0; i < 3; i++) root = [root stringByDeletingLastPathComponent];
    return root.length ? root : nil;
}

static NSString *_Nullable dh_jb_path(NSString *relative) {
    NSString *root = dh_jbroot_from_engine();
    if (!root.length) return nil;
    return [root stringByAppendingPathComponent:relative];
}

static NSString *_Nullable dh_existing_engine_dir(void) {
    NSMutableArray<NSString *> *dirs = [NSMutableArray array];
    [dirs addObject:@"/usr/lib/IOSDecryptHub"];
    [dirs addObject:@"/var/jb/usr/lib/IOSDecryptHub"];
    NSString *root = dh_bootstrap_root();
    if (root.length) {
        char resolved[PATH_MAX];
        if (realpath(root.fileSystemRepresentation, resolved)) {
            NSString *real = [NSString stringWithUTF8String:resolved];
            if (real.length && ![real isEqualToString:@"/"]) {
                [dirs addObject:[real stringByAppendingPathComponent:@"usr/lib/IOSDecryptHub"]];
            }
        }
        if (![root isEqualToString:@"/"]) {
            [dirs addObject:[root stringByAppendingPathComponent:@"usr/lib/IOSDecryptHub"]];
        }
    }
    NSMutableArray<NSString *> *seen = [NSMutableArray array];
    NSString *readable = nil;
    for (NSString *dir in dirs) {
        if ([seen containsObject:dir]) continue;
        [seen addObject:dir];
        errno = 0;
        if (dh_dylib_readable(dir)) {
            readable = dir;
            break;
        }
        dh_log("引擎目录不可读，跳过 %s (%s)", dir.UTF8String ?: "", strerror(errno));
    }
    return readable;
}

// 引擎 dylib 缺失时 dh_existing_engine_dir 会返回 nil，但目录本身可能还在。
// 这种情况仍要能写 state，让 App 看到“引擎不存在”的错误，而不是静默退出。
static NSString *_Nullable dh_existing_engine_dir_loose(void) {
    NSMutableArray<NSString *> *dirs = [NSMutableArray array];
    [dirs addObject:@"/usr/lib/IOSDecryptHub"];
    [dirs addObject:@"/var/jb/usr/lib/IOSDecryptHub"];
    NSString *root = dh_bootstrap_root();
    if (root.length) {
        char resolved[PATH_MAX];
        if (realpath(root.fileSystemRepresentation, resolved)) {
            NSString *real = [NSString stringWithUTF8String:resolved];
            if (real.length && ![real isEqualToString:@"/"]) {
                [dirs addObject:[real stringByAppendingPathComponent:@"usr/lib/IOSDecryptHub"]];
            }
        }
        if (![root isEqualToString:@"/"]) {
            [dirs addObject:[root stringByAppendingPathComponent:@"usr/lib/IOSDecryptHub"]];
        }
    }
    for (NSString *dir in dirs) {
        int fd = open(dir.fileSystemRepresentation, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            close(fd);
            return dir;
        }
    }
    return nil;
}

#pragma mark - 单实例锁

// launchd 的 WatchPaths 与 StartInterval 可能叠在一起触发。并发改写引擎 =
// 半写 + 备份互踩，所以第二个实例必须立刻退出（拿不到锁就当作"已有实例在跑"）。
static int dh_acquire_lock(void) {
    NSString *path = nil;
    if (g_engine_writable && g_engine_dir.length) {
        path = [g_engine_dir stringByAppendingPathComponent:@".updated.lock"];
    } else {
        path = dh_jb_path(DH_JB_LOCK_REL);
        if (path.length) dh_ensure_dir([path stringByDeletingLastPathComponent]);
        if (!path.length || !dh_dir_is_writable([path stringByDeletingLastPathComponent])) {
            path = DH_LOCK_PATH;
            dh_ensure_dir([path stringByDeletingLastPathComponent]);
        }
    }
    // O_CLOEXEC：下面重启 App 会 fork+exec，子进程绝不能继承这把锁，
    // 否则它退出前后续所有 daemon 实例都会被挡在门外。
    int fd = open(path.fileSystemRepresentation, O_CREAT | O_RDWR | O_CLOEXEC, 0644);
    if (fd < 0) {
        dh_log("锁文件 open 失败 %s: %s", path.fileSystemRepresentation ?: "", strerror(errno));
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        dh_log("锁文件 flock 失败 %s: %s", path.UTF8String ?: "", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

#pragma mark - state

static void dh_state_save(void) {
    if (!g_state) return;
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    [paths addObject:DH_STATE_PATH];
    NSString *jbState = dh_jb_path(DH_JB_STATE_REL);
    if (jbState.length) [paths addObject:jbState];
    if (g_engine_dir.length) {
        [paths addObject:[g_engine_dir stringByAppendingPathComponent:DH_STATE_FILE]];
    }
    for (NSString *path in paths) {
        if (dh_write_plist(g_state, path)) {
            chmod(path.fileSystemRepresentation, 0644);
        }
    }
}

static void dh_record_op(NSString *kind, NSString *_Nullable version,
    NSString *result, NSString *_Nullable error, NSArray *_Nullable restarted) {
    NSMutableDictionary *op = [NSMutableDictionary dictionary];
    op[@"kind"] = kind;
    if (version) op[@"version"] = version;
    op[@"time"] = @([[NSDate date] timeIntervalSince1970]);
    op[@"result"] = result;
    if (error) op[@"error"] = error;
    if (restarted) op[@"restartedApps"] = restarted;
    g_state[@"lastOp"] = op;
    dh_state_save();
}

static void dh_notify_state(void) {
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
        (__bridge CFStringRef)DH_NOTIFY_STATE, NULL, NULL, TRUE);
}

#pragma mark - 版本比较

static NSString *dh_strip_v(NSString *s) {
    if ([s hasPrefix:@"v"] || [s hasPrefix:@"V"]) return [s substringFromIndex:1];
    return s;
}

static NSComparisonResult dh_compare_versions(NSString *left, NSString *right) {
    NSArray<NSString *> *a = [dh_strip_v(left ?: @"") componentsSeparatedByString:@"."];
    NSArray<NSString *> *b = [dh_strip_v(right ?: @"") componentsSeparatedByString:@"."];
    NSUInteger n = MAX(a.count, b.count);
    for (NSUInteger i = 0; i < n; i++) {
        NSInteger x = (i < a.count) ? a[i].integerValue : 0;
        NSInteger y = (i < b.count) ? b[i].integerValue : 0;
        if (x < y) return NSOrderedAscending;
        if (x > y) return NSOrderedDescending;
    }
    return NSOrderedSame;
}

static NSDictionary *_Nullable dh_resolve_latest(NSString **errOut) {
    __block NSDictionary *info = nil;
    __block NSError *error = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    NSURLSessionDataTask *task = DHFetchPackageUpdate(^(NSDictionary *result, NSError *failure) {
        info = result; error = failure; dispatch_semaphore_signal(sem);
    });
    if (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 35LL * NSEC_PER_SEC)) != 0) {
        [task cancel];
        if (errOut) *errOut = @"越狱源检查超时";
        return nil;
    }
    if (!info && errOut) *errOut = error.localizedDescription ?: @"源中没有匹配的完整包";
    return info;
}

// bundleID → 可执行名（root 可读全部容器；/Applications 覆盖越狱应用）
static NSDictionary<NSString *, NSString *> *dh_executable_map(void) {
    NSMutableDictionary<NSString *, NSString *> *map = [NSMutableDictionary dictionary];
    @try {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSMutableArray<NSString *> *bases = [NSMutableArray arrayWithObject:@"/var/containers/Bundle/Application"];
        // 越狱安装的 App 在 <jbroot>/Applications（rootless 是 /private/preboot/...，roothide 是 /），
        // 只扫 /Applications 会漏掉它们 —— 表现为装完"重启 0 个应用"。
        NSString *root = dh_bootstrap_root();
        if (root.length > 1) {
            [bases addObject:[root stringByAppendingPathComponent:@"Applications"]];
        }
        [bases addObject:@"/Applications"];
        for (NSString *base in bases) {
            for (NSString *container in [fm contentsOfDirectoryAtPath:base error:nil]) {
                NSString *containerPath = [base stringByAppendingPathComponent:container];
                BOOL wantApp = [container.pathExtension.lowercaseString isEqualToString:@"app"];
                NSArray<NSString *> *entries = wantApp ? @[@""] : [fm contentsOfDirectoryAtPath:containerPath error:nil];
                for (NSString *entry in entries) {
                    if (!wantApp && ![entry.pathExtension.lowercaseString isEqualToString:@"app"]) continue;
                    NSString *appPath = wantApp ? containerPath : [containerPath stringByAppendingPathComponent:entry];
                    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                        [appPath stringByAppendingPathComponent:@"Info.plist"]];
                    NSString *bid = info[@"CFBundleIdentifier"];
                    NSString *exec = info[@"CFBundleExecutable"];
                    if (bid.length && exec.length && !map[bid]) map[bid] = exec;
                }
            }
        }
    } @catch (__unused NSException *e) {
    }
    return map;
}

// best-effort：按可执行名 SIGKILL，杀不到不算错；返回实际杀掉的名字
static NSArray<NSString *> *dh_kill_processes_named(NSSet<NSString *> *names) {
    NSMutableArray<NSString *> *killed = [NSMutableArray array];
    if (names.count == 0) return killed;
    pid_t selfPid = getpid();
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t len = 0;
    if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0 || len == 0) return killed;
    struct kinfo_proc *procs = malloc(len);
    if (!procs) return killed;
    if (sysctl(mib, 4, procs, &len, NULL, 0) != 0) {
        free(procs);
        return killed;
    }
    size_t n = len / sizeof(struct kinfo_proc);
    for (size_t i = 0; i < n; i++) {
        pid_t pid = procs[i].kp_proc.p_pid;
        if (pid <= 1 || pid == selfPid) continue;
        char comm[MAXCOMLEN + 1];
        memcpy(comm, procs[i].kp_proc.p_comm, MAXCOMLEN);
        comm[MAXCOMLEN] = '\0';
        for (NSString *name in names) {
            const char *want = name.UTF8String;
            if (!want || !want[0]) continue;
            // p_comm 最长 16 字节：短名精确比，长名比前缀
            BOOL match = (strlen(want) <= MAXCOMLEN - 1)
                ? (strcmp(comm, want) == 0)
                : (strncmp(comm, want, MAXCOMLEN - 1) == 0);
            if (match && kill(pid, SIGKILL) == 0) {
                if (![killed containsObject:name]) [killed addObject:name];
            }
        }
    }
    free(procs);
    return killed;
}

#pragma mark - 重启指定 App

// 结束目标 App 的进程，并尽量把它重新拉起来（越狱环境才能做这件事）。
// 拉回来依赖 uiopen（uikittools）；设备上没有该工具时就只结束进程，
// 由 App 侧如实告诉用户"需要手动点开"。
static BOOL dh_relaunch_app(NSString *bundleID) {
    const char *candidates[] = { "/var/jb/usr/bin/uiopen", "/usr/local/bin/uiopen",
                                 "/usr/bin/uiopen", NULL };
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    if (g_engine_dir.length) {
        NSString *root = g_engine_dir;
        for (int i = 0; i < 3; i++) root = [root stringByDeletingLastPathComponent];
        if (root.length) [paths addObject:[root stringByAppendingPathComponent:@"usr/bin/uiopen"]];
    }
    for (int i = 0; candidates[i]; i++) {
        [paths addObject:[NSString stringWithUTF8String:candidates[i]]];
    }
    char toolBuf[PATH_MAX];
    toolBuf[0] = '\0';
    for (NSString *path in paths) {
        if (access(path.fileSystemRepresentation, X_OK) == 0) {
            strncpy(toolBuf, path.fileSystemRepresentation, sizeof(toolBuf) - 1);
            toolBuf[sizeof(toolBuf) - 1] = '\0';
            break;
        }
    }
    if (!toolBuf[0]) return NO;
    pid_t pid = fork();
    if (pid < 0) return NO;
    if (pid == 0) {
        setsid();   // 脱离会话，daemon 退出也不影响它
        execl(toolBuf, toolBuf, "--bundleid", bundleID.UTF8String, (char *)NULL);
        _exit(127);
    }
    return YES;
}

// 只结束进程、不重新打开（用户在卡片菜单里主动选择"停止"）
static void dh_do_stop(NSString *bundleID) {
    if (bundleID.length == 0) {
        dh_record_op(@"stop", nil, @"error", @"请求里没有 bundle", nil);
        return;
    }
    NSString *execName = dh_executable_map()[bundleID];
    if (execName.length == 0) {
        dh_record_op(@"stop", nil, @"error", @"找不到该 App 的可执行文件", nil);
        return;
    }
    NSArray<NSString *> *killed = dh_kill_processes_named([NSSet setWithObject:execName]);

    NSMutableDictionary *op = [NSMutableDictionary dictionary];
    op[@"kind"] = @"stop";
    op[@"time"] = @([[NSDate date] timeIntervalSince1970]);
    op[@"bundle"] = bundleID;
    if (killed.count > 0) {
        op[@"result"] = @"ok";
        op[@"restartedApps"] = killed;
    } else {
        op[@"result"] = @"skipped";
        op[@"error"] = @"该 App 当前没有在运行";
    }
    g_state[@"lastOp"] = op;
    dh_state_save();
    dh_log("停止 %s：结束 %lu 个进程", bundleID.UTF8String, (unsigned long)killed.count);
}

static void dh_do_restart(NSString *bundleID) {
    if (bundleID.length == 0) {
        dh_record_op(@"restart", nil, @"error", @"请求里没有 bundle", nil);
        return;
    }
    NSDictionary<NSString *, NSString *> *execMap = dh_executable_map();
    NSString *execName = execMap[bundleID];
    if (execName.length == 0) {
        dh_record_op(@"restart", nil, @"error", @"找不到该 App 的可执行文件", nil);
        return;
    }
    NSArray<NSString *> *killed = dh_kill_processes_named([NSSet setWithObject:execName]);
    BOOL relaunched = dh_relaunch_app(bundleID);

    NSMutableDictionary *op = [NSMutableDictionary dictionary];
    op[@"kind"] = @"restart";
    op[@"time"] = @([[NSDate date] timeIntervalSince1970]);
    op[@"bundle"] = bundleID;
    op[@"relaunched"] = @(relaunched);
    if (killed.count > 0) {
        op[@"result"] = @"ok";
        op[@"restartedApps"] = killed;
    } else {
        op[@"result"] = @"skipped";
        op[@"error"] = @"该 App 当前没有在运行";
    }
    g_state[@"lastOp"] = op;
    dh_state_save();
    dh_log("重启 %s：结束 %lu 个进程，relaunched=%d", bundleID.UTF8String,
           (unsigned long)killed.count, relaunched ? 1 : 0);
}

#pragma mark - 检查 / 安装 / 回滚

static NSString *dh_local_version(void) {
    NSDictionary *meta = dh_read_plist([g_engine_dir stringByAppendingPathComponent:DH_VERSION_FILE]);
    NSString *v = meta[@"version"];
    return ([v isKindOfClass:[NSString class]] && v.length) ? v : @"0";
}

static void dh_do_check(void) {
    NSString *resolveErr = nil;
    NSDictionary *latest = dh_resolve_latest(&resolveErr);
    g_state[@"lastCheck"] = @([[NSDate date] timeIntervalSince1970]);
    if (!latest) {
        g_state[@"lastCheckError"] = resolveErr ?: @"网络失败";
        dh_state_save();
        dh_log("检查更新失败: %s", ((NSString *)g_state[@"lastCheckError"]).UTF8String);
        return;
    }
    NSString *tag = latest[@"tag"];
    [g_state removeObjectForKey:@"lastCheckError"];
    g_state[@"latestVersion"] = tag;
    // 显式转 BOOL：C 的 == 结果是 int，落盘会变成 <integer>1</integer> 而不是 <true/>
    g_state[@"updateAvailable"] = @((BOOL)(dh_compare_versions(dh_local_version(), latest[@"version"]) == NSOrderedAscending));
    dh_state_save();
    dh_log("检查更新: 本地 %s 最新 %s", dh_local_version().UTF8String, ((NSString *)tag).UTF8String);
}

static void dh_do_set_enabled(id raw) {
    NSMutableArray<NSString *> *bundles = [NSMutableArray array];
    if ([raw isKindOfClass:[NSArray class]]) {
        for (id item in (NSArray *)raw) {
            if (![item isKindOfClass:[NSString class]]) continue;
            NSString *bid = item;
            if (bid.length == 0 || bid.length > 256) continue;
            [bundles addObject:bid];
            if (bundles.count >= 4096) break;
        }
    }
    [bundles sortUsingSelector:@selector(compare:)];
    NSString *dir = [g_engine_dir stringByAppendingPathComponent:@"config"];
    NSString *path = [dir stringByAppendingPathComponent:@"enabledBundles.plist"];
    mkdir(dir.fileSystemRepresentation, 0777);
    NSError *serErr = nil;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:@{DH_KEY_BUNDLES: bundles}
        format:NSPropertyListXMLFormat_v1_0 options:0 error:&serErr];
    BOOL ok = NO;
    if (data) {
        NSString *tmp = [path stringByAppendingString:@".new"];
        int fd = open(tmp.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
        if (fd >= 0) {
            const uint8_t *buf = data.bytes;
            NSUInteger left = data.length;
            BOOL wrote = YES;
            while (left) {
                ssize_t n = write(fd, buf, left);
                if (n <= 0) { wrote = NO; break; }
                buf += (NSUInteger)n;
                left -= (NSUInteger)n;
            }
            fsync(fd);
            close(fd);
            if (wrote && rename(tmp.fileSystemRepresentation, path.fileSystemRepresentation) == 0) {
                ok = YES;
            } else {
                unlink(tmp.fileSystemRepresentation);
            }
        }
    }
    if (ok) {
        chown(dir.fileSystemRepresentation, 501, 501);
        chown(path.fileSystemRepresentation, 501, 501);
        chmod(dir.fileSystemRepresentation, 0777);
        chmod(path.fileSystemRepresentation, 0666);
        dh_log("已写入启用名单 %lu 项", (unsigned long)bundles.count);
        dh_record_op(DH_REQ_SET_ENABLED, nil, @"ok", nil, nil);
    } else {
        dh_log("写入启用名单失败: %s", path.UTF8String ?: "");
        dh_record_op(DH_REQ_SET_ENABLED, nil, @"error", @"write failed", nil);
    }
}

#pragma mark - 请求处理

static void dh_ensure_request_file(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:DH_REQUEST_PATH]) return;
    dh_write_plist(@{@"action": DH_REQ_NONE}, DH_REQUEST_PATH);
    chown(DH_REQUEST_PATH.fileSystemRepresentation, 501, 501); // mobile
    chmod(DH_REQUEST_PATH.fileSystemRepresentation, 0644);
}

static void dh_process_request(void) {
    dh_ensure_request_file();
    NSMutableDictionary *req = [(dh_read_plist(DH_REQUEST_PATH) ?: @{}) mutableCopy];
    NSString *action = req[@"action"];
    BOOL fromLoaderPrefs = NO;
    if (![action isKindOfClass:[NSString class]] || [action isEqualToString:DH_REQ_NONE]) {
        // roothide: App 的 /var/mobile 写入可能落在容器视图，request 文件到不了
        // daemon。loader prefs 是 App 与 daemon 都稳定使用的通道，这里兜底读取。
        NSString *loaderPath = dh_jb_path(@"var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist");
        if (!loaderPath.length) loaderPath = DH_LOADER_PREFS;
        NSDictionary *loader = dh_read_plist(loaderPath) ?: dh_read_plist(DH_LOADER_PREFS);
        NSDictionary *pending = loader[@"updaterRequest"];
        if ([pending isKindOfClass:[NSDictionary class]]) {
            req = [pending mutableCopy];
            action = req[@"action"];
            fromLoaderPrefs = YES;
        }
    }
    if (![action isKindOfClass:[NSString class]] || [action isEqualToString:DH_REQ_NONE]) {
        return;
    }
    // 先清零再执行：本次写入会再次触发 WatchPaths，但下次进来 action=none 直接返回，不会循环
    req[@"action"] = DH_REQ_NONE;
    if (fromLoaderPrefs) {
        NSString *loaderPath = dh_jb_path(@"var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist");
        if (!loaderPath.length) loaderPath = DH_LOADER_PREFS;
        NSMutableDictionary *loader = [(dh_read_plist(loaderPath) ?: @{}) mutableCopy];
        [loader removeObjectForKey:@"updaterRequest"];
        dh_write_plist(loader, loaderPath);
        chown(loaderPath.fileSystemRepresentation, 501, 501);
        chmod(loaderPath.fileSystemRepresentation, 0644);
    } else {
        dh_write_plist(req, DH_REQUEST_PATH);
    }
    dh_log("处理请求: %s%s", action.UTF8String, fromLoaderPrefs ? " (loader-prefs)" : "");
    if ([action isEqualToString:DH_REQ_CHECK]) {
        dh_do_check();
    } else if (DHPackageManagerRequired(action)) {
        dh_record_op(action, nil, @"error", @"请通过包管理器更新或回退完整 deb，不再单独替换引擎", nil);
    } else if ([action isEqualToString:DH_REQ_RESTART]) {
        id bundle = req[@"bundle"];
        dh_do_restart([bundle isKindOfClass:[NSString class]] ? bundle : nil);
    } else if ([action isEqualToString:DH_REQ_STOP]) {
        id bundle = req[@"bundle"];
        dh_do_stop([bundle isKindOfClass:[NSString class]] ? bundle : nil);
    } else if ([action isEqualToString:DH_REQ_SET_ENABLED]) {
        dh_do_set_enabled(req[DH_KEY_BUNDLES]);
    } else {
        dh_log("未知请求: %s，已忽略", action.UTF8String);
    }
    req[@"lastAction"] = action;
    req[@"time"] = @([[NSDate date] timeIntervalSince1970]);
    dh_write_plist(req, DH_REQUEST_PATH);
}

static void dh_periodic_check(void) {
    NSTimeInterval last = [g_state[@"lastCheck"] doubleValue];
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (now - last < DH_CHECK_INTERVAL) return;
    dh_do_check();
}

#pragma mark - main

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    @autoreleasepool {
        dh_log("启动");
        g_engine_dir = dh_existing_engine_dir();
        if (!g_engine_dir) {
            NSString *fallbackDir = dh_existing_engine_dir_loose();
            if (fallbackDir.length) {
                NSDictionary *state = @{
                    @"lastOp": @{
                        @"kind": @"install",
                        @"result": @"error",
                        @"error": @"引擎不存在",
                        @"time": @([[NSDate date] timeIntervalSince1970]),
                    },
                };
                NSString *statePath = [fallbackDir stringByAppendingPathComponent:DH_STATE_FILE];
                if (dh_write_plist(state, statePath)) {
                    chmod(statePath.fileSystemRepresentation, 0644);
                }
            }
            dh_log("引擎目录不存在，退出");
            return 0;
        }
        g_engine_writable = dh_dir_is_writable(g_engine_dir);
        dh_log("引擎目录 %s writable=%d", g_engine_dir.UTF8String ?: "(nil)", g_engine_writable ? 1 : 0);
        int lockFd = dh_acquire_lock();
        if (lockFd < 0) {
            dh_log("拿不到锁，退出");
            return 0;
        }
        NSDictionary *mobileState = dh_read_plist(DH_STATE_PATH);
        NSDictionary *jbState = dh_read_plist(dh_jb_path(DH_JB_STATE_REL));
        NSDictionary *engineState = dh_read_plist([g_engine_dir stringByAppendingPathComponent:DH_STATE_FILE]);
        g_state = [((mobileState ?: jbState) ?: (engineState ?: @{})) mutableCopy];
        dh_process_request();
        dh_periodic_check();
        g_state[@"daemonHeartbeat"] = @([[NSDate date] timeIntervalSince1970]);
        dh_state_save();
        dh_notify_state();
        close(lockFd);
        dh_log("结束");
    }
    return 0;
}
