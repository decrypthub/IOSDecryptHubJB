// loader.m — IOSDecryptHub 越狱注入加载器
//
// 由 Substrate/ElleKit/libhooker 加载到所有 App 进程中（Filter.plist: Bundles=*）。
// 唯一职责：读取偏好设置 → 判断当前 App 是否启用 → dlopen 主 dylib。
// 不包含任何 hook 逻辑。hook 全部由主 dylib 的 constructor 完成。
//
// 三端路径：
//   rootless / roothide: /var/jb/usr/lib/IOSDecryptHub/decrypt_helper.dylib
//   rootful:             /usr/lib/IOSDecryptHub/decrypt_helper.dylib

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <unistd.h>
#import <syslog.h>

#define LOADER_TAG      "[IOSDecryptHub]"
#define PREFS_DOMAIN    @"com.iosdecrypthub.loader"
#define PREFS_KEY       @"enabledBundles"

// 按优先级探测主 dylib 路径（兼容三端越狱）
static const char *dh_find_dylib_path(void) {
    static const char *candidates[] = {
        "/var/jb/usr/lib/IOSDecryptHub/decrypt_helper.dylib",   // rootless / roothide
        "/usr/lib/IOSDecryptHub/decrypt_helper.dylib",           // rootful
        NULL
    };
    for (int i = 0; candidates[i]; i++) {
        if (access(candidates[i], F_OK) == 0) {
            return candidates[i];
        }
    }
    return NULL;
}

// 读取偏好：判断当前 bundleID 是否在启用列表中
static BOOL dh_should_inject(NSString *bundleID) {
    if (!bundleID || bundleID.length == 0) return NO;

    // 跳过系统关键进程（避免不必要的开销）
    if ([bundleID hasPrefix:@"com.apple."]) return NO;

    // 读取偏好域
    NSDictionary *prefs = [[NSUserDefaults standardUserDefaults]
        persistentDomainForName:PREFS_DOMAIN];
    if (!prefs) return NO;

    NSArray *enabled = prefs[PREFS_KEY];
    if (!enabled || ![enabled isKindOfClass:[NSArray class]]) return NO;

    return [enabled containsObject:bundleID];
}

__attribute__((constructor))
static void dh_loader_init(void) {
    @autoreleasepool {
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];

        // 默认不注入任何 App —— 只有用户在设置中明确开启的才注入
        if (!dh_should_inject(bundleID)) {
            return;
        }

        const char *dylib_path = dh_find_dylib_path();
        if (!dylib_path) {
            syslog(LOG_WARNING, LOADER_TAG " 主 dylib 未找到, 跳过注入 (%s)",
                   bundleID.UTF8String);
            return;
        }

        syslog(LOG_INFO, LOADER_TAG " 注入 %s → %s", bundleID.UTF8String, dylib_path);

        // dlopen 主 dylib —— 其 __attribute__((constructor)) 会自动执行
        void *handle = dlopen(dylib_path, RTLD_NOW);
        if (!handle) {
            syslog(LOG_ERR, LOADER_TAG " dlopen 失败: %s", dlerror());
        }
    }
}
