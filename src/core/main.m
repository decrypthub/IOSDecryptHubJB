// main.m - IOSDecryptHub (Decrypt Helper)
// 注入入口: 在 dylib 被加载时安装所有 hook 并初始化悬浮窗 UI。
// 悬浮窗只负责状态与基础控制，日志查看和分析统一由 Web 控制台完成。

#import <Foundation/Foundation.h>
#if __has_include(<UIKit/UIKit.h>)
#import <UIKit/UIKit.h>
#endif
#import "log_store.h"
#import "ui_float.h"
#import "http_server.h"
#import "dh_health.h"
#import "dh_capture.h"
#import "dh_noise.h"
#import "dh_spoof.h"

extern void dh_install_digest_hooks(void);
extern void dh_install_hmac_hooks(void);
extern void dh_install_symmetric_hooks(void);
extern void dh_install_asymmetric_hooks(void);
extern void dh_install_kdf_hooks(void);
extern void dh_install_evp_hooks(void);
extern void dh_install_file_hooks(void);
extern void dh_install_system_hooks(void);
extern void dh_install_keychain_hooks(void);
extern void dh_install_env_hooks(void);
extern void dh_install_spoof_objc_hooks(void);
extern void dh_install_dyld_hooks(void);
extern void dh_install_network_hooks(void);

static void dh_install_all_hooks(void) {
    dh_install_digest_hooks();
    dh_install_hmac_hooks();
    dh_install_symmetric_hooks();
    dh_install_asymmetric_hooks();
    dh_install_kdf_hooks();
    dh_install_evp_hooks();
    dh_install_file_hooks();
    dh_install_system_hooks();
    dh_install_keychain_hooks();
    dh_install_env_hooks();
    dh_install_spoof_objc_hooks();
    dh_install_dyld_hooks();
    dh_install_network_hooks();
}

// ---- 注入开关: 越狱变体读 Settings 偏好, 默认不激活 ----
// 偏好文件由 PreferenceLoader 写入, 路径:
//   rootless/roothide: /var/jb/var/mobile/Library/Preferences/com.dh.decrypthelper.plist
//   rootful:           /var/mobile/Library/Preferences/com.dh.decrypthelper.plist
// 键:
//   DHEnabled (BOOL)          — 总开关, 默认 NO
//   DHTargetBundleId (String) — 目标 App Bundle ID, 留空 = 所有 App
static BOOL dh_prefs_should_activate(void) {
#if DH_VARIANT >= 2  // rootless(2) / rootful(3) / roothide(4) 才走偏好门控
    // 尝试两个路径 (兼容 rootful 无 /var/jb 前缀)
    NSDictionary *prefs = nil;
    NSArray *paths = @[
        @"/var/jb/var/mobile/Library/Preferences/com.dh.decrypthelper.plist",
        @"/var/mobile/Library/Preferences/com.dh.decrypthelper.plist",
    ];
    for (NSString *p in paths) {
        prefs = [NSDictionary dictionaryWithContentsOfFile:p];
        if (prefs) break;
    }
    // 无偏好文件 = 从未在设置里开启过 → 不注入
    if (!prefs) return NO;
    // 总开关
    if (![prefs[@"DHEnabled"] boolValue]) return NO;
    // 目标 Bundle ID 过滤 (留空 = 全部)
    NSString *target = prefs[@"DHTargetBundleId"];
    if (target.length > 0) {
        NSString *self_bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
        if (![self_bid isEqualToString:target]) return NO;
    }
    return YES;
#else
    // dev / trollstore 变体: 手动注入, 不走偏好门控
    return YES;
#endif
}

__attribute__((constructor))
static void dh_bootstrap(void) {
    // 越狱变体: 设置未开启则不注入, 静默退出
    if (!dh_prefs_should_activate()) return;
    // 预热 Foundation 的 locale / NSDateFormatter / backtrace, 避免 hook 安装后首次时间格式化
    // 在 hooked_open 内部触发 open/dlopen 递归(与 dh_in_hook 标志双保险).
    (void)DHTimestampNow();
    (void)DHCallStackFiltered();
    // 诊断落盘目录 + 捕获配置, 都在装 hook 前就绪(持久化的开关/诊断从一开始生效)。
    NSString *docsDir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    dh_diag_set_dir(docsDir.fileSystemRepresentation);
    dh_diag_append(DH_DIAG_GENERAL, "INFO", "IOSDecryptHub 启动, 开始安装 hook");
    dh_capture_load([docsDir stringByAppendingPathComponent:@".dh_capture.conf"].fileSystemRepresentation);
    dh_noise_load([docsDir stringByAppendingPathComponent:@".dh_noise.conf"]);
    dh_spoof_load([docsDir stringByAppendingPathComponent:@".dh_spoof.conf"]);
    // 安装 hook —— 尽早完成, 否则早期发生的加解密会漏抓.
    dh_install_all_hooks();
    dh_diag_append(DH_DIAG_GENERAL, "INFO", "hook 安装完成 (Digest/HMAC/对称/非对称/KDF/EVP/文件/系统)");
    NSLog(@"[IOSDecryptHub] hook 已全部安装 (Digest / HMAC / 对称 / 非对称 / KDF / EVP / 文件 / 系统 / dlsym)");

    // 启动本地 HTTP 服务 - 不依赖 UIApplication, 可以立刻起.
    dh_http_start();

#if __has_include(<UIKit/UIKit.h>)
    // UI 必须等 UIApplication 实例化后再做; 用 didFinishLaunching 通知做后置初始化.
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                       object:nil queue:nil usingBlock:^(NSNotification *_) {
        dh_ui_install_floating();
    }];
    // 一些 app 加载 dylib 时 UIApplication 已经存在, 直接尝试创建一次, 失败也无所谓.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        dh_ui_install_floating();
    });
#endif

    NSLog(@"[IOSDecryptHub] 日志文件: %@", [[DHLogStore shared] logFilePath]);
}
