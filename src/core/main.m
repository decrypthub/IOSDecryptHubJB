// main.m - IOSDecryptHub (Decrypt Helper)
// 注入入口: 在 dylib 被加载时安装所有 hook 并初始化悬浮窗 UI.
//
// 严格约束:
//   1. 悬浮窗只显示统计信息和操作按钮, 不显示日志正文.
//   2. 完整日志只能通过点击悬浮窗的 "日志" 按钮在全屏查看器里看.
//   3. 落盘文件路径: Documents/decrypt_helper.log

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

extern void dh_install_digest_hooks(void);
extern void dh_install_hmac_hooks(void);
extern void dh_install_symmetric_hooks(void);
extern void dh_install_asymmetric_hooks(void);
extern void dh_install_kdf_hooks(void);
extern void dh_install_file_hooks(void);
extern void dh_install_system_hooks(void);

static void dh_install_all_hooks(void) {
    dh_install_digest_hooks();
    dh_install_hmac_hooks();
    dh_install_symmetric_hooks();
    dh_install_asymmetric_hooks();
    dh_install_kdf_hooks();
    dh_install_file_hooks();
    dh_install_system_hooks();
}

__attribute__((constructor))
static void dh_bootstrap(void) {
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
    // 安装 hook —— 尽早完成, 否则早期发生的加解密会漏抓.
    dh_install_all_hooks();
    dh_diag_append(DH_DIAG_GENERAL, "INFO", "hook 安装完成 (Digest/HMAC/对称/非对称/KDF/文件/系统/dlopen+dlsym)");
    NSLog(@"[IOSDecryptHub] hook 已全部安装 (Digest / HMAC / 对称 / 非对称 / KDF / 文件 / 系统 / dlsym)");

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
