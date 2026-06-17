// main.m - 解密助手 (Decrypt Helper)
// 注入入口: 在 dylib 被加载时安装所有 hook 并初始化悬浮窗 UI.
//
// 严格约束:
//   1. 悬浮窗只显示统计信息和操作按钮, 不显示日志正文.
//   2. 完整日志只能通过点击悬浮窗的 "日志" 按钮在全屏查看器里看.
//   3. 落盘文件路径: Documents/decrypt_helper.log

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "log_store.h"
#import "ui_float.h"

extern void dh_install_digest_hooks(void);
extern void dh_install_hmac_hooks(void);
extern void dh_install_symmetric_hooks(void);
extern void dh_install_asymmetric_hooks(void);

static void dh_install_all_hooks(void) {
    dh_install_digest_hooks();
    dh_install_hmac_hooks();
    dh_install_symmetric_hooks();
    dh_install_asymmetric_hooks();
}

__attribute__((constructor))
static void dh_bootstrap(void) {
    // 先安装 hook —— 这一步要在尽可能早的时刻完成, 否则早期发生的加解密会漏抓.
    dh_install_all_hooks();
    NSLog(@"[解密助手] hook 已全部安装 (Digest / HMAC / 对称 / 非对称)");

    // UI 必须等 UIApplication 实例化后再做; 用 didFinishLaunching 通知做后置初始化.
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                       object:nil queue:nil usingBlock:^(NSNotification *_) {
        dh_ui_install_floating();
    }];
    // 一些 app 加载 dylib 时 UIApplication 已经存在, 直接尝试创建一次, 失败也无所谓.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        dh_ui_install_floating();
    });

    NSLog(@"[解密助手] 日志文件: %@", [[DHLogStore shared] logFilePath]);
}
