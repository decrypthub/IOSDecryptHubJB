// dh_noise.h — 噪点特征串管理 (ObjC, 变长字符串列表)
//
// 系统本身高频调用一些"业务无关"的 API(如 MobileGestalt MGCopyAnswer* 系列内部缓存键),
// 会在摘要/HMAC 等 hook 里以 input 形式出现, 混进主事件流干扰渗透测试者注意力。这里维护一份
// 用户可增删的"噪点特征串"列表, 供 log_store.m 的 append: 判定是否把条目改投到噪点桶。
// 持久化到沙箱(Documents/.dh_noise.conf), 格式: 第一行 1/0(总开关), 之后每行一条特征串。

#ifndef DH_NOISE_H
#define DH_NOISE_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// 从沙箱加载持久化配置(应在安装 hook 之前调用一次)。confPath = .dh_noise.conf 绝对路径;
// 文件不存在则用默认值(enabled=YES, patterns=["MGCopyAnswer"])。
void dh_noise_load(NSString *confPath);

BOOL dh_noise_enabled(void);
void dh_noise_set_enabled(BOOL on);   // 立即存盘

NSArray<NSString *> *dh_noise_patterns(void);
BOOL dh_noise_add_pattern(NSString *pattern);      // 去重(忽略大小写); 立即存盘; 已存在返回 NO
BOOL dh_noise_remove_pattern(NSString *pattern);   // 不存在返回 NO; 立即存盘

// 对当前特征串列表做不区分大小写子串匹配 (总开关关闭时也照常匹配, 由调用方结合 dh_noise_enabled 判断)。
BOOL dh_noise_matches(NSString * _Nullable text);

NS_ASSUME_NONNULL_END

#endif // DH_NOISE_H
