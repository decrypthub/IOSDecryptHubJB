// dh_spoof.h — 进程内伪装/绕过配置中心 (越狱隐藏 / 反调试 / 改机)
//
// 与 dh_capture(记什么) 职责分离: dh_spoof 管「改写什么」。持久化到沙箱 .dh_spoof.conf (JSON)。
// 三组开关:
//   jb      —— 越狱检测绕过: 对敏感文件路径/URL scheme 返回不存在/隐藏 (总开关 + 路径清单 + scheme 清单)
//   anti    —— 反调试: ptrace(PT_DENY_ATTACH) 空转、sysctl 清 P_TRACED、csops 清 CS_DEBUGGED
//   device  —— 改机: hw.machine/hw.model/系统版本/设备名/IDFV/IDFA 伪造 (总开关默认关, 避免误伤)
//
// 热路径 (open/stat/access 每次调) 走 dh_spoof_jb_should_hide_path, 已用 volatile 总开关早退 +
// 小临界区集合匹配。观测默认开、改写默认关(device);jb/anti 默认开以便开箱即用越狱绕过。

#ifndef DH_SPOOF_H
#define DH_SPOOF_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// 加载持久化配置(装 hook 前调用)。文件不存在则用内置默认(常见越狱清单 + 空设备 profile)。
void dh_spoof_load(NSString *confPath);

// ---- 越狱隐藏 ----
BOOL dh_spoof_jb_on(void);
void dh_spoof_jb_set_on(BOOL on);
// 热路径: 总开关关 → 立即返回 NO(volatile, 无锁)。命中(精确或前缀)配置清单则 YES。
BOOL dh_spoof_jb_should_hide_path(const char *path);
BOOL dh_spoof_jb_should_hide_scheme(const char *scheme);
NSArray<NSString *> *dh_spoof_jb_paths(void);
NSArray<NSString *> *dh_spoof_jb_schemes(void);
BOOL dh_spoof_jb_add_path(NSString *p);
BOOL dh_spoof_jb_remove_path(NSString *p);
BOOL dh_spoof_jb_add_scheme(NSString *s);
BOOL dh_spoof_jb_remove_scheme(NSString *s);

// ---- 反调试 ----
BOOL dh_spoof_anti_debug_on(void);
void dh_spoof_anti_debug_set_on(BOOL on);

// ---- 改机 ----
BOOL dh_spoof_device_on(void);
void dh_spoof_device_set_on(BOOL on);
// key ∈ {hw_machine, hw_model, os_version, device_name, idfv, idfa}。未设置/空 → 返回 nil(表示该项不伪造)。
NSString * _Nullable dh_spoof_device_value(NSString *key);
void dh_spoof_device_set_value(NSString *key, NSString * _Nullable val);

// 给 /api/spoof 的整份配置快照(JSON 友好的 NSDictionary)。
NSDictionary *dh_spoof_snapshot(void);

NS_ASSUME_NONNULL_END

#endif // DH_SPOOF_H
