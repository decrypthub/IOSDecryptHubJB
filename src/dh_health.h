// dh_health.h — 进程级「健康状态中心」(fail-loud 基础设施)
//
// 设计目标: 把 hook 没挂上 / 落盘失败 / HTTP 服务失败这类「失效」集中收集,
// 让悬浮窗与 Web 面板能一眼看见、精确定位失效锚点 —— 而不是偷偷兜底造成「时好时坏」。
//
// 纯 C 接口: fishhook.c(纯 C) 与各 ObjC 文件都能调用。内部用 stdatomic + 互斥,
// 零外部依赖, 不引入 Foundation。

#ifndef DH_HEALTH_H
#define DH_HEALTH_H

// 统一错误日志宏 —— 仅在 ObjC 文件(.m)里使用(依赖 NSLog)。
// 纯 C 文件(.c)请直接调用下面的 dh_health_* 函数, 内部已写 stderr。
#ifdef __OBJC__
#import <Foundation/Foundation.h>
#define DH_ERR(fmt, ...) NSLog(@"[IOSDecryptHub/ERR] " fmt, ##__VA_ARGS__)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ---- 上报失效 ----
void dh_health_hook_fail(const char *sym);      // 某符号 rebind 后 orig 仍为 NULL = 没挂上
void dh_health_persist_fail(int err);           // 日志落盘失败 (errno)
void dh_health_http_fail(const char *reason);   // HTTP 服务起不来
void dh_health_http_ok(void);                   // HTTP 服务成功启动, 清除失败态
void dh_health_note_localonly(void);            // 只拿到 127.0.0.1, 仅本地可访问 (info, 非错误)

// ---- 查询状态 ----
unsigned    dh_health_hook_fail_count(void);
int         dh_health_persist_failed(void);     // 0/1
int         dh_health_http_failed(void);        // 0/1
int         dh_health_local_only(void);         // 0/1

// 给 UI / Web 的简短摘要(仅含真正失效: hook/服务/落盘; 不含 localOnly)。
// 无问题返回 "" (空串)。返回内部静态缓冲, 调用方应尽快拷贝。
const char *dh_health_summary(void);

#ifdef __cplusplus
}
#endif

#endif // DH_HEALTH_H
