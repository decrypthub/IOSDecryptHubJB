// dh_log_json.h — 日志条目 -> JSON 字典的共享成型逻辑
//
// http_server (面板 /api/logs) 与 mcp_server (取证工具) 共用同一套字段成型, 避免两处漂移。

#ifndef DH_LOG_JSON_H
#define DH_LOG_JSON_H

#import <Foundation/Foundation.h>
#import "log_store.h"

NS_ASSUME_NONNULL_BEGIN

// 分类数量 (= DHCategoryOther + 1); 供各处遍历派生, 替代硬编码平行数组。
NSInteger dh_log_category_count(void);
// DHCategory -> 短名 ("digest"/"hmac"/"sym"/.../"net"/"keychain"/"other")
const char *dh_log_category_name(NSInteger c);

// 摘要 (列表用): seq / category / algorithm / operation / timestamp / in-outLen / detail / preview
NSDictionary *dh_log_entry_summary(DHLogEntry *e);

// 详情 (单条用): 摘要 + key/iv/input/output 的 hex / utf8 / hexdump + callStack + publicKeyInfo
NSDictionary *dh_log_entry_detail(DHLogEntry *e);

NS_ASSUME_NONNULL_END

#endif // DH_LOG_JSON_H
