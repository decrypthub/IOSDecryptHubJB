// dump_manager.h — 砸壳任务管理 (单例)
//
// 砸壳/打包可能耗时(大 IPA 几秒~几十秒), 不能阻塞 HTTP worker。这里用一条串行队列
// 跑单任务, 维护状态机 (idle/running/done/error + 进度), 产物落 Documents, 供 HTTP 下载。
// 按需触发: 不点按钮就不跑, 零额外开销。

#ifndef DH_DUMP_MANAGER_H
#define DH_DUMP_MANAGER_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DHDumpManager : NSObject

+ (instancetype)shared;

// 已加载且属于本 App 的镜像清单 (给 GET /api/dump/images)
- (NSDictionary *)listImagesDict;

// 发起砸壳; mode = @"bin"(裸二进制 zip) | @"ipa"(可重签 IPA)。
// 返回 NO 表示已有任务在跑或 mode 非法。
- (BOOL)startDump:(NSString *)mode;

// 当前任务状态 (给 GET /api/dump/status)
- (NSDictionary *)statusDict;

// 产物路径; kind = @"bin" | @"ipa"; 不存在返回 nil (给 GET /api/dump/download)
- (nullable NSString *)artifactPathForKind:(NSString *)kind;

@end

NS_ASSUME_NONNULL_END

#endif // DH_DUMP_MANAGER_H
