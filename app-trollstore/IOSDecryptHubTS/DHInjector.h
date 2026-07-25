// DHInjector.h — TrollStore 注入引擎 (ObjC 封装)
//
// 职责:
//   1. 枚举已安装 App (LSApplicationWorkspace 私有 API)
//   2. 注入: 备份 Mach-O → 复制 dylib → 插入 LC_LOAD_DYLIB → ct_bypass 重签名 → chown
//   3. 卸载: 移除 LC_LOAD_DYLIB → 删 dylib → 恢复备份 → 重签名 → chown
//   4. 状态查询: 检查备份文件是否存在
//
// ⚠️ 本文件属于 TrollStore 变体, 不得引用 daemon/plist/Substrate 任何代码。

#ifndef DHInjector_h
#define DHInjector_h

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// App 信息模型
@interface DHAppInfo : NSObject
@property (nonatomic, copy) NSString *bundleId;
@property (nonatomic, copy) NSString *name;
@property (nonatomic, copy) NSString *version;
@property (nonatomic, copy) NSString *teamId;
@property (nonatomic, copy) NSURL *bundleURL;
@property (nonatomic, assign) BOOL isSystem;
@property (nonatomic, assign) BOOL injected;  // 是否已注入
@end

// 注入引擎
@interface DHInjector : NSObject

+ (instancetype)shared;

// dylib 路径 (App bundle 内嵌, 可能为 nil)
@property (nonatomic, copy, readonly, nullable) NSString *dylibPath;
// 工具路径 (可能为 nil)
@property (nonatomic, copy, readonly, nullable) NSString *ctBypassPath;
@property (nonatomic, copy, readonly, nullable) NSString *ldidPath;

// 枚举已安装 App
- (NSArray<DHAppInfo *> *)listApps;

// 注入 dylib 到目标 App (失败时抛 NSError)
- (BOOL)injectApp:(DHAppInfo *)app error:(NSError **)error;

// 卸载 dylib / 恢复原始二进制 (失败时抛 NSError)
- (BOOL)ejectApp:(DHAppInfo *)app error:(NSError **)error;

// 刷新注入状态
- (void)refreshInjectionStatus:(DHAppInfo *)app;

@end

NS_ASSUME_NONNULL_END

#endif
