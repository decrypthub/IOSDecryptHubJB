// log_store.h - 解密助手
// 公共日志记录中心：所有 hook 模块都把抓到的明文/密文/算法信息丢到这里。
// 严格遵守约束：悬浮窗只用 entry_count 这种统计数据，不显示明细。

#ifndef DECRYPT_HELPER_LOG_STORE_H
#define DECRYPT_HELPER_LOG_STORE_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// 算法分类 —— 用于过滤和着色
typedef NS_ENUM(NSInteger, DHCategory) {
    DHCategoryDigest = 0,        // MD2/4/5, SHA*
    DHCategoryHMAC,              // HMAC-*
    DHCategorySymmetric,         // AES / DES / 3DES / CAST / RC2 / RC4 / Blowfish
    DHCategoryAsymmetric,        // RSA / EC sign / encrypt / verify / decrypt
    DHCategoryOther,
};

// 单条日志
@interface DHLogEntry : NSObject
@property (nonatomic, assign) DHCategory category;
@property (nonatomic, copy)   NSString *algorithm;          // e.g. "MD5" / "AES-128-CBC" / "HMAC-SHA256" / "RSA-SIGN-PKCS1v15-SHA256"
@property (nonatomic, copy)   NSString *operation;          // "encrypt" / "decrypt" / "sign" / "verify" / "digest"
@property (nonatomic, copy, nullable) NSData *key;          // 对称 key / HMAC key (二进制)
@property (nonatomic, copy, nullable) NSData *iv;           // CBC/CTR 等模式的 IV
@property (nonatomic, copy, nullable) NSData *input;        // 输入 (明文/密文/待签数据)
@property (nonatomic, copy, nullable) NSData *output;       // 输出 (摘要/密文/明文/签名)
@property (nonatomic, copy, nullable) NSString *publicKeyInfo;  // RSA 公钥摘要描述
@property (nonatomic, copy)   NSString *timestamp;          // 格式化时间
@property (nonatomic, copy)   NSString *callStack;          // 应用层调用栈 (已过滤)
@property (nonatomic, assign) uint64_t seq;                 // 自增序号
@end

@interface DHLogStore : NSObject

+ (instancetype)shared;

// 写入一条日志 (线程安全)
- (void)append:(DHLogEntry *)entry;

// 当前所有日志快照 (按 seq 升序; 限制最近 N 条以防 UI 卡顿)
- (NSArray<DHLogEntry *> *)snapshot;
- (NSArray<DHLogEntry *> *)snapshotMatching:(nullable NSString *)keyword
                                   category:(NSInteger)categoryOrMinusOne;

// 单条查询 (用于 web detail 端点)
- (nullable DHLogEntry *)entryWithSeq:(uint64_t)seq;

// 统计
- (NSUInteger)totalCount;
- (NSUInteger)countForCategory:(DHCategory)cat;

// 暂停/恢复
@property (atomic, assign) BOOL paused;

// 清空 (内存 + 文件)
- (void)clearAll;

// 日志文件路径 (落盘文件用于 share/导出)
- (NSString *)logFilePath;

@end

// ===== 工具函数 =====
NSString *DHHexFromData(NSData * _Nullable d);
NSString *DHHexDumpFromData(NSData * _Nullable d);
NSString *DHUTF8FromData(NSData * _Nullable d);
NSString *DHCallStackFiltered(void);   // 已过滤系统 / 自身的调用栈
NSString *DHTimestampNow(void);

NS_ASSUME_NONNULL_END
#endif
