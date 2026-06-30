// macho_dump.h — 砸壳核心
//
// 在目标进程内对「已加载进内存、属于本 App bundle」的 Mach-O 镜像做脱壳:
// FairPlay 加密的 __TEXT 段在运行时已被内核解密进内存, 这里把解密后的页写回
// 一份磁盘镜像副本, 并把 LC_ENCRYPTION_INFO_64 的 cryptid 置 0, 得到脱壳二进制。
//
// 仅处理 arm64 (64 位 Mach-O); 32 位镜像跳过。

#ifndef DH_MACHO_DUMP_H
#define DH_MACHO_DUMP_H

#import <Foundation/Foundation.h>
#import <mach-o/loader.h>

NS_ASSUME_NONNULL_BEGIN

// 一个可砸壳目标镜像的描述
@interface DHDumpImage : NSObject
@property (nonatomic, copy)   NSString *path;       // 磁盘路径 (_dyld_get_image_name)
@property (nonatomic, copy)   NSString *name;       // 文件名
@property (nonatomic, copy)   NSString *kind;       // "main" / "framework"
@property (nonatomic, assign) uint32_t  cryptid;    // 0=未加密, 非0=加密
@property (nonatomic, assign) uint64_t  cryptsize;  // 加密段大小 (字节)
@property (nonatomic, assign) const struct mach_header *header;  // 内存中的 Mach-O 头 (内部用)
@end

// 枚举当前进程已加载、且属于主 App bundle 的 64 位镜像 (主程序 + 内嵌 Frameworks/.dylib)。
NSArray<DHDumpImage *> *dh_dump_list_images(void);

// 对一个镜像砸壳, 返回脱壳后的 thin Mach-O 数据 (cryptid 已置 0)。
// 若 cryptid 本就为 0, 返回该镜像的原始 thin slice (相当于直接导出明文二进制)。
// 失败返回 nil 并填充 error。
NSData * _Nullable dh_dump_decrypt_image(DHDumpImage *img, NSError * _Nullable * _Nullable error);

NS_ASSUME_NONNULL_END

#endif // DH_MACHO_DUMP_H
