// macho_patch.h — Mach-O 二进制 LC_LOAD_DYLIB 插入/移除 (纯 C, 零外部依赖)
//
// 支持 thin (MH_MAGIC_64) 和 fat (FAT_MAGIC / FAT_MAGIC_64) 二进制。
// 用于 TrollStore 变体的注入/卸载, 替代 insert_dylib / optool 外部工具。
//
// 返回值: 0 = 成功, 负数 = 错误码 (见 DH_MACHO_ERR_*)

#ifndef MACHO_PATCH_H
#define MACHO_PATCH_H

#ifdef __cplusplus
extern "C" {
#endif

// 错误码
#define DH_MACHO_OK              0
#define DH_MACHO_ERR_OPEN       -1   // 无法打开文件
#define DH_MACHO_ERR_READ       -2   // 读取失败
#define DH_MACHO_ERR_WRITE      -3   // 写入失败
#define DH_MACHO_ERR_MAGIC      -4   // 不是有效的 Mach-O
#define DH_MACHO_ERR_NOSPACE    -5   // load commands 后无足够空间
#define DH_MACHO_ERR_NOTFOUND   -6   // 未找到目标 load command
#define DH_MACHO_ERR_EXISTS     -7   // dylib 已存在 (插入时)
#define DH_MACHO_ERR_ALLOC      -8   // 内存分配失败

// 检查 Mach-O 是否已加载指定 dylib (匹配路径后缀)
// 返回: 1 = 已加载, 0 = 未加载, 负数 = 错误
int dh_macho_has_dylib(const char *macho_path, const char *dylib_name);

// 插入 LC_LOAD_DYLIB (dylib_path 如 "@executable_path/decrypt_helper.dylib")
// 如果已存在则返回 DH_MACHO_ERR_EXISTS
int dh_macho_insert_dylib(const char *macho_path, const char *dylib_path);

// 移除 LC_LOAD_DYLIB (匹配 dylib_name 后缀)
// 如果不存在则返回 DH_MACHO_ERR_NOTFOUND
int dh_macho_remove_dylib(const char *macho_path, const char *dylib_name);

// 获取 Mach-O 的 team ID (从 code signature 提取, 用于 ct_bypass)
// 返回: 0 = 成功 (team_id 写入 buf), 负数 = 错误
int dh_macho_get_team_id(const char *macho_path, char *buf, int buf_size);

#ifdef __cplusplus
}
#endif

#endif // MACHO_PATCH_H
