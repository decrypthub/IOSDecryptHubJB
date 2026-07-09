// analysis.h — 二进制分析模块 (capstone 反汇编 + 进程内存读取 + Mach-O 镜像枚举)
//
// 对 capstone 与项目现有的 macho_dump 能力做统一包装, 供 MCP 工具调用。
// 符号表枚举不在这里 —— MCP 层直接用 dh_symtab (与 /api/symbols 同一条路径)。

#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================
// 反汇编
// ============================================================

// 单条反汇编指令
typedef struct {
    uint64_t address;          // 指令地址
    char     mnemonic[32];     // 助记符 (如 "stp", "mov")
    char     op_str[192];      // 操作数字符串
    uint8_t  bytes[16];        // 原始机器码
    uint8_t  size;             // 指令长度 (字节)
} AnalysisInsn;

// 反汇编一段字节缓冲。
//   arch: "arm64"/"aarch64" | "arm" | "thumb"; NULL 默认 arm64。
// 返回反汇编出的指令数, 或 -1 表示 capstone 初始化/参数错误。
int analysis_disassemble(const uint8_t *code, size_t size, uint64_t address,
                         const char *arch, AnalysisInsn *out, int max_count);

// 安全读取本进程内存 address 处的 size 字节并反汇编。
// 用 vm_read_overwrite: 地址不可读时返回 -2 (而非崩溃), 参数/反汇编错误返回 -1。
// size 会被截断到 64KB 上限。
int analysis_disassemble_at(uint64_t address, size_t size, const char *arch,
                            AnalysisInsn *out, int max_count);

// 从 address 反汇编, 遇到 ret 即停 (函数边界启发式), 或达到 max_bytes/max_count。
// 内存不可读返回 -2, 参数/反汇编错误返回 -1, 否则返回指令数。max_bytes 截断到 64KB。
int analysis_disassemble_func(uint64_t address, size_t max_bytes, const char *arch,
                              AnalysisInsn *out, int max_count);

// ============================================================
// 符号 / 内存
// ============================================================

// 解析符号名到运行时地址 (dlsym RTLD_DEFAULT)。
// 找到返回 0 并填 *out_addr 与 out_image(所属镜像短名); 未找到返回 -1。
int analysis_resolve_symbol(const char *name, uint64_t *out_addr,
                            char *out_image, size_t image_len);

// 地址 -> 最近符号名 + 偏移 (dladdr)。找到返回 0, 填 out_sym / *out_offset / out_image;
// 该地址无符号信息返回 -1。out_sym 已去前导下划线。
int analysis_symbolicate(uint64_t addr, char *out_sym, size_t sym_len,
                         uint64_t *out_offset, char *out_image, size_t image_len);

// 安全读内存到 out_buf。返回实际读到的字节数, -2 不可读, -1 参数错误。
// size 截断到 min(buf_cap, 64KB)。
int analysis_read_memory(uint64_t addr, size_t size, uint8_t *out_buf, size_t buf_cap);

// 在 [addr, addr+length) 内搜索 pattern (plen 字节, 分块读, 跳过不可读页, 处理块边界)。
// 命中地址写入 out_hits(至多 max_hits), 返回命中数; length 截断到 256MB。
int analysis_search_memory(uint64_t addr, size_t length,
                           const uint8_t *pattern, size_t plen,
                           uint64_t *out_hits, int max_hits);

// ============================================================
// Mach-O 镜像 (复用 macho_dump)
// ============================================================

typedef struct {
    char     name[256];        // 镜像短名
    char     kind[16];         // "main" / "framework"
    uint64_t load_address;     // 内存中的 Mach-O 头地址 (= 加载基址, 可直接喂给 disassemble_at)
    int      encrypted;        // cryptid != 0
    uint32_t cryptid;
    uint64_t cryptsize;        // 加密段大小 (字节); 未加密镜像为 0
} AnalysisMachoImage;

// 枚举主 App bundle 内已加载的 64 位镜像 (主程序 + 内嵌 Frameworks/.dylib)。
// 返回镜像数, 或 -1 表示参数错误。
int analysis_list_macho_images(AnalysisMachoImage *out, int max_count);

#ifdef __cplusplus
}
#endif

#endif // ANALYSIS_H
