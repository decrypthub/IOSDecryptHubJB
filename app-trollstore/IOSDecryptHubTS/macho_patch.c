// macho_patch.c — Mach-O LC_LOAD_DYLIB 插入/移除 (纯 C 实现)
//
// 原理:
//   插入: 在 load commands 区域末尾的 padding 中写入新的 dylib_command,
//         更新 ncmds / sizeofcmds。需要 padding 足够 (绝大多数 App 都有)。
//   移除: 找到匹配的 dylib_command, memmove 后续命令覆盖它, 尾部清零,
//         更新 ncmds / sizeofcmds。
//   fat:  遍历每个 arch slice, 对每个 thin Mach-O 执行操作。
//
// 参考: insert_dylib (optool), TrollFools InjectorV3

#include "macho_patch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

// ---------- 工具函数 ----------

// 8 字节对齐
static uint32_t align8(uint32_t v) { return (v + 7) & ~7u; }

// 路径后缀匹配: "/a/b/c.dylib" 匹配 "c.dylib" 或 "@executable_path/c.dylib"
static int path_suffix_match(const char *full, const char *suffix) {
    size_t fl = strlen(full), sl = strlen(suffix);
    if (sl > fl) return 0;
    if (strcmp(full + fl - sl, suffix) == 0) {
        // 确保匹配在 '/' 边界
        if (fl == sl) return 1;
        char c = full[fl - sl - 1];
        return c == '/' || c == '\0';
    }
    return 0;
}

// ---------- 单个 thin Mach-O 操作 ----------

// 在 thin Mach-O 数据中查找 dylib (返回 dylib_command 指针, 或 NULL)
static struct dylib_command *find_dylib_in_slice(
    uint8_t *base, uint32_t size, const char *dylib_name)
{
    if (size < sizeof(struct mach_header_64)) return NULL;
    struct mach_header_64 *hdr = (struct mach_header_64 *)base;
    if (hdr->magic != MH_MAGIC_64) return NULL;

    uint8_t *ptr = base + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        struct load_command *lc = (struct load_command *)ptr;
        if (ptr + sizeof(struct load_command) > base + size) break;
        if (lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB) {
            struct dylib_command *dc = (struct dylib_command *)ptr;
            const char *name = (const char *)(ptr + dc->dylib.name.offset);
            if (path_suffix_match(name, dylib_name)) return dc;
        }
        ptr += lc->cmdsize;
    }
    return NULL;
}

// 计算 load commands 区域之后、第一个 section 数据之前的可用 padding
static uint32_t available_padding(uint8_t *base, uint32_t size) {
    struct mach_header_64 *hdr = (struct mach_header_64 *)base;
    uint32_t lc_end = sizeof(struct mach_header_64) + hdr->sizeofcmds;

    // 找所有 section 的最小 offset (即数据区起始)
    uint32_t min_data = size; // 兜底: 整个文件
    uint8_t *ptr = base + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        struct load_command *lc = (struct load_command *)ptr;
        if (ptr + sizeof(struct load_command) > base + size) break;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)ptr;
            // segment 本身的 fileoff (如 __LINKEDIT)
            if (seg->fileoff > 0 && seg->fileoff < min_data)
                min_data = seg->fileoff;
            // 各 section 的 offset
            uint8_t *sptr = ptr + sizeof(struct segment_command_64);
            for (uint32_t j = 0; j < seg->nsects; j++) {
                struct section_64 *sect = (struct section_64 *)sptr;
                if (sect->offset > 0 && sect->offset < min_data)
                    min_data = sect->offset;
                sptr += sizeof(struct section_64);
            }
        }
        ptr += lc->cmdsize;
    }
    if (min_data <= lc_end) return 0;
    return min_data - lc_end;
}

// 在 thin Mach-O 中插入 LC_LOAD_DYLIB
static int insert_dylib_in_slice(uint8_t *base, uint32_t size, const char *dylib_path) {
    struct mach_header_64 *hdr = (struct mach_header_64 *)base;
    if (hdr->magic != MH_MAGIC_64) return DH_MACHO_ERR_MAGIC;

    // 已存在?
    // 取文件名部分做匹配
    const char *fname = strrchr(dylib_path, '/');
    fname = fname ? fname + 1 : dylib_path;
    if (find_dylib_in_slice(base, size, fname)) return DH_MACHO_ERR_EXISTS;

    // 计算新命令大小: dylib_command + 字符串 + '\0', 8 字节对齐
    uint32_t name_len = (uint32_t)strlen(dylib_path) + 1;
    uint32_t new_cmd_size = align8((uint32_t)sizeof(struct dylib_command) + name_len);

    // 检查 padding
    uint32_t pad = available_padding(base, size);
    if (pad < new_cmd_size) return DH_MACHO_ERR_NOSPACE;

    // 写入位置: load commands 末尾
    uint32_t lc_end = sizeof(struct mach_header_64) + hdr->sizeofcmds;
    uint8_t *insert_at = base + lc_end;

    // 构造 dylib_command
    struct dylib_command *dc = (struct dylib_command *)insert_at;
    memset(dc, 0, new_cmd_size);
    dc->cmd = LC_LOAD_DYLIB;
    dc->cmdsize = new_cmd_size;
    dc->dylib.name.offset = (uint32_t)sizeof(struct dylib_command);
    dc->dylib.timestamp = 2; // 标准值
    dc->dylib.current_version = 0x00010000;    // 1.0.0
    dc->dylib.compatibility_version = 0x00010000;
    memcpy(insert_at + sizeof(struct dylib_command), dylib_path, name_len);

    // 更新 header
    hdr->ncmds++;
    hdr->sizeofcmds += new_cmd_size;

    return DH_MACHO_OK;
}

// 在 thin Mach-O 中移除 LC_LOAD_DYLIB
static int remove_dylib_in_slice(uint8_t *base, uint32_t size, const char *dylib_name) {
    struct mach_header_64 *hdr = (struct mach_header_64 *)base;
    if (hdr->magic != MH_MAGIC_64) return DH_MACHO_ERR_MAGIC;

    struct dylib_command *target = find_dylib_in_slice(base, size, dylib_name);
    if (!target) return DH_MACHO_ERR_NOTFOUND;

    uint32_t target_size = target->cmdsize;
    uint8_t *target_ptr = (uint8_t *)target;
    uint32_t lc_end = sizeof(struct mach_header_64) + hdr->sizeofcmds;

    // memmove: 把 target 之后的所有 load commands 前移
    uint8_t *after = target_ptr + target_size;
    uint32_t tail_len = lc_end - (uint32_t)(after - base);
    if (tail_len > 0) {
        memmove(target_ptr, after, tail_len);
    }
    // 尾部清零
    memset(base + lc_end - target_size, 0, target_size);

    // 更新 header
    hdr->ncmds--;
    hdr->sizeofcmds -= target_size;

    return DH_MACHO_OK;
}

// 检查 thin Mach-O 是否包含指定 dylib
static int has_dylib_in_slice(uint8_t *base, uint32_t size, const char *dylib_name) {
    struct mach_header_64 *hdr = (struct mach_header_64 *)base;
    if (hdr->magic != MH_MAGIC_64) return 0;
    return find_dylib_in_slice(base, size, dylib_name) ? 1 : 0;
}

// ---------- fat binary 支持 ----------

typedef int (*slice_op_fn)(uint8_t *base, uint32_t size, const char *arg);

// 对 fat/thin 二进制执行操作 (自动判断)
static int apply_to_macho(const char *path, slice_op_fn op, const char *arg) {
    int fd = open(path, O_RDWR);
    if (fd < 0) return DH_MACHO_ERR_OPEN;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return DH_MACHO_ERR_READ; }
    uint32_t file_size = (uint32_t)st.st_size;

    uint8_t *data = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (data == MAP_FAILED) { close(fd); return DH_MACHO_ERR_ALLOC; }

    int result = DH_MACHO_OK;
    uint32_t magic = *(uint32_t *)data;

    if (magic == MH_MAGIC_64) {
        // thin binary
        result = op(data, file_size, arg);
    } else if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        // fat binary (big-endian header)
        struct fat_header *fh = (struct fat_header *)data;
        uint32_t nfat = magic == FAT_CIGAM ? __builtin_bswap32(fh->nfat_arch) : fh->nfat_arch;
        struct fat_arch *archs = (struct fat_arch *)(data + sizeof(struct fat_header));

        for (uint32_t i = 0; i < nfat && result == DH_MACHO_OK; i++) {
            uint32_t offset = magic == FAT_CIGAM ? __builtin_bswap32(archs[i].offset) : archs[i].offset;
            uint32_t sz     = magic == FAT_CIGAM ? __builtin_bswap32(archs[i].size)   : archs[i].size;
            if (offset + sz > file_size) continue;
            // 只处理 64-bit slice
            uint32_t slice_magic = *(uint32_t *)(data + offset);
            if (slice_magic == MH_MAGIC_64) {
                result = op(data + offset, sz, arg);
            }
        }
    } else if (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
        // fat 64-bit header
        struct fat_header *fh = (struct fat_header *)data;
        uint32_t nfat = (magic == FAT_CIGAM_64) ? __builtin_bswap32(fh->nfat_arch) : fh->nfat_arch;
        struct fat_arch_64 *archs = (struct fat_arch_64 *)(data + sizeof(struct fat_header));

        for (uint32_t i = 0; i < nfat && result == DH_MACHO_OK; i++) {
            uint64_t offset = (magic == FAT_CIGAM_64) ? __builtin_bswap64(archs[i].offset) : archs[i].offset;
            uint64_t sz     = (magic == FAT_CIGAM_64) ? __builtin_bswap64(archs[i].size)   : archs[i].size;
            if (offset + sz > file_size) continue;
            uint32_t slice_magic = *(uint32_t *)(data + offset);
            if (slice_magic == MH_MAGIC_64) {
                result = op(data + offset, (uint32_t)sz, arg);
            }
        }
    } else {
        result = DH_MACHO_ERR_MAGIC;
    }

    msync(data, file_size, MS_SYNC);
    munmap(data, file_size);
    close(fd);
    return result;
}

// ---------- 公开 API ----------

int dh_macho_has_dylib(const char *macho_path, const char *dylib_name) {
    // 用只读方式打开
    int fd = open(macho_path, O_RDONLY);
    if (fd < 0) return DH_MACHO_ERR_OPEN;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return DH_MACHO_ERR_READ; }
    uint32_t file_size = (uint32_t)st.st_size;

    uint8_t *data = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED) return DH_MACHO_ERR_ALLOC;

    int result = 0;
    uint32_t magic = *(uint32_t *)data;

    if (magic == MH_MAGIC_64) {
        result = has_dylib_in_slice(data, file_size, dylib_name);
    } else if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        struct fat_header *fh = (struct fat_header *)data;
        uint32_t nfat = (magic == FAT_CIGAM) ? __builtin_bswap32(fh->nfat_arch) : fh->nfat_arch;
        struct fat_arch *archs = (struct fat_arch *)(data + sizeof(struct fat_header));
        for (uint32_t i = 0; i < nfat; i++) {
            uint32_t offset = (magic == FAT_CIGAM) ? __builtin_bswap32(archs[i].offset) : archs[i].offset;
            uint32_t sz     = (magic == FAT_CIGAM) ? __builtin_bswap32(archs[i].size)   : archs[i].size;
            if (offset + sz > file_size) continue;
            if (*(uint32_t *)(data + offset) == MH_MAGIC_64) {
                if (has_dylib_in_slice(data + offset, sz, dylib_name)) { result = 1; break; }
            }
        }
    } else if (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
        struct fat_header *fh = (struct fat_header *)data;
        uint32_t nfat = (magic == FAT_CIGAM_64) ? __builtin_bswap32(fh->nfat_arch) : fh->nfat_arch;
        struct fat_arch_64 *archs = (struct fat_arch_64 *)(data + sizeof(struct fat_header));
        for (uint32_t i = 0; i < nfat; i++) {
            uint64_t offset = (magic == FAT_CIGAM_64) ? __builtin_bswap64(archs[i].offset) : archs[i].offset;
            uint64_t sz     = (magic == FAT_CIGAM_64) ? __builtin_bswap64(archs[i].size)   : archs[i].size;
            if (offset + sz > file_size) continue;
            if (*(uint32_t *)(data + offset) == MH_MAGIC_64) {
                if (has_dylib_in_slice(data + offset, (uint32_t)sz, dylib_name)) { result = 1; break; }
            }
        }
    }

    munmap(data, file_size);
    return result;
}

int dh_macho_insert_dylib(const char *macho_path, const char *dylib_path) {
    return apply_to_macho(macho_path, insert_dylib_in_slice, dylib_path);
}

int dh_macho_remove_dylib(const char *macho_path, const char *dylib_name) {
    return apply_to_macho(macho_path, remove_dylib_in_slice, dylib_name);
}

// ---------- team ID 提取 (简化版: 从 code signature 中读取) ----------
// ct_bypass 需要 team ID; 如果提取失败, 调用方可用空字符串兜底。

int dh_macho_get_team_id(const char *macho_path, char *buf, int buf_size) {
    if (!buf || buf_size < 1) return DH_MACHO_ERR_ALLOC;
    buf[0] = '\0';

    int fd = open(macho_path, O_RDONLY);
    if (fd < 0) return DH_MACHO_ERR_OPEN;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return DH_MACHO_ERR_READ; }
    uint32_t file_size = (uint32_t)st.st_size;

    uint8_t *data = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED) return DH_MACHO_ERR_ALLOC;

    // 只处理第一个 thin slice (fat 取第一个 arm64)
    uint8_t *base = data;
    uint32_t size = file_size;
    uint32_t magic = *(uint32_t *)data;

    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        struct fat_header *fh = (struct fat_header *)data;
        uint32_t nfat = (magic == FAT_CIGAM) ? __builtin_bswap32(fh->nfat_arch) : fh->nfat_arch;
        struct fat_arch *archs = (struct fat_arch *)(data + sizeof(struct fat_header));
        for (uint32_t i = 0; i < nfat; i++) {
            uint32_t offset = (magic == FAT_CIGAM) ? __builtin_bswap32(archs[i].offset) : archs[i].offset;
            uint32_t sz     = (magic == FAT_CIGAM) ? __builtin_bswap32(archs[i].size)   : archs[i].size;
            if (offset + sz <= file_size && *(uint32_t *)(data + offset) == MH_MAGIC_64) {
                base = data + offset; size = sz; break;
            }
        }
    }

    int result = DH_MACHO_ERR_NOTFOUND;
    if (*(uint32_t *)base == MH_MAGIC_64) {
        struct mach_header_64 *hdr = (struct mach_header_64 *)base;
        uint8_t *ptr = base + sizeof(struct mach_header_64);
        for (uint32_t i = 0; i < hdr->ncmds; i++) {
            struct load_command *lc = (struct load_command *)ptr;
            if (ptr + sizeof(struct load_command) > base + size) break;
            if (lc->cmd == LC_CODE_SIGNATURE) {
                // linkedit_data_command: dataoff, datasize
                struct linkedit_data_command *cs = (struct linkedit_data_command *)ptr;
                // 在 code signature blob 中搜索 team ID 字符串
                // team ID 通常在 CSSLOT_CODEDIRECTORY 的 ident 字段附近
                // 简化: 在 signature 数据中搜索可打印 ASCII 串 (长度 6-12, 大写字母+数字)
                uint8_t *sig = base + cs->dataoff;
                uint32_t sig_size = cs->datasize;
                if (sig + sig_size <= data + file_size && sig_size > 64) {
                    // 扫描找 team ID 模式: 10 位大写字母+数字
                    for (uint32_t j = 0; j + 10 < sig_size; j++) {
                        int ok = 1;
                        for (int k = 0; k < 10; k++) {
                            char c = sig[j + k];
                            if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) { ok = 0; break; }
                        }
                        if (ok && (sig[j + 10] == '\0' || sig[j + 10] == '.')) {
                            int len = 10;
                            if (len < buf_size) {
                                memcpy(buf, sig + j, len);
                                buf[len] = '\0';
                                result = DH_MACHO_OK;
                            }
                            break;
                        }
                    }
                }
                break;
            }
            ptr += lc->cmdsize;
        }
    }

    munmap(data, file_size);
    return result;
}
