// analysis.m — 二进制分析实现
//
// capstone 反汇编 + vm_read_overwrite 安全读内存 + macho_dump 镜像枚举

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#include <dlfcn.h>
#include <string.h>
#include <libgen.h>
#include "capstone/capstone.h"
#include "analysis.h"
#include "macho_dump.h"

#define ANALYSIS_MAX_READ   (64 * 1024)          // 单次读内存上限
#define ANALYSIS_MAX_SEARCH (256 * 1024 * 1024)  // search_memory 范围上限

// ============================================================
// Capstone 反汇编
// ============================================================

// 把 arch 字符串映射成 capstone 的 (arch, mode); 未识别时回退 arm64。
static void arch_to_cs(const char *arch, cs_arch *out_arch, cs_mode *out_mode) {
    cs_arch a = CS_ARCH_ARM64;
    cs_mode m = CS_MODE_ARM;
    if (arch) {
        if (strcmp(arch, "arm") == 0)        { a = CS_ARCH_ARM;   m = CS_MODE_ARM; }
        else if (strcmp(arch, "thumb") == 0) { a = CS_ARCH_ARM;   m = CS_MODE_THUMB; }
        // "arm64"/"aarch64"/其它 → 默认 arm64
    }
    *out_arch = a;
    *out_mode = m;
}

int analysis_disassemble(const uint8_t *code, size_t size, uint64_t address,
                         const char *arch, AnalysisInsn *out, int max_count) {
    if (!code || size == 0 || !out || max_count <= 0) return -1;

    cs_arch cs_a; cs_mode cs_m;
    arch_to_cs(arch, &cs_a, &cs_m);

    csh handle = 0;
    if (cs_open(cs_a, cs_m, &handle) != CS_ERR_OK) return -1;

    cs_insn *insn = cs_malloc(handle);
    if (!insn) { cs_close(&handle); return -1; }

    int count = 0;
    const uint8_t *p = code;
    size_t remaining = size;
    uint64_t cur = address;

    while (count < max_count && remaining > 0 &&
           cs_disasm_iter(handle, &p, &remaining, &cur, insn)) {
        AnalysisInsn *o = &out[count];
        o->address = insn->address;
        o->size = insn->size;
        strncpy(o->mnemonic, insn->mnemonic, sizeof(o->mnemonic) - 1);
        o->mnemonic[sizeof(o->mnemonic) - 1] = '\0';
        strncpy(o->op_str, insn->op_str, sizeof(o->op_str) - 1);
        o->op_str[sizeof(o->op_str) - 1] = '\0';
        size_t nb = insn->size < sizeof(o->bytes) ? insn->size : sizeof(o->bytes);
        memcpy(o->bytes, insn->bytes, nb);
        count++;
    }

    cs_free(insn, 1);
    cs_close(&handle);
    return count;
}

int analysis_disassemble_at(uint64_t address, size_t size, const char *arch,
                            AnalysisInsn *out, int max_count) {
    if (!out || max_count <= 0 || size == 0) return -1;
    if (size > ANALYSIS_MAX_READ) size = ANALYSIS_MAX_READ;

    uint8_t *buf = malloc(size);
    if (!buf) return -1;

    // vm_read_overwrite: 目标区域不可读时返回错误码而非触发 SIGSEGV。
    vm_size_t outsize = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                         (vm_address_t)address, (vm_size_t)size,
                                         (vm_address_t)buf, &outsize);
    if (kr != KERN_SUCCESS || outsize == 0) {
        free(buf);
        return -2;   // 内存不可读
    }

    int n = analysis_disassemble(buf, (size_t)outsize, address, arch, out, max_count);
    free(buf);
    return n;
}

int analysis_disassemble_func(uint64_t address, size_t max_bytes, const char *arch,
                              AnalysisInsn *out, int max_count) {
    if (!out || max_count <= 0) return -1;
    if (max_bytes == 0 || max_bytes > ANALYSIS_MAX_READ) max_bytes = ANALYSIS_MAX_READ;

    uint8_t *buf = malloc(max_bytes);
    if (!buf) return -1;
    vm_size_t outsize = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                         (vm_address_t)address, (vm_size_t)max_bytes,
                                         (vm_address_t)buf, &outsize);
    if (kr != KERN_SUCCESS || outsize == 0) { free(buf); return -2; }

    cs_arch cs_a; cs_mode cs_m;
    arch_to_cs(arch, &cs_a, &cs_m);
    csh handle = 0;
    if (cs_open(cs_a, cs_m, &handle) != CS_ERR_OK) { free(buf); return -1; }
    cs_insn *insn = cs_malloc(handle);
    if (!insn) { cs_close(&handle); free(buf); return -1; }

    int count = 0;
    const uint8_t *p = buf;
    size_t remaining = (size_t)outsize;
    uint64_t cur = address;
    while (count < max_count && remaining > 0 &&
           cs_disasm_iter(handle, &p, &remaining, &cur, insn)) {
        AnalysisInsn *o = &out[count];
        o->address = insn->address;
        o->size = insn->size;
        strncpy(o->mnemonic, insn->mnemonic, sizeof(o->mnemonic) - 1);
        o->mnemonic[sizeof(o->mnemonic) - 1] = '\0';
        strncpy(o->op_str, insn->op_str, sizeof(o->op_str) - 1);
        o->op_str[sizeof(o->op_str) - 1] = '\0';
        size_t nb = insn->size < sizeof(o->bytes) ? insn->size : sizeof(o->bytes);
        memcpy(o->bytes, insn->bytes, nb);
        count++;
        // 函数边界启发式: 遇到 ret 收尾 (arm64 函数以 ret 结束)。
        if (strcmp(insn->mnemonic, "ret") == 0) break;
    }

    cs_free(insn, 1);
    cs_close(&handle);
    free(buf);
    return count;
}

// ============================================================
// 符号 / 内存
// ============================================================

// 取路径 basename 到 buf (dli_fname 是完整路径)。
static void copy_basename(const char *path, char *buf, size_t buflen) {
    if (!buf || buflen == 0) return;
    if (!path) { buf[0] = '\0'; return; }
    char tmp[1024];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    const char *b = basename(tmp);
    strncpy(buf, b ?: "?", buflen - 1);
    buf[buflen - 1] = '\0';
}

int analysis_resolve_symbol(const char *name, uint64_t *out_addr,
                            char *out_image, size_t image_len) {
    if (!name || !out_addr) return -1;
    void *p = dlsym(RTLD_DEFAULT, name);
    if (!p) return -1;
    *out_addr = (uint64_t)(uintptr_t)p;
    if (out_image && image_len) {
        Dl_info info;
        if (dladdr(p, &info) && info.dli_fname) copy_basename(info.dli_fname, out_image, image_len);
        else { out_image[0] = '\0'; }
    }
    return 0;
}

int analysis_symbolicate(uint64_t addr, char *out_sym, size_t sym_len,
                         uint64_t *out_offset, char *out_image, size_t image_len) {
    Dl_info info;
    if (!dladdr((void *)(uintptr_t)addr, &info) || !info.dli_saddr) return -1;
    if (out_sym && sym_len) {
        const char *s = info.dli_sname ?: "";
        if (s[0] == '_') s++;   // 去前导下划线, 与 dh_symtab 一致
        strncpy(out_sym, s, sym_len - 1);
        out_sym[sym_len - 1] = '\0';
    }
    if (out_offset) *out_offset = addr - (uint64_t)(uintptr_t)info.dli_saddr;
    if (out_image && image_len) copy_basename(info.dli_fname, out_image, image_len);
    return 0;
}

int analysis_read_memory(uint64_t addr, size_t size, uint8_t *out_buf, size_t buf_cap) {
    if (!out_buf || size == 0 || buf_cap == 0) return -1;
    if (size > buf_cap) size = buf_cap;
    if (size > ANALYSIS_MAX_READ) size = ANALYSIS_MAX_READ;
    vm_size_t outsize = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                         (vm_address_t)addr, (vm_size_t)size,
                                         (vm_address_t)out_buf, &outsize);
    if (kr != KERN_SUCCESS) return -2;
    return (int)outsize;
}

int analysis_search_memory(uint64_t addr, size_t length,
                           const uint8_t *pattern, size_t plen,
                           uint64_t *out_hits, int max_hits) {
    if (!pattern || plen == 0 || !out_hits || max_hits <= 0) return -1;
    if (length > ANALYSIS_MAX_SEARCH) length = ANALYSIS_MAX_SEARCH;

    const size_t CHUNK = 64 * 1024;
    uint8_t *buf = malloc(CHUNK);
    if (!buf) return -1;

    int hits = 0;
    uint64_t pos = addr;
    uint64_t end = addr + length;
    while (pos < end && hits < max_hits) {
        size_t want = (size_t)((end - pos) < CHUNK ? (end - pos) : CHUNK);
        vm_size_t got = 0;
        kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                             (vm_address_t)pos, (vm_size_t)want,
                                             (vm_address_t)buf, &got);
        if (kr != KERN_SUCCESS || got == 0) {
            // 不可读页: 跳过整块继续 (跨该间隙的匹配会漏, 可接受)。
            pos += CHUNK;
            continue;
        }
        if (got >= plen) {
            const uint8_t *base = buf;
            const uint8_t *hit;
            size_t remain = (size_t)got;
            while (hits < max_hits &&
                   (hit = memmem(base, remain, pattern, plen)) != NULL) {
                out_hits[hits++] = pos + (uint64_t)(hit - buf);
                size_t consumed = (size_t)(hit - base) + 1;
                base += consumed;
                remain = (size_t)got - (size_t)(base - buf);
                if (remain < plen) break;
            }
        }
        // 重叠 plen-1 字节, 避免跨块边界漏匹配 (间隙块除外)。
        pos += (got > (plen - 1)) ? (got - (plen - 1)) : got;
    }
    free(buf);
    return hits;
}

// ============================================================
// Mach-O 镜像枚举 (复用 macho_dump)
// ============================================================

int analysis_list_macho_images(AnalysisMachoImage *out, int max_count) {
    if (!out || max_count <= 0) return -1;

    NSArray<DHDumpImage *> *images = dh_dump_list_images();
    int count = 0;
    for (DHDumpImage *img in images) {
        if (count >= max_count) break;
        AnalysisMachoImage *o = &out[count];

        strncpy(o->name, img.name.UTF8String ?: "?", sizeof(o->name) - 1);
        o->name[sizeof(o->name) - 1] = '\0';
        strncpy(o->kind, img.kind.UTF8String ?: "?", sizeof(o->kind) - 1);
        o->kind[sizeof(o->kind) - 1] = '\0';

        o->load_address = (uint64_t)(uintptr_t)img.header;
        o->encrypted = (img.cryptid != 0) ? 1 : 0;
        o->cryptid = img.cryptid;
        o->cryptsize = img.cryptsize;
        count++;
    }
    return count;
}
