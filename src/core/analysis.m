// analysis.m — 二进制分析实现
//
// capstone 反汇编 + vm_read_overwrite 安全读内存 + macho_dump 镜像枚举

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#include "capstone/capstone.h"
#include "analysis.h"
#include "macho_dump.h"

#define ANALYSIS_MAX_READ (64 * 1024)   // disassemble_at 单次读内存上限

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
