// analysis.m — 二进制分析实现
//
// capstone 反汇编 + vm_read_overwrite 安全读内存 + macho_dump 镜像枚举

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#include <dlfcn.h>
#include <string.h>
#include <libgen.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/getsect.h>
#include <pthread.h>
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

// ============================================================
// 交叉引用 (xref) —— tier-1: 直接 BL 调用
// ============================================================

// dli_fname 的 basename 指针 (只读, 不拷贝)。
static const char *base_ptr(const char *p) {
    const char *b = p ? p : "";
    for (const char *s = b; *s; s++) if (*s == '/') b = s + 1;
    return b;
}

// dladdr 取去下划线的符号名到 buf; 命中回填 *out_off(相对符号起点偏移) 返回 1, 否则置空串返回 0。
static int name_at(uint64_t addr, char *buf, size_t buflen, uint64_t *out_off) {
    if (buf && buflen) buf[0] = '\0';
    if (out_off) *out_off = 0;
    Dl_info info;
    if (!dladdr((void *)(uintptr_t)addr, &info) || !info.dli_sname) return 0;
    const char *s = info.dli_sname;
    if (s[0] == '_') s++;
    if (!s[0]) return 0;
    if (buf && buflen) { strncpy(buf, s, buflen - 1); buf[buflen - 1] = '\0'; }
    if (out_off && info.dli_saddr) *out_off = addr - (uint64_t)(uintptr_t)info.dli_saddr;
    return 1;
}

// 选镜像: image_query 为名字子串; NULL/"" 选主程序(MH_EXECUTE)。回填 slide/短名。
static const struct mach_header_64 *xref_select_image(const char *q, intptr_t *slideOut,
                                                      char *nameOut, size_t nameLen) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!mh || mh->magic != MH_MAGIC_64) continue;
        const char *bn = base_ptr(_dyld_get_image_name(i));
        if (q && q[0]) { if (!strstr(bn, q)) continue; }
        else if (mh->filetype != MH_EXECUTE) continue;   // 默认主程序
        if (slideOut) *slideOut = _dyld_get_image_vmaddr_slide(i);
        if (nameOut && nameLen) { strncpy(nameOut, bn, nameLen - 1); nameOut[nameLen - 1] = '\0'; }
        return mh;
    }
    return NULL;
}

// 取镜像内某 section 的运行时 [start,end)。不存在或空返回 0。
static int xref_sect_range(const struct mach_header_64 *mh, intptr_t slide,
                           const char *seg, const char *sect,
                           uint64_t *start, uint64_t *end) {
    const struct section_64 *s = getsectbynamefromheader_64(mh, seg, sect);
    if (!s || s->size == 0) return 0;
    *start = (uint64_t)((uintptr_t)s->addr + (uintptr_t)slide);
    *end   = *start + s->size;
    return 1;
}

static inline int in_range(uint64_t a, uint64_t lo, uint64_t hi) { return lo && a >= lo && a < hi; }

// tier-1 PAC 处理: arm64 上是空操作; arm64e 上抹掉高位鉴权位到 48-bit VA。
static inline uint64_t strip_pac(uint64_t p) { return p & 0x0000FFFFFFFFFFFFULL; }

// 安全读 8 字节指针。成功返回 1。
static int read_ptr(uint64_t addr, uint64_t *out) {
    vm_size_t got = 0;
    if (vm_read_overwrite(mach_task_self(), (vm_address_t)addr, 8,
                          (vm_address_t)out, &got) != KERN_SUCCESS || got != 8) return 0;
    return 1;
}

// 反汇编 stub 起始处若干条, 求它加载的 GOT/auth-GOT slot 地址 (ADRP + LDR 同寄存器)。
// 覆盖 __stubs 的 adrp/ldr 与 __auth_stubs 的 adrp/ldr/braa 变种。成功返回 1。
static int decode_stub_slot(csh h, cs_insn *insn, uint64_t stub_addr, uint64_t *slot_out) {
    uint8_t buf[32];
    vm_size_t got = 0;
    if (vm_read_overwrite(mach_task_self(), (vm_address_t)stub_addr, sizeof(buf),
                          (vm_address_t)buf, &got) != KERN_SUCCESS || got < 8) return 0;
    const uint8_t *p = buf; size_t rem = (size_t)got; uint64_t cur = stub_addr;
    int adrp_reg = -1; uint64_t page = 0; int steps = 0;
    while (steps < 6 && cs_disasm_iter(h, &p, &rem, &cur, insn)) {
        steps++;
        cs_arm64 *a = &insn->detail->arm64;
        if (insn->id == ARM64_INS_ADRP && a->op_count >= 2 &&
            a->operands[0].type == ARM64_OP_REG && a->operands[1].type == ARM64_OP_IMM) {
            adrp_reg = a->operands[0].reg;
            page = (uint64_t)a->operands[1].imm;      // capstone 已算好页基址
        } else if (insn->id == ARM64_INS_LDR && adrp_reg >= 0 && a->op_count >= 2 &&
                   a->operands[1].type == ARM64_OP_MEM &&
                   a->operands[1].mem.base == (arm64_reg)adrp_reg) {
            *slot_out = page + (uint64_t)a->operands[1].mem.disp;
            return 1;
        }
    }
    return 0;
}

// ---- LC_FUNCTION_STARTS 归属 (tier-1.5) ----
// 说明: FUNCTION_STARTS 是 ULEB128 delta 序列, 从 __TEXT 段 vmaddr 起累加得每个函数入口偏移。
// 数据位置仍走 __LINKEDIT 映射(linkedit_base + dataoff), 不能把 dataoff 当 runtime 地址。
// 只做「call_site 二分归属到最近函数入口」, 不恢复函数边界(end 用下一个入口近似)。

typedef struct { uint64_t runtime; uint64_t vmaddr; } FuncStart;

typedef struct FuncStartsCache {
    const struct mach_header_64 *mh;   // 缓存键
    FuncStart *arr;                    // 按地址升序(构造即有序)
    size_t     count;
    uint64_t   text_hi;                // 末函数 end 兜底 = __text 运行时上界
    struct FuncStartsCache *next;
} FuncStartsCache;

static FuncStartsCache *g_fs_cache = NULL;
static pthread_mutex_t  g_fs_lock  = PTHREAD_MUTEX_INITIALIZER;

static uint64_t read_uleb(const uint8_t **pp, const uint8_t *end) {
    uint64_t result = 0; int bit = 0;
    while (*pp < end) {
        uint8_t b = *(*pp)++;
        if (bit <= 63) result |= ((uint64_t)(b & 0x7f)) << bit;
        bit += 7;
        if (!(b & 0x80)) break;
    }
    return result;
}

// 解析一个镜像的 FUNCTION_STARTS(未命中缓存则构造)。始终返回一个 cache 条目(可能 count==0)。
static FuncStartsCache *func_starts_for(const struct mach_header_64 *mh, intptr_t slide, uint64_t text_hi) {
    pthread_mutex_lock(&g_fs_lock);
    for (FuncStartsCache *c = g_fs_cache; c; c = c->next)
        if (c->mh == mh) { pthread_mutex_unlock(&g_fs_lock); return c; }

    FuncStartsCache *nc = calloc(1, sizeof(FuncStartsCache));
    if (!nc) { pthread_mutex_unlock(&g_fs_lock); return NULL; }
    nc->mh = mh; nc->text_hi = text_hi;

    uint64_t text_vmaddr = 0; int have_text = 0;
    const struct segment_command_64 *linkedit = NULL;
    const struct linkedit_data_command *fs = NULL;
    const uint8_t *cmds = (const uint8_t *)mh + sizeof(struct mach_header_64);
    const uint8_t *cend = cmds + mh->sizeofcmds;
    const uint8_t *p = cmds;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (p + sizeof(struct load_command) > cend) break;
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < sizeof(struct load_command) || p + lc->cmdsize > cend) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (strcmp(sg->segname, "__TEXT") == 0) { text_vmaddr = sg->vmaddr; have_text = 1; }
            else if (strcmp(sg->segname, "__LINKEDIT") == 0) linkedit = sg;
        } else if (lc->cmd == LC_FUNCTION_STARTS) {
            fs = (const struct linkedit_data_command *)lc;
        }
        p += lc->cmdsize;
    }

    if (have_text && linkedit && fs && fs->datasize > 0 &&
        fs->dataoff >= linkedit->fileoff &&
        (uint64_t)fs->dataoff + fs->datasize <= (uint64_t)linkedit->fileoff + linkedit->filesize) {
        uintptr_t le_base = (uintptr_t)slide + (uintptr_t)linkedit->vmaddr - (uintptr_t)linkedit->fileoff;
        const uint8_t *data = (const uint8_t *)(le_base + fs->dataoff);
        const uint8_t *dend = data + fs->datasize;
        // 两遍: 先数个数(delta==0 结束), 再填充。
        size_t n = 0;
        for (const uint8_t *q = data; q < dend; ) { if (read_uleb(&q, dend) == 0) break; n++; }
        if (n > 0) {
            nc->arr = malloc(n * sizeof(FuncStart));
            if (nc->arr) {
                uint64_t cum = 0; size_t idx = 0;
                for (const uint8_t *q = data; q < dend && idx < n; ) {
                    uint64_t d = read_uleb(&q, dend);
                    if (d == 0) break;
                    cum += d;
                    nc->arr[idx].vmaddr  = text_vmaddr + cum;
                    nc->arr[idx].runtime = text_vmaddr + (uint64_t)slide + cum;
                    idx++;
                }
                nc->count = idx;
            }
        }
    }

    nc->next = g_fs_cache; g_fs_cache = nc;
    pthread_mutex_unlock(&g_fs_lock);
    return nc;
}

// 二分: addr 归属到 <= addr 的最大函数入口; end 用下一个入口(末个用 text_hi)近似。
// 落在函数间隙外(>= 近似 end)不强行归属。命中返回 1。
static int resolve_func(FuncStartsCache *c, uint64_t addr,
                        uint64_t *start_rt, uint64_t *start_vm, uint64_t *off) {
    if (!c || c->count == 0 || addr < c->arr[0].runtime) return 0;
    size_t lo = 0, hi = c->count;
    while (lo < hi) { size_t mid = lo + (hi - lo) / 2; if (c->arr[mid].runtime <= addr) lo = mid + 1; else hi = mid; }
    size_t idx = lo - 1;
    uint64_t fend = (idx + 1 < c->count) ? c->arr[idx + 1].runtime : c->text_hi;
    if (fend && addr >= fend) return 0;
    *start_rt = c->arr[idx].runtime;
    *start_vm = c->arr[idx].vmaddr;
    *off = addr - c->arr[idx].runtime;
    return 1;
}

// 把 site 归属到函数: 优先 dladdr 符号(name+off); 否则 FUNCTION_STARTS(sub_<runtime>+off); 都无留空。
static void attribute_addr(FuncStartsCache *fc, intptr_t slide, uint64_t site,
                           char *from_func, size_t ff_len, uint64_t *off,
                           uint64_t *start, uint64_t *vm) {
    from_func[0] = '\0'; *off = 0; *start = 0; *vm = 0;
    char sym[256] = {0}; uint64_t symoff = 0;
    if (name_at(site, sym, sizeof(sym), &symoff)) {
        strncpy(from_func, sym, ff_len - 1); from_func[ff_len - 1] = '\0';
        *off = symoff; *start = site - symoff; *vm = *start - (uint64_t)slide;
        return;
    }
    uint64_t frt = 0, fvm = 0, foff = 0;
    if (resolve_func(fc, site, &frt, &fvm, &foff)) {
        snprintf(from_func, ff_len, "sub_%llx", frt);
        *off = foff; *start = frt; *vm = fvm;
    }
}

static void attribute_call_site(FuncStartsCache *fc, intptr_t slide, AnalysisXref *r) {
    attribute_addr(fc, slide, r->call_site, r->from_func, sizeof(r->from_func),
                   &r->from_offset, &r->from_func_start, &r->from_func_vmaddr);
}

#define XREF_MAX_SCAN_INSNS  (12 * 1000 * 1000)   // 指令安全上限(~48MB 代码), 超过标记 truncated

int analysis_find_xrefs(const char *image_query,
                        const char *sym_name, uint64_t target_addr,
                        AnalysisXref *out, int max_results,
                        uint64_t *out_query_addr, char *out_image, size_t image_len,
                        uint64_t *out_scanned, int *out_truncated) {
    if (out_scanned) *out_scanned = 0;
    if (out_truncated) *out_truncated = 0;
    if (!out || max_results <= 0) return -1;
    if ((!sym_name || !sym_name[0]) && target_addr == 0) return -1;

    // 目标定位: 符号经 dlsym → 运行时地址; 或直接用 target_addr。
    char sym_deunder[256] = {0};
    uint64_t query_addr = target_addr;
    if (sym_name && sym_name[0]) {
        const char *nm = (sym_name[0] == '_') ? sym_name + 1 : sym_name;
        strncpy(sym_deunder, nm, sizeof(sym_deunder) - 1);
        void *pp = dlsym(RTLD_DEFAULT, nm);
        if (!pp && target_addr == 0) return -3;   // 符号解析不了且没给地址
        if (pp) query_addr = (uint64_t)(uintptr_t)pp;
    }
    if (out_query_addr) *out_query_addr = query_addr;

    intptr_t slide = 0; char imgnm[256] = {0};
    const struct mach_header_64 *mh = xref_select_image(image_query, &slide, imgnm, sizeof(imgnm));
    if (!mh) return -2;
    if (out_image && image_len) { strncpy(out_image, imgnm, image_len - 1); out_image[image_len - 1] = '\0'; }

    // __text 范围(优先 __TEXT,__text; 退回 __TEXT_EXEC,__text)。
    uint64_t text_lo = 0, text_hi = 0;
    if (!xref_sect_range(mh, slide, "__TEXT", "__text", &text_lo, &text_hi) &&
        !xref_sect_range(mh, slide, "__TEXT_EXEC", "__text", &text_lo, &text_hi)) return -2;

    // tier-1.5: 函数归属表(缺 LC_FUNCTION_STARTS 时 count==0, attribute_call_site 退回 dladdr/空)。
    FuncStartsCache *fc = func_starts_for(mh, slide, text_hi);

    // 目标分类需要的 stub 段范围(缺省为 0, in_range 会跳过)。
    uint64_t st_lo = 0, st_hi = 0, au_lo = 0, au_hi = 0, oc_lo = 0, oc_hi = 0;
    xref_sect_range(mh, slide, "__TEXT", "__stubs", &st_lo, &st_hi);
    xref_sect_range(mh, slide, "__TEXT", "__auth_stubs", &au_lo, &au_hi);
    xref_sect_range(mh, slide, "__TEXT", "__objc_stubs", &oc_lo, &oc_hi);

    // capstone: 主扫描 handle + 独立的 stub 解码 handle(各自 insn 状态互不干扰)。
    csh h = 0, hs = 0;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &h) != CS_ERR_OK) return -1;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &hs) != CS_ERR_OK) { cs_close(&h); return -1; }
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(hs, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *insn = cs_malloc(h);
    cs_insn *sinsn = cs_malloc(hs);
    if (!insn || !sinsn) {
        if (insn) cs_free(insn, 1);
        if (sinsn) cs_free(sinsn, 1);
        cs_close(&h); cs_close(&hs);
        return -1;
    }

    // __text 在本进程已映射(FairPlay 段运行时已解密), 直接按运行时地址反汇编, 不额外拷贝。
    const uint8_t *code = (const uint8_t *)(uintptr_t)text_lo;
    size_t remaining = (size_t)(text_hi - text_lo);
    uint64_t cur = text_lo;
    uint64_t scanned = 0;
    int found = 0, truncated = 0;

    while (cs_disasm_iter(h, &code, &remaining, &cur, insn)) {
        scanned++;
        if (scanned >= XREF_MAX_SCAN_INSNS) { truncated = 1; break; }
        if (insn->id != ARM64_INS_BL) continue;

        cs_arm64 *a = &insn->detail->arm64;
        if (a->op_count < 1 || a->operands[0].type != ARM64_OP_IMM) continue;
        uint64_t tgt = (uint64_t)a->operands[0].imm;

        // 分类 + 解析真实目标。
        const char *kind = "call_direct";
        uint64_t resolved = tgt;
        char rname[256] = {0}; uint64_t roff = 0;

        if (in_range(tgt, st_lo, st_hi) || in_range(tgt, au_lo, au_hi)) {
            kind = "call_import_stub";
            uint64_t slot = 0, raw = 0;
            if (decode_stub_slot(hs, sinsn, tgt, &slot) && read_ptr(slot, &raw)) {
                uint64_t stripped = strip_pac(raw);
                // 先按原值 dladdr, 不中再按 strip 后的值(arm64e auth 指针)。
                if (name_at(raw, rname, sizeof(rname), &roff)) resolved = raw;
                else if (name_at(stripped, rname, sizeof(rname), &roff)) resolved = stripped;
                else resolved = stripped;   // lazy 未绑定/无符号: 记裸值, 保留调用点
            }
            // slot 解不出: resolved 仍 == tgt(stub 地址), rname 空
        } else if (in_range(tgt, oc_lo, oc_hi)) {
            kind = "call_objc_stub";
            resolved = tgt;
            name_at(tgt, rname, sizeof(rname), &roff);   // 拿不到就空串, MCP 层回退 objc_stub@
        } else {
            name_at(tgt, rname, sizeof(rname), &roff);
        }

        // 命中判定: 地址相等(裸目标或解析后目标) 或 符号名相等; objc_stub 额外允许
        // "sym$..." 前缀(现代 objc_msgSend$selector 降级 stub)。
        int addr_match = (query_addr && (resolved == query_addr || tgt == query_addr));
        int name_match = 0;
        if (sym_deunder[0] && rname[0]) {
            if (strcmp(rname, sym_deunder) == 0) name_match = 1;
            else if (strcmp(kind, "call_objc_stub") == 0) {
                size_t L = strlen(sym_deunder);
                if (strncmp(rname, sym_deunder, L) == 0 && rname[L] == '$') name_match = 1;
            }
        }
        if (!addr_match && !name_match) continue;

        if (found >= max_results) { truncated = 1; break; }
        AnalysisXref *r = &out[found++];
        r->call_site = insn->address;
        r->target = tgt;
        r->resolved_target = resolved;
        strncpy(r->kind, kind, sizeof(r->kind) - 1); r->kind[sizeof(r->kind) - 1] = '\0';
        strncpy(r->resolved_name, rname, sizeof(r->resolved_name) - 1);
        r->resolved_name[sizeof(r->resolved_name) - 1] = '\0';
        // from_func: dladdr 符号优先, 否则 LC_FUNCTION_STARTS 归属到 sub_<runtime>, 都无则留空。
        attribute_call_site(fc, slide, r);
        snprintf(r->insn_text, sizeof(r->insn_text), "%s %s", insn->mnemonic, insn->op_str);
    }

    cs_free(insn, 1);
    cs_free(sinsn, 1);
    cs_close(&h);
    cs_close(&hs);
    if (out_scanned) *out_scanned = scanned;
    if (out_truncated) *out_truncated = truncated;
    return found;
}

// ============================================================
// 字符串引用 (string ref) —— tier-2A
// ============================================================

// arm64_reg → 0..30 索引(仅 X0..X30); 其余(W/SP/XZR)返回 -1 不跟踪。
static int xreg_idx(arm64_reg r) {
    if (r >= ARM64_REG_X0 && r <= ARM64_REG_X28) return (int)(r - ARM64_REG_X0);
    if (r == ARM64_REG_FP) return 29;   // X29
    if (r == ARM64_REG_LR) return 30;   // X30
    return -1;
}

// 一段范围表
typedef struct { uint64_t lo, hi; const char *label; } SecRange;

static const char *classify_sec(uint64_t addr, const SecRange *secs, int n) {
    for (int i = 0; i < n; i++) if (addr >= secs[i].lo && addr < secs[i].hi) return secs[i].label;
    return NULL;
}

// 安全读一个 C 字符串到 buf(截断)。返回复制的字节数(不含 NUL); 0=不可读/空。
static int read_cstring(uint64_t addr, char *buf, size_t buflen) {
    if (!buf || buflen == 0) return 0;
    buf[0] = '\0';
    uint8_t tmp[256];
    size_t want = (buflen - 1 < sizeof(tmp)) ? buflen - 1 : sizeof(tmp);
    vm_size_t got = 0;
    if (vm_read_overwrite(mach_task_self(), (vm_address_t)addr, (vm_size_t)want,
                          (vm_address_t)tmp, &got) != KERN_SUCCESS || got == 0) return 0;
    size_t i = 0;
    for (; i < (size_t)got && tmp[i]; i++) { buf[i] = (char)tmp[i]; }
    buf[i] = '\0';
    return (int)i;
}

// 某已加载镜像头的 slide(遍历 dyld 表按头指针匹配)。
static intptr_t slide_for_header(const struct mach_header_64 *mh) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++)
        if ((const struct mach_header_64 *)_dyld_get_image_header(i) == mh)
            return _dyld_get_image_vmaddr_slide(i);
    return 0;
}

// 跨镜像判定 addr 是否落在「某镜像的字符串 section」。用于间接引用: 运行时 selref 已被
// 定到 SEL(常在别的镜像/共享缓存), 目标字符串不在被扫镜像内。命中回填 label/vmaddr 返回 1。
static int string_sec_global(uint64_t addr, char *out_label, size_t len, uint64_t *out_vmaddr) {
    Dl_info info;
    if (!dladdr((void *)(uintptr_t)addr, &info) || !info.dli_fbase) return 0;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)info.dli_fbase;
    if (mh->magic != MH_MAGIC_64) return 0;
    intptr_t sl = slide_for_header(mh);
    static const char *SS[][2] = {
        {"__TEXT", "__cstring"}, {"__TEXT", "__objc_methname"},
        {"__TEXT", "__objc_classname"}, {"__TEXT", "__objc_methtype"},
    };
    for (int i = 0; i < 4; i++) {
        uint64_t lo, hi;
        if (xref_sect_range(mh, sl, SS[i][0], SS[i][1], &lo, &hi) && addr >= lo && addr < hi) {
            snprintf(out_label, len, "%s,%s", SS[i][0], SS[i][1]);
            if (out_vmaddr) *out_vmaddr = addr - (uint64_t)sl;
            return 1;
        }
    }
    return 0;
}

int analysis_find_string_refs(const char *image_query,
                              const char *query_str, uint64_t query_addr,
                              AnalysisStringRef *out, int max_results,
                              char *out_image, size_t image_len,
                              uint64_t *out_scanned, int *out_truncated) {
    if (out_scanned) *out_scanned = 0;
    if (out_truncated) *out_truncated = 0;
    if (!out || max_results <= 0) return -1;
    if ((!query_str || !query_str[0]) && query_addr == 0) return -1;

    intptr_t slide = 0; char imgnm[256] = {0};
    const struct mach_header_64 *mh = xref_select_image(image_query, &slide, imgnm, sizeof(imgnm));
    if (!mh) return -2;
    if (out_image && image_len) { strncpy(out_image, imgnm, image_len - 1); out_image[image_len - 1] = '\0'; }

    uint64_t text_lo = 0, text_hi = 0;
    if (!xref_sect_range(mh, slide, "__TEXT", "__text", &text_lo, &text_hi) &&
        !xref_sect_range(mh, slide, "__TEXT_EXEC", "__text", &text_lo, &text_hi)) return -2;

    // 字符串 section(存字符本身)。label 用静态串, 免每次调用 strdup 泄漏。
    SecRange strsec[4]; int nstr = 0;
    static const char *SS[][2] = {
        {"__TEXT", "__cstring"}, {"__TEXT", "__objc_methname"},
        {"__TEXT", "__objc_classname"}, {"__TEXT", "__objc_methtype"},
    };
    static const char *SS_LABEL[4] = {
        "__TEXT,__cstring", "__TEXT,__objc_methname",
        "__TEXT,__objc_classname", "__TEXT,__objc_methtype",
    };
    for (int i = 0; i < 4; i++) {
        uint64_t lo, hi;
        if (xref_sect_range(mh, slide, SS[i][0], SS[i][1], &lo, &hi)) {
            strsec[nstr].lo = lo; strsec[nstr].hi = hi; strsec[nstr].label = SS_LABEL[i];
            nstr++;
        }
    }
    if (nstr == 0) return 0;   // 无字符串 section, 无从谈起

    // 指针 section(slot 存指向字符串的指针) — 间接引用 ADRP+LDR 用, 白名单防误报
    SecRange ptrsec[16]; int nptr = 0;
    static const char *PS[][2] = {
        {"__DATA", "__objc_selrefs"}, {"__DATA_CONST", "__objc_selrefs"},
        {"__DATA", "__objc_classrefs"}, {"__DATA_CONST", "__objc_classrefs"},
        {"__DATA", "__objc_superrefs"}, {"__DATA_CONST", "__objc_superrefs"},
        {"__DATA", "__got"}, {"__DATA_CONST", "__got"}, {"__DATA_CONST", "__auth_got"},
        {"__DATA", "__la_symbol_ptr"}, {"__DATA", "__cfstring"}, {"__DATA_CONST", "__cfstring"},
    };
    for (int i = 0; i < (int)(sizeof(PS)/sizeof(PS[0])) && nptr < 16; i++) {
        uint64_t lo, hi;
        if (xref_sect_range(mh, slide, PS[i][0], PS[i][1], &lo, &hi)) {
            ptrsec[nptr].lo = lo; ptrsec[nptr].hi = hi; ptrsec[nptr].label = "ptr"; nptr++;
        }
    }

    FuncStartsCache *fc = func_starts_for(mh, slide, text_hi);

    csh h = 0;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &h) != CS_ERR_OK) return -1;
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *insn = cs_malloc(h);
    if (!insn) { cs_close(&h); return -1; }

    const uint8_t *code = (const uint8_t *)(uintptr_t)text_lo;
    size_t remaining = (size_t)(text_hi - text_lo);
    uint64_t cur = text_lo;
    uint64_t scanned = 0;
    int found = 0, truncated = 0;

    // 每寄存器缓存最近 ADRP 页; 被写即失效(局部窗口回溯的等价实现)。
    uint64_t reg_page[31]; uint8_t reg_valid[31];
    memset(reg_valid, 0, sizeof(reg_valid));

    while (cs_disasm_iter(h, &code, &remaining, &cur, insn)) {
        scanned++;
        if (scanned >= XREF_MAX_SCAN_INSNS) { truncated = 1; break; }
        cs_arm64 *a = &insn->detail->arm64;

        if (insn->id == ARM64_INS_ADRP && a->op_count >= 2 &&
            a->operands[0].type == ARM64_OP_REG && a->operands[1].type == ARM64_OP_IMM) {
            int di = xreg_idx(a->operands[0].reg);
            if (di >= 0) { reg_page[di] = (uint64_t)a->operands[1].imm; reg_valid[di] = 1; }
            continue;   // ADRP 只设缓存, 不作为使用点
        }

        // 恢复候选数据地址: ADD 直接 / LDR 间接
        int hit = 0, indirect = 0;
        uint64_t str_addr = 0;
        if (insn->id == ARM64_INS_ADD && a->op_count >= 3 &&
            a->operands[1].type == ARM64_OP_REG && a->operands[2].type == ARM64_OP_IMM) {
            int bi = xreg_idx(a->operands[1].reg);
            if (bi >= 0 && reg_valid[bi]) {
                str_addr = reg_page[bi] + (uint64_t)a->operands[2].imm;
                if (classify_sec(str_addr, strsec, nstr)) { hit = 1; indirect = 0; }
            }
        } else if (insn->id == ARM64_INS_LDR && a->op_count >= 2 &&
                   a->operands[1].type == ARM64_OP_MEM &&
                   a->operands[1].mem.index == ARM64_REG_INVALID) {
            int bi = xreg_idx(a->operands[1].mem.base);
            if (bi >= 0 && reg_valid[bi]) {
                uint64_t slot = reg_page[bi] + (uint64_t)a->operands[1].mem.disp;
                // 仅认白名单指针 section(selrefs/got/...); 读出指针即为候选, 目标可能跨镜像
                // (运行时 selref 已定到别处的 SEL), 故不在此限定目标 section, 交由下面读串+匹配。
                if (classify_sec(slot, ptrsec, nptr)) {
                    uint64_t raw = 0;
                    if (read_ptr(slot, &raw)) { str_addr = strip_pac(raw); hit = 1; indirect = 1; }
                }
            }
        }

        if (hit) {
            char sbuf[192];
            int slen = read_cstring(str_addr, sbuf, sizeof(sbuf));
            int match = 0;
            if (slen > 0) {
                if (query_addr) match = (str_addr == query_addr);
                else if (query_str && query_str[0]) match = (strstr(sbuf, query_str) != NULL);
            }
            if (match) {
                if (found >= max_results) { truncated = 1; break; }
                AnalysisStringRef *r = &out[found++];
                r->ref_site = insn->address;
                r->string_addr = str_addr;
                r->indirect = indirect;
                strncpy(r->string, sbuf, sizeof(r->string) - 1); r->string[sizeof(r->string) - 1] = '\0';
                // section + vmaddr: 直接引用在被扫镜像内; 间接引用目标可能跨镜像, 走全局判定。
                const char *lbl = NULL; char glbl[32];
                if (!indirect) { lbl = classify_sec(str_addr, strsec, nstr); r->string_vmaddr = str_addr - (uint64_t)slide; }
                else if (string_sec_global(str_addr, glbl, sizeof(glbl), &r->string_vmaddr)) lbl = glbl;
                else { lbl = "(external)"; r->string_vmaddr = 0; }
                strncpy(r->section, lbl ?: "?", sizeof(r->section) - 1); r->section[sizeof(r->section) - 1] = '\0';
                snprintf(r->insn_text, sizeof(r->insn_text), "%s %s", insn->mnemonic, insn->op_str);
                attribute_addr(fc, slide, insn->address, r->from_func, sizeof(r->from_func),
                               &r->from_offset, &r->from_func_start, &r->from_func_vmaddr);
            }
        }

        // 失效被写寄存器(先用后失效, 支持 add xN,xN,#off 自更新场景)。
        for (uint8_t i = 0; i < a->op_count; i++) {
            if (a->operands[i].type == ARM64_OP_REG && (a->operands[i].access & CS_AC_WRITE)) {
                int wi = xreg_idx(a->operands[i].reg);
                if (wi >= 0) reg_valid[wi] = 0;
            }
        }
    }

    cs_free(insn, 1);
    cs_close(&h);
    if (out_scanned) *out_scanned = scanned;
    if (out_truncated) *out_truncated = truncated;
    return found;
}
