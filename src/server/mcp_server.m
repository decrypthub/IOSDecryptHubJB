// mcp_server.m — MCP 服务器实现
//
// MCP over JSON-RPC 2.0。方法分发 + 工具执行 + 标准 content 信封。
// 传输层 (HTTP/SSE/会话头) 在 http_server.m 的 handle_mcp 里。

#import <Foundation/Foundation.h>
#include "mcp_server.h"
#include "analysis.h"
#include "dh_symtab.h"
#include "log_store.h"
#include "dh_log_json.h"
#include "dh_capture.h"
#include "dh_health.h"
#include "dh_noise.h"
#include "dh_spoof.h"
#include "dh_files.h"
#include "dump_manager.h"
#include <string.h>

#define MCP_SERVER_NAME     "ios-decrypt-helper"
#ifndef DH_VERSION_STR
#define DH_VERSION_STR "0.0.0"   // 兜底; 正常由 Makefile -D 注入(单一真相源)
#endif
#define MCP_SERVER_VERSION  DH_VERSION_STR
#define MCP_DEFAULT_PROTO   "2024-11-05"

// 我方支持的协议版本 (initialize 时若客户端请求其一则原样回应, 否则回默认)
static NSArray<NSString *> *mcp_supported_protocols(void) {
    return @[@"2024-11-05", @"2025-03-26", @"2025-06-18"];
}

// ============================================================
// JSON-RPC 应答构造
// ============================================================
static NSDictionary *rpc_result(id reqId, NSDictionary *result) {
    return @{@"jsonrpc": @"2.0", @"id": reqId ?: [NSNull null], @"result": result ?: @{}};
}

static NSDictionary *rpc_error(id reqId, NSInteger code, NSString *message) {
    return @{@"jsonrpc": @"2.0", @"id": reqId ?: [NSNull null],
             @"error": @{@"code": @(code), @"message": message ?: @"error"}};
}

// tools/call 的标准结果信封: content(文本, JSON 串) + structuredContent(机器可读) + isError。
static NSDictionary *tool_ok(NSDictionary *structured) {
    NSData *jd = [NSJSONSerialization dataWithJSONObject:structured ?: @{}
                                                options:NSJSONWritingPrettyPrinted error:nil];
    NSString *text = jd ? [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding] : @"{}";
    return @{
        @"content": @[@{@"type": @"text", @"text": text ?: @"{}"}],
        @"structuredContent": structured ?: @{},
        @"isError": @NO,
    };
}

static NSDictionary *tool_err(NSString *message) {
    return @{
        @"content": @[@{@"type": @"text", @"text": [NSString stringWithFormat:@"Error: %@", message ?: @"failed"]}],
        @"isError": @YES,
    };
}

// ============================================================
// 工具实现 —— 返回「tools/call 结果信封」(tool_ok / tool_err)
// ============================================================

// hex 编解码统一用 log_store 的 DHHexFromData / DHDataFromHex, 不再各处手写。

static NSArray *insns_to_array(const AnalysisInsn *insns, int count) {
    NSMutableArray *arr = [NSMutableArray arrayWithCapacity:count];
    for (int i = 0; i < count; i++) {
        const AnalysisInsn *n = &insns[i];
        NSMutableString *bhex = [NSMutableString stringWithCapacity:n->size * 2];
        for (int j = 0; j < n->size; j++) [bhex appendFormat:@"%02x", n->bytes[j]];
        [arr addObject:@{
            @"address": [NSString stringWithFormat:@"0x%llx", n->address],
            @"mnemonic": @(n->mnemonic),
            @"op_str": @(n->op_str),
            @"bytes": bhex,
            @"size": @(n->size),
        }];
    }
    return arr;
}

// disassemble —— 反汇编一段 hex 字节
static NSDictionary *tool_disassemble(NSDictionary *args) {
    NSString *bytesHex = args[@"bytes"];
    NSString *addrStr  = args[@"address"];
    NSString *arch     = args[@"arch"] ?: @"arm64";
    if (![bytesHex isKindOfClass:NSString.class] || bytesHex.length == 0)
        return tool_err(@"missing 'bytes' (hex string)");

    NSData *code = DHDataFromHex(bytesHex);
    if (code.length == 0) return tool_err(@"'bytes' has no valid hex");

    uint64_t addr = addrStr ? strtoull(addrStr.UTF8String, NULL, 0) : 0;
    AnalysisInsn insns[256];
    int n = analysis_disassemble(code.bytes, code.length, addr, arch.UTF8String, insns, 256);
    if (n < 0) return tool_err(@"capstone init failed");

    BOOL truncated = (n == 256);
    return tool_ok(@{
        @"arch": arch,
        @"count": @(n),
        @"truncated": @(truncated),
        @"instructions": insns_to_array(insns, n),
    });
}

// analyze_function —— 读进程内存 address..+size 并反汇编
static NSDictionary *tool_analyze_function(NSDictionary *args) {
    NSString *addrStr = args[@"address"];
    NSNumber *sizeNum = args[@"size"];
    NSString *arch    = args[@"arch"] ?: @"arm64";
    if (![addrStr isKindOfClass:NSString.class]) return tool_err(@"missing 'address'");
    if (![sizeNum isKindOfClass:NSNumber.class]) return tool_err(@"missing 'size'");

    uint64_t addr = strtoull(addrStr.UTF8String, NULL, 0);
    size_t size = (size_t)sizeNum.unsignedLongLongValue;
    if (addr == 0 || size == 0) return tool_err(@"'address' and 'size' must be non-zero");

    AnalysisInsn insns[512];
    int n = analysis_disassemble_at(addr, size, arch.UTF8String, insns, 512);
    if (n == -2) return tool_err([NSString stringWithFormat:@"memory not readable at 0x%llx", addr]);
    if (n < 0)  return tool_err(@"capstone init failed");

    return tool_ok(@{
        @"address": [NSString stringWithFormat:@"0x%llx", addr],
        @"arch": arch,
        @"count": @(n),
        @"truncated": (n == 512) ? @YES : @NO,
        @"instructions": insns_to_array(insns, n),
    });
}

// C 回调: 把符号名收集进 NSMutableArray (与 http_server 的 /api/symbols 同路)
static void sym_collect_cb(const char *name, void *ctx) {
    if (name) [(__bridge NSMutableArray *)ctx addObject:@(name)];
}

// list_images —— 列出 symtab 镜像索引清单 (list_imports 的 image_index 从这里来)
// 默认只列有导入符号的镜像(= fishhook 可 rebind 候选; 也是 list_imports 有意义的目标),
// 主程序排最前; 可用 query 按名过滤。
static NSDictionary *tool_list_images(NSDictionary *args) {
    NSString *q = [args[@"query"] isKindOfClass:NSString.class] ? [args[@"query"] lowercaseString] : nil;
    int n = dh_symtab_image_count();
    NSMutableArray *arr = [NSMutableArray array];
    for (int i = 0; i < n; i++) {
        char nm[256] = {0}; int isMain = 0;
        dh_symtab_image_name(i, nm, sizeof(nm), &isMain);
        int imports = dh_symtab_imports(i, NULL, 0, NULL, NULL);   // 只计数
        if (imports <= 0) continue;
        NSString *name = @(nm);
        if (q && [name.lowercaseString rangeOfString:q].location == NSNotFound) continue;
        [arr addObject:@{@"idx": @(i), @"name": name, @"main": isMain ? @YES : @NO, @"imports": @(imports)}];
    }
    [arr sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        BOOL am = [a[@"main"] boolValue], bm = [b[@"main"] boolValue];
        if (am != bm) return am ? NSOrderedAscending : NSOrderedDescending;   // 主程序最前
        return [a[@"name"] caseInsensitiveCompare:b[@"name"]];
    }];
    return tool_ok(@{@"count": @(arr.count), @"images": arr});
}

// list_imports —— 真正遍历某镜像的导入符号
static NSDictionary *tool_list_imports(NSDictionary *args) {
    NSNumber *idxNum = args[@"image_index"];
    if (![idxNum isKindOfClass:NSNumber.class]) return tool_err(@"missing 'image_index'");
    int idx = idxNum.intValue;
    int total_images = dh_symtab_image_count();
    if (idx < 0 || idx >= total_images)
        return tool_err([NSString stringWithFormat:@"image_index out of range (0..%d)", total_images - 1]);

    NSString *q = [args[@"query"] isKindOfClass:NSString.class] ? args[@"query"] : nil;
    int limit = [args[@"limit"] isKindOfClass:NSNumber.class] ? [args[@"limit"] intValue] : 500;
    if (limit <= 0 || limit > 5000) limit = 500;

    char nm[256] = {0}; int isMain = 0;
    dh_symtab_image_name(idx, nm, sizeof(nm), &isMain);

    NSMutableArray *syms = [NSMutableArray array];
    const char *qc = (q.length ? q.UTF8String : NULL);
    int total = dh_symtab_imports(idx, qc, limit, sym_collect_cb, (__bridge void *)syms);

    return tool_ok(@{
        @"image_index": @(idx),
        @"image": @(nm),
        @"main": isMain ? @YES : @NO,
        @"total": @(total),
        @"shown": @(syms.count),
        @"symbols": syms,
    });
}

// disassemble_function —— 从地址反汇编, 遇 ret 停 (函数边界)
static NSDictionary *tool_disassemble_function(NSDictionary *args) {
    NSString *addrStr = args[@"address"];
    NSString *arch    = args[@"arch"] ?: @"arm64";
    if (![addrStr isKindOfClass:NSString.class]) return tool_err(@"missing 'address'");
    uint64_t addr = strtoull(addrStr.UTF8String, NULL, 0);
    if (addr == 0) return tool_err(@"'address' must be non-zero");
    size_t maxBytes = [args[@"max_bytes"] isKindOfClass:NSNumber.class] ? (size_t)[args[@"max_bytes"] unsignedLongLongValue] : 4096;

    AnalysisInsn insns[1024];
    int n = analysis_disassemble_func(addr, maxBytes, arch.UTF8String, insns, 1024);
    if (n == -2) return tool_err([NSString stringWithFormat:@"memory not readable at 0x%llx", addr]);
    if (n < 0)  return tool_err(@"capstone init failed");
    BOOL endsWithRet = (n > 0 && strcmp(insns[n-1].mnemonic, "ret") == 0);
    return tool_ok(@{
        @"address": [NSString stringWithFormat:@"0x%llx", addr],
        @"arch": arch,
        @"count": @(n),
        @"ends_with_ret": @(endsWithRet),
        @"instructions": insns_to_array(insns, n),
    });
}

// resolve_symbol —— 符号名 -> 运行时地址
static NSDictionary *tool_resolve_symbol(NSDictionary *args) {
    NSString *name = args[@"name"];
    if (![name isKindOfClass:NSString.class] || name.length == 0) return tool_err(@"missing 'name'");
    uint64_t addr = 0; char img[256] = {0};
    if (analysis_resolve_symbol(name.UTF8String, &addr, img, sizeof(img)) != 0)
        return tool_err([NSString stringWithFormat:@"symbol not found: %@", name]);
    return tool_ok(@{
        @"name": name,
        @"address": [NSString stringWithFormat:@"0x%llx", addr],
        @"image": @(img),
    });
}

// symbolicate —— 地址 -> 最近符号 + 偏移
static NSDictionary *tool_symbolicate(NSDictionary *args) {
    NSString *addrStr = args[@"address"];
    if (![addrStr isKindOfClass:NSString.class]) return tool_err(@"missing 'address'");
    uint64_t addr = strtoull(addrStr.UTF8String, NULL, 0);
    char sym[512] = {0}, img[256] = {0}; uint64_t off = 0;
    if (analysis_symbolicate(addr, sym, sizeof(sym), &off, img, sizeof(img)) != 0)
        return tool_ok(@{@"address": [NSString stringWithFormat:@"0x%llx", addr], @"found": @NO});
    return tool_ok(@{
        @"address": [NSString stringWithFormat:@"0x%llx", addr],
        @"found": @YES,
        @"symbol": @(sym),
        @"offset": @(off),
        @"display": [NSString stringWithFormat:@"%s+0x%llx", sym, off],
        @"image": @(img),
    });
}

// 经典 hexdump 格式 (地址 / 16 字节 hex / ASCII)
static NSString *format_hexdump(uint64_t base, const uint8_t *buf, int n) {
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < n; i += 16) {
        [s appendFormat:@"%016llx  ", base + (uint64_t)i];
        NSMutableString *asc = [NSMutableString string];
        for (int j = 0; j < 16; j++) {
            if (i + j < n) {
                uint8_t c = buf[i + j];
                [s appendFormat:@"%02x ", c];
                [asc appendFormat:@"%c", (c >= 32 && c < 127) ? c : '.'];
            } else {
                [s appendString:@"   "];
            }
            if (j == 7) [s appendString:@" "];
        }
        [s appendFormat:@" |%@|\n", asc];
    }
    return s;
}

// read_memory —— 读内存并 hexdump
static NSDictionary *tool_read_memory(NSDictionary *args) {
    NSString *addrStr = args[@"address"];
    NSNumber *sizeNum = args[@"size"];
    if (![addrStr isKindOfClass:NSString.class]) return tool_err(@"missing 'address'");
    uint64_t addr = strtoull(addrStr.UTF8String, NULL, 0);
    size_t size = [sizeNum isKindOfClass:NSNumber.class] ? (size_t)sizeNum.unsignedLongLongValue : 256;
    if (size == 0) size = 256;

    uint8_t buf[4096];
    int got = analysis_read_memory(addr, size, buf, sizeof(buf));
    if (got == -2) return tool_err([NSString stringWithFormat:@"memory not readable at 0x%llx", addr]);
    if (got < 0)  return tool_err(@"invalid arguments");

    NSString *hex = DHHexFromData([NSData dataWithBytes:buf length:got]);
    return tool_ok(@{
        @"address": [NSString stringWithFormat:@"0x%llx", addr],
        @"size": @(got),
        @"hex": hex,
        @"hexdump": format_hexdump(addr, buf, got),
    });
}

// search_memory —— 在 [address, address+length) 搜索 pattern(hex) 或 string
static NSDictionary *tool_search_memory(NSDictionary *args) {
    NSString *addrStr = args[@"address"];
    NSNumber *lenNum  = args[@"length"];
    if (![addrStr isKindOfClass:NSString.class]) return tool_err(@"missing 'address'");
    if (![lenNum isKindOfClass:NSNumber.class])  return tool_err(@"missing 'length'");
    uint64_t addr = strtoull(addrStr.UTF8String, NULL, 0);
    size_t length = (size_t)lenNum.unsignedLongLongValue;

    NSData *pat = nil;
    if ([args[@"string"] isKindOfClass:NSString.class])
        pat = [args[@"string"] dataUsingEncoding:NSUTF8StringEncoding];
    else if ([args[@"pattern"] isKindOfClass:NSString.class])
        pat = DHDataFromHex(args[@"pattern"]);
    if (pat.length == 0) return tool_err(@"provide 'string' or 'pattern' (hex)");

    uint64_t hits[256];
    int n = analysis_search_memory(addr, length, pat.bytes, pat.length, hits, 256);
    if (n < 0) return tool_err(@"invalid arguments");
    NSMutableArray *arr = [NSMutableArray arrayWithCapacity:n];
    for (int i = 0; i < n; i++) [arr addObject:[NSString stringWithFormat:@"0x%llx", hits[i]]];
    return tool_ok(@{
        @"count": @(n),
        @"truncated": (n == 256) ? @YES : @NO,
        @"hits": arr,
    });
}

// get_macho_info —— 列举 App bundle 内已加载镜像
static NSDictionary *tool_get_macho_info(NSDictionary *args) {
    AnalysisMachoImage imgs[64];
    int n = analysis_list_macho_images(imgs, 64);
    if (n < 0) return tool_err(@"failed to list mach-o images");

    NSMutableArray *arr = [NSMutableArray arrayWithCapacity:n];
    int encrypted = 0;
    for (int i = 0; i < n; i++) {
        AnalysisMachoImage *m = &imgs[i];
        if (m->encrypted) encrypted++;
        [arr addObject:@{
            @"name": @(m->name),
            @"kind": @(m->kind),
            @"load_address": [NSString stringWithFormat:@"0x%llx", m->load_address],
            @"encrypted": m->encrypted ? @YES : @NO,
            @"cryptid": @(m->cryptid),
            @"cryptsize": @(m->cryptsize),
        }];
    }
    return tool_ok(@{@"count": @(n), @"encrypted_count": @(encrypted), @"images": arr});
}

// find_xrefs —— tier-1: 扫某镜像 __text 里所有直接 BL 到目标符号/地址的调用点
static NSDictionary *tool_find_xrefs(NSDictionary *args) {
    NSString *sym     = [args[@"symbol"] isKindOfClass:NSString.class] ? args[@"symbol"] : nil;
    NSString *addrStr = [args[@"address"] isKindOfClass:NSString.class] ? args[@"address"] : nil;
    NSString *image   = [args[@"image"] isKindOfClass:NSString.class] ? args[@"image"] : nil;
    if (sym.length == 0 && addrStr.length == 0)
        return tool_err(@"need 'symbol' or 'address' to locate the xref target");

    uint64_t targetAddr = addrStr.length ? strtoull(addrStr.UTF8String, NULL, 0) : 0;
    int maxR = [args[@"max_results"] isKindOfClass:NSNumber.class] ? [args[@"max_results"] intValue] : 256;
    if (maxR <= 0 || maxR > 2000) maxR = 256;

    AnalysisXref *rows = calloc((size_t)maxR, sizeof(AnalysisXref));
    if (!rows) return tool_err(@"out of memory");

    uint64_t qaddr = 0, scanned = 0; char imgNm[256] = {0}; int truncated = 0;
    int n = analysis_find_xrefs(image.length ? image.UTF8String : NULL,
                                sym.length ? sym.UTF8String : NULL, targetAddr,
                                rows, maxR, &qaddr, imgNm, sizeof(imgNm), &scanned, &truncated);
    if (n == -1) { free(rows); return tool_err(@"invalid arguments"); }
    if (n == -2) { free(rows); return tool_err(@"image or __text section not found"); }
    if (n == -3) { free(rows); return tool_err([NSString stringWithFormat:@"symbol not resolvable via dlsym: %@ (try passing 'address' instead)", sym]); }

    NSMutableArray *arr = [NSMutableArray arrayWithCapacity:(NSUInteger)n];
    for (int i = 0; i < n; i++) {
        AnalysisXref *r = &rows[i];
        NSMutableDictionary *d = [@{
            @"call_site":       [NSString stringWithFormat:@"0x%llx", r->call_site],
            @"target":          [NSString stringWithFormat:@"0x%llx", r->target],
            @"resolved_target": [NSString stringWithFormat:@"0x%llx", r->resolved_target],
            @"kind":            @(r->kind),
            @"instruction":     @(r->insn_text),
        } mutableCopy];
        d[@"resolved_name"] = r->resolved_name[0] ? @(r->resolved_name)
                            : ([@(r->kind) isEqualToString:@"call_objc_stub"]
                               ? [NSString stringWithFormat:@"objc_stub@0x%llx", r->target] : (id)[NSNull null]);
        if (r->from_func[0]) {
            d[@"from_func"]        = [NSString stringWithFormat:@"%s+0x%llx", r->from_func, r->from_offset];
            d[@"from_func_start"]  = [NSString stringWithFormat:@"0x%llx", r->from_func_start];
            d[@"from_func_offset"] = [NSString stringWithFormat:@"0x%llx", r->from_offset];
            if (r->from_func_vmaddr)
                d[@"from_func_vmaddr"] = [NSString stringWithFormat:@"0x%llx", r->from_func_vmaddr];
        } else {
            d[@"from_func"]       = [NSNull null];
            d[@"from_func_start"] = [NSNull null];
        }
        [arr addObject:d];
    }
    free(rows);

    NSMutableDictionary *out = [@{
        @"query":         sym ?: addrStr,
        @"image":         @(imgNm),
        @"scanned_insns": @(scanned),
        @"count":         @(n),
        @"truncated":     truncated ? @YES : @NO,
        @"results":       arr,
    } mutableCopy];
    if (qaddr) out[@"query_address"] = [NSString stringWithFormat:@"0x%llx", qaddr];
    return tool_ok(out);
}

// find_string_refs —— tier-2A: 谁引用了某字符串(ADRP+ADD 直接 / ADRP+LDR 间接)
static NSDictionary *tool_find_string_refs(NSDictionary *args) {
    NSString *str     = [args[@"string"] isKindOfClass:NSString.class] ? args[@"string"] : nil;
    NSString *addrStr = [args[@"address"] isKindOfClass:NSString.class] ? args[@"address"] : nil;
    NSString *image   = [args[@"image"] isKindOfClass:NSString.class] ? args[@"image"] : nil;
    if (str.length == 0 && addrStr.length == 0)
        return tool_err(@"need 'string' (substring) or 'address' (exact string address)");

    uint64_t queryAddr = addrStr.length ? strtoull(addrStr.UTF8String, NULL, 0) : 0;
    int maxR = [args[@"max_results"] isKindOfClass:NSNumber.class] ? [args[@"max_results"] intValue] : 256;
    if (maxR <= 0 || maxR > 2000) maxR = 256;

    AnalysisStringRef *rows = calloc((size_t)maxR, sizeof(AnalysisStringRef));
    if (!rows) return tool_err(@"out of memory");

    uint64_t scanned = 0; char imgNm[256] = {0}; int truncated = 0;
    int n = analysis_find_string_refs(image.length ? image.UTF8String : NULL,
                                      str.length ? str.UTF8String : NULL, queryAddr,
                                      rows, maxR, imgNm, sizeof(imgNm), &scanned, &truncated);
    if (n == -1) { free(rows); return tool_err(@"invalid arguments"); }
    if (n == -2) { free(rows); return tool_err(@"image or __text section not found"); }

    NSMutableArray *arr = [NSMutableArray arrayWithCapacity:(NSUInteger)n];
    for (int i = 0; i < n; i++) {
        AnalysisStringRef *r = &rows[i];
        NSMutableDictionary *d = [@{
            @"ref_site":       [NSString stringWithFormat:@"0x%llx", r->ref_site],
            @"string_addr":    [NSString stringWithFormat:@"0x%llx", r->string_addr],
            @"string_vmaddr":  [NSString stringWithFormat:@"0x%llx", r->string_vmaddr],
            @"string":         @(r->string),
            @"section":        @(r->section),
            @"instruction":    @(r->insn_text),
            @"xref_type":      @"string_ref",
            @"indirect":       r->indirect ? @YES : @NO,
        } mutableCopy];
        if (r->from_func[0]) {
            d[@"from_func"]        = [NSString stringWithFormat:@"%s+0x%llx", r->from_func, r->from_offset];
            d[@"from_func_start"]  = [NSString stringWithFormat:@"0x%llx", r->from_func_start];
            d[@"from_func_offset"] = [NSString stringWithFormat:@"0x%llx", r->from_offset];
            if (r->from_func_vmaddr)
                d[@"from_func_vmaddr"] = [NSString stringWithFormat:@"0x%llx", r->from_func_vmaddr];
        } else {
            d[@"from_func"]       = [NSNull null];
            d[@"from_func_start"] = [NSNull null];
        }
        [arr addObject:d];
    }
    free(rows);

    NSMutableDictionary *out = [@{
        @"query":         str ?: addrStr,
        @"image":         @(imgNm),
        @"scanned_insns": @(scanned),
        @"count":         @(n),
        @"truncated":     truncated ? @YES : @NO,
        @"results":       arr,
    } mutableCopy];
    return tool_ok(out);
}

// ============================================================
// 取证工具 —— 复用面板同款数据源 (DHLogStore / dh_files / DHDumpManager / dh_capture / dh_health)
// ============================================================

// 分类字符串 -> DHCategory; "all"/未知 -> -1。规范名查分类表, 另收几个别名。
static NSInteger category_from_string(NSString *c) {
    if (![c isKindOfClass:NSString.class] || c.length == 0 || [c isEqualToString:@"all"]) return -1;
    for (NSInteger i = 0; i < dh_log_category_count(); i++)
        if ([c isEqualToString:@(dh_log_category_name(i))]) return i;
    // 别名
    if ([c isEqualToString:@"symmetric"])  return DHCategorySymmetric;
    if ([c isEqualToString:@"asymmetric"]) return DHCategoryAsymmetric;
    if ([c isEqualToString:@"system"])     return DHCategorySystem;
    if ([c isEqualToString:@"network"])    return DHCategoryNetwork;
    if ([c isEqualToString:@"kc"])         return DHCategoryKeychain;
    return -1;
}

// get_stats —— 取证总览: 事件计数 / 捕获开关 / 进程 / 健康 / 落盘量 / 噪声
static NSDictionary *tool_get_stats(NSDictionary *args) {
    DHLogStore *s = [DHLogStore shared];
    NSMutableDictionary *byCat = [NSMutableDictionary dictionary];
    for (NSInteger c = 0; c < dh_log_category_count(); c++)   // 由分类表派生, 不再硬编码
        byCat[@(dh_log_category_name(c))] = @([s countForCategory:(DHCategory)c]);
    NSMutableDictionary *capture = [NSMutableDictionary dictionary];
    for (int i = 0; i < DH_CAP_SUB_COUNT; i++)
        capture[@(dh_capture_sub_name((dh_cap_sub)i))] = @(dh_capture_sub_enabled((dh_cap_sub)i));
    const char *hsum = dh_health_summary();
    return tool_ok(@{
        @"total":      @([s totalCount]),
        @"paused":     @(s.paused),
        @"byCategory": byCat,
        @"capture":    capture,
        @"logBytes":   @([s totalLogBytes]),
        @"process":    [s processInfo] ?: @{},
        @"noise":      @{@"crypto": @([s noiseCountForBoard:DHNoiseBoardCrypto]),
                         @"sys":    @([s noiseCountForBoard:DHNoiseBoardSys])},
        @"health":     @{
            @"hookFails":     @(dh_health_hook_fail_count()),
            @"persistFailed": dh_health_persist_failed() ? @YES : @NO,
            @"httpFailed":    dh_health_http_failed() ? @YES : @NO,
            @"summary":       (hsum && hsum[0]) ? @(hsum) : @"",
        },
    });
}

// 事件是否通过「增量过滤」(output_hex/output_len/thread_id/时间窗/stack_contains)。
// 复用于 query_events 与 correlate_request。传入的过滤值缺省(nil/0)即不约束该项。
static BOOL event_passes_extra(DHLogEntry *e,
                               NSString *outHexEq, NSString *outHexPrefix, NSNumber *outLen,
                               NSNumber *tid, uint64_t sinceMs, uint64_t untilMs, NSString *stackHas) {
    if (outLen && e.output.length != outLen.unsignedIntegerValue) return NO;
    if (tid && e.threadId != tid.unsignedLongLongValue) return NO;
    if (sinceMs && e.timestampMs < sinceMs) return NO;
    if (untilMs && e.timestampMs > untilMs) return NO;
    if (stackHas.length && [e.callStack rangeOfString:stackHas].location == NSNotFound) return NO;
    if (outHexEq.length || outHexPrefix.length) {
        NSString *oh = e.output.length ? [DHHexFromData(e.output) lowercaseString] : @"";
        if (outHexEq.length && ![oh isEqualToString:[outHexEq lowercaseString]]) return NO;
        if (outHexPrefix.length && ![oh hasPrefix:[outHexPrefix lowercaseString]]) return NO;
    }
    return YES;
}

// query_events —— 过滤检索捕获事件 (最新在前), 返回摘要
static NSDictionary *tool_query_events(NSDictionary *args) {
    NSInteger cat = category_from_string(args[@"category"]);
    NSString *q = [args[@"query"] isKindOfClass:NSString.class] ? args[@"query"] : @"";
    NSUInteger minSize = [args[@"min_size"] isKindOfClass:NSNumber.class] ? [args[@"min_size"] unsignedIntegerValue] : 0;
    NSUInteger maxSize = [args[@"max_size"] isKindOfClass:NSNumber.class] ? [args[@"max_size"] unsignedIntegerValue] : 0;
    uint64_t since = [args[@"since_seq"] isKindOfClass:NSNumber.class] ? [args[@"since_seq"] unsignedLongLongValue] : 0;
    NSInteger limit = [args[@"limit"] isKindOfClass:NSNumber.class] ? [args[@"limit"] integerValue] : 100;
    if (limit <= 0 || limit > 1000) limit = 100;

    // 增量过滤参数 (Batch 1)
    NSString *outHexEq   = [args[@"output_hex"] isKindOfClass:NSString.class] ? args[@"output_hex"] : nil;
    NSString *outHexPre  = [args[@"output_hex_prefix"] isKindOfClass:NSString.class] ? args[@"output_hex_prefix"] : nil;
    NSNumber *outLen     = [args[@"output_len"] isKindOfClass:NSNumber.class] ? args[@"output_len"] : nil;
    NSNumber *tid        = [args[@"thread_id"] isKindOfClass:NSNumber.class] ? args[@"thread_id"] : nil;
    uint64_t sinceMs     = [args[@"since_ts_ms"] isKindOfClass:NSNumber.class] ? [args[@"since_ts_ms"] unsignedLongLongValue] : 0;
    uint64_t untilMs     = [args[@"until_ts_ms"] isKindOfClass:NSNumber.class] ? [args[@"until_ts_ms"] unsignedLongLongValue] : 0;
    NSString *stackHas   = [args[@"stack_contains"] isKindOfClass:NSString.class] ? args[@"stack_contains"] : nil;

    NSArray *src = [[DHLogStore shared] snapshotMatching:q category:cat minInputSize:minSize maxInputSize:maxSize];
    NSMutableArray *out = [NSMutableArray array];
    NSUInteger matched = 0;
    for (NSInteger i = (NSInteger)src.count - 1; i >= 0; i--) {
        DHLogEntry *e = src[i];
        if (since && e.seq <= since) continue;
        if (!event_passes_extra(e, outHexEq, outHexPre, outLen, tid, sinceMs, untilMs, stackHas)) continue;
        matched++;
        if ((NSInteger)out.count < limit) [out addObject:dh_log_entry_summary(e)];
    }
    return tool_ok(@{@"count": @(out.count), @"matched": @(matched), @"events": out});
}

// correlate_request —— 以一次 net 请求为锚, 聚合时间窗内 crypto/sys 事件, 并按 X-Validator 反查命中。
// 把「AES→Hash→设 Header→发包」串成一次请求, match 块给 AI「命中即闭合」的自动化验收。
static NSDictionary *tool_correlate_request(NSDictionary *args) {
    NSNumber *netSeqN = args[@"net_seq"];
    if (![netSeqN isKindOfClass:NSNumber.class]) return tool_err(@"missing 'net_seq'");
    DHLogEntry *anchor = [[DHLogStore shared] entryWithSeq:(uint64_t)netSeqN.unsignedLongLongValue];
    if (!anchor) return tool_err([NSString stringWithFormat:@"no event with seq %@", netSeqN]);
    if (anchor.timestampMs == 0) return tool_err(@"anchor is a legacy event without timestampMs — re-capture after 1.14.0");

    uint64_t windowMs = [args[@"window_ms"] isKindOfClass:NSNumber.class] ? [args[@"window_ms"] unsignedLongLongValue] : 300;
    BOOL sameThread = [args[@"same_thread_only"] isKindOfClass:NSNumber.class] ? [args[@"same_thread_only"] boolValue] : NO;

    // include 分类集合 (默认全部)
    NSMutableSet *allow = [NSMutableSet set];
    NSArray *inc = [args[@"include"] isKindOfClass:NSArray.class] ? args[@"include"] : nil;
    for (id s in inc) { NSInteger c = category_from_string(s); if (c >= 0) [allow addObject:@(c)]; }
    BOOL allowAll = (allow.count == 0);

    // 解析锚点 request headers ("> KEY: VALUE") + URL + X-Validator
    NSMutableDictionary *headers = [NSMutableDictionary dictionary];
    NSString *method = anchor.operation ?: @"";
    NSArray *lines = [(anchor.detail ?: @"") componentsSeparatedByString:@"\n"];
    NSString *url = lines.count ? lines[0] : @"";
    if ([url hasPrefix:[method stringByAppendingString:@" "]]) url = [url substringFromIndex:method.length + 1];
    for (NSString *ln in lines) {
        if (![ln hasPrefix:@"> "]) continue;
        NSString *kv = [ln substringFromIndex:2];
        NSRange colon = [kv rangeOfString:@": "];
        if (colon.location == NSNotFound) continue;
        headers[[kv substringToIndex:colon.location]] = [kv substringFromIndex:colon.location + 2];
    }
    // 匹配头: 指定 match_header 则只查它, 否则扫描全部请求头(任何 base64 值都试着反查)。
    // 不再把 X-Validator 写死 —— 它只是「优先展示」的兼容默认。
    NSString *matchHeader = [args[@"match_header"] isKindOfClass:NSString.class] ? args[@"match_header"] : nil;

    // 聚合时间窗事件, 同时建 输出hex -> 首个事件 索引
    NSArray *all = [[DHLogStore shared] snapshotMatching:@"" category:-1 minInputSize:0 maxInputSize:0];
    NSMutableArray *events = [NSMutableArray array];
    NSMutableDictionary *outIndex = [NSMutableDictionary dictionary];   // hex -> @{seq,category,algorithm}
    for (DHLogEntry *e in all) {
        if (e.seq == anchor.seq || e.timestampMs == 0) continue;
        if (!allowAll && ![allow containsObject:@(e.category)]) continue;
        if (sameThread && e.threadId != anchor.threadId) continue;
        long long delta = (long long)e.timestampMs - (long long)anchor.timestampMs;
        if (llabs(delta) > (long long)windowMs) continue;
        NSString *oh = e.output.length ? [DHHexFromData(e.output) lowercaseString] : @"";
        [events addObject:@{
            @"seq": @(e.seq), @"category": @(dh_log_category_name(e.category)),
            @"deltaMs": @(delta), @"algorithm": e.algorithm ?: @"",
            @"outLen": @(e.output.length),
            @"outputHexPreview": oh.length > 16 ? [oh substringToIndex:16] : oh,
        }];
        if (oh.length && !outIndex[oh])
            outIndex[oh] = @{@"seq": @(e.seq), @"category": @(dh_log_category_name(e.category)), @"algorithm": e.algorithm ?: @""};
    }
    [events sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) { return [a[@"deltaMs"] compare:b[@"deltaMs"]]; }];

    // 反查: 每个候选头 base64 解码 -> hex, 在事件输出里找命中(泛化到任意 base64 头, 不止 X-Validator)
    NSMutableArray *matches = [NSMutableArray array];
    NSString *validatorHex = @"";   // 兼容: anchor 仍单独给 X-Validator 的解码 hex
    for (NSString *h in headers) {
        if (matchHeader && [h caseInsensitiveCompare:matchHeader] != NSOrderedSame) continue;
        NSData *dec = [[NSData alloc] initWithBase64EncodedString:headers[h] options:0];
        if (!dec.length) continue;
        NSString *hex = [DHHexFromData(dec) lowercaseString];
        if ([h caseInsensitiveCompare:@"X-Validator"] == NSOrderedSame) validatorHex = hex;
        NSDictionary *hit = outIndex[hex];
        if (hit) [matches addObject:@{@"header": h, @"decodedHex": hex, @"matchedSeq": hit[@"seq"],
                                      @"matchedCategory": hit[@"category"], @"matchedAlgorithm": hit[@"algorithm"]}];
    }
    // match 块: 兼容旧字段(X-Validator 命中优先, 否则第一个命中) + 全部命中数组 matches
    NSDictionary *primary = nil;
    for (NSDictionary *m in matches) if ([m[@"header"] caseInsensitiveCompare:@"X-Validator"] == NSOrderedSame) { primary = m; break; }
    if (!primary) primary = matches.firstObject;
    NSMutableDictionary *matchDict = [@{@"validatorOutputFound": (primary != nil) ? @YES : @NO, @"matches": matches} mutableCopy];
    if (primary) {
        matchDict[@"matchedHeader"]    = primary[@"header"];
        matchDict[@"matchedSeq"]       = primary[@"matchedSeq"];
        matchDict[@"matchedCategory"]  = primary[@"matchedCategory"];
        matchDict[@"matchedAlgorithm"] = primary[@"matchedAlgorithm"];
    }

    return tool_ok(@{
        @"anchor": @{
            @"seq": @(anchor.seq), @"timestampMs": @(anchor.timestampMs), @"threadId": @(anchor.threadId),
            @"method": method, @"url": url, @"headers": headers, @"validatorDecodedHex": validatorHex,
        },
        @"events": events,
        @"match": matchDict,
    });
}

// 把格式化调用栈字符串解析成结构化帧, 让 AI 直接拿 address 续接 disassemble_function/symbolicate,
// 不必自己正则抠地址。每行形如 "[ 0] 0  libSystem.B.dylib  0x... symbol + 44"。
static NSArray *parse_callstack_frames(NSString *cs) {
    if (![cs isKindOfClass:NSString.class] || cs.length == 0) return @[];
    static NSRegularExpression *re = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        re = [NSRegularExpression regularExpressionWithPattern:
              @"\\d+\\s+(\\S+)\\s+(0x[0-9a-fA-F]+)\\s+(.+?)\\s+\\+\\s+(\\d+)" options:0 error:nil];
    });
    NSMutableArray *frames = [NSMutableArray array];
    int idx = 0;
    for (NSString *line in [cs componentsSeparatedByString:@"\n"]) {
        NSTextCheckingResult *m = [re firstMatchInString:line options:0 range:NSMakeRange(0, line.length)];
        if (!m) continue;
        [frames addObject:@{
            @"index":   @(idx++),
            @"image":   [line substringWithRange:[m rangeAtIndex:1]],
            @"address": [line substringWithRange:[m rangeAtIndex:2]],
            @"symbol":  [line substringWithRange:[m rangeAtIndex:3]],
            @"offset":  @([[line substringWithRange:[m rangeAtIndex:4]] integerValue]),
        }];
    }
    return frames;
}

// get_event —— 单条完整详情 (key / iv / 明文 / 密文 / 调用栈 + 结构化帧)
static NSDictionary *tool_get_event(NSDictionary *args) {
    NSNumber *seqN = args[@"seq"];
    if (![seqN isKindOfClass:NSNumber.class]) return tool_err(@"missing 'seq'");
    DHLogEntry *e = [[DHLogStore shared] entryWithSeq:(uint64_t)seqN.unsignedLongLongValue];
    if (!e) return tool_err([NSString stringWithFormat:@"no event with seq %@", seqN]);
    NSDictionary *detail = dh_log_entry_detail(e);
    NSString *cs = detail[@"callStack"];
    if (cs.length) {
        NSMutableDictionary *m = [detail mutableCopy];
        m[@"callStackFrames"] = parse_callstack_frames(cs);   // [{index,image,address,symbol,offset}]
        detail = m;
    }
    return tool_ok(detail);
}

// query_noise —— 噪声板块事件 (被过滤掉的高频调用)
static NSDictionary *tool_query_noise(NSDictionary *args) {
    NSString *b = args[@"board"];
    DHNoiseBoard board = [b isEqualToString:@"sys"] ? DHNoiseBoardSys : DHNoiseBoardCrypto;
    NSString *q = [args[@"query"] isKindOfClass:NSString.class] ? args[@"query"] : @"";
    NSInteger limit = [args[@"limit"] isKindOfClass:NSNumber.class] ? [args[@"limit"] integerValue] : 100;
    if (limit <= 0 || limit > 1000) limit = 100;
    NSArray *src = [[DHLogStore shared] snapshotNoiseMatching:q board:board];
    NSMutableArray *out = [NSMutableArray array];
    for (NSInteger i = (NSInteger)src.count - 1; i >= 0 && (NSInteger)out.count < limit; i--)
        [out addObject:dh_log_entry_summary(src[i])];
    return tool_ok(@{@"board": (board == DHNoiseBoardSys) ? @"sys" : @"crypto",
                     @"count": @(out.count), @"events": out});
}

// list_files —— 沙箱目录列举 (Documents/Library/tmp)
static NSDictionary *tool_list_files(NSDictionary *args) {
    NSString *path = [args[@"path"] isKindOfClass:NSString.class] ? args[@"path"] : nil;
    NSError *err = nil;
    NSDictionary *d = dh_files_list_dict(path, &err);
    if (!d) return tool_err(err.localizedDescription ?: @"list failed");
    return tool_ok(d);
}

// read_file —— 沙箱文件预览 (UTF-8 文本或 Hex Dump)
static NSDictionary *tool_read_file(NSDictionary *args) {
    NSString *path = args[@"path"];
    if (![path isKindOfClass:NSString.class]) return tool_err(@"missing 'path'");
    NSUInteger limit = [args[@"limit"] isKindOfClass:NSNumber.class] ? [args[@"limit"] unsignedIntegerValue] : 4096;
    NSError *err = nil;
    NSDictionary *d = dh_files_preview_dict(path, limit, &err);
    if (!d) return tool_err(err.localizedDescription ?: @"read failed");
    return tool_ok(d);
}

// dump_status —— 可砸壳镜像清单 + 当前砸壳任务状态
static NSDictionary *tool_dump_status(NSDictionary *args) {
    return tool_ok(@{
        @"dump_images": [[DHDumpManager shared] listImagesDict] ?: @{},
        @"task_status": [[DHDumpManager shared] statusDict] ?: @{},
    });
}

// ---- 控制类 (有副作用) ----

// set_capture —— 开关某个捕获子类 (名称见 get_stats.capture)
static NSDictionary *tool_set_capture(NSDictionary *args) {
    NSString *name = args[@"name"];
    NSNumber *on = args[@"enabled"];
    if (![name isKindOfClass:NSString.class] || ![on isKindOfClass:NSNumber.class])
        return tool_err(@"need 'name' and 'enabled'");
    for (int i = 0; i < DH_CAP_SUB_COUNT; i++) {
        if ([name isEqualToString:@(dh_capture_sub_name((dh_cap_sub)i))]) {
            dh_capture_set_sub((dh_cap_sub)i, on.boolValue ? 1 : 0);
            return tool_ok(@{@"name": name, @"enabled": @(on.boolValue)});
        }
    }
    return tool_err([NSString stringWithFormat:@"unknown capture name: %@ (see get_stats.capture)", name]);
}

// set_pause —— 暂停/恢复记录 (全局或按分类)
static NSDictionary *tool_set_pause(NSDictionary *args) {
    NSNumber *paused = args[@"paused"];
    if (![paused isKindOfClass:NSNumber.class]) return tool_err(@"need 'paused' (bool)");
    DHLogStore *s = [DHLogStore shared];
    NSString *cat = args[@"category"];
    if ([cat isKindOfClass:NSString.class] && ![cat isEqualToString:@"all"]) {
        NSInteger c = category_from_string(cat);
        if (c < 0) return tool_err([NSString stringWithFormat:@"invalid category: %@", cat]);
        [s setPaused:paused.boolValue forCategory:(DHCategory)c];
        return tool_ok(@{@"category": cat, @"paused": @(paused.boolValue)});
    }
    s.paused = paused.boolValue;
    return tool_ok(@{@"category": @"all", @"paused": @(paused.boolValue)});
}

// clear_events —— 清空内存事件 (破坏性; 落盘文件不动, 仍可 /download 取回)
static NSDictionary *tool_clear_events(NSDictionary *args) {
    NSString *cat = args[@"category"];
    DHLogStore *s = [DHLogStore shared];
    if ([cat isKindOfClass:NSString.class] && ![cat isEqualToString:@"all"]) {
        NSInteger c = category_from_string(cat);
        if (c < 0) return tool_err([NSString stringWithFormat:@"invalid category: %@", cat]);
        [s clearCategory:c];
        return tool_ok(@{@"cleared": cat});
    }
    [s clearAll];
    return tool_ok(@{@"cleared": @"all"});
}

// start_dump —— 触发砸壳 (异步, 轮询 dump_status)
static NSDictionary *tool_start_dump(NSDictionary *args) {
    NSString *mode = [args[@"mode"] isKindOfClass:NSString.class] ? args[@"mode"] : @"bin";
    if (![[DHDumpManager shared] startDump:mode])
        return tool_err(@"dump already running or invalid mode (use 'bin' or 'ipa')");
    return tool_ok(@{@"started": @YES, @"mode": mode, @"note": @"poll dump_status for progress"});
}

// ---- 配置面: 改机 / 噪声规则 / 日志配置 / 审查日志 ----

// get_spoof —— 改机/越狱隐藏/反调试的整份配置快照
static NSDictionary *tool_get_spoof(NSDictionary *args) {
    return tool_ok(dh_spoof_snapshot() ?: @{});
}

// set_spoof —— 改写伪装配置 (镜像面板 op 语义), 返回更新后快照
static NSDictionary *tool_set_spoof(NSDictionary *args) {
    NSString *group = args[@"group"];
    NSString *op = args[@"op"];
    if (![group isKindOfClass:NSString.class] || ![op isKindOfClass:NSString.class])
        return tool_err(@"need 'group' (jb/anti/device) and 'op'");
    BOOL on = [args[@"on"] isKindOfClass:NSNumber.class] ? [args[@"on"] boolValue] : YES;
    NSString *text = [args[@"text"] isKindOfClass:NSString.class] ? args[@"text"] : nil;

    if ([group isEqualToString:@"jb"]) {
        if      ([op isEqualToString:@"enable"])        dh_spoof_jb_set_on(on);
        else if ([op isEqualToString:@"add_path"]      && text) dh_spoof_jb_add_path(text);
        else if ([op isEqualToString:@"remove_path"]   && text) dh_spoof_jb_remove_path(text);
        else if ([op isEqualToString:@"add_scheme"]    && text) dh_spoof_jb_add_scheme(text);
        else if ([op isEqualToString:@"remove_scheme"] && text) dh_spoof_jb_remove_scheme(text);
        else if ([op isEqualToString:@"add_image"]     && text) dh_spoof_jb_add_image(text);
        else if ([op isEqualToString:@"remove_image"]  && text) dh_spoof_jb_remove_image(text);
        else return tool_err(@"invalid jb op (enable / add_path|remove_path|add_scheme|remove_scheme|add_image|remove_image + text)");
    } else if ([group isEqualToString:@"anti"]) {
        if ([op isEqualToString:@"enable"]) dh_spoof_anti_debug_set_on(on);
        else return tool_err(@"anti supports op 'enable' only");
    } else if ([group isEqualToString:@"device"]) {
        if      ([op isEqualToString:@"enable"])    dh_spoof_device_set_on(on);
        else if ([op isEqualToString:@"randomize"]) dh_spoof_device_randomize();
        else if ([op isEqualToString:@"set"]) {
            NSString *key = args[@"key"];
            if (![key isKindOfClass:NSString.class]) return tool_err(@"device 'set' needs 'key' (hw_machine/hw_model/os_version/device_name/idfv/idfa)");
            dh_spoof_device_set_value(key, [args[@"value"] isKindOfClass:NSString.class] ? args[@"value"] : @"");
        } else return tool_err(@"invalid device op (enable / randomize / set+key+value)");
    } else {
        return tool_err(@"group must be jb / anti / device");
    }
    return tool_ok(dh_spoof_snapshot() ?: @{});
}

static DHNoiseBoard noise_board_from(NSDictionary *args) {
    return [args[@"board"] isEqualToString:@"sys"] ? DHNoiseBoardSys : DHNoiseBoardCrypto;
}

static NSDictionary *noise_config_snapshot(DHNoiseBoard b) {
    return @{@"board": (b == DHNoiseBoardSys) ? @"sys" : @"crypto",
             @"enabled": @(dh_noise_enabled_for_board(b)),
             @"patterns": dh_noise_patterns_for_board(b) ?: @[]};
}

// get_noise_config —— 某板块噪声过滤开关 + 特征串清单
static NSDictionary *tool_get_noise_config(NSDictionary *args) {
    return tool_ok(noise_config_snapshot(noise_board_from(args)));
}

// set_noise_config —— 开关 / 增删噪声特征串
static NSDictionary *tool_set_noise_config(NSDictionary *args) {
    DHNoiseBoard b = noise_board_from(args);
    NSString *op = args[@"op"];
    NSString *text = [args[@"text"] isKindOfClass:NSString.class] ? args[@"text"] : nil;
    if ([op isEqualToString:@"enable"])
        dh_noise_set_enabled_for_board(b, [args[@"on"] isKindOfClass:NSNumber.class] ? [args[@"on"] boolValue] : YES);
    else if ([op isEqualToString:@"add"] && text)    dh_noise_add_pattern_for_board(b, text);
    else if ([op isEqualToString:@"remove"] && text) dh_noise_remove_pattern_for_board(b, text);
    else return tool_err(@"op must be enable / add / remove (add|remove need 'text')");
    return tool_ok(noise_config_snapshot(b));
}

// clear_noise —— 清空某板块噪声事件 (内存, 不动落盘)
static NSDictionary *tool_clear_noise(NSDictionary *args) {
    DHNoiseBoard b = noise_board_from(args);
    [[DHLogStore shared] clearNoiseForBoard:b];
    return tool_ok(@{@"cleared": (b == DHNoiseBoardSys) ? @"sys" : @"crypto"});
}

// get_config —— 日志保留配置
static NSDictionary *tool_get_config(NSDictionary *args) {
    DHLogStore *s = [DHLogStore shared];
    return tool_ok(@{@"maxPerCategory": @([s maxPerCategory]), @"maxLogFileBytes": @([s maxLogFileBytes])});
}

// set_config —— 改日志保留 (每类内存条数 / 单文件落盘上限, 0=不限)
static NSDictionary *tool_set_config(NSDictionary *args) {
    DHLogStore *s = [DHLogStore shared];
    if ([args[@"maxEntries"] isKindOfClass:NSNumber.class]) {
        NSInteger n = [args[@"maxEntries"] integerValue];
        if (n > 0) [s setMaxPerCategory:(NSUInteger)n];
    }
    if ([args[@"maxFileBytes"] isKindOfClass:NSNumber.class]) {
        long long n = [args[@"maxFileBytes"] longLongValue];
        if (n >= 0) [s setMaxLogFileBytes:(unsigned long long)n];
    }
    return tool_ok(@{@"maxPerCategory": @([s maxPerCategory]), @"maxLogFileBytes": @([s maxLogFileBytes])});
}

// get_diag —— 审查/诊断日志时间线 (board 省略=全部板块) + 未挂上的符号清单
static NSDictionary *tool_get_diag(NSDictionary *args) {
    NSString *b = args[@"board"];
    int board = -1;
    if      ([b isEqualToString:@"general"]) board = DH_DIAG_GENERAL;
    else if ([b isEqualToString:@"crypto"])  board = DH_DIAG_CRYPTO;
    else if ([b isEqualToString:@"file"])    board = DH_DIAG_FILE;
    else if ([b isEqualToString:@"sys"])     board = DH_DIAG_SYS;
    else if ([b isEqualToString:@"dump"])    board = DH_DIAG_DUMP;
    const char *txt = dh_diag_dump(board);
    const char *unh = dh_health_hook_unhooked();
    return tool_ok(@{
        @"board":    [b isKindOfClass:NSString.class] ? b : @"all",
        @"diag":     (txt && txt[0]) ? @(txt) : @"",
        @"unhooked": (unh && unh[0]) ? @(unh) : @"",
    });
}

// ============================================================
// 工具元数据 (tools/list 用) + 分发
// ============================================================
static NSArray *tool_definitions(void) {
    return @[
        @{
            @"name": @"disassemble",
            @"description": @"Disassemble a hex byte string into assembly instructions (ARM64/ARM/Thumb).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"bytes": @{@"type": @"string", @"description": @"Hex-encoded machine code, e.g. \"fd7bbfa9\""},
                    @"address": @{@"type": @"string", @"description": @"Base address for listing, e.g. \"0x100000000\" (default 0)"},
                    @"arch": @{@"type": @"string", @"enum": @[@"arm64", @"arm", @"thumb"], @"description": @"Default arm64"},
                },
                @"required": @[@"bytes"],
            },
        },
        @{
            @"name": @"analyze_function",
            @"description": @"Read `size` bytes from process memory at `address` and disassemble them. Safe against unmapped addresses.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"address": @{@"type": @"string", @"description": @"In-process address, e.g. \"0x1029ac000\""},
                    @"size": @{@"type": @"number", @"description": @"Bytes to read (capped at 65536)"},
                    @"arch": @{@"type": @"string", @"enum": @[@"arm64", @"arm", @"thumb"], @"description": @"Default arm64"},
                },
                @"required": @[@"address", @"size"],
            },
        },
        @{
            @"name": @"disassemble_function",
            @"description": @"Disassemble process memory starting at `address` until a `ret` (function-boundary heuristic) or max_bytes. Better than analyze_function for reading a whole function.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"address": @{@"type": @"string", @"description": @"Function start address, e.g. \"0x1029ac000\""},
                    @"max_bytes": @{@"type": @"number", @"description": @"Read cap before forced stop (default 4096, max 65536)"},
                    @"arch": @{@"type": @"string", @"enum": @[@"arm64", @"arm", @"thumb"], @"description": @"Default arm64"},
                },
                @"required": @[@"address"],
            },
        },
        @{
            @"name": @"resolve_symbol",
            @"description": @"Resolve a symbol name to its runtime address via dlsym (exported/dynamic symbols). Feed the result to disassemble_function.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"name": @{@"type": @"string", @"description": @"Symbol name, e.g. \"CCCrypt\" (no leading underscore)"},
                },
                @"required": @[@"name"],
            },
        },
        @{
            @"name": @"symbolicate",
            @"description": @"Resolve an address to the nearest symbol + offset via dladdr. Use to label branch targets and call-stack addresses.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"address": @{@"type": @"string", @"description": @"In-process address, e.g. \"0x1029ac1f8\""},
                },
                @"required": @[@"address"],
            },
        },
        @{
            @"name": @"read_memory",
            @"description": @"Read process memory at `address` and return a hex + ASCII hexdump. Safe against unmapped addresses. For inspecting data/keys/structs (not code).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"address": @{@"type": @"string", @"description": @"In-process address"},
                    @"size": @{@"type": @"number", @"description": @"Bytes to read (default 256, max 4096)"},
                },
                @"required": @[@"address"],
            },
        },
        @{
            @"name": @"search_memory",
            @"description": @"Scan [address, address+length) for a byte pattern or string. Skips unmapped pages. Returns hit addresses. Use to find constants/keys/xrefs.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"address": @{@"type": @"string", @"description": @"Start address (e.g. an image load_address)"},
                    @"length": @{@"type": @"number", @"description": @"Bytes to scan (capped at 256MB)"},
                    @"string": @{@"type": @"string", @"description": @"UTF-8 string to find (alternative to pattern)"},
                    @"pattern": @{@"type": @"string", @"description": @"Hex byte pattern to find, e.g. \"deadbeef\""},
                },
                @"required": @[@"address", @"length"],
            },
        },
        @{
            @"name": @"list_images",
            @"description": @"List loaded images (with imports) and their index — call this FIRST to get a valid image_index for list_imports. Main executable listed first.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"query": @{@"type": @"string", @"description": @"Optional substring filter on image name"},
                },
            },
        },
        @{
            @"name": @"list_imports",
            @"description": @"List the imported (undefined) symbols of a loaded image — the fishhook-rebindable candidates.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"image_index": @{@"type": @"number", @"description": @"Image index from list_images (NOT get_macho_info — different index space)"},
                    @"query": @{@"type": @"string", @"description": @"Optional substring filter"},
                    @"limit": @{@"type": @"number", @"description": @"Max symbols returned (default 500)"},
                },
                @"required": @[@"image_index"],
            },
        },
        @{
            @"name": @"get_macho_info",
            @"description": @"List loaded Mach-O images in the app bundle with load address and FairPlay encryption status.",
            @"inputSchema": @{@"type": @"object", @"properties": @{}},
        },
        @{
            @"name": @"find_xrefs",
            @"description": @"Find who calls a symbol/address: scan an image's __TEXT,__text for direct `bl` calls to the target. Resolves import stubs to the real symbol via the runtime-bound GOT + dladdr. tier-1 only: direct BL (no BLR/BR indirect calls, no string/selector refs, no CFG). Give 'symbol' (resolved via dlsym) or 'address'.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"symbol": @{@"type": @"string", @"description": @"Target symbol name, e.g. \"CCCrypt\" (no leading underscore). Resolved via dlsym."},
                    @"address": @{@"type": @"string", @"description": @"Target runtime address (alternative to symbol), e.g. \"0x1a2345678\""},
                    @"image": @{@"type": @"string", @"description": @"Image name substring to scan (default: main executable)"},
                    @"max_results": @{@"type": @"number", @"description": @"Max call sites returned (default 256, max 2000)"},
                },
            },
        },
        @{
            @"name": @"find_string_refs",
            @"description": @"Find who references a string: scan an image's __TEXT,__text for ADRP+ADD (direct) / ADRP+LDR-slot (indirect) address recovery landing in a string section (__cstring / __objc_methname / __objc_classname / __objc_methtype). tier-2A: local-window backtrack only (no cross-block/func dataflow). Give 'string' (substring match) or 'address' (exact string address).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"string": @{@"type": @"string", @"description": @"Substring to match against string contents, e.g. \"AES\""},
                    @"address": @{@"type": @"string", @"description": @"Exact string runtime address (alternative to string)"},
                    @"image": @{@"type": @"string", @"description": @"Image name substring to scan (default: main executable)"},
                    @"max_results": @{@"type": @"number", @"description": @"Max ref sites returned (default 256, max 2000)"},
                },
            },
        },
        // ---- 取证: 读 ----
        @{
            @"name": @"get_stats",
            @"description": @"Forensic overview: captured-event counts per category, capture toggles, host process info, hook health, on-disk log bytes, noise counts.",
            @"inputSchema": @{@"type": @"object", @"properties": @{}},
        },
        @{
            @"name": @"query_events",
            @"description": @"Search captured runtime events (crypto/file/system) — the core forensic feed. Returns summaries newest-first. Use get_event for a full record.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"category": @{@"type": @"string", @"enum": @[@"all", @"digest", @"hmac", @"sym", @"asym", @"file", @"sys", @"net", @"keychain", @"other"], @"description": @"Filter by category (default all). 'net'=network, 'keychain'=Keychain items."},
                    @"query": @{@"type": @"string", @"description": @"Keyword filter (algorithm/path/preview)"},
                    @"min_size": @{@"type": @"number", @"description": @"Min input bytes"},
                    @"max_size": @{@"type": @"number", @"description": @"Max input bytes (0 = no cap)"},
                    @"since_seq": @{@"type": @"number", @"description": @"Only events with seq > this (incremental polling)"},
                    @"output_hex": @{@"type": @"string", @"description": @"Exact output match (case-insensitive hex). Decode a header/token to hex and find which crypto op produced it."},
                    @"output_hex_prefix": @{@"type": @"string", @"description": @"Output hex prefix match (e.g. MD5 s= first 8 chars)"},
                    @"output_len": @{@"type": @"number", @"description": @"Exact output byte length (e.g. 32 for SHA256/AES block)"},
                    @"thread_id": @{@"type": @"number", @"description": @"Only events on this thread"},
                    @"since_ts_ms": @{@"type": @"number", @"description": @"Only events with timestampMs >= this"},
                    @"until_ts_ms": @{@"type": @"number", @"description": @"Only events with timestampMs <= this"},
                    @"stack_contains": @{@"type": @"string", @"description": @"Only events whose call stack contains this substring (e.g. an address/module)"},
                    @"limit": @{@"type": @"number", @"description": @"Max results (default 100, max 1000)"},
                },
            },
        },
        @{
            @"name": @"correlate_request",
            @"description": @"Anchor on a captured network request (net_seq) and gather all crypto/keychain/net events within window_ms, sorted by deltaMs. Base64-decodes the request headers and reports which event's output matches each — 'matches' lists every header→event hit; 'match' surfaces the primary one (X-Validator first, else the first). Pass match_header to restrict to one header.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"net_seq": @{@"type": @"number", @"description": @"seq of the anchor network event (from query_events category=net)"},
                    @"window_ms": @{@"type": @"number", @"description": @"Time window around the anchor (default 300)"},
                    @"include": @{@"type": @"array", @"items": @{@"type": @"string"}, @"description": @"Categories to include, e.g. [\"digest\",\"hmac\",\"sym\",\"keychain\",\"net\"] (default all)"},
                    @"same_thread_only": @{@"type": @"boolean", @"description": @"Only events on the anchor's thread (default false)"},
                    @"match_header": @{@"type": @"string", @"description": @"Restrict reverse-match to one request header (e.g. \"X-Validator\"); default scans all base64 headers"},
                },
                @"required": @[@"net_seq"],
            },
        },
        @{
            @"name": @"get_event",
            @"description": @"Full detail of one captured event by seq: algorithm, key, IV, plaintext, ciphertext (hex + utf8 + hexdump), and the app-level call stack — both as text (callStack) and structured frames (callStackFrames: [{index,image,address,symbol,offset}]) you can feed straight into disassemble_function / symbolicate.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{@"seq": @{@"type": @"number", @"description": @"Event sequence number (from query_events)"}},
                @"required": @[@"seq"],
            },
        },
        @{
            @"name": @"query_noise",
            @"description": @"List noise-filtered events (high-frequency calls diverted from the main feed).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"board": @{@"type": @"string", @"enum": @[@"crypto", @"sys"], @"description": @"Noise board (default crypto)"},
                    @"query": @{@"type": @"string", @"description": @"Keyword filter"},
                    @"limit": @{@"type": @"number", @"description": @"Max results (default 100)"},
                },
            },
        },
        @{
            @"name": @"list_files",
            @"description": @"List sandbox files/dirs under the host app's Documents/Library/tmp (empty path = the three roots).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{@"path": @{@"type": @"string", @"description": @"Relative sandbox path (empty for roots)"}},
            },
        },
        @{
            @"name": @"read_file",
            @"description": @"Preview a sandbox file as UTF-8 text or hex dump.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"path": @{@"type": @"string", @"description": @"Relative sandbox file path"},
                    @"limit": @{@"type": @"number", @"description": @"Max bytes to preview (default 4096)"},
                },
                @"required": @[@"path"],
            },
        },
        @{
            @"name": @"dump_status",
            @"description": @"List dumpable (in-memory, App-bundle) Mach-O images with encryption status, plus current unpacking task state.",
            @"inputSchema": @{@"type": @"object", @"properties": @{}},
        },
        // ---- 取证: 控制 (有副作用) ----
        @{
            @"name": @"set_capture",
            @"description": @"Enable/disable a capture subtype (names from get_stats.capture, e.g. CCCrypt, open, dlopen).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"name": @{@"type": @"string", @"description": @"Capture subtype name"},
                    @"enabled": @{@"type": @"boolean", @"description": @"true to capture, false to skip"},
                },
                @"required": @[@"name", @"enabled"],
            },
        },
        @{
            @"name": @"set_pause",
            @"description": @"Pause/resume event recording, globally or for one category.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"paused": @{@"type": @"boolean", @"description": @"true to pause, false to resume"},
                    @"category": @{@"type": @"string", @"description": @"Category to target, or 'all' (default all)"},
                },
                @"required": @[@"paused"],
            },
        },
        @{
            @"name": @"clear_events",
            @"description": @"Clear in-memory captured events (destructive). On-disk log is untouched and still downloadable.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{@"category": @{@"type": @"string", @"description": @"Category to clear, or 'all' (default all)"}},
            },
        },
        @{
            @"name": @"start_dump",
            @"description": @"Trigger on-device unpacking (decrypt loaded images). Async — poll dump_status for progress and artifacts.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{@"mode": @{@"type": @"string", @"enum": @[@"bin", @"ipa"], @"description": @"'bin' = decrypted binaries zip; 'ipa' = re-signable IPA (default bin)"}},
            },
        },
        // ---- 配置面: 改机 / 噪声规则 / 日志配置 / 审查日志 ----
        @{
            @"name": @"get_spoof",
            @"description": @"Get the anti-detection config: jailbreak-hiding (paths/schemes/injection-image cloaking), anti-debug, and device-spoofing (改机) values.",
            @"inputSchema": @{@"type": @"object", @"properties": @{}},
        },
        @{
            @"name": @"set_spoof",
            @"description": @"Change anti-detection config. Returns the updated snapshot. group=jb: enable / add_path|remove_path|add_scheme|remove_scheme|add_image|remove_image (+text). group=anti: enable. group=device: enable / randomize / set (+key +value).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"group": @{@"type": @"string", @"enum": @[@"jb", @"anti", @"device"], @"description": @"jb=jailbreak-hide, anti=anti-debug, device=改机"},
                    @"op": @{@"type": @"string", @"description": @"enable/randomize/set or jb list ops"},
                    @"on": @{@"type": @"boolean", @"description": @"For op=enable"},
                    @"text": @{@"type": @"string", @"description": @"Path/scheme/image for jb add|remove ops"},
                    @"key": @{@"type": @"string", @"description": @"device set key: hw_machine/hw_model/os_version/device_name/idfv/idfa"},
                    @"value": @{@"type": @"string", @"description": @"device set value"},
                },
                @"required": @[@"group", @"op"],
            },
        },
        @{
            @"name": @"get_noise_config",
            @"description": @"Get a noise board's filter state: enabled flag + pattern list (events matching a pattern are diverted from the main feed).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{@"board": @{@"type": @"string", @"enum": @[@"crypto", @"sys"], @"description": @"Default crypto"}},
            },
        },
        @{
            @"name": @"set_noise_config",
            @"description": @"Toggle a noise board or add/remove a noise pattern. Returns updated config.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"board": @{@"type": @"string", @"enum": @[@"crypto", @"sys"]},
                    @"op": @{@"type": @"string", @"enum": @[@"enable", @"add", @"remove"]},
                    @"on": @{@"type": @"boolean", @"description": @"For op=enable"},
                    @"text": @{@"type": @"string", @"description": @"Pattern for add/remove"},
                },
                @"required": @[@"op"],
            },
        },
        @{
            @"name": @"clear_noise",
            @"description": @"Clear a noise board's in-memory events (on-disk untouched).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{@"board": @{@"type": @"string", @"enum": @[@"crypto", @"sys"]}},
            },
        },
        @{
            @"name": @"get_config",
            @"description": @"Get log retention config: in-memory entries per category and on-disk log file cap.",
            @"inputSchema": @{@"type": @"object", @"properties": @{}},
        },
        @{
            @"name": @"set_config",
            @"description": @"Change log retention. Returns updated config.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"maxEntries": @{@"type": @"number", @"description": @"Max in-memory events per category"},
                    @"maxFileBytes": @{@"type": @"number", @"description": @"On-disk log cap in bytes (0 = unlimited)"},
                },
            },
        },
        @{
            @"name": @"get_diag",
            @"description": @"Get the diagnostic/audit log timeline (hook health, persistence, service events) and the list of symbols that failed to hook. Omit board for all boards.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{@"board": @{@"type": @"string", @"enum": @[@"general", @"crypto", @"file", @"sys", @"dump"], @"description": @"Diag board (default all)"}},
            },
        },
    ];
}

static NSDictionary *dispatch_tool(NSString *name, NSDictionary *args) {
    if ([name isEqualToString:@"disassemble"])           return tool_disassemble(args);
    if ([name isEqualToString:@"analyze_function"])      return tool_analyze_function(args);
    if ([name isEqualToString:@"disassemble_function"])  return tool_disassemble_function(args);
    if ([name isEqualToString:@"resolve_symbol"])        return tool_resolve_symbol(args);
    if ([name isEqualToString:@"symbolicate"])           return tool_symbolicate(args);
    if ([name isEqualToString:@"read_memory"])           return tool_read_memory(args);
    if ([name isEqualToString:@"search_memory"])         return tool_search_memory(args);
    if ([name isEqualToString:@"list_images"])           return tool_list_images(args);
    if ([name isEqualToString:@"list_imports"])          return tool_list_imports(args);
    if ([name isEqualToString:@"get_macho_info"])        return tool_get_macho_info(args);
    if ([name isEqualToString:@"find_xrefs"])            return tool_find_xrefs(args);
    if ([name isEqualToString:@"find_string_refs"])      return tool_find_string_refs(args);
    // 取证: 读
    if ([name isEqualToString:@"get_stats"])             return tool_get_stats(args);
    if ([name isEqualToString:@"query_events"])          return tool_query_events(args);
    if ([name isEqualToString:@"correlate_request"])     return tool_correlate_request(args);
    if ([name isEqualToString:@"get_event"])             return tool_get_event(args);
    if ([name isEqualToString:@"query_noise"])           return tool_query_noise(args);
    if ([name isEqualToString:@"list_files"])            return tool_list_files(args);
    if ([name isEqualToString:@"read_file"])             return tool_read_file(args);
    if ([name isEqualToString:@"dump_status"])           return tool_dump_status(args);
    // 取证: 控制 (有副作用)
    if ([name isEqualToString:@"set_capture"])           return tool_set_capture(args);
    if ([name isEqualToString:@"set_pause"])             return tool_set_pause(args);
    if ([name isEqualToString:@"clear_events"])          return tool_clear_events(args);
    if ([name isEqualToString:@"start_dump"])            return tool_start_dump(args);
    // 配置面: 改机 / 噪声规则 / 日志配置 / 审查日志
    if ([name isEqualToString:@"get_spoof"])             return tool_get_spoof(args);
    if ([name isEqualToString:@"set_spoof"])             return tool_set_spoof(args);
    if ([name isEqualToString:@"get_noise_config"])      return tool_get_noise_config(args);
    if ([name isEqualToString:@"set_noise_config"])      return tool_set_noise_config(args);
    if ([name isEqualToString:@"clear_noise"])           return tool_clear_noise(args);
    if ([name isEqualToString:@"get_config"])            return tool_get_config(args);
    if ([name isEqualToString:@"set_config"])            return tool_set_config(args);
    if ([name isEqualToString:@"get_diag"])              return tool_get_diag(args);
    return nil;   // 未知工具
}

// ============================================================
// MCP 协议分发
// ============================================================
@implementation MCPServer

+ (NSString *)sessionId {
    static NSString *sid = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ sid = [[NSUUID UUID] UUIDString]; });
    return sid;
}

+ (nullable NSDictionary *)handleMessage:(NSDictionary *)message {
    if (![message isKindOfClass:NSDictionary.class])
        return rpc_error(nil, -32600, @"Invalid Request");

    NSString *method = message[@"method"];
    id reqId = message[@"id"];                 // 缺失 => 通知
    BOOL isNotification = (reqId == nil);

    if (![method isKindOfClass:NSString.class]) {
        return isNotification ? nil : rpc_error(reqId, -32600, @"Invalid Request: missing method");
    }

    // ---- 通知 (无需应答) ----
    if (isNotification) {
        // notifications/initialized 等: 收下即可, 不回应答体。
        return nil;
    }

    NSDictionary *params = [message[@"params"] isKindOfClass:NSDictionary.class] ? message[@"params"] : @{};

    // ---- initialize ----
    if ([method isEqualToString:@"initialize"]) {
        NSString *reqProto = params[@"protocolVersion"];
        NSString *proto = ([reqProto isKindOfClass:NSString.class] &&
                           [mcp_supported_protocols() containsObject:reqProto])
                          ? reqProto : @MCP_DEFAULT_PROTO;
        return rpc_result(reqId, @{
            @"protocolVersion": proto,
            @"capabilities": @{@"tools": @{@"listChanged": @NO}},
            @"serverInfo": @{@"name": @MCP_SERVER_NAME, @"version": @MCP_SERVER_VERSION},
            @"instructions": @"iOS binary analysis tools: disassemble, analyze_function, list_imports, get_macho_info.",
        });
    }

    // ---- ping ----
    if ([method isEqualToString:@"ping"]) {
        return rpc_result(reqId, @{});
    }

    // ---- tools/list ----
    if ([method isEqualToString:@"tools/list"]) {
        return rpc_result(reqId, @{@"tools": tool_definitions()});
    }

    // ---- tools/call ----
    if ([method isEqualToString:@"tools/call"]) {
        NSString *name = params[@"name"];
        NSDictionary *args = [params[@"arguments"] isKindOfClass:NSDictionary.class] ? params[@"arguments"] : @{};
        if (![name isKindOfClass:NSString.class])
            return rpc_error(reqId, -32602, @"Invalid params: missing tool name");

        NSDictionary *toolResult = dispatch_tool(name, args);
        if (!toolResult)   // 未知工具名: 按 MCP 惯例走工具级错误信封, 而非协议错误
            return rpc_result(reqId, tool_err([NSString stringWithFormat:@"Unknown tool: %@", name]));
        return rpc_result(reqId, toolResult);
    }

    return rpc_error(reqId, -32601, [NSString stringWithFormat:@"Method not found: %@", method]);
}

@end
