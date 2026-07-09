// mcp_server.m — MCP 服务器实现
//
// MCP over JSON-RPC 2.0。方法分发 + 工具执行 + 标准 content 信封。
// 传输层 (HTTP/SSE/会话头) 在 http_server.m 的 handle_mcp 里。

#import <Foundation/Foundation.h>
#include "mcp_server.h"
#include "analysis.h"
#include "dh_symtab.h"
#include <string.h>

#define MCP_SERVER_NAME     "ios-decrypt-helper"
#define MCP_SERVER_VERSION  "1.11.0"
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

// hex 串 -> NSData; 容忍 "0x" 前缀、空白、大小写。奇数位末尾忽略。
static NSData *hex_to_data(NSString *hex) {
    NSMutableData *d = [NSMutableData data];
    const char *s = hex.UTF8String;
    if (!s) return d;
    int hi = -1;
    for (; *s; s++) {
        int v;
        char c = *s;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else continue;   // 跳过 0x/空格/分隔符
        if (hi < 0) { hi = v; }
        else { uint8_t b = (uint8_t)((hi << 4) | v); [d appendBytes:&b length:1]; hi = -1; }
    }
    return d;
}

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

    NSData *code = hex_to_data(bytesHex);
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
        @"truncated": @(n == 512),
        @"instructions": insns_to_array(insns, n),
    });
}

// C 回调: 把符号名收集进 NSMutableArray (与 http_server 的 /api/symbols 同路)
static void sym_collect_cb(const char *name, void *ctx) {
    if (name) [(__bridge NSMutableArray *)ctx addObject:@(name)];
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
            @"name": @"list_imports",
            @"description": @"List the imported (undefined) symbols of a loaded image — the fishhook-rebindable candidates.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"image_index": @{@"type": @"number", @"description": @"Image index; use get_macho_info / order of loaded images"},
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
    ];
}

static NSDictionary *dispatch_tool(NSString *name, NSDictionary *args) {
    if ([name isEqualToString:@"disassemble"])       return tool_disassemble(args);
    if ([name isEqualToString:@"analyze_function"])  return tool_analyze_function(args);
    if ([name isEqualToString:@"list_imports"])      return tool_list_imports(args);
    if ([name isEqualToString:@"get_macho_info"])    return tool_get_macho_info(args);
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
