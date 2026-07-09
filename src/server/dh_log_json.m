// dh_log_json.m — 日志条目 JSON 成型 (从 http_server 抽出, 供面板与 MCP 共用)

#import <Foundation/Foundation.h>
#import "dh_log_json.h"

const char *dh_log_category_name(NSInteger c) {
    switch (c) {
        case DHCategoryDigest:     return "digest";
        case DHCategoryHMAC:       return "hmac";
        case DHCategorySymmetric:  return "sym";
        case DHCategoryAsymmetric: return "asym";
        case DHCategoryFile:       return "file";
        case DHCategorySystem:     return "sys";
        case DHCategoryNetwork:    return "net";
        default: return "other";
    }
}

NSDictionary *dh_log_entry_summary(DHLogEntry *e) {
    NSString *preview = nil;
    if (e.input.length) {
        // 预览取前 256 字节足以填满一整行; 整体解码后按字符截断, 避免多字节 UTF-8 中点切断致乱码
        NSUInteger cap = MIN(e.input.length, (NSUInteger)256);
        NSString *u = nil;
        for (NSUInteger n = cap; n >= (cap > 3 ? cap - 3 : 1); n--) {
            u = [[NSString alloc] initWithData:[e.input subdataWithRange:NSMakeRange(0, n)] encoding:NSUTF8StringEncoding];
            if (u) break;
        }
        if (u.length) {
            BOOL more = e.input.length > cap || u.length > 200;
            if (u.length > 200) u = [u substringToIndex:200];
            preview = more ? [u stringByAppendingString:@"…"] : u;
        } else {
            NSData *d = e.input.length > 32 ? [e.input subdataWithRange:NSMakeRange(0, 32)] : e.input;
            preview = DHHexFromData(d);
        }
    }
    return @{
        @"seq":          @(e.seq),
        @"category":     @(e.category),
        @"categoryName": @(dh_log_category_name(e.category)),
        @"algorithm":    e.algorithm ?: @"",
        @"operation":    e.operation ?: @"",
        @"timestamp":    e.timestamp ?: @"",
        @"inLen":        @(e.input.length),
        @"outLen":       @(e.output.length),
        @"detail":       e.detail ?: @"",
        @"preview":      preview ?: @"",
    };
}

NSDictionary *dh_log_entry_detail(DHLogEntry *e) {
    NSMutableDictionary *m = [dh_log_entry_summary(e) mutableCopy] ?: [NSMutableDictionary dictionary];
    if (e.key)    { m[@"key"]    = @(e.key.length);    m[@"keyHex"]    = DHHexFromData(e.key); }
    if (e.iv)     { m[@"iv"]     = @(e.iv.length);     m[@"ivHex"]     = DHHexFromData(e.iv); }
    if (e.input)  {
        m[@"input"]    = @(e.input.length);
        m[@"inputHex"] = DHHexFromData(e.input);
        NSString *u = DHUTF8FromData(e.input);
        if (![u isEqualToString:@"(非UTF-8)"]) m[@"inputUtf8"] = u;
        m[@"inputDump"] = DHHexDumpFromData(e.input);
    }
    if (e.output) {
        m[@"output"]    = @(e.output.length);
        m[@"outputHex"] = DHHexFromData(e.output);
        NSString *u = DHUTF8FromData(e.output);
        if (![u isEqualToString:@"(非UTF-8)"]) m[@"outputUtf8"] = u;
        m[@"outputDump"] = DHHexDumpFromData(e.output);
    }
    if (e.publicKeyInfo) m[@"publicKeyInfo"] = e.publicKeyInfo;
    if (e.callStack)     m[@"callStack"] = e.callStack;
    return m;
}
