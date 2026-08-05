// dh_log_json.m — 日志条目 JSON 成型 (从 http_server 抽出, 供面板与 MCP 共用)

#import <Foundation/Foundation.h>
#import "dh_log_json.h"

// 分类短名单一真相源 —— 顺序必须与 DHCategory 枚举一致。
// 加分类只改这里(和 log_store.h 枚举 + dh_capture.h 的 DH_CAP_CAT_COUNT), 其余处(http byCat/
// pausedByCat / mcp get_stats / category_from_string / web CAT_CLS)全部由此派生, 不再各自硬编码。
static const char *kCategoryNames[] = {
    "digest", "hmac", "sym", "asym", "file", "sys", "net", "keychain", "other",
};

NSInteger dh_log_category_count(void) {
    return (NSInteger)(sizeof(kCategoryNames) / sizeof(kCategoryNames[0]));
}

const char *dh_log_category_name(NSInteger c) {
    if (c < 0 || c >= dh_log_category_count()) return "other";
    return kCategoryNames[c];
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
    // outputHexPreview: 输出前 16 个 hex 字符, 便于 query_events 不逐条 get_event 就能眼判命中
    NSString *outPrev = @"";
    if (e.output.length) {
        NSString *oh = DHHexFromData(e.output);
        outPrev = oh.length > 16 ? [oh substringToIndex:16] : oh;
    }
    return @{
        @"seq":          @(e.seq),
        @"category":     @(e.category),
        @"categoryName": @(dh_log_category_name(e.category)),
        @"algorithm":    e.algorithm ?: @"",
        @"operation":    e.operation ?: @"",
        @"timestamp":    e.timestamp ?: @"",
        @"timestampMs":  @(e.timestampMs),
        @"threadId":     @(e.threadId),
        @"inLen":        @(e.input.length),
        @"outLen":       @(e.output.length),
        @"outputHexPreview": outPrev,
        @"detail":       e.detail ?: @"",
        @"preview":      preview ?: @"",
    };
}

static NSData *bounded_blob(NSData *data, NSUInteger maxBytes, BOOL *truncated) {
    if (truncated) *truncated = data.length > maxBytes;
    if (data.length <= maxBytes) return data;
    return [data subdataWithRange:NSMakeRange(0, maxBytes)];
}

NSDictionary *dh_log_entry_detail_bounded(DHLogEntry *e, NSUInteger maxBlobBytes,
                                           BOOL includeDumps) {
    NSMutableDictionary *m = [dh_log_entry_summary(e) mutableCopy] ?: [NSMutableDictionary dictionary];
    if (e.key) {
        BOOL truncated = NO;
        NSData *data = bounded_blob(e.key, maxBlobBytes, &truncated);
        m[@"key"] = @(e.key.length);
        m[@"keyHex"] = DHHexFromData(data);
        if (truncated) m[@"keyTruncated"] = @YES;
    }
    if (e.iv) {
        BOOL truncated = NO;
        NSData *data = bounded_blob(e.iv, maxBlobBytes, &truncated);
        m[@"iv"] = @(e.iv.length);
        m[@"ivHex"] = DHHexFromData(data);
        if (truncated) m[@"ivTruncated"] = @YES;
    }
    if (e.input)  {
        BOOL truncated = NO;
        NSData *data = bounded_blob(e.input, maxBlobBytes, &truncated);
        m[@"input"]    = @(e.input.length);
        m[@"inputHex"] = DHHexFromData(data);
        NSString *u = DHUTF8FromData(data);
        if (![u isEqualToString:@"(非UTF-8)"]) m[@"inputUtf8"] = u;
        if (includeDumps) m[@"inputDump"] = DHHexDumpFromData(data);
        if (truncated) m[@"inputTruncated"] = @YES;
    }
    if (e.output) {
        BOOL truncated = NO;
        NSData *data = bounded_blob(e.output, maxBlobBytes, &truncated);
        m[@"output"]    = @(e.output.length);
        m[@"outputHex"] = DHHexFromData(data);
        NSString *u = DHUTF8FromData(data);
        if (![u isEqualToString:@"(非UTF-8)"]) m[@"outputUtf8"] = u;
        if (includeDumps) m[@"outputDump"] = DHHexDumpFromData(data);
        if (truncated) m[@"outputTruncated"] = @YES;
    }
    if (e.publicKeyInfo) m[@"publicKeyInfo"] = e.publicKeyInfo;
    if (e.callStack)     m[@"callStack"] = e.callStack;
    return m;
}

NSDictionary *dh_log_entry_detail(DHLogEntry *e) {
    return dh_log_entry_detail_bounded(e, NSUIntegerMax, YES);
}
