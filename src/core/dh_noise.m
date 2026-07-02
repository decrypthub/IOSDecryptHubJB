// dh_noise.m — 见 dh_noise.h
#import "dh_noise.h"
#import "dh_health.h"

static NSMutableArray<NSString *> *gPatterns = nil;
static BOOL          gEnabled  = YES;
static NSString     *gConfPath = nil;
static NSLock       *gLock     = nil;

static void dh_noise_set_defaults_locked(void) {
    gEnabled  = YES;
    gPatterns = [NSMutableArray arrayWithObject:@"MGCopyAnswer"];
}

// 须持有 gLock 调用。格式: 第一行 1/0, 之后每行一条特征串。
static void dh_noise_save_locked(void) {
    if (!gConfPath) return;
    NSMutableString *txt = [NSMutableString stringWithFormat:@"%d\n", gEnabled ? 1 : 0];
    for (NSString *p in gPatterns) [txt appendFormat:@"%@\n", p];
    int saved = dh_in_hook; dh_in_hook = 1;
    [txt writeToFile:gConfPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    dh_in_hook = saved;
}

void dh_noise_load(NSString *confPath) {
    if (!gLock) gLock = [NSLock new];
    [gLock lock];
    dh_noise_set_defaults_locked();
    gConfPath = [confPath copy];
    if (gConfPath) {
        int saved = dh_in_hook; dh_in_hook = 1;
        NSString *txt = [NSString stringWithContentsOfFile:gConfPath encoding:NSUTF8StringEncoding error:nil];
        dh_in_hook = saved;
        if (txt.length) {
            NSArray<NSString *> *lines = [txt componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
            if (lines.count >= 1) {
                gEnabled = [lines[0] isEqualToString:@"1"];
                NSMutableArray<NSString *> *pats = [NSMutableArray array];
                for (NSUInteger i = 1; i < lines.count; i++) {
                    NSString *p = lines[i];
                    if (p.length) [pats addObject:p];
                }
                gPatterns = pats;   // 允许空列表(用户把默认特征串也删了)
            }
        }
    }
    [gLock unlock];
}

BOOL dh_noise_enabled(void) {
    if (!gLock) return gEnabled;
    [gLock lock]; BOOL v = gEnabled; [gLock unlock];
    return v;
}

void dh_noise_set_enabled(BOOL on) {
    if (!gLock) gLock = [NSLock new];
    [gLock lock];
    gEnabled = on;
    dh_noise_save_locked();
    [gLock unlock];
}

NSArray<NSString *> *dh_noise_patterns(void) {
    if (!gLock) return @[];
    [gLock lock]; NSArray *r = [gPatterns copy]; [gLock unlock];
    return r;
}

BOOL dh_noise_add_pattern(NSString *pattern) {
    if (pattern.length == 0) return NO;
    if (!gLock) gLock = [NSLock new];
    [gLock lock];
    for (NSString *p in gPatterns) {
        if ([p caseInsensitiveCompare:pattern] == NSOrderedSame) { [gLock unlock]; return NO; }
    }
    [gPatterns addObject:pattern];
    dh_noise_save_locked();
    [gLock unlock];
    return YES;
}

BOOL dh_noise_remove_pattern(NSString *pattern) {
    if (!gLock) return NO;
    [gLock lock];
    NSUInteger idx = NSNotFound;
    for (NSUInteger i = 0; i < gPatterns.count; i++) {
        if ([gPatterns[i] caseInsensitiveCompare:pattern] == NSOrderedSame) { idx = i; break; }
    }
    if (idx == NSNotFound) { [gLock unlock]; return NO; }
    [gPatterns removeObjectAtIndex:idx];
    dh_noise_save_locked();
    [gLock unlock];
    return YES;
}

BOOL dh_noise_matches(NSString *text) {
    if (text.length == 0 || !gLock) return NO;
    [gLock lock];
    NSArray<NSString *> *pats = [gPatterns copy];
    [gLock unlock];
    if (pats.count == 0) return NO;
    NSString *lower = [text lowercaseString];
    for (NSString *p in pats) {
        if (p.length && [lower containsString:[p lowercaseString]]) return YES;
    }
    return NO;
}
