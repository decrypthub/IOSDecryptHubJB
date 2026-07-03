// dh_spoof.m — 见 dh_spoof.h。JSON 持久化 + NSLock, 热路径总开关 volatile 早退。

#import "dh_spoof.h"
#import "dh_health.h"

static NSLock *gLock = nil;
static NSString *gConfPath = nil;

// 热路径总开关(无锁 volatile 快读)。清单/字符串值改动都在锁内, 但读开关不必进锁。
static volatile BOOL gJbOn      = YES;
static volatile BOOL gAntiOn    = YES;
static volatile BOOL gDeviceOn  = NO;

static NSMutableArray<NSString *> *gJbPaths   = nil;
static NSMutableArray<NSString *> *gJbSchemes = nil;
static NSMutableDictionary<NSString *, NSString *> *gDevice = nil;   // key→值

static NSArray<NSString *> *kDeviceKeys(void) {
    return @[@"hw_machine", @"hw_model", @"os_version", @"device_name", @"idfv", @"idfa"];
}

static void spoof_set_defaults_locked(void) {
    gJbOn = YES; gAntiOn = YES; gDeviceOn = NO;
    gJbPaths = [@[
        @"/Applications/Cydia.app", @"/Applications/Sileo.app", @"/Applications/Zebra.app",
        @"/Applications/Filza.app", @"/Applications/WinterBoard.app", @"/Applications/SBSettings.app",
        @"/Library/MobileSubstrate", @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/Library/MobileSubstrate/DynamicLibraries",
        @"/usr/sbin/sshd", @"/usr/bin/ssh", @"/usr/libexec/cydia", @"/usr/libexec/sftp-server",
        @"/usr/lib/libjailbreak.dylib", @"/bin/bash", @"/bin/sh",
        @"/etc/apt", @"/private/var/lib/apt", @"/private/var/lib/cydia", @"/private/var/stash",
        @"/private/var/tmp/cydia.log", @"/var/jb", @"/var/binpack",
    ] mutableCopy];
    gJbSchemes = [@[@"cydia", @"sileo", @"zbra", @"filza", @"undecimus", @"activator", @"apt-repo"] mutableCopy];
    gDevice = [NSMutableDictionary dictionary];
    for (NSString *k in kDeviceKeys()) gDevice[k] = @"";
}

// ---- 持久化 ----
static void spoof_save_locked(void) {
    if (!gConfPath) return;
    NSDictionary *root = @{
        @"jb":         @{ @"on": @(gJbOn), @"paths": [gJbPaths copy], @"schemes": [gJbSchemes copy] },
        @"anti_debug": @{ @"on": @(gAntiOn) },
        @"device":     [@{ @"on": @(gDeviceOn) } mutableCopy],
    };
    NSMutableDictionary *dev = [root[@"device"] mutableCopy];
    for (NSString *k in kDeviceKeys()) dev[k] = gDevice[k] ?: @"";
    NSMutableDictionary *out = [root mutableCopy];
    out[@"device"] = dev;

    NSData *data = [NSJSONSerialization dataWithJSONObject:out
                                                  options:NSJSONWritingPrettyPrinted error:nil];
    if (!data) return;
    int saved = dh_in_hook; dh_in_hook = 1;
    [data writeToFile:gConfPath atomically:YES];
    dh_in_hook = saved;
}

static void spoof_apply_json_locked(NSDictionary *root) {
    if (![root isKindOfClass:[NSDictionary class]]) return;
    NSDictionary *jb = root[@"jb"];
    if ([jb isKindOfClass:[NSDictionary class]]) {
        if (jb[@"on"]) gJbOn = [jb[@"on"] boolValue];
        if ([jb[@"paths"] isKindOfClass:[NSArray class]])   gJbPaths   = [jb[@"paths"] mutableCopy];
        if ([jb[@"schemes"] isKindOfClass:[NSArray class]]) gJbSchemes = [jb[@"schemes"] mutableCopy];
    }
    NSDictionary *anti = root[@"anti_debug"];
    if ([anti isKindOfClass:[NSDictionary class]] && anti[@"on"]) gAntiOn = [anti[@"on"] boolValue];
    NSDictionary *dev = root[@"device"];
    if ([dev isKindOfClass:[NSDictionary class]]) {
        if (dev[@"on"]) gDeviceOn = [dev[@"on"] boolValue];
        for (NSString *k in kDeviceKeys()) {
            id v = dev[k];
            if ([v isKindOfClass:[NSString class]]) gDevice[k] = v;
        }
    }
}

void dh_spoof_load(NSString *confPath) {
    if (!gLock) gLock = [NSLock new];
    [gLock lock];
    spoof_set_defaults_locked();
    gConfPath = [confPath copy];
    if (gConfPath) {
        int saved = dh_in_hook; dh_in_hook = 1;
        NSData *data = [NSData dataWithContentsOfFile:gConfPath];
        dh_in_hook = saved;
        if (data.length) {
            NSDictionary *root = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            spoof_apply_json_locked(root);
        }
    }
    [gLock unlock];
}

// ---- 越狱隐藏 ----
BOOL dh_spoof_jb_on(void) { return gJbOn; }
void dh_spoof_jb_set_on(BOOL on) {
    if (!gLock) gLock = [NSLock new];
    [gLock lock]; gJbOn = on; spoof_save_locked(); [gLock unlock];
}

BOOL dh_spoof_jb_should_hide_path(const char *path) {
    if (!gJbOn || !path || !*path || !gLock) return NO;
    NSString *p = [NSString stringWithUTF8String:path];
    if (!p) return NO;
    [gLock lock];
    BOOL hit = NO;
    for (NSString *e in gJbPaths) {
        if (e.length == 0) continue;
        // 精确匹配, 或探测路径落在配置目录下(前缀 + '/'), 或配置项作为子串出现。
        if ([p isEqualToString:e] ||
            [p hasPrefix:[e hasSuffix:@"/"] ? e : [e stringByAppendingString:@"/"]] ||
            [p rangeOfString:e].location != NSNotFound) { hit = YES; break; }
    }
    [gLock unlock];
    return hit;
}

BOOL dh_spoof_jb_should_hide_scheme(const char *scheme) {
    if (!gJbOn || !scheme || !*scheme || !gLock) return NO;
    NSString *s = [NSString stringWithUTF8String:scheme];
    if (!s) return NO;
    s = [s lowercaseString];
    [gLock lock];
    BOOL hit = NO;
    for (NSString *e in gJbSchemes) {
        if (e.length && [s isEqualToString:[e lowercaseString]]) { hit = YES; break; }
    }
    [gLock unlock];
    return hit;
}

NSArray<NSString *> *dh_spoof_jb_paths(void) {
    if (!gLock) return @[];
    [gLock lock]; NSArray *r = [gJbPaths copy]; [gLock unlock]; return r;
}
NSArray<NSString *> *dh_spoof_jb_schemes(void) {
    if (!gLock) return @[];
    [gLock lock]; NSArray *r = [gJbSchemes copy]; [gLock unlock]; return r;
}

static BOOL spoof_list_add(NSMutableArray *arr, NSString *v) {
    if (v.length == 0) return NO;
    if (!gLock) gLock = [NSLock new];
    [gLock lock];
    for (NSString *e in arr) if ([e caseInsensitiveCompare:v] == NSOrderedSame) { [gLock unlock]; return NO; }
    [arr addObject:v];
    spoof_save_locked();
    [gLock unlock];
    return YES;
}
static BOOL spoof_list_remove(NSMutableArray *arr, NSString *v) {
    if (v.length == 0 || !gLock) return NO;
    [gLock lock];
    NSUInteger idx = NSNotFound;
    for (NSUInteger i = 0; i < arr.count; i++)
        if ([arr[i] caseInsensitiveCompare:v] == NSOrderedSame) { idx = i; break; }
    if (idx == NSNotFound) { [gLock unlock]; return NO; }
    [arr removeObjectAtIndex:idx];
    spoof_save_locked();
    [gLock unlock];
    return YES;
}
BOOL dh_spoof_jb_add_path(NSString *p)    { return spoof_list_add(gJbPaths, p); }
BOOL dh_spoof_jb_remove_path(NSString *p) { return spoof_list_remove(gJbPaths, p); }
BOOL dh_spoof_jb_add_scheme(NSString *s)    { return spoof_list_add(gJbSchemes, s); }
BOOL dh_spoof_jb_remove_scheme(NSString *s) { return spoof_list_remove(gJbSchemes, s); }

// ---- 反调试 ----
BOOL dh_spoof_anti_debug_on(void) { return gAntiOn; }
void dh_spoof_anti_debug_set_on(BOOL on) {
    if (!gLock) gLock = [NSLock new];
    [gLock lock]; gAntiOn = on; spoof_save_locked(); [gLock unlock];
}

// ---- 改机 ----
BOOL dh_spoof_device_on(void) { return gDeviceOn; }
void dh_spoof_device_set_on(BOOL on) {
    if (!gLock) gLock = [NSLock new];
    [gLock lock]; gDeviceOn = on; spoof_save_locked(); [gLock unlock];
}

NSString *dh_spoof_device_value(NSString *key) {
    if (!gDeviceOn || key.length == 0 || !gLock) return nil;
    [gLock lock];
    NSString *v = gDevice[key];
    [gLock unlock];
    return (v.length > 0) ? v : nil;   // 空串视为「不伪造此项」
}

void dh_spoof_device_set_value(NSString *key, NSString *val) {
    if (key.length == 0 || !gLock) return;
    if (![kDeviceKeys() containsObject:key]) return;
    [gLock lock]; gDevice[key] = val ?: @""; spoof_save_locked(); [gLock unlock];
}

NSDictionary *dh_spoof_snapshot(void) {
    if (!gLock) gLock = [NSLock new];
    [gLock lock];
    NSDictionary *snap = @{
        @"jb":         @{ @"on": @(gJbOn), @"paths": [gJbPaths copy] ?: @[], @"schemes": [gJbSchemes copy] ?: @[] },
        @"anti_debug": @{ @"on": @(gAntiOn) },
        @"device":     ({
            NSMutableDictionary *d = [@{ @"on": @(gDeviceOn) } mutableCopy];
            for (NSString *k in kDeviceKeys()) d[k] = gDevice[k] ?: @"";
            d;
        }),
    };
    [gLock unlock];
    return snap;
}
