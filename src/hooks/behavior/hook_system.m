// hook_system.m
// 系统: hook dlopen 记录运行时载入了哪些动态库(模块). 低频、安全.
// dh_in_hook: 记录用的 backtrace_symbols 可能内部 dlopen → 递归, 置标志期间放行.

#import <Foundation/Foundation.h>
#import "fishhook.h"
#import "log_store.h"
#import "dh_health.h"

static void *(*orig_dlopen)(const char *, int);
static void *hooked_dlopen(const char *path, int mode) {
    void *h = orig_dlopen(path, mode);
    if (!dh_in_hook && path && *path) {
        dh_in_hook = 1;
        DHLogEntry *e = [DHLogEntry new];
        e.category  = DHCategorySystem;
        e.algorithm = @"dlopen";
        e.operation = h ? @"loaded" : @"failed";
        e.detail    = [NSString stringWithUTF8String:path];
        e.timestamp = DHTimestampNow();
        e.callStack = DHCallStackFiltered();
        [[DHLogStore shared] append:e];
        dh_in_hook = 0;
    }
    return h;
}

void dh_install_system_hooks(void) {
    struct rebinding r[] = {
        {"dlopen", hooked_dlopen, (void **)&orig_dlopen},
    };
    rebind_symbols(r, sizeof(r)/sizeof(r[0]));
    for (size_t k = 0; k < sizeof(r)/sizeof(r[0]); k++)
        if (r[k].replaced && *(void **)r[k].replaced == NULL) dh_health_hook_fail(r[k].name);
}
