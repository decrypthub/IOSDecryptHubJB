// dh_capability.c — 见 dh_capability.h

#include "dh_capability.h"
#include <string.h>
#include <sys/stat.h>

// 变体在编译期决定; Makefile 未注入时按开发者 dylib 处理。
#ifndef DH_VARIANT
#define DH_VARIANT 0
#endif

dh_variant dh_variant_current(void) {
    int v = DH_VARIANT;
    if (v < 0 || v >= DH_VARIANT_COUNT) return DH_VARIANT_DEV;
    return (dh_variant)v;
}

const char *dh_variant_id(dh_variant v) {
    switch (v) {
        case DH_VARIANT_DEV:        return "dev";
        case DH_VARIANT_TROLLSTORE: return "trollstore";
        case DH_VARIANT_ROOTLESS:   return "rootless";
        case DH_VARIANT_ROOTFUL:    return "rootful";
        case DH_VARIANT_ROOTHIDE:   return "roothide";
        default:                    return "dev";
    }
}

const char *dh_variant_label(dh_variant v) {
    switch (v) {
        case DH_VARIANT_DEV:        return "开发者 dylib (insert_dylib / DYLD_INSERT_LIBRARIES)";
        case DH_VARIANT_TROLLSTORE: return "巨魔 (TrollStore) 持久化";
        case DH_VARIANT_ROOTLESS:   return "越狱 rootless (/var/jb)";
        case DH_VARIANT_ROOTFUL:    return "越狱 rootful (/)";
        case DH_VARIANT_ROOTHIDE:   return "roothide (动态 jbroot)";
        default:                    return "未知变体";
    }
}

const char *dh_cpu_arch(void) {
#if defined(__arm64e__)
    return "arm64e";
#elif defined(__arm64__) || defined(__aarch64__)
    return "arm64";
#elif defined(__arm__)
    return "arm";
#elif defined(__x86_64__)
    return "x86_64";
#else
    return "unknown";
#endif
}

static int dh_path_exists(const char *p) {
    struct stat st;
    return p && stat(p, &st) == 0;
}

// 越狱根路径探测: 一次性缓存。只读探测, 不落任何标记。
const char *dh_jbroot(void) {
    static char root[1024];
    static int done = 0;
    if (done) return root;
    done = 1;
    root[0] = '\0';
    // rootless 固定挂载点
    if (dh_path_exists("/var/jb")) { strncpy(root, "/var/jb", sizeof(root) - 1); return root; }
    // rootful 标记 (Cydia/APT/常见越狱残留)
    if (dh_path_exists("/private/var/lib/apt") ||
        dh_path_exists("/Applications/Cydia.app") ||
        dh_path_exists("/var/lib/undecimus")) {
        strncpy(root, "/", sizeof(root) - 1);
        return root;
    }
    // roothide 使用随机化 jbroot, 静态探测不到; 由变体标记兜底(见 dh_is_jailbroken)。
    return root;
}

int dh_is_jailbroken(void) {
    dh_variant v = dh_variant_current();
    if (v == DH_VARIANT_ROOTLESS || v == DH_VARIANT_ROOTFUL || v == DH_VARIANT_ROOTHIDE)
        return 1;   // 越狱变体: 编译期即确定
    // 开发者/巨魔变体也可能装在越狱机上, 用只读路径探测兜底
    return dh_jbroot()[0] != '\0';
}

uint32_t dh_capability_bits(void) {
    // 全平台都具备: 改导入符号表 + ObjC swizzle + 脱壳
    uint32_t bits = DH_CAPBIT_HOOK_IMPORT | DH_CAPBIT_HOOK_METHOD | DH_CAPBIT_UNPACK;
    // inline hook: 仅越狱变体 + 编译期开启 inline 引擎(二期落地前恒关)
#if defined(DH_ENABLE_INLINE_HOOK)
    if (dh_is_jailbroken()) bits |= DH_CAPBIT_HOOK_INLINE;
#endif
    // override(改写参数/返回值)二期实现, 一期恒关。
    return bits;
}
