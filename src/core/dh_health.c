// dh_health.c — 见 dh_health.h。纯 C 实现, stdatomic 计数 + 互斥保护原因字符串。

#include "dh_health.h"
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

static atomic_uint g_hook_fails     = 0;
static atomic_int  g_persist_failed = 0;
static atomic_int  g_persist_errno  = 0;
static atomic_int  g_http_failed    = 0;
static atomic_int  g_local_only     = 0;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_hook_names[256] = {0};   // 拼接没挂上的符号名
static char g_http_reason[128] = {0};
static char g_summary[512]     = {0};

__thread int dh_in_hook = 0;   // 见 dh_health.h: hook 记录路径的递归保护标志

void dh_health_hook_fail(const char *sym) {
    // 去重: vm_protect 失败可能在多个 image / 多次 add-image 回调里对同一符号重复触发,
    // 计数应反映「不同失败符号数」而非触发次数。
    pthread_mutex_lock(&g_lock);
    int dup = (sym && sym[0] && strstr(g_hook_names, sym)) ? 1 : 0;
    if (!dup) {
        atomic_fetch_add(&g_hook_fails, 1);
        if (sym && sym[0]) {
            size_t len = strlen(g_hook_names);
            if (len + strlen(sym) + 2 < sizeof(g_hook_names)) {
                if (len) strlcat(g_hook_names, ",", sizeof(g_hook_names));
                strlcat(g_hook_names, sym, sizeof(g_hook_names));
            }
        }
    }
    pthread_mutex_unlock(&g_lock);
    if (!dup) fprintf(stderr, "[IOSDecryptHub/ERR] hook 未挂上: %s\n", sym ? sym : "(?)");
}

void dh_health_persist_fail(int err) {
    atomic_store(&g_persist_failed, 1);
    atomic_store(&g_persist_errno, err);
    fprintf(stderr, "[IOSDecryptHub/ERR] 日志落盘失败 errno=%d\n", err);
}

void dh_health_http_fail(const char *reason) {
    atomic_store(&g_http_failed, 1);
    pthread_mutex_lock(&g_lock);
    if (reason) strlcpy(g_http_reason, reason, sizeof(g_http_reason));
    pthread_mutex_unlock(&g_lock);
    fprintf(stderr, "[IOSDecryptHub/ERR] HTTP 服务失败: %s\n", reason ? reason : "");
}

void dh_health_http_ok(void) {
    atomic_store(&g_http_failed, 0);
}

void dh_health_note_localonly(void) {
    atomic_store(&g_local_only, 1);
    fprintf(stderr, "[IOSDecryptHub/ERR] 未找到局域网 IP, 仅本地可访问\n");
}

unsigned dh_health_hook_fail_count(void) { return atomic_load(&g_hook_fails); }
int      dh_health_persist_failed(void)  { return atomic_load(&g_persist_failed); }
int      dh_health_http_failed(void)     { return atomic_load(&g_http_failed); }
int      dh_health_local_only(void)      { return atomic_load(&g_local_only); }

const char *dh_health_summary(void) {
    pthread_mutex_lock(&g_lock);
    g_summary[0] = '\0';
    unsigned hf = atomic_load(&g_hook_fails);
    if (hf) {
        char tmp[320];
        snprintf(tmp, sizeof(tmp), "%u个hook未挂上(%s)", hf, g_hook_names);
        strlcat(g_summary, tmp, sizeof(g_summary));
    }
    if (atomic_load(&g_http_failed)) {
        if (g_summary[0]) strlcat(g_summary, " · ", sizeof(g_summary));
        strlcat(g_summary, "服务失败:", sizeof(g_summary));
        strlcat(g_summary, g_http_reason, sizeof(g_summary));
    }
    if (atomic_load(&g_persist_failed)) {
        if (g_summary[0]) strlcat(g_summary, " · ", sizeof(g_summary));
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "落盘失败(errno=%d)", atomic_load(&g_persist_errno));
        strlcat(g_summary, tmp, sizeof(g_summary));
    }
    pthread_mutex_unlock(&g_lock);
    return g_summary;
}
