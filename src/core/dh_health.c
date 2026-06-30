// dh_health.c — 见 dh_health.h。纯 C 实现, stdatomic 计数 + 互斥保护原因字符串。

#include "dh_health.h"
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

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

// ============================================================
// 诊断日志(审查日志): 行环形缓冲, 收集所有内部事件供开发者复制溯源
// ============================================================
#define DIAG_LINES    400      // 保留最近 400 条
#define DIAG_LINE_LEN 240      // 单行上限
static char  g_diag[DIAG_LINES][DIAG_LINE_LEN];
static int   g_diag_head  = 0;   // 下一个写入行
static int   g_diag_count = 0;   // 已写入行数 (饱和于 DIAG_LINES)
static char  g_diag_out[DIAG_LINES * DIAG_LINE_LEN + 64];   // dump 拼接缓冲
// g_lock 复用: 与 hook 名/summary 共用一把锁即可, 诊断写入很轻。

void dh_diag_append(const char *level, const char *msg) {
    char ts[16];
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    snprintf(ts, sizeof(ts), "%02d:%02d:%02d", tmv.tm_hour, tmv.tm_min, tmv.tm_sec);

    pthread_mutex_lock(&g_lock);
    snprintf(g_diag[g_diag_head], DIAG_LINE_LEN, "[%s] %s: %s",
             ts, level ? level : "INFO", msg ? msg : "");
    g_diag_head = (g_diag_head + 1) % DIAG_LINES;
    if (g_diag_count < DIAG_LINES) g_diag_count++;
    pthread_mutex_unlock(&g_lock);
}

const char *dh_diag_dump(void) {
    pthread_mutex_lock(&g_lock);
    g_diag_out[0] = '\0';
    size_t pos = 0;
    int start = (g_diag_count < DIAG_LINES) ? 0 : g_diag_head;   // 最旧行
    for (int i = 0; i < g_diag_count; i++) {
        int idx = (start + i) % DIAG_LINES;
        size_t len = strlen(g_diag[idx]);
        if (pos + len + 2 >= sizeof(g_diag_out)) break;
        memcpy(g_diag_out + pos, g_diag[idx], len);
        pos += len;
        g_diag_out[pos++] = '\n';
    }
    g_diag_out[pos] = '\0';
    pthread_mutex_unlock(&g_lock);
    return g_diag_out;
}

const char *dh_health_hook_unhooked(void) {
    return g_hook_names;   // 只读; 拼接发生在 hook_fail 的锁内, 读取时是稳定字符串
}

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
    if (!dup) {
        char m[160];
        snprintf(m, sizeof(m), "hook 未挂上(若该 App 未调用此 API 属正常): %s", sym ? sym : "(?)");
        fprintf(stderr, "[IOSDecryptHub] %s\n", m);
        dh_diag_append("INFO", m);   // 仅入诊断日志, 不上顶部红字横幅
    }
}

void dh_health_persist_fail(int err) {
    atomic_store(&g_persist_failed, 1);
    atomic_store(&g_persist_errno, err);
    char m[64]; snprintf(m, sizeof(m), "日志落盘失败 errno=%d", err);
    fprintf(stderr, "[IOSDecryptHub/ERR] %s\n", m);
    dh_diag_append("ERR", m);
}

void dh_health_http_fail(const char *reason) {
    atomic_store(&g_http_failed, 1);
    pthread_mutex_lock(&g_lock);
    if (reason) strlcpy(g_http_reason, reason, sizeof(g_http_reason));
    pthread_mutex_unlock(&g_lock);
    char m[160]; snprintf(m, sizeof(m), "HTTP 服务失败: %s", reason ? reason : "");
    fprintf(stderr, "[IOSDecryptHub/ERR] %s\n", m);
    dh_diag_append("ERR", m);
}

void dh_health_http_ok(void) {
    atomic_store(&g_http_failed, 0);
    dh_diag_append("INFO", "HTTP 服务启动成功");
}

void dh_health_note_localonly(void) {
    atomic_store(&g_local_only, 1);
    fprintf(stderr, "[IOSDecryptHub] 未找到局域网 IP, 仅本地可访问\n");
    dh_diag_append("INFO", "未找到局域网 IP, 仅本地可访问");
}

unsigned dh_health_hook_fail_count(void) { return atomic_load(&g_hook_fails); }
int      dh_health_persist_failed(void)  { return atomic_load(&g_persist_failed); }
int      dh_health_http_failed(void)     { return atomic_load(&g_http_failed); }
int      dh_health_local_only(void)      { return atomic_load(&g_local_only); }

const char *dh_health_summary(void) {
    pthread_mutex_lock(&g_lock);
    g_summary[0] = '\0';
    // 注意: hook 未挂上不再计入顶部红字横幅(对真实 App 多为常态, 见 dh_diag_*),
    // 只保留真正的运行时失效: 服务失败 / 落盘失败。
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
