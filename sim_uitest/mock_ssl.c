// sim_uitest/mock_ssl.c
// 最小 mock: 仅为给测试 App 提供可被 fishhook 重绑定的 SSL_write/SSL_read 跨 image 导入符号
// (真实 App 自带 BoringSSL/OpenSSL 时同理 —— fishhook 只能 hook 经符号表的跨 image 导入)。
// 不是真 TLS, 不做任何加密, 只回显长度 / 返回一段固定明文.

#include <string.h>

int SSL_write(void *ssl, const void *buf, int num) {
    (void)ssl; (void)buf;
    return num;   // 模拟"已发送 num 字节明文"
}

int SSL_read(void *ssl, void *buf, int num) {
    (void)ssl;
    static const char *resp =
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        "{\"user\":\"alice\",\"token\":\"sk-secret-abc123\",\"role\":\"admin\"}";
    int n = (int)strlen(resp);
    if (n > num) n = num;
    if (buf && n > 0) memcpy(buf, resp, n);
    return n;     // 模拟"收到 n 字节明文响应"
}
