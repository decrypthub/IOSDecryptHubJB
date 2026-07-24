// bonjour_publisher.h - 发布现有 HTTP/MCP 端口供 PC 端 idh 自动发现。

#ifndef DECRYPT_HELPER_BONJOUR_PUBLISHER_H
#define DECRYPT_HELPER_BONJOUR_PUBLISHER_H

#include <stdint.h>

// 在 local. 域发布 _idh-mcp._tcp.；port 为 HTTP 服务已经绑定的实际端口。
void dh_bonjour_start(uint16_t port);

#endif

