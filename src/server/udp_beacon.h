// udp_beacon.h - UDP 广播信标，替代 Bonjour（注入场景无 plist/entitlement 条件）。

#ifndef DECRYPT_HELPER_UDP_BEACON_H
#define DECRYPT_HELPER_UDP_BEACON_H

#include <stdint.h>

// 启动 UDP 广播信标，每 2 秒向 255.255.255.255:DH_BEACON_PORT 发送 JSON 包。
// port 为 HTTP 服务实际监听端口。
void dh_beacon_start(uint16_t port);

// 停止广播（一般不需要调用，进程退出自动停）。
void dh_beacon_stop(void);

#define DH_BEACON_PORT 8089

#endif
