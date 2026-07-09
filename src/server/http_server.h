// http_server.h - IOSDecryptHub
// 极简本地 HTTP 服务, 用 BSD socket, 暴露 hook 日志给浏览器看 / 筛 / 下载.
//
// 端点:
//   GET  /                   嵌入式单页前端
//   GET  /api/stats          {total, paused, byCategory:[...], port, ip, version}
//   GET  /api/logs?cat=N&q=KW&since=SEQ&limit=N
//                            日志摘要数组 (不含 key/iv/in/out 原文, 只给元信息)
//   GET  /api/logs/:seq      单条详情 (含 hex / hexdump / 调用栈)
//   POST /api/clear          清空
//   POST /api/pause?paused=1 暂停 / 恢复
//   GET  /download           下载 decrypt_helper.log

#ifndef DH_HTTP_SERVER_H
#define DH_HTTP_SERVER_H
#import <Foundation/Foundation.h>

// 启动服务, 自动选 8088..8108 第一个空闲端口
void      dh_http_start(void);
// 返回成功绑定的端口, 0 表示未启动
uint16_t  dh_http_port(void);
// 形如 "http://192.168.x.x:8088/?token=123456" (自带访问令牌)
NSString *dh_http_url(void);
// 6 位数字访问令牌 (每 App 一个, 持久化到沙箱)
NSString *dh_http_token(void);

#endif
