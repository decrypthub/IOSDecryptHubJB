# 真实 App 登录协议分析记录

本目录记录用 IOSDecryptHub 对真实 App 做的运行时分析。两份主文档：

- [哔哩哔哩-登录协议.md](哔哩哔哩-登录协议.md)
- [中国移动-登录加密.md](中国移动-登录加密.md)
- [WebKit-能力规划.md](WebKit-能力规划.md)

> 所有记录只写协议结构，不含真实密钥、手机号、设备标识或令牌。

## 一、结论速览

| | 哔哩哔哩 `tv.danmaku.bilianime` | 中国移动 `cn.10086.app` |
|---|---|---|
| 登录主机 | `passport.bilibili.com`（**运行时抓到 SNI**） | `client.app.coc.10086.cn`（HTTP 事件 + 包内接口码表） |
| 登录路径 | `/x/passport-login/oauth2/login`（二进制字符串表；运行时拼装） | `/biz-orange/LN/uamthreenetworklogin/login`（码表 `60028`） |
| 请求体 | appkey 方案 query string（MD5 签名） | `Base64(AES-128-CBC(JSON))`，**已实际解密复核** |
| 敏感字段 | 密码 = `base64(RSA-PKCS1(盐+密码))`；请求密钥 = `base64(RSA-PKCS1(盐+AESKey))`；指纹 = `hex(AES-128-CBC(设备JSON))` | 手机号 = `AES-128-ECB(固定密钥)`；`cellNum` = **128B RSA-1024 随机填充密文** |
| 签名 | `sign = MD5(待签名 query string)` | `x-sign = MD5(x-token + "_" + x-time + "_" + x-nonce + "_null")` ✅ 复核一致；`xs = MD5(url + "_" + JSON + "_Leadeon/SecurityOrganization")` ✅ |
| 加密原语可见性 | 全部可见（RSA/AES/MD5 均为 hook 到明文的原始调用） | 对称/摘要可见；RSA 为静态实现，**明文不可观测** |

## 二、证据等级标注

每份文档里的结论都标了来源，三种等级：

1. **实测**：IOSDecryptHub 运行时事件（含 key/iv/明文/密文/调用栈）或网络层 SNI/DNS/socket 事件；
2. **复核**：用抓到的数据在本地做字节级等式/解密验证（如 `openssl enc -d` 还原出明文 JSON）；
3. **推断**：由前两类排除后得到的唯一合理候选（文档中明确标注）。

## 三、分析过程中发现并修掉的工具缺陷

这一轮分析本身就是一次产品打磨，按版本记录：

| 版本 | 修复/新增 |
|---|---|
| 1.25.6 | **新增** Apple SecureTransport(`SSLWrite/SSLRead`)、BSD socket(`connect/getaddrinfo/send`)、Network.framework(`nw_connection_send`) 覆盖 + TLS ClientHello **SNI 解析**（此前这些请求完全隐形） |
| 1.25.6 | **新增** 越狱隐藏清单扩充（按实测风控检测项：Dopamine/TrollStore/FlyJB/`/jb/*`/frida/cycript 等）+ 纯 C 锚点预过滤（启动热路径提速） |
| 1.25.6 | **修复** xref 扫描 `calloc(48MB)` 无内存闸门 → 改 8MB 默认窗口 + `os_proc_available_memory` 闸门；重活统一串行队列；HTTP 服务移出 constructor（治启动看门狗 `0x8badf00d`） |
| 1.25.6 | **修复** `find_objc_methods` 枚举到 Swift 泛型类时 `abort()`（中国移动实测 100% 复现）→ SIGABRT 线程局部兜底 + 跳过该类 |
| 1.25.9 | **修复** ObjC 伪装 swizzle 按配置门控（此前无条件安装，被 App 的 `doSwizzlingHookCheck` 一眼看穿）；补旧版 Security RSA 符号 |
| 1.26.0 | **新增** `hook_method(describe_args:true)` —— 参数反引用（NSData→hex / NSString→文本 / 其它→description），从「只看到指针」到「看到内容」 |
| 1.26.1 | **新增** `get_capture_coverage` —— 一次调用回答「为什么抓不到」：逐层检查导入表，列出可用层与 blind_spots |
| 1.26.2 | **新增** 重活工具审计日志（开始/完成+耗时写入 diag，崩溃可归因）；**修复** 装包重置用户注入白名单（prefs 与 jb 配置按 mtime 双向同步） |
| 1.26.3 | **修复** `describe_args` 在 arm64e/Apple Silicon 上失效并可能段错误：isa 是 PAC 签名 + 低位标志，改为「多候选剥离 → 必须命中运行时类表」的双层校验，裸缓冲/出参指针(NSError**)一律跳过；**新增** import hook 的 C 字符串反引用（getaddrinfo 域名 / dlopen 路径） |
| 1.26.4 | **通用化网络补面**：BSD socket 全家族（`socket/accept/close/send/sendto/sendmsg/recv/recvfrom/recvmsg/read/write`）+ fd 生命周期跟踪；Network.framework 明文 `send/receive`；`NSURLSessionWebSocketTask` 发送/接收/心跳帧；所有新增 payload 限长 8KB，并排除 dylib 自身 HTTP 服务 fd，避免污染业务证据 |
| 1.27.0 | **新增 WebKit 宿主侧观测 P0**：`WKWebView` 导航与 `evaluateJavaScript`、`WKUserContentController` / `WKScriptMessage` bridge、`WKHTTPCookieStore` 与 `WKWebsiteDataStore`、`WKURLSchemeHandler`、`WKWebView.inspectable`；只走 ObjC swizzle，WebKit 晚加载时自动安装，TrollStore / Jailbreak 共用 |
| 1.27.1 | **新增 WebKit JS 网络探针 P1（默认关闭）**：`set_webkit_probe` 可开启 document-start JS 探针，记录 `fetch` / `XMLHttpRequest` / `WebSocket` / `sendBeacon` 的 URL、Header、请求/响应体（默认 8KB 截断）；支持域名 allow/deny 和敏感 Header 默认脱敏；仅对新创建的 WKWebView 生效 |
| 1.27.2 | **扩展 WebKit JS 探针 P1.1**：新增 `EventSource`、`console`、localStorage/sessionStorage 和 WebCrypto 元数据观测；相对 URL 统一解析为绝对 URL；simulator 场景覆盖 fetch/XHR/WebSocket/SSE/存储/WebCrypto |

## 四、已知结构性边界（不是缺陷，是模型限制）

两处「最后一公里」在**禁止 inline hook** 的项目铁律下不可达：

1. **中国移动 `cellNum` 的明文**：RSA 为自包含静态实现（自带大数运算 + RNG），不在任何导入表；已在文档中给出排除法与唯一合理候选 `AES_ECB(phone)`。
2. **哔哩哔哩登录 POST 的方法/头字段**：请求经其自研网络栈（裸 socket + 自带 TLS）发出，明文只存在于静态栈内部；host 已由运行时 SNI 实测确认。

要突破这两点，需要在 App 自己的加密/HTTP 调用层挂钩（若该层是 ObjC/Swift 则本工具已能覆盖，见 `hook_method(describe_args)`），或引入 inline hook —— 后者与项目架构铁律冲突。

## 五、复现方式

```bash
# 设备端（越狱 rootless）
/var/jb/usr/lib/IOSDecryptHub/decrypt_helper.dylib  # 引擎
# PC 端
idh connect <设备IP>:8088
idh call <target> get_capture_coverage     # 先看哪些层可抓
idh call <target> query_events --arguments '{"category":"net","limit":50}'
```
