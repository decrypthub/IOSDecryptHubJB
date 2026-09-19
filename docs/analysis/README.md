# 真实 App 登录协议分析记录

本目录记录用 IOSDecryptHub 对真实 App 做的运行时分析。主文档：

- [哔哩哔哩-登录协议.md](哔哩哔哩-登录协议.md)
- [中国移动-登录加密.md](中国移动-登录加密.md)
- [山东航空-登录加密.md](山东航空-登录加密.md)
- [逆向技巧-静态链接加密库.md](逆向技巧-静态链接加密库.md)
- [WebKit-能力规划.md](WebKit-能力规划.md)

> 所有记录只写协议结构，不含真实密钥、手机号、设备标识或令牌。

## 一、结论速览

| | 哔哩哔哩 `tv.danmaku.bilianime` | 中国移动 `cn.10086.app` | 山东航空 `cn.com.shandongair.m` |
|---|---|---|---|
| 登录主机 | `passport.bilibili.com`（**运行时抓到 SNI**） | `client.app.coc.10086.cn`（HTTP 事件 + 包内接口码表） | `scapp.sda.cn`（HTTP 事件） |
| 登录路径 | `/x/passport-login/oauth2/login`（二进制字符串表；运行时拼装） | `/biz-orange/LN/uamthreenetworklogin/login`（码表 `60028`） | `/api/api-bff-service/bff_service/customer/login/login4UserNamePassword` |
| 请求体 | appkey 方案 query string（MD5 签名） | `Base64(AES-128-CBC(JSON))`，**已实际解密复核** | `{"param": Base64(AES-128-ECB(JSON))}`，**已实际解密 + 回加密复核** |
| 敏感字段 | 密码 = `base64(RSA-PKCS1(盐+密码))`；请求密钥 = `base64(RSA-PKCS1(盐+AESKey))`；指纹 = `hex(AES-128-CBC(设备JSON))` | 手机号 = `AES-128-ECB(固定密钥)`；`cellNum` = **128B RSA-1024 随机填充密文** | `password` 明文进业务 JSON（外层 AES 套壳）；key 为二进制内硬编码 16 字节常量，无 RSA |
| 签名 | `sign = MD5(待签名 query string)` | `x-sign = MD5(x-token + "_" + x-time + "_" + x-nonce + "_null")` ✅ 复核一致；`xs = MD5(url + "_" + JSON + "_Leadeon/SecurityOrganization")` ✅ | 本次实测请求头无 sign |
| 加密原语可见性 | 全部可见（RSA/AES/MD5 均为 hook 到明文的原始调用） | 对称/摘要可见；RSA 为静态实现，**明文不可观测** | 静态 CryptoSwift；1.27.3 用 `mlock + capture_memory` 在命中瞬间抓到 key，**已闭环** |

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
| 1.27.3 | **新增 `capture_memory` 参数内存快照**：`hook_import` / `hook_method` 可在命中瞬间按寄存器参数抓一段内存（`{ptr_arg, len_arg, max_bytes}`，上限 8KB）写入事件 `input`。解决「缓冲区在函数返回后被释放/复用，事后回读只剩零」的结构性盲区（如 CryptoSwift AES 的 key buffer 经 `mlock` 锁定后立即释放）；仍只改 GOT/IMP 指针，不引入 inline hook 或可执行内存 |
| 1.27.3 | **修复 TrollStore/TrollFools 注入下的 WebKit 递归崩溃**：宿主 App 若先 swizzle 了 `-[WKWebView loadRequest:]` 等系统方法（bilibili 实测），我们再把该 IMP 当 original 叠加，会形成「我们 → 宿主实现 → `objc_msgSend(_cmd)` → 我们」的无限递归，主线程栈溢出（SIGSEGV KERN_PROTECTION_FAILURE）。现在系统类上的方法若已被非系统镜像占用则跳过该 hook，把行为完整交还宿主；App 自定义类（scheme handler / delegate）不受影响 |
| 1.27.4 | **事件管线稳定性加固（保守版）**：日志落盘改批量写（64KB / 150ms 上限），队列加背压（soft 1024 只丢系统/文件/其它低价值事件，hard 4096 才丢全部；加解密/网络/Keychain 优先保留并计数），时间戳改用 `localtime_r`；`/api/stats` 与 `get_stats` 暴露 `pending/dropped/rss`。调用栈符号化优化因新 dyld 下 image 归属不可靠而暂缓，仍用系统 `callStackSymbols` 保证符号正确。真机 bilibili 20 分钟导航 soak：pending/dropped 全程 0，RSS 稳定，无新崩溃 |
| 1.27.4 | **新增事件持久化回载**：非噪点事件追加到 JSONL journal（8MB/段 ×2），高价值事件逐条落盘、低价值事件 150ms 批量；启动时在日志队列异步回载最近尾部（512KB、最多 1000 条），App/插件重开后面板不再空白；进入后台/退出前 flush；clearAll/clearCategory 带持久化清除标记。完整历史仍在 `decrypt_helper.log` / journal 各段并可下载。真机 3 轮 `kill -9` 重启校验同 seq 内容一致；20 分钟 soak 无数据丢失、无崩溃 |
| 1.27.4 | **修复 WebKit 反递归守卫漏网**：宿主自定义 WKWebView 子类（bilibili `BFCWKWebViewV2`）覆写/二次 swizzle 了 `loadRequest:` 等系统 API 时，仅按类镜像判断会漏掉；现改为 WebKit API 按 selector 强制要求系统 IMP，实测命中 20 条 skip 日志且递归不再发生。同时修正模拟器系统路径识别（`RuntimeRoot/System/Library/...`），模拟器 WebKit 用例 37/37 恢复 |

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

## 六、通用逆向技巧

- [逆向技巧-静态链接加密库.md](逆向技巧-静态链接加密库.md)：标准 `sym` / `asym` / `digest` hook 全空、
  网络层却有密文时，如何用 `list_imports` + `hook_import(capture_memory)` 抓静态链接加密库的 key，
  以及「解密 + 回加密」闭环验证和仍然抓不到时的边界。
