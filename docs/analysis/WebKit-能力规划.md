# WebKit 能力扩展规划

> 目标：把 IDH 的观测面从原生网络栈扩展到 WKWebView，同时保持 fishhook + ObjC swizzle
> 的边界，不把 WebKit 分析做成某个 App 的地址/类名特判。
>
> 当前状态：P0 已在 `1.27.0` 实现，P1 已在 `1.27.1` 实现；两者均通过 iOS Simulator
> 31/31 场景验证。P2 仍为规划。

## 一、先分清三个进程边界

WKWebView 不是一个单纯运行在宿主 App 进程里的控件：

| 位置 | 能看到什么 | 宿主 dylib 能不能直接 hook |
|---|---|---|
| 宿主 App 进程 | `WKWebView`、`WKWebViewConfiguration`、`WKUserContentController`、`WKNavigationDelegate`、cookie API 的 Objective-C 调用 | 可以，ObjC swizzle |
| `com.apple.WebKit.WebContent` | DOM、JavaScriptCore、页面加载、Web 资源请求的 WebKit 内部对象 | 默认不可以，独立进程 |
| `com.apple.WebKit.Networking` | 实际 HTTP/HTTPS 网络请求、缓存、cookie 存储 | 默认不可以，独立进程 |

因此“WebKit 抓包”至少有三条不同路线，不能混成一个开关。

## 二、能力分层

### A. 宿主 App 侧 WKWebView 观测（P0，TrollStore / 越狱通用）

这一层只 swizzle 公开或不公开的 Objective-C 入口，不进入 WebContent，风险最低：

- 导航：`loadRequest:`、`loadHTMLString:baseURL:`、`loadFileURL:allowingReadAccessToURL:`、
  `loadData:MIMEType:characterEncodingName:baseURL:`。
- 脚本：`evaluateJavaScript:completionHandler:`、
  `callAsyncJavaScript:arguments:inFrame:inContentWorld:completionHandler:`。
- JS bridge：`WKUserContentController addScriptMessageHandler:name:`、
  `addUserScript:`，以及对 `userContentController:didReceiveScriptMessage:` 的具体实现类做
  record-only swizzle。
- Cookie / storage：`WKHTTPCookieStore` 的 `getAllCookies:`、`setCookie:completionHandler:`、
  `deleteCookie:completionHandler:`，以及 `WKWebsiteDataStore` 的数据记录查询/删除。
- 自定义协议：`WKURLSchemeHandler startURLSchemeTask:` / `stopURLSchemeTask:`。
- 配置与安全状态：`WKWebView.inspectable`、`limitsNavigationsToAppBoundDomains`、
  JavaScript 开关、持久化/临时 `WKWebsiteDataStore`、自定义 `WKURLSchemeHandler` 注册。

交付价值：能回答“这个 App 加载了哪些页面、注入了哪些 JS、JS 调了哪些 native 消息、
用了哪些 cookie/存储、有没有开启 inspectable”，但不承诺看到 WebKit 内部的完整网络报文。

### B. 可选 JavaScript 网络探针（P1，宿主 App 侧，主动注入，已实现）

在 `documentStart` 注入一个 `WKUserScript`，包装页面可见的网络与存储 API：

- `fetch`、`XMLHttpRequest`、`EventSource`、`WebSocket`、`navigator.sendBeacon`
- `localStorage`、`sessionStorage`
- `crypto.subtle`、`console`

优点：

- 直接在 JS 层看到 HTTPS 的明文 URL、Header、Body 和 WebSocket 帧，不依赖 WebContent 注入。
- 对所有使用标准 Web API 的页面通用，不依赖域名或业务 SDK。
- 观测结果通过已有的 `WKScriptMessageHandler` 通道回传，不额外开网络端口。

约束：

- 这是主动改写页面环境，必须显式开启，不能默认注入。
- 需要域白名单/黑名单、请求体大小上限、Cookie/Authorization 脱敏策略。
- 页面可能检测到 `fetch`/`XMLHttpRequest` 被包装，因此不能把它宣称为透明观测。

实现开关：MCP `get_webkit_probe` / `set_webkit_probe`。默认关闭；`allow` / `deny`
按 hostname 或子域名匹配；`redact=true` 时 Cookie、Authorization、token/sign 一类 Header
值替换为 `<redacted>`。探针只注入到新建的 `WKWebView`，修改配置后需要重新加载页面或重建
WebView。

### C. Web Inspector / WebContent / Networking 进程（P2，高保真 / 高复杂度）

两条实现路线：

1. **Web Inspector 协议桥**
   - iOS 16.4+ 可通过 `WKWebView.inspectable` 暴露 Web Inspector。
   - 由 `idh` 连接 WebKit Inspector 服务，实现 Network / DOM / Console / Page 域。
   - 可以拿到请求/响应正文、时序、console 和 JS 执行信息，版本协议复杂度较高。
2. **越狱专用 WebKit 进程注入**
   - 把 IDH 核心能力扩展到 `com.apple.WebKit.WebContent` 和
     `com.apple.WebKit.Networking`。
   - 在 Networking 进程里覆盖 CFNetwork / NSURLSession / BSD socket / 可 hook 的导出符号。
   - 能覆盖非 JS 发起的资源加载，但只适用于越狱路线，且需要单独的进程白名单和稳定性验证。

不建议把 C 伪装成 TrollStore 能力；它必须在覆盖报告里明确标记为越狱专属。

## 三、推荐交付顺序

1. **1.27.0**：A 层观测，新增 `webkit_navigation`、`webkit_js`、`webkit_cookie`、
   `webkit_scheme` 事件；默认开启 record-only，不改页面行为。
2. **1.27.x**：B 层可选 JS 探针，新增 MCP 工具开关和域过滤配置；默认关闭。
3. **后续**：C 层 Inspector 桥，先做 Network/Console，再做 DOM/Page。
4. **越狱支线**：Networking 进程注入，单独能力位、单独立项验证，不进入共享核心默认路径。

## 四、验证要求

需要一个本地 WKWebView 测试宿主，至少覆盖：

- 普通导航、`loadHTMLString:`、重定向。
- `fetch` GET/POST、`XMLHttpRequest`、WebSocket 文本帧。
- `postMessage` 到 native，native `evaluateJavaScript` 回页面。
- `WKHTTPCookieStore` 写入/读取/删除，持久化与临时 data store 各一次。
- 自定义 `WKURLSchemeHandler` 请求。
- 关闭观测时，页面网络调用次数、顺序、响应内容与未注入版本完全一致。

每个正例都要有对应负例，尤其是“页面不加载时不能产生 WebKit 事件”和“非 WebKit
的 NSURLSession 请求不能被误标为 WebKit”。

## 五、隐私边界

WebKit 数据天然包含 Cookie、Authorization、表单、localStorage 和页面正文。实现时必须：

- 默认只记录结构元信息和长度，正文按配置开启；
- 对 Cookie、Authorization、token、密码字段做固定脱敏；
- 所有 payload 设上限，不把完整页面或视频缓冲塞进日志；
- 文档继续标注 HTTP/MCP 仅限可信网络。
