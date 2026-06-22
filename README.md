# ios-decrypt-helper

基于 fishhook 的 iOS 加解密算法调试 dylib 插件。通过 fishhook 透明拦截系统加解密、哈希、密钥派生 API，记录每次调用的算法、操作、Key、IV、明文、密文、派生密钥及应用层调用栈。用于 iOS 逆向工程中快速还原一个 App 的加密体系。

注入到目标 App 后，它自己调用系统加密 API 时，你能在旁边实时看到全部参数。

## 截图

交互式测试台（逐个触发各类算法）与内置 Web 日志面板（含进程信息、大小过滤、分类着色、详情展开）：

| 交互式测试台 | Web 日志面板 |
| --- | --- |
| ![test-host](docs/screenshots/01-test-host.png) | ![web-panel](docs/screenshots/02-web-panel.png) |

## 覆盖的算法

拦截的是 CommonCrypto 与 Security.framework 这两套系统库，macOS 与 iOS 上同名同接口。

- 摘要（Digest）：MD2 / MD4 / MD5、SHA1 / SHA224 / SHA256 / SHA384 / SHA512，一次性与流式 Init/Update/Final 都覆盖，流式会把分片喂入的数据拼回完整明文。
- HMAC：CCHmac 系列，解析为 HMAC-SHA256 等。
- 对称加密：AES / DES / 3DES / RC4 / RC2 / CAST / Blowfish，覆盖 CCCrypt（一次性）、CCCryptorCreate / CCCryptorCreateWithMode / CCCryptorUpdate / CCCryptorFinal（流式），自动识别 ECB / CBC / CTR / CFB / OFB 模式与 PKCS7 填充。
- 非对称：RSA / EC 的签名、验签、加密、解密（SecKey 系列）。
- 密钥派生（KDF）：CCKeyDerivationPBKDF（PBKDF2），记录明文口令、salt、迭代次数、PRF 与派生出的密钥。

## 三种查看方式

1. 本地 Web 服务（推荐）。dylib 加载后自动在 8088 起一个零依赖的 HTTP 服务，浏览器访问即可。支持实时列表、分类切换、关键字搜索、按数据大小过滤、详情展开（Key/IV/明文/密文的 Hex 与 HexDump、调用栈）、暂停、清空、下载日志文件。顶部展示当前宿主进程信息（应用名、bundle id、PID、系统版本、设备型号、物理内存）。
2. iOS 内嵌悬浮窗 + 全屏查看器。悬浮窗是一个毛玻璃质感的小窗，显示各分类计数与服务地址，可拖动、可缩小成胶囊；点其中的日志按钮弹出全屏查看器看完整明细。
3. 文件落盘。所有日志同时异步追加到 Documents/decrypt_helper.log，可用于导出。

安全提示：Web 服务无认证、监听所有网卡（0.0.0.0），会把 Key 与明文暴露给同网络中任何能连接的人，仅建议在可信网络中调试使用。

## 性能与实现要点

- 日志写入走独立串行队列异步落盘，不阻塞被 hook 的调用方（宿主 App）。
- 分类计数为 O(1) 缓存读取，悬浮窗每秒刷新无遍历开销。
- 内存中按环形缓冲保留最近若干条；单段 blob 落盘有上限（默认 64KB），避免大数据撑爆内存。
- HTTP 服务用信号量限制并发连接、设读超时、fd 耗尽时指数退避，并支持日志文件分块下载。

## HTTP API

| 端点 | 说明 |
| --- | --- |
| GET / | 嵌入式单页前端 |
| GET /api/stats | total / paused / byCategory / port / version / process（进程信息） |
| GET /api/logs?cat=N&q=KW&minSize=N&since=SEQ&limit=N | 日志摘要数组，minSize 按字节数过滤 |
| GET /api/logs/:seq | 单条详情（含 Hex / HexDump / 调用栈） |
| POST /api/clear | 清空内存与文件 |
| POST /api/pause?paused=1 | 暂停 / 恢复 |
| GET /download | 下载日志文件 |

## 编译

```
make            # iOS 真机 (arm64, iPhoneOS SDK)
make mac        # macOS 原生 (用于 Mac 灰度自测)
make linux      # Linux 交叉编译 (需 IOS_SDK 与 CROSS_CC 环境变量)
```

产物为 decrypt_helper.dylib。

## 注入到 IPA

```
./scripts/inject.sh <input.ipa> decrypt_helper.dylib
```

脚本用 insert_dylib 写入 LC_LOAD_DYLIB，产出 hooked_<input>.ipa，用 AltStore / Sideloadly 重签后安装到非越狱设备；越狱设备可直接安装。

## 测试

仓库自带一个交互式测试宿主 App（sim_uitest/），按分类提供按钮，点哪个按钮就触发对应算法，便于逐个观察 hook 效果，而不是一次性全跑。

Mac 灰度（最快）：

```
make test-mac
```

编出 dylib 与一个命令行 exerciser，用 DYLD_INSERT_LIBRARIES 注入运行，浏览器开 http://127.0.0.1:8088 看结果。

iOS 模拟器 / 真机：编出 sim_uitest 这个测试 App，注入 dylib 后安装运行，点界面上的按钮触发算法。该测试 App 还注册了 dhtest:// URL scheme，可用 xcrun simctl openurl <device> dhtest://md5 之类的命令模拟点击对应按钮，方便无人值守的自动化测试（可用的 key：md5 / sha1 / sha256 / sha512 / hmac / aes / 3des / des / rc4 / rsasign / rsaenc / pbkdf / big / all / log）。

Release 附带一个已注入 dylib 的测试 IPA（未签名），重签后即可在真机上体验。

## 目录结构

```
src/
  fishhook.{c,h}        上游 fishhook
  log_store.{h,m}       日志中心 (环形缓冲 + 异步落盘 + 分类计数 + 进程信息)
  hook_digest.m         摘要 hook
  hook_hmac.m           HMAC hook
  hook_symmetric.m      对称加密 hook
  hook_asymmetric.m     非对称 hook
  hook_kdf.m            PBKDF2 密钥派生 hook
  http_server.{h,m}     零依赖本地 HTTP 服务
  web_index_html.h      内嵌的单页前端
  ui_float.{h,m}        悬浮控制窗
  ui_logview.{h,m}      全屏日志查看器
  main.m                注入入口 (构造函数)
sim_uitest/             交互式测试宿主 App
scripts/inject.sh       IPA 注入脚本
```
