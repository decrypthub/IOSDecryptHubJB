# 解密助手 (Decrypt Helper)

> iOS 加解密算法调试 dylib。基于 [fishhook](https://github.com/facebook/fishhook) 对常见加解密 / 哈希 API 做透明拦截，把每次调用的 **算法、操作、Key、IV、明文、密文、调用栈** 都记录下来。

## 覆盖的算法

| 分类 | API | 说明 |
|---|---|---|
| 摘要 (Digest) | `CC_MD2/4/5`, `CC_SHA1/224/256/384/512` + 对应 `_Init/_Update/_Final` | 流式调用会自动把切片拼起来 |
| HMAC | `CCHmac`, `CCHmacInit/Update/Final` | 解析算法枚举为 `HMAC-SHA256` 等 |
| 对称 | `CCCrypt`, `CCCryptorCreate`, `CCCryptorCreateWithMode`, `CCCryptorUpdate/Final/Release` | AES / DES / 3DES / RC4 / Blowfish / CAST / RC2; 自动识别 ECB / CBC / CTR / CFB 等 |
| 非对称 | `SecKeyCreateSignature`, `SecKeyVerifySignature`, `SecKeyCreateEncryptedData`, `SecKeyCreateDecryptedData` | RSA / EC; 记录 Key 信息和算法 OID |

## 三种查看方式

### 1. 本地 Web 服务 ⭐ (v1.1.0+, 推荐)

dylib 自动起一个本地 HTTP 服务（端口 `8088`，被占用则顺延到 8108），手机 / PC 浏览器直接访问：

```
http://<手机Wi-Fi IP>:8088
```

悬浮窗里直接显示 URL，点一下复制到剪贴板。功能：

- 实时列表 + 自动刷新
- 分类切换（摘要 / HMAC / 对称 / 非对称）
- 关键字搜索（算法、明文、Hex、操作）
- 详情页：Key / IV / Input / Output 的 Hex / UTF-8 / HexDump + 调用栈，一键复制
- 暂停 / 恢复 / 清空
- 整文件下载（`/download`）

**安全提示**：服务无认证，明文密钥都暴露给同网段任何人。**只在可信网络下使用**。

### 2. iOS 内嵌的悬浮窗 + 全屏查看器

* **悬浮窗**：只显示状态（各类计数 + 运行/暂停）+ URL + `日志 / 暂停 / 清空` 按钮，长按收起，可拖动。**不显示** 明文 / Hex / 摘要。
* **全屏查看器**：分类切换、关键字搜索、详情页、系统分享日志文件。

### 3. 文件落盘

每条日志同步追加到 `Documents/decrypt_helper.log`，可用 `iTools / iMazing / SSH` 拉下来。

## HTTP API

| 端点 | 说明 |
|---|---|
| `GET /` | 嵌入式单页前端 |
| `GET /api/stats` | `{total, paused, byCategory, port, version}` |
| `GET /api/logs?cat=N&q=KW&since=SEQ&limit=N` | 日志摘要数组 |
| `GET /api/logs/:seq` | 单条详情（含 hex / hexdump / 调用栈） |
| `POST /api/clear` | 清空内存 + 文件 |
| `POST /api/pause?paused=1` | 暂停 / 恢复 |
| `GET /download` | 下载日志文件 |

## 编译

### macOS / GitHub Actions (默认)

```bash
make           # 产出 decrypt_helper.dylib
```

CI: 推到 `main` 或在 Actions 页面手动触发 `workflow_dispatch`，可选填 `ipa_url` 自动下载并注入。

### Linux / WSL 交叉编译（无需 sudo）

```bash
bash scripts/wsl_setup_toolchain.sh    # 一次性, 下载 ~250MB 到 ~/dh-cross
bash scripts/wsl_build.sh              # 编译 + ldid 自签
```

工具链：[kabiroberai/swift-toolchain-linux](https://github.com/kabiroberai/swift-toolchain-linux) v2.3.0 +
[theos/sdks](https://github.com/theos/sdks) iPhoneOS16.5.sdk +
[ProcursusTeam/ldid](https://github.com/ProcursusTeam/ldid)，全部用户态安装。

## 注入到 IPA

```bash
./scripts/inject.sh input.ipa decrypt_helper.dylib
# 产出 hooked_input.ipa, 直接用 AltStore / Sideloadly 重签后安装
```

## 文件结构

```
src/
├── fishhook.{c,h}        # 上游 fishhook 原版
├── log_store.{h,m}       # 日志中心 (内存环 + 落盘)
├── hook_digest.m         # MD2/4/5 + SHA1/224/256/384/512
├── hook_hmac.m           # HMAC
├── hook_symmetric.m      # AES / DES / 3DES / RC4 / Blowfish ...
├── hook_asymmetric.m     # RSA / EC sign / verify / encrypt / decrypt
├── http_server.{h,m}     # 本地 HTTP 服务 (BSD socket, 0 依赖)
├── web_index_html.h      # 嵌入式单页前端
├── ui_float.{h,m}        # 悬浮控制窗 (无日志正文)
├── ui_logview.{h,m}      # 全屏日志查看器
└── main.m                # 入口 + 构造函数
```
