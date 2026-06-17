# 解密助手 (Decrypt Helper)

> iOS 加解密算法调试 dylib。基于 [fishhook](https://github.com/facebook/fishhook) 对常见加解密 / 哈希 API 做透明拦截，把每次调用的 **算法、操作、Key、IV、明文、密文、调用栈** 都记录下来。

## 覆盖的算法

| 分类 | API | 说明 |
|---|---|---|
| 摘要 (Digest) | `CC_MD2/4/5`, `CC_SHA1/224/256/384/512` + 对应 `_Init/_Update/_Final` | 流式调用会自动把切片拼起来 |
| HMAC | `CCHmac`, `CCHmacInit/Update/Final` | 解析算法枚举为 `HMAC-SHA256` 等 |
| 对称 | `CCCrypt`, `CCCryptorCreate`, `CCCryptorCreateWithMode`, `CCCryptorUpdate/Final/Release` | AES / DES / 3DES / RC4 / Blowfish / CAST / RC2; 自动识别 ECB / CBC / CTR / CFB 等 |
| 非对称 | `SecKeyCreateSignature`, `SecKeyVerifySignature`, `SecKeyCreateEncryptedData`, `SecKeyCreateDecryptedData` | RSA / EC; 记录 Key 信息和算法 OID |

## UI

* **悬浮窗**: 只显示状态 (各类计数 + 运行/暂停)，提供 `日志 / 暂停 / 清空` 三个按钮和折叠/拖动手势。**不显示** 任何明文 / Hex / 摘要。
* **日志查看器**: 全屏模态，支持
  * 按算法分类切换 (全部 / 摘要 / HMAC / 对称 / RSA)
  * 关键字搜索 (算法名、明文、Hex)
  * 详情页 (Key/IV/明文/Hex/HexDump/输出/调用栈)，长按可拷贝
  * 一键 **分享** 日志文件 (`Documents/decrypt_helper.log`)

## 编译

### macOS / GitHub Actions (默认)

```bash
make           # 产出 decrypt_helper.dylib
```

CI: 推到 `main` 或在 Actions 页面手动触发 `workflow_dispatch`，可选填 `ipa_url` 自动下载并注入。

### Linux / WSL 交叉编译

需要先准备 iPhoneOS SDK 与支持 Apple 目标的 clang。推荐用 [Theos](https://github.com/theos/theos)：

```bash
# 一次性安装
bash -c "$(curl -fsSL https://raw.githubusercontent.com/theos/theos/master/bin/install-theos)"

export IOS_SDK="$THEOS/sdks/iPhoneOS17.5.sdk"      # 实际版本以你下的为准
export CROSS_CC="$THEOS/toolchain/linux/iphone/bin/clang"
make linux
```

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
├── ui_float.{h,m}        # 悬浮控制窗 (无日志正文)
├── ui_logview.{h,m}      # 全屏日志查看器
└── main.m                # 入口 + 构造函数
```
