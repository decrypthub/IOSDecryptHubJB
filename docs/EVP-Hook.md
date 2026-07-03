# OpenSSL EVP 加解密 Hook — 功能说明

> 面向 iOS 逆向 / 加解密分析场景，为 IOSDecryptHub 新增 OpenSSL `EVP_*` 对称加解密的运行时抓取能力。
> 本文说明它**做什么、怎么做、边界在哪**，以及一次代码评审中发现并修复的两个缺陷。

## 一、背景

IOSDecryptHub 原先已覆盖 iOS 系统原生加解密：CommonCrypto（摘要 / HMAC / 对称 / PBKDF）、Security.framework（RSA/SecKey）、文件与 dlopen/dlsym。

但相当一部分 App 不用系统 API，而是集成 **OpenSSL** 自己做对称加解密（AES / DES / ChaCha20 / SM4，以及 GCM/CCM 等 AEAD 模式）。这些调用一律通过 OpenSSL 的 `EVP_CIPHER_CTX` + `EVP_*Update` 流水线完成，系统 hook 抓不到。本功能补上这一块。

## 二、能力概览

新增 hook 覆盖 OpenSSL EVP 对称加解密的完整调用链：

| 阶段 | 被 hook 的函数 |
|---|---|
| 初始化 | `EVP_EncryptInit_ex` / `EVP_DecryptInit_ex` / `EVP_CipherInit_ex`（含 `_ex2` OpenSSL 3 变体） |
| 数据流 | `EVP_EncryptUpdate` / `EVP_DecryptUpdate` / `EVP_CipherUpdate` |
| 收尾 | `EVP_EncryptFinal_ex` / `EVP_DecryptFinal_ex` / `EVP_CipherFinal_ex` |
| AEAD 控制 | `EVP_CIPHER_CTX_ctrl`（GCM/CCM 的 tag 读写） |

**每条加解密操作抓取的字段**：

- 算法名（从 `EVP_CIPHER` 解析，如 `AES-256-CBC`）
- 操作方向（encrypt / decrypt）
- 密钥 key、初始向量 iv
- 明文（输入）、密文（输出）
- AEAD 场景下的 AAD 与 认证 tag
- 调用栈（已过滤系统 / 自身帧）

结果落到统一日志，可在悬浮窗计数与本地 Web 面板查看。

## 三、工作原理

### 为什么要 hook Init

算法名、密钥长度、IV 长度都在 **Init 阶段**从 `EVP_CIPHER` 绑定；而 `Update` 只带 `ctx / in / out`，本身不携带算法信息。因此必须 hook Init，建立一张 `ctx → 算法状态` 的映射表，后续 Update / Final 再按 `ctx` 把明文、密文、tag 累积回同一条记录。

### AEAD 的特殊路径

- GCM/CCM 的 **AAD** 通过 `Update(out=NULL)` 传入，据此与正文区分；
- **tag** 通过 `EVP_CIPHER_CTX_ctrl` 的 `GET_TAG` / `SET_TAG` 读写，或在 Final 阶段产生。

### 底层机制：fishhook

所有 hook 通过 fishhook 重写 Mach-O 的 GOT/PLT 完成符号重绑定。这决定了它的适用边界（见第五节）。

## 四、评审中发现并修复的两个缺陷

本功能上线前做了一次代码评审 + 实测验证，发现并修复了两处问题。

### 缺陷 1（严重）：信号量在初始化前被使用，导致必崩

状态表用一个 `dispatch_semaphore` 保护，该信号量在 `evp_map_init()` 里惰性创建。但初始化函数 `evp_apply_init` 一进来就对信号量 `wait`，而创建它的 `evp_map_init()` 却要等到其后调用的 `evp_state_for()` 内部才第一次执行——**取锁时信号量还是 `nil`**。

后果：注入后目标 App **一调用 OpenSSL EVP 加密就崩溃**：

```
Thread crashed: EXC_BAD_ACCESS (SIGSEGV) at 0x30
    dispatch_semaphore_wait
    evp_apply_init
    hooked_EVP_EncryptInit_ex
```

这是个只有真正跑起来才会暴露的致命问题——静态检查、编译都不会报。

**修复**：在所有 7 个取锁点之前先调用 `evp_map_init()`（内部 `dispatch_once`，幂等且开销极小），确保信号量先于任何 `wait` 建立。

### 缺陷 2：CCM 的 ctrl 常量值写错

`EVP_CIPHER_CTX_ctrl` 的类型常量里，CCM 的三个值被写成了 `0x16 / 0x17 / 0x18`。对照 OpenSSL 头文件，这三个值实际对应的是完全不同的控制码：

| 代码里的写法（错误） | 值 | 实际含义 |
|---|---|---|
| `CCM_GET_TAG` | 0x16 | `EVP_CTRL_AEAD_TLS1_AAD` |
| `CCM_SET_TAG` | 0x17 | `EVP_CTRL_AEAD_SET_MAC_KEY` |
| `CCM_SET_IVLEN` | 0x18 | `EVP_CTRL_GCM_SET_IV_INV` |

事实上，OpenSSL 里 CCM 的这些常量本就是 GCM（AEAD）常量的**别名、同值**（`0x10 / 0x11 / 0x9`）。原写法既冗余、又会把 TLS 的 AAD、拼接算法的 MAC 密钥错误地当成认证 tag 记录下来。

**修复**：删除冗余且错误的 CCM 项，tag 过滤只判 GCM(=AEAD) 常量，天然同时覆盖 CCM。

## 五、适用边界（务必了解）

**fishhook 只能重绑定“动态绑定”的符号**（走 GOT/PLT 的外部导入）。由此：

- ✅ **动态链接** OpenSSL（App 以 `.framework` / `.dylib` 形式导入 `EVP_*`）→ 可 hook。
- ❌ **静态链接** OpenSSL（`.a` 静态库把 `EVP_*` 内联进主二进制）→ 符号不走 GOT，**fishhook 抓不到**。

需要清楚的是：iOS App 自带的 OpenSSL **相当一部分是静态链接的**。对这类目标，本功能不生效——这不是实现缺陷，而是 fishhook 机制的固有边界。静态场景需要另一套思路（对已知导出符号做 inline hook 改指令），目前未实现。

一句话：**这套 EVP hook 面向“动态链接 OpenSSL”的 App**；面对静态链接目标请不要期待它出日志。

## 六、验证情况

在 macOS 上做了端到端实测（macOS 与 iOS 共用同一套 hook 代码）：

- 用链接了 OpenSSL 3 的测试程序，注入修复后的 dylib，真实调用 `EVP_aes_256_cbc` 的 Init/Update/Final；
- 修复前：进程在 `EVP_EncryptInit` 处 SIGSEGV 崩溃；
- 修复后：进程正常跑完，**无崩溃、无新崩溃报告**；
- hook 抓取的字段全部正确：算法名 `AES-256-CBC`、key、iv、明文与 App 传入值一致，**抓到的密文与 OpenSSL 实际输出逐字节相同**。

> 说明：iOS 模拟器 runtime 不自带 OpenSSL，且模拟器测试程序默认不调用 EVP，因此 EVP 抓取逻辑的正确性以上述 macOS 路径验证为准；在 iOS 上的实效取决于目标 App 是否动态链接 OpenSSL（见第五节）。

## 七、小结

- 为 IOSDecryptHub 补上了 OpenSSL EVP 对称加解密（含 AEAD tag/AAD）的运行时抓取。
- 评审 + 实测修掉了一个“注入即崩”的致命缺陷和一处 CCM 常量错误。
- 明确了适用边界：**只对动态链接 OpenSSL 的 App 生效**，静态链接场景需另辟蹊径。
