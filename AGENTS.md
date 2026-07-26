# AGENTS.md — IOSDecryptHub 主仓库开发指南

Always respond in Chinese-simplified

> **开始任何代码变更前，必须先读 `docs/ARCHITECTURE_BOUNDARY.md`（架构铁律）。**
> 本文件是仓库级开发指南；工作区级产品说明见上层 `../AGENTS.md`。

---

## 产品简介

IOSDecryptHub 是一个**免越狱** iOS 运行时安全分析 dylib。注入目标 App 进程后，实时捕获加解密（CommonCrypto / SecKey / OpenSSL EVP）、文件、网络、Keychain、动态加载行为，提供 Web 面板 + MCP 分析服务 + 脱壳能力。

通过 TrollStore 管理器 App 或手动 `insert_dylib` 注入，全程不依赖越狱。

---

## 项目结构

```
IOSDecryptHub/
├── Makefile                # 唯一构建入口
├── src/
│   ├── core/               # 引擎：fishhook、capture 桥接、日志、配置、capstone、脱壳
│   │   ├── main.m          # dylib 入口（constructor，启动顺序不可调换）
│   │   ├── capstone/       # 内嵌 Capstone 5.0.1 源码（仅 ARM/AArch64，勿动）
│   │   └── ...
│   ├── hooks/crypto/       # 加解密 hook（digest/hmac/symmetric/asymmetric/kdf/evp）
│   ├── hooks/behavior/     # 行为 hook（file/system/keychain/network/dyld/env/spoof_objc）
│   ├── server/             # HTTP 服务 + MCP 服务 + UDP 信标 + Web 面板
│   └── ui/                 # iOS 悬浮窗
├── app-trollstore/         # TrollStore 管理器 App（SwiftUI + ObjC + 纯 C macho_patch）
├── scripts/                # inject.sh / publish_release.sh / sim_install.sh 等
├── tests/                  # mcp_test.sh + test_patch_info_plist.py
├── web/                    # Web 面板源文件（编译时生成 C 头文件）
├── tools/                  # gen_web.py / patch_info_plist.py
├── sim_uitest/             # 模拟器测试宿主 App
└── docs/                   # 架构文档（ARCHITECTURE_BOUNDARY.md 为最高优先级）
```

---

## 构建命令

| 命令 | 说明 |
|------|------|
| `make` | 编译 iOS 真机 dylib（dev 变体，默认） |
| `make VARIANT=trollstore` | 编译巨魔变体 dylib |
| `make mac` | macOS 原生编译（灰度自测） |
| `make sim` | iOS 模拟器 dylib |
| `make ipa` | 构建 TrollStore 管理器 IPA |
| `make test-mcp` | MCP 集成测试（需 jq） |
| `make clean` | 清理构建产物 |

**仅两个变体**：`dev`（默认）和 `trollstore`。不存在越狱变体。

---

## 架构铁律（摘要）

完整内容见 `docs/ARCHITECTURE_BOUNDARY.md`，此处列出最关键的：

- **只做巨魔，不做越狱**。不得引入 Substrate/ElleKit/daemon/deb/plist 门控
- **Hook 只用 fishhook + ObjC swizzle**。不做 inline hook，不生成可执行内存
- **不崩溃原则**：dylib 在别人进程里跑，任何 crash 都杀死宿主 App
- **MCP 复用 8088 端口**（`POST /api/mcp`），不额外开端口
- **UDP 信标发现**（端口 8089），不依赖 Bonjour/mDNS

---

## 编码规范

- **语言**：C / Objective-C（ARC），管理器 App 为 SwiftUI + ObjC 桥接
- **缩进**：4 空格
- **函数前缀**：`dh_`（核心）/ `hooked_`（hook 函数）/ `orig_`（原始指针）
- **类型前缀**：`DH`（如 `DHLogEntry`、`DHCategory`）
- **注释**：中文为主
- **版本号**：Makefile 顶部 `VERSION` 为单一真相源

### MCP 加工具的 3 个插入点

在 `src/server/mcp_server.m` 中：
1. handler 函数实现
2. `tool_definitions` 数组添加定义
3. `dispatch_tool` 分发链添加路由

### Web 面板修改

改 `web/index.html` 后**必须**执行 `python3 tools/gen_web.py` 重新生成 C 头文件。

---

## 启动顺序（不可调换）

```objc
// src/core/main.m — constructor
预热 Foundation（时间格式化、backtrace）  // 防止 hook 后懒加载递归
  → 加载配置（.dh_capture.conf / .dh_noise.conf / .dh_spoof.conf）
    → dh_install_all_hooks()              // 12 类 hook 一次装完
      → dh_http_start()                   // HTTP + MCP 服务
        → UIApplication didFinishLaunching → 悬浮窗
```

---

## 测试

- `make test-mcp`：集成断言（Shell + jq 驱动真实 HTTP/MCP 端点）
- `make mac` 后浏览器访问 `http://127.0.0.1:8088` 灰度验证
- `tests/test_patch_info_plist.py`：Info.plist patch 单元测试
- 新 hook 模块应补充对应的 exercise 触发路径

---

## Git 规范

- 当前分支：`main`
- Commit 格式：`type: 中文描述`（type = feat/fix/refactor/docs/test/style）
- 不提交：密钥/token/dylib 产物/dSYM/build 目录
- `.gitignore` 已排除构建产物

---

## 安全提醒

- Web/MCP 服务 `0.0.0.0:8088` 无认证，仅限可信网络
- 不得在代码/文档/Issue 中出现真实密钥或用户数据
- 仅限分析自有 App 或已获授权目标
