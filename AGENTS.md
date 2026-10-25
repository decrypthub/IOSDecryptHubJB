# AGENTS.md — IOSDecryptHub 主仓库开发指南

Always respond in Chinese-simplified

> **开始任何代码变更前，必须先读 `docs/ARCHITECTURE_BOUNDARY.md`（架构铁律）。**
> 本文件是仓库级开发指南；工作区级产品说明见上层 `../AGENTS.md`。

---

## 产品简介

IOSDecryptHub 是一个 iOS 运行时安全分析 dylib。注入目标 App 进程后，实时捕获加解密（CommonCrypto / SecKey / OpenSSL EVP）、文件、网络、Keychain、动态加载行为，提供 Web 面板 + MCP 分析服务 + 脱壳能力。

项目以两个长期分支分别维护：`main` 为 TrollStore 巨魔版，`jailbreak` 为越狱版。两条路线复用 `src/` 下的公共核心，公共修复按提交同步；越狱专属增强仅在 `jailbreak` 推进。共享核心只使用 fishhook + ObjC swizzle；Inline Hook / Trace 等高级能力应隔离在越狱侧独立扩展中，详见架构文档 §3.1。

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
├── jailbreak/              # 薄入口：编译闭源 dylib → 拷进 ../IOSDecryptHubJB/vendor → 打包
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
| `make VARIANT=rootless` | 编译越狱加载器使用的共享 dylib |
| `make mac` | macOS 原生编译（灰度自测） |
| `make sim` | iOS 模拟器 dylib |
| `make ipa` | 构建 TrollStore 管理器 IPA |
| `make deb` | 编译闭源 dylib，拷进并列开源仓 `../IOSDecryptHubJB/vendor/`，再打 rootless + roothide deb |
| `make test-mcp` | MCP 集成测试（需 jq） |
| `make clean` | 清理构建产物 |

**三个编译变体**：`dev`（默认）、`trollstore` 和 `rootless`。`jailbreak` 是维护分支名，不是 `VARIANT` 值。变体只决定注入载体和能力标识，共享核心 hook 引擎保持一致。巨魔版构建在 `main` 进行，越狱版构建与 deb 打包在 `jailbreak` 进行。

---

## 架构铁律（摘要）

完整内容见 `docs/ARCHITECTURE_BOUNDARY.md`，此处列出最关键的：

- **巨魔 + 越狱分支维护**。`main` 维护巨魔版，`jailbreak` 维护越狱版；公共核心修复按提交同步
- **共享核心与越狱扩展隔离**。`src/` 不得使用 MSHookFunction、`%hook` 等越狱框架 API，不得引用 daemon / dh_server；越狱高级能力由独立扩展承载，加载器继续保持薄层
- **共享 Hook 只用 fishhook + ObjC swizzle**。共享核心不做 inline hook、不生成可执行内存；越狱侧 Inline Hook / Trace 按架构文档 §3.1 的隔离条件开发，当前属于后续规划
- **不崩溃原则**：dylib 在别人进程里跑，任何 crash 都杀死宿主 App
- **MCP 复用 8088 端口**（`POST /api/mcp`），不额外开端口
- **手动连接**：PC 端 `idh connect <设备 IP>:8088` 指定设备，无自动发现

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

改 `web/index.html` 后可执行 `python3 tools/gen_web.py web/index.html src/server/web_index_html.h` 验证生成结果。生成的头文件由 Makefile 自动更新并已加入 `.gitignore`，不得提交。

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

### 发布完整性

- 正式产物必须面向所有受支持环境完整可用，单台设备跑通不能代替发布验证
- 必需组件必须整合进产物，或在 deb/IPA 清单中声明为硬依赖并由安装器解析
- 禁止用强装、删除硬依赖、降级为建议依赖或设备侧手工补文件来掩盖打包缺陷
- 越狱 deb 发布前必须验证依赖、架构、签名、安装路径、PreferenceLoader 入口和默认应用选择流程

---

## Git 规范

- 长期维护分支：`main`（巨魔版，默认）/ `jailbreak`（越狱版）
- 平台专属功能从对应维护分支创建功能分支，并回到同一维护分支；不得将越狱专属依赖整分支合入 `main`
- 公共修复通过 `git cherry-pick -x <commit>` 按需同步；同步后分别验证巨魔与越狱兼容性
- 后续发布标签：`trollstore-v<版本号>` / `jailbreak-v<版本号>`，从对应维护分支打标签；历史 `v*` 标签不重写
- Commit 格式：`type: 中文描述`（type = feat/fix/refactor/docs/test/style）
- 不提交：密钥/token/dylib 产物/dSYM/build 目录、自动生成的 Web 头文件、自动下载的签名二进制
- `.gitignore` 已排除构建产物

---

## 安全提醒

- Web/MCP 服务 `0.0.0.0:8088` 无认证，仅限可信网络
- 不得在代码/文档/Issue 中出现真实密钥或用户数据
