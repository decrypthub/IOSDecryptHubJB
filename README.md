# IOSDecryptHub

<div align="right">
  <b>中文</b> | <a href="./README.en.md">English</a>
</div>


IOSDecryptHub 是一个注入到 iOS App 进程中的运行时分析 dylib，可捕获加解密、文件、网络、Keychain 与动态加载行为，并提供 Web 面板、脱壳和 MCP 分析能力。

完整能力与效果演示请访问：[ios.decrypthub.com](https://ios.decrypthub.com/)

## 版本与维护分支

巨魔版与越狱版采用两个长期分支独立维护：

| 版本 | 维护分支 | 定位与开发方向 |
|------|----------|----------------|
| 巨魔版（TrollStore） | [`main`](https://github.com/taisuii/IOSDecryptHub/tree/main)（默认分支） | 面向免越狱注入，维护 TrollStore 管理器、IPA 注入、fishhook / ObjC swizzle 与现有 Web / MCP 分析能力，优先保证兼容性与稳定性 |
| 越狱版（Jailbreak） | [`jailbreak`](https://github.com/taisuii/IOSDecryptHub/tree/jailbreak) | 面向 rootless / roothide 越狱环境，在现有能力上持续开发更强的运行时分析功能，包括 Inline Hook、Trace 等 |

```bash
git fetch origin
git switch main        # 巨魔版开发与维护
git switch jailbreak   # 越狱版开发与维护；首次切换时自动跟踪 origin/jailbreak
```

公共引擎修复按需通过 `git cherry-pick -x <commit>` 同步，并分别验证两端兼容性；平台专属功能只进入对应分支。越狱版增强功能不整分支合回 `main`，避免引入免越狱环境不支持的依赖。后续发布分别使用 `trollstore-v<版本号>` / `jailbreak-v<版本号>` 标签，历史 `v*` 标签保持不变。

### 越狱版后续规划

以下是 `jailbreak` 分支的开发方向，**本次分支拆分不代表这些增强功能已经实现**：

- **Inline Hook**：面向静态链接函数、同镜像内部直接调用和自研算法等 fishhook 无法覆盖的调用点，逐步支持参数、返回值与内存快照观测。
- **Trace**：逐步提供函数调用追踪、调用链分析，并探索指令级执行追踪，帮助定位关键算法及数据流。
- **分析联动**：将越狱扩展产生的事件接入现有 Web / MCP，提供可控的启停、过滤与导出能力。

高级能力需按设备权限、架构和运行环境检测后启用；Inline Hook / Trace 实现保持在越狱专属扩展中，共用引擎继续使用 fishhook + ObjC swizzle。详细约束见 [架构边界](./docs/ARCHITECTURE_BOUNDARY.md)。

## 获取 dylib

从 [官网首页](https://ios.decrypthub.com/) 或 [GitHub Releases](https://github.com/taisuii/IOSDecryptHub/releases) 下载 `decrypt_helper.dylib`，或自行编译：

```bash
make
```

编译产物位于项目根目录：`decrypt_helper.dylib`。

## 使用方法

### 方式一：巨魔注入器（推荐）

适用于已通过 TrollStore 安装巨魔注入器的设备：

1. 在巨魔注入器中选择目标 App。
2. 添加 `decrypt_helper.dylib` 并执行注入。
3. 启动目标 App。
4. 在同一局域网的浏览器中访问 `http://<设备 IP>:8088`。

不同注入器的界面可能略有差异，核心操作都是将 dylib 注入目标 App 后重新启动 App。

### 方式二：IPA 重打包

macOS 先安装 `insert_dylib`：

```bash
brew install insert_dylib
```

执行仓库内置脚本：

```bash
./scripts/inject.sh <input.ipa> decrypt_helper.dylib
```

脚本会生成 `hooked_<input>.ipa`。使用 TrollStore、Sideloadly 或 AltStore 安装/重签后启动 App，再访问：

```text
http://<设备 IP>:8088
```

### 方式三：TrollStore 管理器 App

编译并安装专用管理器 IPA：

```bash
make ipa
```

产物位于 `build/trollstore/`，通过 TrollStore 安装后可在 App 内直接选择目标并注入。

### PC 端连接与 MCP 网关

在电脑上安装 `idh`，手动连接设备（设备 IP 从 App 面板或局域网内获取）：

```bash
pip install ios-decrypt-hub
idh connect <设备 IP>:8088
idh mcp
```

`idh mcp` 将设备上的 HTTP MCP 转换为本机 stdio MCP，可作为 Codex、Claude 等客户端的固定 MCP 配置。`connect` 会把设备保存为持久连接，之后 `devices` / `watch` / `open` / `mcp` 直接使用；也可以临时用 `--endpoint http://<设备 IP>:8088` 指定。

## 编译变体

| 变体 | 命令 | 用途 |
|------|------|------|
| dev（默认） | `make` | 开发者手动注入 / 本地调试 |
| trollstore | `make VARIANT=trollstore` | 巨魔注入器 / 管理器 IPA |
| rootless | `make VARIANT=rootless` | 越狱 deb 包 |

### 越狱 deb 包（rootless / roothide）

请先切换到 `jailbreak` 分支。打包还依赖并列仓库 `../IOSDecryptHubJB/`（也可通过 `DH_JB_DIR` 指定路径），详见 [越狱打包说明](./jailbreak/README.md)。

```bash
make deb              # 同时构建普通 rootless 与 roothide 包
make deb-rootless     # 普通 rootless（arm64）
make deb-roothide     # roothide（arm64e）
```

产物在 `build/deb/`。必须安装与设备环境对应的包；roothide 不可安装普通 rootless 包，否则设置面板会因 `arm64` / `arm64e` 不兼容而无法加载。

## 注意事项

- Web 与 MCP 服务默认监听 `0.0.0.0:8088`，且没有身份认证，请仅在可信网络中使用。
- 注入、重签和脱壳能力受设备环境及目标 App 保护机制影响。
- 请勿将捕获到的 Key、口令、明文或其他敏感数据提交到公开 Issue。

遇到问题可在 [GitHub Issues](https://github.com/taisuii/IOSDecryptHub/issues/new/choose) 反馈。

## 协议

[MIT](./LICENSE)

内嵌 [fishhook](https://github.com/facebook/fishhook) 与 [Capstone](https://www.capstone-engine.org/)（均为 BSD-3-Clause），版权声明见 [NOTICE](./NOTICE)。
