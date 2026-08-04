# IOSDecryptHub

<div align="right">
  <b>中文</b> | <a href="./README.en.md">English</a>
</div>


IOSDecryptHub 是一个注入到 iOS App 进程中的运行时分析 dylib，可捕获加解密、文件、网络、Keychain 与动态加载行为，并提供 Web 面板、脱壳和 MCP 分析能力。

完整能力与效果演示请访问：[ios.decrypthub.com](https://ios.decrypthub.com/)

> 仅限自有 App 或已获授权的安全测试与研究。

## 获取 dylib

从 [官网首页](https://ios.decrypthub.com/) 或 [GitHub Releases](https://github.com/taisuii/ios-decrypt-helper/releases) 下载 `decrypt_helper.dylib`，或自行编译：

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

### PC 自动发现与 MCP 网关

插件会将实际 HTTP 端口发布为 `_idh-mcp._tcp.` Bonjour 服务。安装 `idh` 后，无需复制会变化的设备 IP：

```bash
pip install ios-decrypt-hub
idh --devices
idh mcp
```

`idh mcp` 将设备上的 HTTP MCP 转换为本机 stdio MCP，可作为 Codex、Claude 等客户端的固定 MCP 配置。仓库的 `inject.sh` 会自动合并 `NSLocalNetworkUsageDescription` 与 `NSBonjourServices`；使用第三方注入器时，需要由宿主 App 或注入器提供这两个 `Info.plist` 声明。

## 编译变体

| 变体 | 命令 | 用途 |
|------|------|------|
| dev（默认） | `make` | 开发者手动注入 / 本地调试 |
| trollstore | `make VARIANT=trollstore` | 巨魔注入器 / 管理器 IPA |
| rootless | `make VARIANT=rootless` | 越狱 deb 包 |

### 越狱 deb 包（rootless / roothide）

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

遇到问题可在 [GitHub Issues](https://github.com/taisuii/ios-decrypt-helper/issues/new/choose) 反馈。
