# IOSDecryptHubJB

独立的 iOS 越狱运行时分析项目。面向 rootless / RootHide，以一个 deb 整包交付常驻守护程序、手机 Manager UI、注入 Loader 与 Agent 引擎，支持通过 APT 越狱源统一更新。

本项目与 [IOSDecryptHub 巨魔版](https://github.com/taisuii/IOSDecryptHub) 分别维护自己的 main、版本和发布，不再通过同仓分支区分产品。

## 产品使用流程

安装越狱源中的整包 → 打开 Manager → 在应用列表开启目标注入 → 启动或重新启动目标 → 查看采集与分析 → 按需配置 Inline Hook / Trace 任务。

- 常驻 daemon 独立于 Manager 和目标 App，管理界面退出后仍可运行。
- 手机可以开启/关闭某个应用或全局注入，展示配置与真实加载状态。
- dylib 是整包内部组件，不要求用户单独下载、编译、选择或更新。
- 手机 daemon 提供会话、存储、Web / MCP 和受限分析，PC 是可选客户端。
- 更新由 Sileo / Zebra 等包管理器完成，整包组件统一版本，不使用宿主内覆盖 dylib 的更新方式。

## 当前状态

**当前为独立工程与设计迁移阶段，尚无新版可安装整包。** 仓库保留旧引擎源码和历史作为迁移基线；新版 daemon、Manager、scope IPC、完整 deb / 源更新，以及 Inline / Trace 均未实现。正式源 URL 尚未配置。

已验证旧引擎可经 SSH 在 Mac 编译 arm64 / arm64e；这不等于新版整包或真机功能已验收。旧 Makefile 和跨仓脚本仅用于追溯/迁移，不是新版产品交付入口。

## 设计与实施

- [产品架构、整包与实施顺序](./docs/PRODUCT_ARCHITECTURE.md)
- [手机 Manager 页面与交互](./docs/MANAGER_UI.md)
- [Hook / ABI / 事件 / Trace 技术设计](./docs/HOOK_AND_TRACE_DESIGN.md)
- [项目当前进度](./docs/PROGRESS.md)
- [开发边界](./AGENTS.md)

优先交付基础整包与逐应用注入闭环，再完成源升级、Inline、出口采集和 Trace。内部组件自动构建完成后，rootless / RootHide 各输出本环境匹配的一份完整 deb。

## 协议

[MIT](./LICENSE)，第三方组件声明见 [NOTICE](./NOTICE)。
