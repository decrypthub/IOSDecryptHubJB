# IOSDecryptHubJB

独立的 iOS 越狱运行时分析项目。面向 rootless / RootHide，以一个 deb 整包交付常驻守护程序、手机 Manager UI、注入 Loader 与 Agent 引擎，支持通过 APT 越狱源统一更新。

本项目与 [IOSDecryptHub 巨魔版](https://github.com/decrypthub/IOSDecryptHubTrollStore) 分别维护自己的 main、版本和发布，不再通过同仓分支区分产品。

本项目在 `decrypthub` 组织公开维护。既有公开 [IOSDecryptHub v1](https://github.com/decrypthub/IOSDecryptHub) 另有已发布的管理器、加载器、updater 和整包脚本，保留原地址和发布链路；v2 后续从这些实际实现迁移，不将其误判为不存在。

## 产品使用流程

安装越狱源中的整包 → 打开 Manager → 在应用列表开启目标注入 → 启动或重新启动目标 → 查看采集与分析 → 按需配置 Inline Hook / Trace 任务。

- 常驻 daemon 独立于 Manager 和目标 App，管理界面退出后仍可运行。
- 手机可以开启/关闭某个应用或全局注入，展示配置与真实加载状态。
- dylib 是整包内部组件，不要求用户单独下载、编译、选择或更新。
- 手机 daemon 提供会话、存储、Web / MCP 和受限分析，PC 是可选客户端。
- 更新由 Sileo / Zebra 等包管理器完成，整包组件统一版本，不使用宿主内覆盖 dylib 的更新方式。

## 当前状态

**当前已校正到组织正式仓 `a94a396` 的完整 v1 基线，尚未发布独立新版。** 现有 Manager、Loader、一次性 updater 和完整 deb 构建已经恢复，Mac 上 `make deb` 两种环境均通过。新版常驻分析服务、Manager 改造、scope IPC、整包升级改造和 Inline / Trace 仍未完成。

正式下载仍使用原公开仓的 [v1.27.5 Release](https://github.com/decrypthub/IOSDecryptHub/releases/tag/v1.27.5)。本仓构建只用于基线核验，不替换正式发布或线上源。详细差异、纠正和线上 SHA-256 见 [基线核验报告](./docs/BASELINE_AUDIT_2026-10-26.md)。

现有 v1 整包可在 Mac 执行 `make deb`，自动构建引擎、Loader、Manager 和 updater；本项目不再需要旧跨仓复制入口。

## 设计与实施

- [产品架构、整包与实施顺序](./docs/PRODUCT_ARCHITECTURE.md)
- [手机 Manager 页面与交互](./docs/MANAGER_UI.md)
- [Hook / ABI / 事件 / Trace 技术设计](./docs/HOOK_AND_TRACE_DESIGN.md)
- [项目当前进度](./docs/PROGRESS.md)
- [开发边界](./AGENTS.md)

优先交付基础整包与逐应用注入闭环，再完成源升级、Inline、出口采集和 Trace。内部组件自动构建完成后，rootless / RootHide 各输出本环境匹配的一份完整 deb。

## 协议

[MIT](./LICENSE)，第三方组件声明见 [NOTICE](./NOTICE)。
