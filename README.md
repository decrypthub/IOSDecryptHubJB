# IOSDecryptHubJB

独立的 iOS 越狱运行时分析项目。面向 rootless / RootHide，以一个 deb 整包交付常驻守护程序、手机 Manager UI、注入 Loader 与 Agent 引擎，支持通过 APT 越狱源统一更新。

本项目与 [IOSDecryptHub 巨魔版](https://github.com/decrypthub/IOSDecryptHubTrollStore) 分别维护自己的 main、版本和发布，不再通过同仓分支区分产品。

本项目在 `decrypthub` 组织公开维护。既有公开 [IOSDecryptHub v1](https://github.com/decrypthub/IOSDecryptHub) 另有已发布的管理器、加载器、updater 和整包脚本，保留原地址和发布链路；v2 后续从这些实际实现迁移，不将其误判为不存在。

## 当前版本与使用

[v1.27.6 完整包](https://github.com/decrypthub/IOSDecryptHubJB/releases/tag/v1.27.6) 基于组织正式 `a94a396` 的完整 v1 源码，包含 Manager、Loader、一次性管理 daemon、引擎与资源。添加源 **https://ios.decrypthub.com**，在 Sileo / Zebra 安装 IOSDecryptHub；rootless / RootHide 请使用对应架构的完整 deb。

打开 Manager → 开启目标应用的注入 → 启动或手动重启目标 → 通过原有 Web / MCP 查看分析。关闭注入影响后续加载；已加载的引擎要在目标退出后才离开进程。

v1.27.6 将版本检查切换到规范 APT 源，按安装包架构选择版本，更新与回退交给系统包管理器。Manager、Loader、daemon 与引擎统一升级；旧单引擎安装/回滚请求会被拒绝，遗留 staging 不再覆盖包内引擎。

**后续规划**：参考 Android 项目改造手机常驻分析服务与新 Manager，增加真实会话/scope 状态、Inline Hook、出口采集和 Trace。当前 daemon 仍按请求或周期运行后退出，这些新能力尚未实现。

## 构建与验证

在 Mac 上执行：

```bash
make test-updater  # 无需网络或手机的版本选择/旧更新请求边界回归
make deb           # 一次构建 rootless 和 RootHide 完整包
```

无需单独编译或从巨魔项目复制 dylib。v1.27.6 已通过 Mac 回归和双环境整包编译、包内容与签名检查；尚未在手机上验收安装、升级或包管理器跳转。详见 [当前进度](./docs/PROGRESS.md)；此前正式基线的核验记录见 [基线核验报告](./docs/BASELINE_AUDIT_2026-10-26.md)。

## 设计与实施

- [产品架构、整包与实施顺序](./docs/PRODUCT_ARCHITECTURE.md)
- [手机 Manager 页面与交互](./docs/MANAGER_UI.md)
- [Hook / ABI / 事件 / Trace 技术设计](./docs/HOOK_AND_TRACE_DESIGN.md)
- [项目当前进度](./docs/PROGRESS.md)
- [开发边界](./AGENTS.md)

优先交付基础整包与逐应用注入闭环，再完成源升级、Inline、出口采集和 Trace。内部组件自动构建完成后，rootless / RootHide 各输出本环境匹配的一份完整 deb。

## 协议

[MIT](./LICENSE)，第三方组件声明见 [NOTICE](./NOTICE)。
