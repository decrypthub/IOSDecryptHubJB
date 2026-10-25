# IOSDecryptHubJB 当前进度

## 2026-10-25：独立工程与手机整包方案

用户决策：巨魔版定型，越狱版独立项目；一个 deb 包含常驻 daemon、手机 UI 和注入引擎，通过 APT 源统一更新；手机可按应用开关注入，UI 参考现有 Android Manager。

已完成：

- 从旧越狱 4858677 导入独立 IOSDecryptHubJB 项目，main 为唯一产品主线，保留引擎源码与提交历史。
- 核对 Android Manager / daemon / scope 代码，落定手机原生 UI 和真实生效状态语义。
- 将 PC 从必需分析中心改为可选客户端，手机 daemon 负责服务与数据。
- 产品、UI、Hook / Trace 设计与开发规则同步更新。
- 上一轮已实测 Mac SSH 和旧引擎 arm64 / arm64e 编译；当前没有新版完整包或设备验收。

尚未实现：

- J0：新版 daemon、Manager、Loader 接入、整包一键构建。
- J1：手机应用目录、scope IPC、开关/生效状态、目标启停。
- J2：本产品正式 APT 源、统一版本、升级与移除交易。
- J3–J5：Inline、出口采集、函数与指令 Trace。

接下来从 J0 开始：先做可安装完整最小包，再按 J1 验证应用 A 开启、B 不受影响、关闭/重启真实生效；不先以独立 dylib 交付新增能力。

## 2026-10-25：统一迁入组织公开维护，补齐旧公开源码发现

- 用户明确不要私有仓。当前仓从个人账号迁入 `decrypthub/IOSDecryptHubJB` 并设为 PUBLIC；巨魔版为 `decrypthub/IOSDecryptHubTrollStore`，官网为 `decrypthub/IOSDecryptHubPage`。
- 组织原有公开 `decrypthub/IOSDecryptHub` 已包含管理器、Loader、一次性 updater、整包脚本和发布链路，并有 v1.27.5 发布。它与本仓历史不同，不强推覆盖；本机加只读参考 `legacy-public/main`，核对提交 a94a396。
- 更正早期判断：“本机未发现并列 JB 仓”不能推断“旧越狱组件不存在”。后续从真实 v1 迁移常驻与整包更新，不从零重复造管理器/打包能力。
- 旧源声明为 `https://ios.decrypthub.com`，旧包 ID 为 `com.iosdecrypthub`；尚需核对线上签名/索引/已有安装和接管方式，本轮不改源、不发包、不操作手机。
- 本轮只迁移公开仓、更新链接与状态记录，不新增运行时功能。
