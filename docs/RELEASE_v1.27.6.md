# v1.27.6 — 独立越狱项目维护更新

基于组织正式 v1 完整源码发布，保留既有 Manager、按应用注入开关、Loader、引擎及一次性管理 daemon。

- 更新检查使用 https://ios.decrypthub.com 的 APT 索引，按安装架构选择候选版本。
- 安装/更新/回退由 Sileo / Zebra 完成完整 deb 交易，所有组件统一版本；不再下载裸 dylib 覆盖引擎。
- 拒绝旧安装/回滚请求，旧 staging 和备份不再替换包内文件；修复启动脚本误删待处理请求。
- rootless 对应 iphoneos-arm64；RootHide 对应 iphoneos-arm64e，包内 Mach-O 包含 arm64 和 arm64e。

验证：Mac 无网络回归测试、两类完整包构建、版本/架构/组件/签名检查。未进行手机安装升级和包管理器跳转验收。

后续：手机常驻分析服务、新 Manager、scope IPC、Inline Hook 与 Trace。本版本仍使用一次性管理 daemon，不包含这些新功能。

安装源：https://ios.decrypthub.com。已有 v1.27.5 用户请在包管理器刷新源后升级完整包。
