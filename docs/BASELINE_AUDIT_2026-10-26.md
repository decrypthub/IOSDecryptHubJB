# 正式公开版本与拆分基线核验

核验日期：2026-10-26。目的：确认已开源的正式代码没有被旧工作仓覆盖，并校正拆分仓的基线。

## 1. 结论与纠正

用户记忆正确：组织的 [IOSDecryptHub](https://github.com/decrypthub/IOSDecryptHub) 早已公开，并且已经包含完整越狱链路。此前把本机指向的个人私有引擎仓误当作唯一项目，导致新 `IOSDecryptHubJB` 没有从正式完整源码开始，这是本次需要纠正的问题。

正式公开仓、既有 Release 和线上包未被这些拆分操作覆盖。新拆分仓此前并不等于“线上最新完整版本”，不能仅凭 Makefile 同为 1.27.5 就判定一致。

## 2. 权威基线

| 对象 | 核验值 |
|---|---|
| 正式源码 main | `a94a3967381459ee1629cc3df450ca4529364f9f`，提交日期 2026-10-19 |
| 最新正式 Release | `v1.27.5`，2026-09-19 发布 |
| Release tag 对应提交 | `59b45fba78f65e062c49442941c06d2eaa84cd6e` |
| 发布后源码修复 | `33473c0` 区分 rootless / roothide 变体，随后完善本仓发布流程与 README |
| 官网拆分前已发布提交 | `e3765e5`，同步 v1.27.5 官网与插件源 |
| 线上源 | `https://ios.decrypthub.com`，两种架构均为 `com.iosdecrypthub` 1.27.5 |

正式 main 的 commit SHA 在本轮核验前后均为 `a94a396`。官网从 `e3765e5` 到当前只增加 README 链接说明，`public/`、首页下载元数据和源索引没有修改。

## 3. 拆分仓原有差异

对 `src/`、`web/`、`tools/` 做 Git blob 比较，排除内嵌第三方 Capstone 后，原新 JB 与正式仓共同路径中 55 个文件完全一致；4 个文件不同，另缺少 Loader 与共享头。

- `dh_capability.c/.h` 缺少正式仓后续添加的 `roothide` 变体及既有枚举语义说明。
- `mcp_server.m` 的工具说明尚未列出 rootless / roothide。
- `web/index.html` 仅为拆分后的 Issue 仓库地址差异。
- 新 JB 缺少正式 `app/`、`daemon/`、`src/loader.m`、`src/dh_shared.h`、`build_deb.sh`、APT 公钥与整包构建链路。
- 新巨魔仓继承的旧个人仓 **latest Release 是 v1.25.5**。此前 README 下载链接指向它会把用户带到旧产物，已改回正式 v1.27.5 下载。

因此不是“所有引擎代码都很旧”，而是缺少正式版本的完整组件和后续变体修复，并存在下载入口误导。

## 4. 已做的基线修正

- 新 JB 纳入正式 `a94a396` 的历史，保留拆分前提交、架构设计与测试资料，不强推重写。
- 直接恢复正式仓的引擎变体修复、Manager、Loader、updater、打包脚本、Makefile、源公钥与现有设备/更新测试。
- Git 对比确认 `src/`、`app/`、`daemon/`、`repo/`、Makefile、打包脚本、Loader 配置、注入脚本和 updater 测试与正式基线一致。Web 的新仓 Issue 地址属于显式保留的拆分差异。
- 巨魔仓同步相同的公共引擎修复，README 明确当前正式下载仍沿用原公开仓 v1.27.5；继承的旧 Release 留作历史。
- 正式发布 workflow 保存为 `docs/reference/official-v1-release.yml` 供迁移核对，不启用新的自动发布。新 JB CI 只验证基线，不创建 Release。

这些修正不等于完成 v2 常驻分析服务、全新 UI、整包升级改造、Inline Hook 或 Trace；现有 daemon 仍是正式 v1 的一次性 updater。

## 5. 线上文件哈希验证

从线上实际下载，分别与 GitHub 正式 Release 的 digest 和官网 Git blob 对照，以下全部一致：

| 产物 | 字节数 | SHA-256 |
|---|---:|---|
| rootless deb | 573336 | `8b9ef5d76570e107b40a04ff5580eae5d3e418da130e3d0143b980424fe583ce` |
| RootHide deb | 763396 | `3ce96d5941f9f63ff5e46aa3ee97a61e5fff1ddfb506d2aeab572f736f14dbc6` |
| 巨魔 dylib | 2568216 | `47d5e072220b6d2db06292cc4402df95534060067883d83ffbe1bfb163eef20f` |

线上 `Packages` 的 SHA-256 为 `22e3c2f90aaa507d0c546d95da2309519adc90f826a681839292e435b75ccba3`，与 `Release` 声明及官网 Git blob 完全一致。Windows 工作树的 CRLF 文件字节会不同，因此比较使用 Git blob 原始字节，不能将换行差异误判为线上版本变化。

## 6. 构建验证与范围

已在独立 Mac 临时目录从校正后的暂存源码执行 `make deb`，完整构建 Manager、Loader、引擎与 updater，并通过脚本内置的包架构、依赖和布局检查：

- rootless：`Version: 1.27.5`、`Architecture: iphoneos-arm64`、`Depends: ellekit`。
- RootHide：`Version: 1.27.5`、`Architecture: iphoneos-arm64e`、`Depends: ellekit`。

本次产物只是本地基线验证，已取回被忽略的 `build/baseline-audit/`，没有上传为 Release、没有更新 APT 索引、没有安装手机。重新编译的包不要求逐字节复现旧 Release，不能把本地测试包的版本号相同当作已正式发布。

下一步开发以正式完整基线及现有组件为起点；手机常驻服务与统一整包更新属于在该基线上的改造，不从旧个人引擎仓重新拼装。
