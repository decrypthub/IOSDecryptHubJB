# L3 / L4 真机验收计划

> 制定日期：2026-09-13
> 上线依据：`docs/AUDIT_CAPABILITY_ROADMAP.md` §3.2 五级验证环境、§四 共用完成标准
> 前置决策：环境与能力体检只落越狱侧（核心保持环境无关）

## 一、缺口

阶段 0 只完成了 L0 / L1 / L2。**L3（真机 TrollStore）与 L4（真机 Jailbreak）从未执行**：

- 测试宿主 `sim_uitest` 只有模拟器形态：`scripts/sim_install.sh` 用 iphonesimulator SDK +
  `xcrun simctl`；`scripts/`、`tests/` 下不存在任何 iphoneos 构建路径。
- `tests/scenarios.json` 的 9 个场景**全部**声明了 `platforms` 含 `device`，但真机上一例未跑。
- 1.25.0 新增管理器 App 与 updater daemon 后，真机验收从"里程碑前补"变成"必须有"。

本计划把这些补齐，且**不另起测试工程**（沿用路线图 §3.1 的约定）。

## 二、分层：新增 L5，避免污染 L4 判据

路线图定义「L4 不允许出现越狱专属核心能力，它只验证加载方式不同、核心行为一致」。
越狱专属能力（inline hook 扩展、daemon 特权操作、环境体检）一旦并入 L4，某场景用上
inline hook 后其观察集与 TrollStore 侧天然不同，"核心行为一致"就变成假命题——判据被
悄悄污染。因此单列：

| 层 | 验什么 | 判据 | 阻塞范围 |
|----|--------|------|----------|
| L3 | 真机 TrollStore：arm64、真实 Framework、注入与稳定性 | 9 场景全绿，与 L2 结论一致 | 里程碑发布前 |
| L4 | 真机 Jailbreak：rootless / roothide 各一台，三载体**一致性** | 9 场景全绿，且与 L3 结论一致 | 涉及加载器时 |
| **L5**（待确认） | 越狱专属能力：inline hook 扩展、daemon 特权操作、环境体检 | 各自的独立正例/负例 | 不阻塞 L3/L4，独立记录 |

## 三、要建的三件事（都在既有工程上加形态）

1. `scripts/device_install.sh` —— 真机形态的同一个宿主 App：
   - iphoneos SDK 编 `sim_uitest/main.m`，场景 ID 与 `tests/scenarios.json` 同源
   - ldid 签名；两种装法：
     - 越狱：打成 dev-only deb（包名 `com.iosdecrypthub.devtest`，独立于正式包），
       App 放 `<jbroot>/Applications/`，由 ElleKit 按启用名单注入 —— 走**真实**注入路径
     - 巨魔：用 `app-trollstore/` 现有工具链 patch 出 IPA
2. `tests/device_test.sh` —— SSH 驱动 + MCP 断言：
   - 断言复用 `tests/mcp_test.sh`（85 条）与 `tests/scenarios.json`
   - endpoint 从 `127.0.0.1:8088` 换成 `<设备IP>:8088`（与 idh 的连接方式一致，不新增端口）
   - 报告复用 `dh_write_results`，格式与阶段 0 相同（manifest / JUnit / 断言明细 / MCP 快照）
3. 设备前置清单（本节第四节）

## 四、设备前置

- 两台已越狱设备：rootless 一台、roothide 一台；均开启 OpenSSH
- 均为可解锁、可 respring、可重启用户空间的测试机（允许中断）
- 越狱设备上另装 1~2 个普通 App 作为"跨容器"类测试样本（免费 App 即可）
- 巨魔设备（若另有一台）：用于 L3
- 测试数据只用虚构哨兵值（沿用路线图 §3.1 的 `DH_FIXTURE_*` 约定）

## 五、1.25.0 专项（App + daemon）

- JB 仓 `docs/device_verification.md` 已列出 7 节清单，作为 L4/L5 的一部分执行。
- 其中 **daemon 能否被 launchd 拉起**在 roothide 上是未知项；该结论决定 roothide 走
  "全功能"还是"App 版 + 源升级"，必须在发布前有答案。

## 六、完成标准

对齐路线图 §四 九条（功能/精度/兼容/安全/性能/诊断/文档/架构/构建/验证），另加：

- 真机产物与提交可追溯：报告文件名含日期与设备标识
- 失败用例必须有可解释原因；"不确定"不得记为"通过"
- 完成后写 `docs/verification/L3_L4_<日期>.md`，沿用阶段 0 的记录模板

## 七、执行顺序

1. 建 `device_install.sh` 与 `device_test.sh`
2. 巨魔设备跑 L3（覆盖 9 场景 + 管理器 App）
3. rootless 设备跑 L4（先跑 9 场景一致性，再跑 1.25.0 App/daemon 清单）
4. roothide 设备跑 L4 + roothide 未知项
5. 各自出记录；L5 单独出记录
