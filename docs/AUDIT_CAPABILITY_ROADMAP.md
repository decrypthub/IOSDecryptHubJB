# IOSDecryptHub 审计能力演进与自验证计划

> 状态：阶段 0 已完成，阶段 1 待开始
> 基线版本：1.23.0
> 制定日期：2026-07-28
> 适用仓库：`IOSDecryptHub/` 与 PC 网关 `../idh/`
> 阶段 0 提交：`b33fc21`

本文档把 IOSDecryptHub 从“运行时事件捕获器”演进为“可验证的审计证据引擎”。每项能力必须先在项目自己的测试宿主中构造确定性场景，再实现能力，最后由自动化脚本通过 MCP 读取结果并完成正例、负例、安全性和资源消耗验证。

本文档不是一次性大改方案。必须按阶段交付，每个阶段独立可用、可回归、可回滚；前一阶段未达到完成标准时，不进入下一阶段。

---

## 一、不可突破的边界

所有实施工作必须服从 `docs/ARCHITECTURE_BOUNDARY.md`，尤其是：

- 共享核心只使用 fishhook 与 Objective-C method swizzle。
- 禁止 inline hook、trampoline、运行时生成机器码和 DBI。
- TrollStore 与 Jailbreak 共用 `src/` 下同一份核心。
- 越狱框架只负责加载 dylib，不得提供第二套 Hook 引擎。
- 不可信内存必须安全读取；任何失败不得导致宿主 App 崩溃。
- Hook 热路径不得执行网络请求或同步耗时 I/O。
- HTTP/MCP 固定复用 `0.0.0.0:8088`，MCP 固定为 `POST /api/mcp`。
- 设备连接由 idh 手动指定（`connect` / `--endpoint`）。
- 服务无认证，只允许在可信网络内使用。
- 测试数据只能使用明确标记的虚构数据，不提交真实密钥、口令或用户数据。

本路线明确不做：

- 任意内存写入、任意函数调用或运行时指令修改。
- TLS Pinning 绕过、业务结果篡改或默认开启的主动干预。
- 以“可能捕获”为依据宣称“完整覆盖”纯 Swift、静态链接 CryptoKit 或 corecrypto。
- 在设备端运行重量级规则引擎、全量 CFG 或无限制内存扫描。

---

## 二、目标状态

最终系统应能稳定回答五类问题：

1. **发生了什么**：哪个 API 在什么时间、线程、调用点执行，输入输出和返回结果是什么。
2. **数据从哪里来、到哪里去**：Keychain、随机数、文件、密码运算、序列化与网络事件如何形成数据链。
3. **观察是否可信**：目标是否导入该符号、Hook 是否真正安装、是否命中、是否丢弃或截断事件。
4. **为什么构成风险**：规则结论必须引用具体证据、调用栈、上下文与置信度。
5. **不同版本有什么变化**：两次测试之间新增、消失或改变了哪些安全行为。

目标数据流：

```text
测试场景
  -> Hook/Swizzle 观测
  -> 统一事件与上下文
  -> 证据节点和关系边
  -> HTTP/MCP 查询
  -> idh 规则分析与案件导出
  -> 自动断言、差异报告、人工复核
```

设备端只负责低开销、可边界化的采集与基础查询；关联推理、规则执行、案件归档和跨运行比较优先放在 `idh` PC 端完成。

---

## 三、自验证体系

### 3.1 复用现有测试宿主

不另起一套不可维护的 Demo 工程，继续使用：

- `tests/exercise_runner.m`：macOS 快速 Hook、HTTP、MCP 和静态分析回归。
- `sim_uitest/main.m`：iOS Simulator 上的 UIKit、沙箱、Keychain、NSURLSession 和注入回归。
- `tests/mcp_test.sh`：真实 HTTP/MCP 端到端断言。
- TrollStore 管理器注入后的测试 App：真机 TrollStore 验收。
- Jailbreak 加载器注入后的同一个测试 App：真机 Jailbreak 验收。

测试宿主必须只包含虚构的哨兵数据，例如：

```text
DH_FIXTURE_KEY_001
DH_FIXTURE_TOKEN_001
DH_FIXTURE_ACCOUNT_001
```

这些值必须在文件头或场景清单中注明“仅用于测试，不是真实凭据”。

### 3.2 五级验证环境

| 级别 | 环境 | 用途 | 每阶段要求 |
|---|---|---|---|
| L0 | 纯函数/解析器单元测试 | 数据模型、规则、序列化、边界输入 | 必须通过 |
| L1 | macOS `exercise_runner` | Hook、MCP、证据关联、静态分析快速回归 | 必须通过 |
| L2 | iOS Simulator `sim_uitest` | UIKit、沙箱、Keychain、网络与生命周期 | Hook 变更必须通过 |
| L3 | iOS 真机 TrollStore | arm64、真实 iOS Framework、注入和稳定性 | 里程碑发布前通过 |
| L4 | iOS 真机 Jailbreak | 三种加载器载体的一致性 | 涉及发布或加载器时通过 |

L4 不允许出现 Jailbreak 专属核心能力。它只验证加载方式不同、核心行为一致。

### 3.3 场景清单作为测试单一真相源

阶段 0 计划新增 `tests/scenarios.json`。每个场景至少包含：

```json
{
  "id": "flow.request-signing.sha256",
  "platforms": ["mac", "sim", "device"],
  "trigger": "request_signing",
  "expected_events": ["SHA256", "HTTP"],
  "expected_edges": ["derived_from", "sent_by"],
  "expected_findings": [],
  "timeout_ms": 5000
}
```

规则：

- 场景 ID 一旦发布不得改名；废弃时保留别名。
- 每个能力至少有一个正例和一个负例。
- 每个风险规则至少有“应命中”和“不应命中”两个场景。
- 自动化按场景完成条件轮询，不使用固定 `sleep` 作为成功依据。
- 预期值使用算法和结构断言，不把真实或长篇敏感载荷写入快照。

### 3.4 统一测试输出

阶段 0 计划统一写入：

```text
build/test-results/<run-id>/
  manifest.json
  junit.xml
  mcp-responses/
  host.log
  diagnostics.json
  coverage.json
  performance.json
```

`run-id` 由时间、平台和短随机串组成。临时目录使用 `mktemp -d`，避免多个测试进程互相覆盖 `/tmp/dh_*.json`。

---

## 四、所有阶段共用的完成标准

每个阶段只有同时满足以下条件才算完成：

- 功能：所有新增场景正例通过。
- 精度：对应负例不误报，模糊关联不得标记为“确定”。
- 兼容：现有 MCP 工具名、参数和旧字段不破坏。
- 安全：坏参数、坏地址、空对象、超大输入和超时均返回可解释错误，不崩宿主。
- 性能：达到第十四节资源预算，或记录获批的例外与原因。
- 诊断：安装失败、丢弃、截断、采样和降级路径均可见。
- 文档：新增字段、MCP 工具、已知盲区和可信网络警告已更新。
- 架构：`src/` 中没有越狱 Hook API、越狱路径、daemon 或可执行内存实现。
- 构建：`dev`、`trollstore`、`jailbreak` 三种变体至少完成编译检查。
- 验证：L0/L1 必须通过；涉及 Hook 的阶段必须通过 L2；发布里程碑必须完成 L3。

每次合并只完成一个可验证的小目标。推荐提交拆分：

1. 测试场景与失败断言。
2. 核心实现。
3. MCP/HTTP 暴露。
4. idh、Web 或文档集成。
5. 真机证据与性能结果。

---

## 五、阶段总览

| 阶段 | 交付目标 | 主要验证结果 |
|---|---|---|
| 0 | 确定性测试底座 | 一条命令产生结构化测试报告 |
| 1 | 事件模型 v2 | 每条事件可稳定标识、计时、判定截断和结果 |
| 2 | 覆盖率账本 | 能解释“未发现事件”的真实原因 |
| 3 | 证据图谱 | 稳定还原数据来源、变换和去向 |
| 4 | 高价值观测面 | 随机数、密钥、TLS、变换、存储和网络补面 |
| 5 | PC 端规则引擎 | 从证据生成可复核审计结论 |
| 6 | 静动态互证 | 运行时事件可定位到更完整的代码关系 |
| 7 | 案件包与差异 | 可复现、可校验、可比较测试结果 |
| 8 | 长稳与发布门禁 | 用稳定性和资源预算约束每次发布 |

建议版本仅用于排期，不在实施前预先修改版本号：

- 1.24：阶段 0 至 2。
- 1.25：阶段 3。
- 1.26：阶段 4。
- 1.27：阶段 5。
- 1.28：阶段 6 至 8。

---

## 六、阶段 0：建立确定性测试底座

### 6.1 目标

把当前“运行宿主、等待若干秒、人工查看面板”升级为场景驱动、可轮询、可归档的自动测试。

### 6.2 实施步骤

- [ ] 为 `exercise_runner` 增加 `--list-scenarios`、`--scenario <id>`、`--all` 和 `--timeout`。
- [ ] 保留当前手工常驻模式，但自动化模式在场景完成后可自行退出。
- [ ] 为 `sim_uitest` 建立统一场景注册表，URL Scheme 与 `DH_AUTOTEST` 共用同一触发实现。
- [ ] 将模拟器网络正例改为 dylib 实际回环地址，不依赖 `httpbin.org` 或其他公网服务。
- [ ] 新增 `tests/scenarios.json`，记录触发器、平台、预期事件、边和规则。
- [ ] 拆分 `tests/mcp_test.sh`：公共 MCP 调用、宿主生命周期和具体断言分别维护。
- [ ] 使用轮询等待 `get_stats`、事件序号或场景标记，不以固定等待时间判断成功。
- [ ] 使用独立临时目录、端口发现和退出清理，允许串行重复运行不污染结果。
- [ ] 新增架构边界检查脚本，扫描 `src/` 中的禁止 API、路径和额外监听端口。
- [ ] 将当前工具数量断言从“至少 30”改为关键工具清单断言，避免无意义增减掩盖兼容问题。

### 6.3 计划新增命令

以下命令在阶段 0 完成前不存在：

```bash
make test-unit
make test-audit-mac
make test-audit-sim
make verify-architecture
make verify-fast
```

`verify-fast` 应包含 L0、L1 和架构检查，不启动真机任务。

### 6.4 验证场景

- `baseline.crypto.digest`：SHA-256 输入输出完全匹配。
- `baseline.crypto.aes-roundtrip`：加密与解密事件均存在，输出可闭环。
- `baseline.file.lifecycle`：open、write、read、rename、unlink 顺序正确。
- `baseline.keychain.lifecycle`：add、copy、update、delete 状态完整。
- `baseline.network.request`：本机请求与响应配对，不依赖公网。
- `baseline.dynamic-load`：dlopen 后新增镜像与 Hook 健康状态可查询。
- `baseline.invalid-params`：每个 MCP 关键工具至少覆盖一个坏参数。

### 6.5 完成判定

- 连续运行 `make test-audit-mac` 10 次全部通过。
- 不存在遗留宿主进程、固定临时文件冲突或端口误判。
- 断网环境下全部 L1 网络场景通过。
- 模拟器自动启动、触发场景、轮询结果并退出，无需人工点击。
- 现有 `make test-mcp` 的有效断言全部迁移或继续保留。

---

## 七、阶段 1：事件模型 v2

### 7.1 目标

让每条事件具备稳定身份、精确计时、执行结果、采集质量和可关联数据指纹，同时保持现有 API 兼容。

### 7.2 建议字段

公共字段：

- `schemaVersion`：从 2 开始；旧事件缺省按 1 处理。
- `sessionId`：宿主进程本次启动的随机标识。
- `eventId`：`sessionId + seq` 的稳定组合。
- `monotonicNs`：用于排序和耗时，墙钟只用于展示。
- `durationNs`：能测量时记录；未知为 0。
- `threadId` 与 `queueLabel`：队列标签只做提示，不作为因果证明。
- `resultCode`、`succeeded`：保留原始 API 结果语义。
- `captureFlags`：截断、采样、安全读取失败、降级解码等状态。
- `inputLength`、`outputLength`：始终记录原始长度。
- `inputDigest`、`outputDigest`：使用 SHA-256 标识数据，不依赖保存完整内容。
- `imageUUID`、`callSite`、`callSiteVMAddr`：用于跨运行稳定定位。

### 7.3 实施步骤

- [ ] 先定义事件 JSON v2 文档和兼容策略，再改 `DHLogEntry`。
- [ ] 建立统一事件初始化函数，消除各 Hook 重复设置时间、线程和调用栈的差异。
- [ ] 摘要计算设置尺寸阈值；热路径不得为超大输入重复复制整块数据。
- [ ] 对完整内容设置独立的最大捕获字节数，超过上限保留长度、摘要与截断标志。
- [ ] 保持 `query_events`、`get_event` 的旧字段；新增字段只做向后兼容扩展。
- [ ] 持久化记录带 schema 版本，未知新字段可以跳过。
- [ ] `get_stats` 增加当前 schema、session 和截断/丢弃计数。

### 7.4 自验证

正例：

- 同一输入的两条事件 `inputDigest` 相同。
- 不同输入的摘要不同。
- 流式 AES 各阶段共享上下文，但事件 ID 唯一。
- 超过捕获上限的 128 KB 场景保留原始长度、摘要和 `truncated=true`。

负例与安全：

- 空输入与零长度输入不得混淆。
- 安全读取失败时不得生成虚假摘要。
- 旧客户端只读取旧字段仍能完成现有测试。
- 并发产生 10,000 条事件，`eventId` 不重复、排序稳定、宿主不崩溃。

### 7.5 完成判定

- 所有内置 Hook 使用统一事件初始化路径。
- MCP v1 消费者无需修改即可继续工作。
- 大数据事件不再依赖保存完整输入才能参与后续关联。
- 事件截断和读取失败能够被查询，而不是静默发生。

---

## 八、阶段 2：覆盖率账本

### 8.1 目标

准确区分：目标未导入、Hook 已安装未命中、安装失败、被禁用、事件被过滤以及技术上不可观测。

### 8.2 覆盖状态

每个观测点至少包含：

- `declared`：构建中存在该能力。
- `importedImages`：哪些镜像导入了目标符号。
- `reboundSlots`：实际改写的槽位数量。
- `installStatus`：`installed`、`not_imported`、`failed`、`unsupported`、`disabled`。
- `hitCount`：进入 Hook 的次数。
- `recordedCount`：成功形成事件的次数。
- `skippedCount`：配置关闭、递归保护、噪点分流或采样跳过次数。
- `readFailureCount` 与 `truncatedCount`。
- `lastHitMonotonicNs` 与最后错误原因。

### 8.3 实施步骤

- [ ] 新增纯 C、定长或有明确上限的 coverage registry。
- [ ] fishhook 安装路径返回按符号、镜像、槽位统计，而非只记录失败字符串。
- [ ] 每个静态 Hook 在入口执行廉价原子计数。
- [ ] 动态 Hook 复用同一账本，不另造状态模型。
- [ ] 新增 MCP `get_coverage`，支持按模块、符号、状态筛选。
- [ ] `get_capabilities` 返回“理论能力”，`get_coverage` 返回“当前宿主实际覆盖”，文档明确区别。
- [ ] Web 面板只展示摘要，不在 UI 主线程计算完整覆盖表。

### 8.4 自验证场景

- `coverage.imported-hit`：调用 `CC_SHA256` 后状态为 installed 且 hit/recorded 增长。
- `coverage.imported-no-hit`：导入但不调用的测试符号显示 installed、hit=0。
- `coverage.not-imported`：宿主不导入的符号显示 not_imported，不显示 failed。
- `coverage.disabled`：关闭捕获后 hit 增长、recorded 不增长、skipped 增长。
- `coverage.dynamic-image`：dlopen 测试库后账本新增镜像与槽位。
- `coverage.recursion-guard`：内部日志引发的系统调用计入 skipped，不污染主事件。

### 8.5 完成判定

- 对任一“没有事件”的 Hook，`get_coverage` 都能给出明确原因。
- 纯 Swift/静态链接能力显示 unsupported 或 blind spot，不显示为已覆盖。
- Hook 失败不再只靠文本诊断判断。
- 覆盖计数自身不会产生递归事件。

---

## 九、阶段 3：证据图谱与因果关联

### 9.1 目标

把孤立事件组织为“来源 -> 变换 -> 去向”的证据图，并明确关系的证据强度。

### 9.2 图模型

节点：

- `event`：一次 API 行为。
- `artifact`：由摘要标识的一段数据、文件、URL、证书或 Keychain 条目。
- `context`：`CCCryptorRef`、`EVP_CTX`、fd、NSURLSessionTask 等生命周期对象。
- `code`：镜像 UUID、稳定 VM 地址和函数。

边：

- `consumes` / `produces`
- `derived_from`
- `reads` / `writes`
- `sent_by` / `received_by`
- `created_by` / `released_by`
- `executed_at`

置信度：

- `exact`：上下文 ID、完整摘要或明确 API 生命周期一致。
- `strong`：变换规则可逆验证，例如 Base64 解码后摘要匹配。
- `heuristic`：只依赖时间窗、线程或调用栈相似。

只有 `exact` 和 `strong` 可以在 UI/MCP 中称为“已关联”。`heuristic` 必须显示为候选。

### 9.3 实施步骤

- [ ] 为有生命周期的 API 建立有界 context registry，释放时及时删除。
- [ ] fd 关系包含路径、打开事件、读写事件和关闭事件，处理 fd 复用。
- [ ] NSURLSessionTask 使用对象身份关联请求、resume、响应和错误。
- [ ] 密码事件通过输入/输出摘要生成 artifact 节点。
- [ ] 实现 Base64、hex 等明确变换的 PC 端关联器。
- [ ] 将现有 `correlate_request` 保留为兼容入口，内部优先读取图关系，时间窗作为降级路径。
- [ ] 新增 MCP `get_trace`、`find_data_path`、`explain_value`。
- [ ] 所有查询限制节点数、边数和遍历深度，超限返回 `capped=true`。

### 9.4 自验证场景

正例：

- `flow.request-signing.sha256`：JSON body -> SHA-256 -> Base64 -> Header -> HTTP。
- `flow.encrypt-store-send`：Keychain 读 -> AES -> 文件写 -> 网络发送。
- `flow.stream-cipher`：Create -> 多次 Update -> Final -> Release 生命周期完整。
- `flow.async-request-signing`：密码运算与响应不在同一线程，仍可通过数据和 task 上下文关联。

负例：

- 两次相邻 SHA-256 只有一个进入 Header，不得把两条都标成 exact。
- 相同长度但内容不同的数据不得关联。
- 相同内容在两个独立场景出现时，必须用 session/context/场景边界避免错误合并。
- 只有时间相近而没有数据或上下文证据时，只能返回 heuristic。

### 9.5 完成判定

- `flow.request-signing.sha256` 不需要扩大时间窗即可闭环。
- 异步场景跨线程仍能闭环。
- 每条边都能返回形成该关系的依据。
- 查询 10,000 个事件时有明确上限，不阻塞宿主主线程。

---

## 十、阶段 4：扩展高价值观测面

阶段 4 必须按 4A 至 4E 分批实现，每一批单独合并和验收。

### 10.1 阶段 4A：随机数与密钥生命周期

候选 API：

- `SecRandomCopyBytes`
- `SecKeyCreateRandomKey`
- `SecKeyCopyPublicKey`
- `SecKeyCopyAttributes`
- `SecKeyCopyExternalRepresentation`，只记录调用和结果元数据，默认不保存私钥内容

记录重点：请求字节数、结果码、密钥类型、位数、token/Secure Enclave 属性、调用点和数据摘要。

测试场景：

- 安全随机 IV 正例。
- 固定 IV 与全零 IV 风险场景。
- RSA/EC 密钥创建与属性读取。
- Secure Enclave 不可导出路径只记录元数据，不将失败判成 Hook 故障。

完成条件：能区分随机生成、固定常量与未知来源，不暴露不可导出的私钥材料。

### 10.2 阶段 4B：TLS 信任决策

候选 API：

- `SecTrustEvaluateWithError`
- 兼容系统上的 `SecTrustEvaluate`
- `SecTrustSetAnchorCertificates`
- `SecTrustSetPolicies`

记录重点：主机名、证书链长度、叶子证书/SPKI 摘要、策略、最终结果和错误域；不保存私钥，不实现绕过。

测试使用仓库内专用的公开测试证书 fixture，不提交对应私钥。正例、过期、主机名不匹配和自定义 anchor 分开验证。

完成条件：测试宿主得到的系统信任结果与审计事件一致；观测功能关闭后不改变系统结果。

### 10.3 阶段 4C：数据变换

候选能力：

- NSData Base64 编解码。
- `NSJSONSerialization` 编解码。
- zlib 与 Compression.framework 的压缩/解压。
- Property List 编解码。

实施原则：

- 先实现低频、稳定、可避免自身递归的入口。
- 所有高频方法必须通过基准测试后才能默认开启。
- 记录变换前后摘要、长度与格式，不默认保存超大完整内容。

测试场景：`JSON -> gzip -> Base64 -> HTTP` 必须生成可验证的 strong 数据链；随机相邻事件不得误连。

### 10.4 阶段 4D：存储安全

候选能力按风险逐项评估：

- Keychain accessibility 与 access-control 语义补全。
- 文件保护等级和扩展属性。
- `NSUserDefaults` 写入敏感哨兵值。
- SQLite `sqlite3_bind_*` 与 `sqlite3_column_*`，只在目标导入且显式开启时使用。

测试场景：

- 相同哨兵数据分别写入 Keychain、受保护文件、UserDefaults 和 SQLite。
- 规则应区分推荐存储与弱存储。
- SQLite 1,000 次循环不得造成不可接受的热路径开销。

### 10.5 阶段 4E：网络覆盖补面

候选能力：

- NSURLSession delegate 型请求与响应。
- upload/download task 的流式和文件路径信息。
- WebSocket task。
- Network.framework 的可 fishhook 导入入口。

完成条件：

- `get_coverage` 明确报告当前 App 使用了哪类网络栈。
- completion、delegate 和 WebSocket 各有独立正例。
- 未支持的纯内部系统网络路径显示盲区，不宣称已捕获。
- 请求观测关闭时，原始 completion/delegate 调用次数与顺序不改变。

---

## 十一、阶段 5：PC 端规则引擎

### 11.1 目标

在 `idh` 中把证据转成可复核的审计发现。保持 Python 零运行时依赖，只使用标准库。

### 11.2 规则输出模型

每条发现包含：

- 稳定 `ruleId`，例如 `IDH-CRYPTO-001`。
- 标题、严重程度、置信度和分类。
- 证据事件 ID、证据边与调用点。
- 判断条件和为何命中。
- 已知误报条件与复核建议。
- App build、镜像 UUID、session 和工具版本。
- 可选 CWE/MASVS 映射。

首批规则：

- MD5/SHA-1 用于安全决策，而不是只因调用就告警。
- ECB、固定/全零 IV、同密钥重复 IV。
- PBKDF2 迭代次数或派生密钥长度不足。
- 密钥或 token 进入 UserDefaults、弱文件保护或网络。
- Keychain accessibility/access-control 过宽。
- 自定义 trust anchor 或异常信任结果。
- 私钥导出尝试。

### 11.3 实施步骤

- [ ] 先定义规则输入 schema 和 finding schema。
- [ ] 规则是纯函数：输入 case/trace，输出 findings，不直接访问网络或设备。
- [ ] 新增 `idh audit`，默认输出人读摘要，支持 `--format json`。
- [ ] 新增 SARIF 输出，供 CI 归档；不增加第三方依赖。
- [ ] 新增抑制文件，按 ruleId、镜像 UUID、函数稳定地址和到期时间精确抑制。
- [ ] MCP 网关增加 `idh_run_audit`，不得把全部设备原始数据默认回传给模型。
- [ ] 每条规则维护正例、负例和边界 fixture。

### 11.4 自验证

每条规则至少包含：

- 一个确定命中场景。
- 一个外观相似但不应命中的场景。
- 一个缺少证据只能返回低置信候选的场景。
- 一个旧 schema 或字段缺失兼容场景。

完成条件：内置 fixture 结果完全确定；重复运行 findings 顺序与稳定 ID 一致；负例集误报数为 0。

---

## 十二、阶段 6：静态与动态互证

### 12.1 目标

让运行时事件从调用栈地址继续追到函数、引用、元数据和有限调用图，同时诚实表达分析边界。

### 12.2 分批能力

- Mach-O：sections、imports、exports、UUID、chained fixups、加密信息、签名与 entitlements 摘要。
- Objective-C：class、category、protocol、method、selector 与 IMP 清单。
- Swift：符号解码和可解析的类型元数据；无法可靠解析时返回原始符号与原因。
- 控制流：基本块、直接分支、尾调用、有限局部传播可确认的 `BLR` 候选。
- 动态互证：事件 callSite -> function -> callers/callees -> string/selector refs。

### 12.3 性能与安全约束

- 扫描继续使用安全内存快照，不直接长时间解引用镜像裸地址。
- 所有扫描按镜像 UUID 缓存，并带最大字节、指令、结果和时间预算。
- 重量分析异步执行，不占 Hook 线程和主线程。
- 不能证明的间接调用返回候选集合，不伪造成唯一目标。

### 12.4 自验证二进制

在 `exercise_runner` 中增加明确标记且禁止内联的函数：

- 直接调用。
- 函数指针间接调用。
- 尾调用。
- switch/jump table。
- Objective-C classic msgSend 与 `__objc_stubs` 两种构建变体。
- stripped 与 unstripped 两种产物。

每种边必须断言调用点、来源函数、目标函数、稳定 VM 地址和置信度；不存在的边必须为 0。

完成条件：直接边保持当前精度，新增间接候选不引入既有负例误报，stripped 目标仍能通过 UUID + VM 地址稳定定位。

---

## 十三、阶段 7：案件包与跨运行差异

### 13.1 目标

让一次测试可以被保存、校验、离线复核，并与后续版本比较。

### 13.2 案件包结构

计划由 `idh case collect` 生成：

```text
case-<app>-<run-id>.zip
  manifest.json
  process.json
  capabilities.json
  coverage.json
  events.jsonl
  traces.jsonl
  findings.json
  diagnostics.json
  artifacts/
  checksums.sha256
```

约束：

- 默认脱敏：密钥、token、Cookie、Authorization、请求体和 Keychain data 只保存摘要、长度和有限预览。
- 原始敏感内容只能通过显式 `--include-sensitive` 开启，并显示可信环境警告。
- `checksums.sha256` 用于检测意外损坏，不宣称能够抵御恶意篡改。
- bundle 中不得包含项目运行所不需要的真实用户数据。

### 13.3 差异模型

`idh case diff old.zip new.zip` 比较：

- 新增/消失的观测能力与盲区。
- 新增/消失的 Hook 命中。
- 新增/修复的 findings。
- 稳定调用点上的算法、参数和数据去向变化。
- 无法比较的镜像或 schema，并明确原因。

### 13.4 自验证

- 同一 fixture 连续两次运行，去除时间和 session 后语义差异为空。
- 修改 AES-CBC 为 ECB，只出现预期规则和事件差异。
- 修改一个二进制字节后 checksum 验证失败。
- 脱敏包中搜索哨兵原文结果为空，但摘要仍能关联。
- v1/v2 schema 案件能够读取，未知新字段不导致失败。

---

## 十四、阶段 8：稳定性、性能与发布门禁

### 14.1 每阶段资源预算

先在阶段 0 记录基线；后续使用同一设备、同一构建和五轮中位数比较。

初始门槛：

- 关闭某捕获项后，对应测试循环耗时增幅不超过 5%。
- 开启普通捕获后，10,000 次短调用循环耗时增幅不超过 20%；超高频 API 必须单独制定预算或默认关闭。
- 10,000 个保留事件下，常用 MCP 查询 p95 小于 300 ms。
- 清空事件并等待 10 秒后，RSS 相对启动稳定值增长不超过 20 MB。
- 模拟器 30 分钟压力测试无 crash、死锁或未解释的持续内存增长。
- 真机 2 小时混合场景无宿主退出；后台/前台切换后服务与 Hook 状态正确。

若设备噪声导致门槛不稳定，必须记录原始结果并调整测量方法，不能直接删除性能测试。

### 14.2 故障场景

- 非法内存地址和跨页读取。
- 超大 MCP 参数、深层 JSON、未知工具和缺失字段。
- 端口占用、网络断开和客户端半开连接。
- 日志目录不可写、磁盘空间不足和文件轮转。
- 分配失败可测试模块的失败注入。
- 并发调用 Hook、清空事件、修改开关和查询事件。
- 动态镜像加载期间执行 Xref/扫描。
- App 进入后台、恢复、重复启动和被系统终止。

故障注入只允许存在于测试构建，不得暴露为生产 MCP 的任意破坏接口。

### 14.3 发布门禁

计划新增 `make verify-release`，依次执行：

```text
架构边界检查
  -> L0 单元测试
  -> L1 macOS E2E
  -> 三变体构建
  -> 模拟器 E2E 与 30 分钟压力测试
  -> idh lint/pytest
  -> 案件包脱敏检查
  -> 真机验收记录存在性检查
```

真机测试不适合在普通 CI 自动完成，但发布清单必须附设备、iOS 版本、注入路线、测试 run-id 和结果摘要。

---

## 十五、建议的首批场景矩阵

| 场景 ID | 正例目标 | 关键负例 | 平台 |
|---|---|---|---|
| `baseline.crypto.digest` | SHA-256 事件准确 | 相邻 MD5 不得混入 | mac/sim/device |
| `baseline.crypto.aes-roundtrip` | encrypt/decrypt 闭环 | 错误 key 不得标记成功 | mac/sim/device |
| `flow.request-signing.sha256` | body->hash->base64->header | 相邻未使用 hash 不得关联 | mac/sim/device |
| `flow.stream-cipher` | Create/Update/Final/Release | 释放后 context 不得复用 | mac/device |
| `coverage.imported-no-hit` | installed、hit=0 | 不得显示 failed | mac |
| `coverage.disabled` | hit 与 skipped 增长 | recorded 不得增长 | mac/sim |
| `entropy.sec-random` | 随机来源被识别 | 固定 IV 不得识别为随机 | sim/device |
| `rule.crypto.ecb` | 命中 ECB | CBC 不命中 | mac/sim |
| `rule.crypto.iv-reuse` | 同 key/IV 重用告警 | 不同随机 IV 不告警 | mac/sim |
| `rule.kdf.low-iterations` | 低迭代命中 | 合理阈值不命中 | mac/sim |
| `trust.evaluate` | 结果与系统一致 | 观测不得改变结果 | sim/device |
| `transform.json-gzip-base64` | strong 数据链 | 仅时间相近不关联 | mac/sim |
| `storage.sensitive-sinks` | 区分存储等级 | Keychain 安全项不误报 | sim/device |
| `safety.invalid-memory` | 返回错误 | 宿主不崩溃 | mac/sim/device |
| `perf.hot-path` | 输出性能报告 | 超预算阻断发布 | mac/sim/device |

---

## 十六、阶段验收记录模板

每个阶段在 PR 或 `docs/verification/` 中保存以下摘要，不提交捕获到的敏感内容：

```markdown
# 阶段 N 验收

- 版本/commit：
- 测试 run-id：
- macOS/Xcode：
- 模拟器型号/iOS：
- 真机型号/iOS：
- 注入路线：dev / TrollStore / Jailbreak

## 场景
- [ ] 正例全部通过
- [ ] 负例全部通过
- [ ] 安全边界全部通过
- [ ] 性能预算通过

## 结果
- PASS：
- FAIL：
- 已知盲区：
- 获批例外：
- 回滚方式：
```

---

## 十七、立即可执行的第一个迭代

第一轮只做阶段 0，不同时修改事件模型或增加新 Hook：

1. 将 `exercise_runner` 的现有调用拆成稳定场景 ID。
2. 建立 `tests/scenarios.json`。
3. 将模拟器网络场景改为本机回环，去除公网依赖。
4. 新建测试公共脚本，使用轮询和独立临时目录。
5. 让 macOS 与模拟器输出同一种 `manifest.json` 和 JUnit 结果。
6. 增加架构边界自动检查。
7. 连续运行 macOS 测试 10 次，修复所有不确定性。
8. 在模拟器上跑通同一批核心场景。
9. 记录第一份性能和稳定性基线。
10. 阶段 0 验收通过后，再开始事件模型 v2。

阶段 0 的目标不是增加任何产品功能，而是让后续每项能力都能证明“确实工作、没有误报、没有改变宿主行为、没有突破架构边界”。这套验证底座完成后，后续阶段必须坚持“先加场景，再实现，再用 MCP 自证”的顺序。
