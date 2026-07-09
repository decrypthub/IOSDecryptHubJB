# Capstone + MCP 集成

在注入的 dylib 内提供一个 **MCP (Model Context Protocol) 服务器**，AI 客户端可通过 HTTP 调用 Capstone 反汇编与镜像分析能力。

## 传输与协议

- **传输**：MCP Streamable HTTP，端点 `POST /api/mcp`，复用现有 8088 HTTP 服务（不额外占端口）。
- **协议**：JSON-RPC 2.0，支持 `initialize` / `notifications/initialized` / `ping` / `tools/list` / `tools/call`。
- **内容协商**：`Accept: text/event-stream` 时以单帧 SSE 返回，否则 `application/json`。
- **会话**：`initialize` 应答下发 `Mcp-Session-Id` 头，客户端后续请求回带。
- **协议版本**：支持 `2024-11-05` / `2025-03-26` / `2025-06-18`，`initialize` 回显客户端请求的版本（不支持则回 `2024-11-05`）。
- `GET /api/mcp` 不提供服务端主动推流，按规范返回 `405 Allow: POST`。

> ⚠️ 与本项目其它端点一致：MCP 服务**无认证**，仅供可信网络调试。

## 工具

| 工具 | 说明 | 必填参数 |
|------|------|---------|
| `disassemble` | 反汇编一段 hex 字节（容忍空格/`0x`前缀） | `bytes` |
| `analyze_function` | 安全读取进程内存 `address..+size` 并反汇编（`vm_read_overwrite` 防护，不可读地址返回 isError 而非崩溃） | `address`, `size` |
| `list_imports` | 列举某镜像的导入（undefined）符号 —— fishhook 可 rebind 的候选 | `image_index` |
| `get_macho_info` | 列举 App bundle 内已加载镜像：load_address、cryptid、加密状态 | 无 |
| `find_xrefs` | 「谁调用了它」：扫某镜像 `__TEXT,__text` 里所有直接 `bl` 到目标符号/地址的调用点，经运行时已绑定的 GOT + dladdr 把 import stub 还原成真实符号 | `symbol` 或 `address` |
| `find_string_refs` | 「谁引用了这个字符串」：扫 `__text` 的 `ADRP+ADD`（直接）/ `ADRP+LDR`（间接指针槽）恢复的数据地址，落在字符串 section 则记引用点 | `string` 或 `address` |
| `find_selector_refs` | 「谁把这个 selector 用在了 objc 调用上」：扫 `__text` 的 objc_msgSend 调用点（经典 selref+`blr` 或现代 `__objc_stubs`），只报真实调用不报裸 selref 加载 | `selector` |

可选参数：`disassemble`/`analyze_function` 的 `arch`（`arm64`/`arm`/`thumb`，默认 arm64）；`list_imports` 的 `query`（子串过滤）、`limit`；`find_xrefs` 的 `image`（镜像名子串，默认主程序）、`max_results`（默认 256）。

`find_xrefs` 仅 tier-1：只认直接 `bl`（不含 `blr`/`br` 间接调用、无 string/selector 引用、无 CFG）。三种 `kind`：`call_direct`（本镜像内部函数）/`call_import_stub`（经 `__stubs`/`__auth_stubs` 的导入 API）/`call_objc_stub`（经 `__objc_stubs` 的 `objc_msgSend$sel` 降级 stub）。lazy slot 尚未绑定时目标记为未知但仍保留调用点。`resolved_name` 反映**运行时真正到达的目标**——若该导入被 fishhook 改写，会如实显示 hook 符号。

**函数归属（tier-1.5）**：每条结果带 `from_func`（`main+0x50` 或 strip 后 `sub_<runtime>+0x50`）、`from_func_start`（函数起点运行时地址）、`from_func_offset`、`from_func_vmaddr`（起点 vmaddr，去 slide，跨 ASLR 稳定，宜作 ID）。归属优先用 `dladdr` 符号，无符号时用 `LC_FUNCTION_STARTS`；`from_func` is resolved by `LC_FUNCTION_STARTS` when available, and function end is approximated by the next function start（不是完整函数边界恢复）。

**`find_string_refs`（tier-2A）**：谁引用了某字符串。给 `string`（子串匹配）或 `address`（精确字符串地址），可选 `image`（默认主程序）、`max_results`。识别两种取址模式——`ADRP+ADD`（直接，`indirect:false`，目标在被扫镜像的 `__cstring`/`__objc_methname`/`__objc_classname`/`__objc_methtype`）与 `ADRP+LDR`→指针槽（间接，`indirect:true`，仅认 `__objc_selrefs`/`__got`/... 白名单槽；运行时 selref 已定到别处的 SEL，目标可能跨镜像，section 标 `(external)` 但字符串内容仍如实读出）。局部窗口回溯：按寄存器缓存最近 `ADRP` 页，寄存器被写即失效，不做跨基本块/跨函数数据流。每条结果带 `ref_site`、`string`、`string_addr`、`string_vmaddr`、`section`、`instruction`、`indirect`，以及与 find_xrefs 同款的 `from_func` 归属字段。

**`find_selector_refs`（tier-2B）**：谁把某 selector 用在了 objc 调用上——xref 站点是 `objc_msgSend` 的 **call_site**，不是裸 selref 加载。给 `selector`，可选 `match`（`exact`/`contains`/`prefix`，默认 exact）、`image`、`max_results`。两条路径：**A 经典** `adrp+ldr x1,[__objc_selrefs]` → `blr/bl objc_msgSend`（靠 x1 状态机 + 跟踪哪个寄存器持 msgSend 指针；`target_kind:objc_msgsend`，带 `selector_load_site`/`selector_slot`）；**B 现代** `bl <__objc_stubs 的 objc_msgSend$sel>`（`target_kind:objc_stub`，`selector_source:__objc_stubs`）。x1 被覆盖或只加载未调用不报，仅命中 `__objc_methname` 不报，不还原 receiver。每条结果带 `call_site`、`selector`、`target`、`target_kind`、`selector_source`、`instruction` 及 `from_func` 归属字段。因此 `find_string_refs("bytes")` 可有结果，但 `find_selector_refs("bytes")` 只在它真参与 objc 调用时才有。

工具执行错误走 MCP 的 `isError:true` content 信封（非 JSON-RPC 协议错误）；返回同时含 `structuredContent`（机器可读）与 `content[].text`（JSON 文本）。

## 调用示例

初始化握手：
```bash
curl -X POST http://<ip>:8088/api/mcp -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
       "params":{"protocolVersion":"2025-06-18","capabilities":{},
                 "clientInfo":{"name":"my-client","version":"1"}}}'
```

发现工具：
```bash
curl -X POST http://<ip>:8088/api/mcp -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```

反汇编字节：
```bash
curl -X POST http://<ip>:8088/api/mcp -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call",
       "params":{"name":"disassemble",
                 "arguments":{"bytes":"fd7bbfa9 fd030091 c0035fd6","arch":"arm64"}}}'
```
返回（节选）：
```json
{"jsonrpc":"2.0","id":3,"result":{
  "isError":false,
  "structuredContent":{"count":3,"instructions":[
    {"address":"0x0","mnemonic":"stp","op_str":"x29, x30, [sp, #-0x10]!","bytes":"fd7bbfa9","size":4},
    {"address":"0x4","mnemonic":"mov","op_str":"x29, sp","bytes":"fd030091","size":4},
    {"address":"0x8","mnemonic":"ret","op_str":"","bytes":"c0035fd6","size":4}]},
  "content":[{"type":"text","text":"{ ...上面的 JSON... }"}]}}
```

分析进程内某函数（先用 `get_macho_info` 拿 `load_address`，再喂给 `analyze_function`）：
```bash
curl -X POST http://<ip>:8088/api/mcp -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call",
       "params":{"name":"analyze_function",
                 "arguments":{"address":"0x1029ac000","size":64,"arch":"arm64"}}}'
```

## 实现

| 文件 | 职责 |
|------|------|
| `src/core/capstone/` | Capstone 5.0.1 源码（仅 ARM/AArch64） |
| `src/core/analysis.h/m` | Capstone 反汇编 + `vm_read_overwrite` 读内存 + macho 镜像枚举 |
| `src/server/mcp_server.h/m` | MCP 方法分发 + 工具执行 + content 信封 |
| `src/server/http_server.m` | `handle_mcp`：Streamable HTTP 传输（SSE 协商 / 通知 202 / 会话头 / 批量） |
| `Makefile` | `CAPSTONE_SRC` 源文件 + `CAPSTONE_DEF` 宏 |

### Capstone 编译宏（关键）

Capstone 以源码方式嵌入，**必须**定义以下宏（在 `Makefile` 的 `CAPSTONE_DEF`），否则运行时失败：

- `CAPSTONE_USE_SYS_DYN_MEM` —— 用系统 `malloc/free`，缺失则 `cs_open` 返回 `CS_ERR_MEMSETUP`
- `CAPSTONE_HAS_ARM` / `CAPSTONE_HAS_ARM64` —— 注册 ARM/AArch64 架构，缺失则 `cs_open` 返回 `CS_ERR_ARCH`

只编 ARM/AArch64 架构，产物 dylib 约 2MB。

## 边界

- **`get_macho_info` 作用域**：仅列 App bundle 内已加载镜像（不含系统库；`PlugIns/*.appex` 等独立进程也不在内）。在非 `.app` 宿主（如 mac 灰度测试的裸可执行）下会返回空列表——这是 `dh_dump_list_images` 的既有行为，非缺陷。
- **`analyze_function` 读的是本进程内存**：地址须是目标进程内已映射的地址；不可读时安全返回 `isError`。
- 无 `resources/prompts` 能力，`initialize` 只声明 `tools`。

## 快速验证（macOS 灰度）

```bash
make mac        # 编译 mac dylib
# 用任意宿主进程注入并保持存活, 然后 curl POST /api/mcp
```
`disassemble` / `list_imports` / `ping` / `initialize` 在 mac 下即可完整验证；`get_macho_info` / `analyze_function` 需真机 iOS App 环境才有实际镜像数据。
