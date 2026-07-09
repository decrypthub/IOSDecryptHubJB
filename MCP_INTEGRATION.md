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

可选参数：`disassemble`/`analyze_function` 的 `arch`（`arm64`/`arm`/`thumb`，默认 arm64）；`list_imports` 的 `query`（子串过滤）、`limit`。

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
