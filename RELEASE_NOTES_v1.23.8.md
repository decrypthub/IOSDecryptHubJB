## IOSDecryptHub v1.23.8

本版本改善大型 App 和多插件注入环境下的运行时逆向工作流。

### 新增

- 新增完整 dyld 镜像地图，包含 UUID、slide、可执行范围和加密信息。
- 新增 Objective-C 方法实体查询，可按类、selector、声明镜像和当前 IMP 镜像过滤。
- 四个 xref 工具支持按 `scan_offset` / `scan_size` 分页扫描大型 `__text`。

### 改进

- xref 响应增加覆盖区间、实际读取字节、不可读页、截断原因和下一页 offset。
- IMP 和符号解析增加 PAC 归一化与真实镜像归属。
- `objc_resolve_imp` 明确返回当前运行时 IMP，不再暗示可恢复第三方 swizzle 前实现。
- 保留原 MCP 工具名和兼容字段，现有客户端无需修改。

### PC 网关

- `idh 0.2.2` 新增 `idh connect <host:port>` 持久手动连接，UDP 扫描失败时可直接指定设备。

> HTTP/MCP 服务无认证，仅限可信网络使用。
