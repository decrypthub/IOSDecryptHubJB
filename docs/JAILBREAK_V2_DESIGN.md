# 越狱 v2 设计已更新为独立整包项目

2026-10-25 后续用户决策已替代本文件早期的“双分支 + 设备 Broker + 必需 PC Host”方案。

- 产品架构、手机常驻服务、逐应用注入、整包与 APT 更新：[PRODUCT_ARCHITECTURE.md](./PRODUCT_ARCHITECTURE.md)。
- 手机 UI：[MANAGER_UI.md](./MANAGER_UI.md)。
- 保留并更新的 Hook / ABI / 事件 / Trace 技术细节：[HOOK_AND_TRACE_DESIGN.md](./HOOK_AND_TRACE_DESIGN.md)。
- 实施状态：[PROGRESS.md](./PROGRESS.md)。

旧方案可在提交 4858677 查阅，不作为并行开发计划。当前独立项目只有 main，巨魔版在另一个仓库维护。
