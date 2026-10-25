# IOSDecryptHubJB

An independent jailbreak runtime-analysis project for rootless / RootHide iOS devices. The product is one complete deb containing a persistent daemon, a phone Manager app, an injection loader and the Agent, updated together through an APT repository.

The [TrollStore edition](https://github.com/taisuii/IOSDecryptHub) is a separate project. Each project maintains its own main branch, versions and releases.

The Manager enables or disables injection per app and shows both saved policy and the actual running state. The daemon continues without the Manager UI; the target app follows its ordinary lifecycle. The phone owns storage, bounded analysis, web and MCP services. A PC is optional.

The injected dylib remains an internal build artifact. Users do not download, compile, select or update it separately. Package managers such as Sileo / Zebra perform complete-package updates.

**Current status: project and design migration only.** The imported legacy engine is available as a migration baseline; the new daemon, Manager, scope IPC, complete deb pipeline, APT channel, Inline Hook and Trace are not implemented. The production repository URL is not configured. Successful Mac builds of the legacy engine do not establish package or device acceptance.

Design documents:

- [Product architecture and delivery](./docs/PRODUCT_ARCHITECTURE.md)
- [Manager UI](./docs/MANAGER_UI.md)
- [Hook and Trace](./docs/HOOK_AND_TRACE_DESIGN.md)
- [Progress](./docs/PROGRESS.md)

[MIT license](./LICENSE); third-party notices: [NOTICE](./NOTICE).
