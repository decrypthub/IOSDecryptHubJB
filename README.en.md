# IOSDecryptHubJB

An independent jailbreak runtime-analysis project for rootless / RootHide iOS devices. The product is one complete deb containing a persistent daemon, a phone Manager app, an injection loader and the Agent, updated together through an APT repository.

The [TrollStore edition](https://github.com/decrypthub/IOSDecryptHubTrollStore) is a separate project. Each project maintains its own main branch, versions and releases.

This project is public under the decrypthub organization. The existing public [IOSDecryptHub v1](https://github.com/decrypthub/IOSDecryptHub) contains a released Manager, loader, updater and package pipeline. Its release URLs remain in place; v2 should migrate those implementations instead of assuming they are absent.

The Manager enables or disables injection per app and shows both saved policy and the actual running state. The daemon continues without the Manager UI; the target app follows its ordinary lifecycle. The phone owns storage, bounded analysis, web and MCP services. A PC is optional.

The injected dylib remains an internal build artifact. Users do not download, compile, select or update it separately. Package managers such as Sileo / Zebra perform complete-package updates.

**Current status: aligned to the complete official v1 source at a94a396; no independent release has been published.** The existing Manager, loader, one-shot updater and complete deb build are restored, and both package variants build on the Mac. The new persistent analysis service, Manager redesign, scope IPC, package-update changes, Inline Hook and Trace remain planned.

Official downloads remain at [v1.27.5](https://github.com/decrypthub/IOSDecryptHub/releases/tag/v1.27.5). Local package builds are verification artifacts, not a new release. See the [baseline audit](./docs/BASELINE_AUDIT_2026-10-26.md).

Design documents:

- [Product architecture and delivery](./docs/PRODUCT_ARCHITECTURE.md)
- [Manager UI](./docs/MANAGER_UI.md)
- [Hook and Trace](./docs/HOOK_AND_TRACE_DESIGN.md)
- [Progress](./docs/PROGRESS.md)

[MIT license](./LICENSE); third-party notices: [NOTICE](./NOTICE).
