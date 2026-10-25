# 越狱插件源码已迁出

本仓库的越狱版由 [`jailbreak`](https://github.com/taisuii/IOSDecryptHub/tree/jailbreak) 分支独立维护，`main` 为巨魔版维护分支。越狱开发与打包前先执行 `git fetch origin`、`git switch jailbreak`。

加载器、设置面板和 deb 打包脚本现在位于工作区并列仓库：

```
../IOSDecryptHubJB/
```

本目录只保留入口脚本：编译闭源 `decrypt_helper.dylib`，拷进 `IOSDecryptHubJB/vendor/dylib/`，再调用开源仓打包。

并列仓库不在默认位置时，可用 `DH_JB_DIR` 指定其路径。

```bash
make deb              # 仍从本私有仓触发，产物同步到 build/deb/
make deb-rootless
make deb-roothide
```

不要在本目录重新放入加载器源码。越狱层必须保持为薄加载器，源码以开源仓为准。

后续将在 `jailbreak` 维护线推进 Inline Hook、函数调用 Trace / 调用链分析，并探索指令级追踪；这些目前属于规划。高级能力由越狱侧独立扩展承载，保持共享 `src/` 的 fishhook + ObjC swizzle 边界，详见 [架构约束](../docs/ARCHITECTURE_BOUNDARY.md)。
