# 越狱插件源码已迁出

加载器、设置面板和 deb 打包脚本现在位于工作区并列仓库：

```
../IOSDecryptHubJB/
```

本目录只保留入口脚本：编译闭源 `decrypt_helper.dylib`，拷进 `IOSDecryptHubJB/vendor/dylib/`，再调用开源仓打包。

```bash
make deb              # 仍从本私有仓触发，产物同步到 build/deb/
make deb-rootless
make deb-roothide
```

不要在本目录重新放入加载器源码。越狱层必须保持为薄加载器，源码以开源仓为准。
