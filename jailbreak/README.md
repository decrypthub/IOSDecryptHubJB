# IOSDecryptHub 越狱注入包

<div align="right">
  <b>中文</b> | <a href="./README.en.md">English</a>
</div>


> 通过 rootless 环境的 ElleKit 将主 dylib 注入目标 App。
> 支持 Dopamine、palera1n 等普通 rootless 环境，以及 roothide 环境。

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│  ElleKit                                                    │
│  加载 IOSDecryptHubLoader.dylib 到 UIKit App                 │
└──────────────────────────┬──────────────────────────────────┘
                           │ %ctor / constructor
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  IOSDecryptHubLoader.dylib（薄层加载器）                      │
│  1. 读取插件自带的 enabledBundles.plist                     │
│  2. 检查当前 bundleID 是否在启用列表中                        │
│  3. 如果启用 → dlopen 主 dylib                               │
│  4. 如果未启用 → 立即返回（零开销）                           │
└──────────────────────────┬──────────────────────────────────┘
                           │ dlopen
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  decrypt_helper.dylib（主引擎，与巨魔版完全相同）             │
│  fishhook GOT + ObjC swizzle + HTTP/MCP 服务 + 悬浮窗        │
└─────────────────────────────────────────────────────────────┘
```

## 构建

```bash
# 同时构建普通 rootless 和 roothide deb
make deb

# 单独构建
make deb-rootless
make deb-roothide

# 或直接调用脚本
./jailbreak/build_deb.sh all
./jailbreak/build_deb.sh roothide
```

产物在 `build/deb/` 下：
- `com.iosdecrypthub_<version>_rootless.deb`
- `com.iosdecrypthub_<version>_roothide.deb`

## 安装路径

| 环境 | Debian 架构 | Mach-O 架构 | 加载器路径 | 主 dylib 路径 |
|------|-------------|-------------|------------|---------------|
| rootless | `iphoneos-arm64` | `arm64` | `/var/jb/Library/MobileSubstrate/DynamicLibraries/` | `/var/jb/usr/lib/IOSDecryptHub/` |
| roothide | `iphoneos-arm64e` | `arm64 + arm64e` | `<jbroot>/Library/MobileSubstrate/DynamicLibraries/` | `<jbroot>/usr/lib/IOSDecryptHub/` |

roothide 包内路径从 `/Library`、`/usr` 开始，由 roothide 在安装和运行时映射到随机 jbroot；不得打入固定 `/var/jb` 前缀。

## 使用

1. 通过 Sileo / Zebra 安装对应端的 deb
2. 打开 **设置 → IOSDecryptHub**
3. 点击「选择要注入的应用」，开启目标 App 的开关
4. 重启目标 App（或 respring）即可生效
5. 浏览器访问 `http://<设备IP>:8088` 查看分析面板

**默认不注入任何 App**，必须手动开启。

应用选择结果保存在主 dylib 目录下的 `config/enabledBundles.plist`。安装脚本会在
干净安装时创建空配置，在旧版升级时自动迁移
`/var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist`。配置目录归属
`mobile`，设置面板可原子更新；loader 从自身实际路径定位该文件，避免宿主 App 的
偏好容器隔离以及 rootless `/var/jb` 别名差异。旧偏好域继续作为降级兼容通道。

## 依赖

- `ellekit` — dylib 加载机制
- `preferenceloader` — 在系统设置中加载 IOSDecryptHub 配置入口
- 应用选择器由设置面板内置，不依赖 AppList
- 不显式依赖 `firmware` 伪包；支持范围由目标架构、rootless 环境和 Mach-O 最低 iOS 14.0 共同约束

## 设计约束

- ❌ 加载器不包含任何 hook 逻辑
- ❌ 不使用 MSHookFunction / %hook 等 inline hook
- ❌ 不使用 daemon
- ✅ 越狱框架仅作为 dylib 加载器
- ✅ 所有 hook 由主 dylib 的 fishhook + swizzle 完成
