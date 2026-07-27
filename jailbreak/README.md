# IOSDecryptHub 越狱注入包

> 通过越狱框架（Substrate/ElleKit/libhooker）将主 dylib 注入目标 App。
> 支持 rootless / roothide / rootful 三端越狱。

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│  Substrate / ElleKit / libhooker                            │
│  加载 IOSDecryptHubLoader.dylib 到所有 App（Filter: *）      │
└──────────────────────────┬──────────────────────────────────┘
                           │ %ctor / constructor
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  IOSDecryptHubLoader.dylib（薄层加载器）                      │
│  1. 读取 plist 偏好（com.iosdecrypthub.loader）              │
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
# 构建全部三端 deb
make deb

# 单独构建
make deb-rootless
make deb-roothide
make deb-rootful

# 或直接调用脚本
./jailbreak/build_deb.sh all
./jailbreak/build_deb.sh rootless
```

产物在 `build/deb/` 下：
- `com.iosdecrypthub.jailbreak_<version>_rootless.deb`
- `com.iosdecrypthub.jailbreak_<version>_roothide.deb`
- `com.iosdecrypthub.jailbreak_<version>_rootful.deb`

## 安装路径

| 端 | 加载器路径 | 主 dylib 路径 |
|----|-----------|--------------|
| rootless | `/var/jb/Library/MobileSubstrate/DynamicLibraries/` | `/var/jb/usr/lib/IOSDecryptHub/` |
| roothide | `/var/jb/Library/MobileSubstrate/DynamicLibraries/` | `/var/jb/usr/lib/IOSDecryptHub/` |
| rootful | `/Library/MobileSubstrate/DynamicLibraries/` | `/usr/lib/IOSDecryptHub/` |

## 使用

1. 通过 Sileo / Zebra 安装对应端的 deb
2. 打开 **设置 → IOSDecryptHub**
3. 点击「选择要注入的应用」，开启目标 App 的开关
4. 重启目标 App（或 respring）即可生效
5. 浏览器访问 `http://<设备IP>:8088` 查看分析面板

**默认不注入任何 App**，必须手动开启。

## 依赖

- `mobilesubstrate` (>= 0.9.5000) 或 `ellekit` — dylib 加载机制
- `applist` (>= 1.5) — 设置面板的 App 列表 UI

## 设计约束

- ❌ 加载器不包含任何 hook 逻辑
- ❌ 不使用 MSHookFunction / %hook 等 inline hook
- ❌ 不使用 daemon
- ✅ 越狱框架仅作为 dylib 加载器
- ✅ 所有 hook 由主 dylib 的 fishhook + swizzle 完成
