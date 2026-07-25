# IOSDecryptHub 架构边界文档（铁律）

> **本文档是所有开发的最高优先级参考。任何代码变更不得违反此文档定义的边界。**
> 最后更新：2026-07-26

---

## 一、两条完全独立的路线

```
┌─────────────────────────────────────────────────────────────────────┐
│                        非越狱路线（TrollStore）                       │
│                                                                     │
│  变体: trollstore (DH_VARIANT=1)                                    │
│  前提: 设备安装了 TrollStore（利用 CoreTrust 漏洞，非越狱）            │
│  产物: 一个 IPA（管理器 App + 内嵌 dylib）                            │
│  注入: App 直接 patch 目标 App 的 Mach-O 二进制（TrollFools 方案）     │
│  门控: 每个 App 独立开关（Toggle ON = 注入, OFF = 恢复原始二进制）     │
│                                                                     │
│  ❌ 不用 Substrate / ElleKit                                        │
│  ❌ 不用 daemon / dh_server                                         │
│  ❌ 不用 deb 打包                                                    │
│  ❌ 不用 plist 偏好门控                                              │
│  ❌ 不依赖 /var/jb 或任何越狱路径                                     │
│  ❌ 不需要 root 权限                                                 │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                        越狱路线（deb 包）                             │
│                                                                     │
│  变体: rootless(2) / rootful(3) / roothide(4)                       │
│  前提: 设备已越狱（有 Substrate 或 ElleKit）                          │
│  产物: .deb 包（dylib + filter plist + daemon + 管理器 App）          │
│  注入: Substrate/ElleKit 读 filter plist 自动注入 dylib              │
│  门控: plist 偏好文件（DHEnabled + DHTargetBundleId）                 │
│        管理器 App → HTTP → dh_server(root daemon) → 写 plist         │
│                                                                     │
│  ✅ 用 Substrate / ElleKit（设备已有，我们只放 dylib + filter plist）  │
│  ✅ 用 daemon（dh_server, root 权限, 127.0.0.1:29817）               │
│  ✅ 用 deb 打包（pack_deb.sh）                                       │
│  ✅ 用 plist 偏好门控（DH_PREFS_PATH 编译期确定）                     │
│  ✅ 依赖越狱文件系统（/var/jb 或 /）                                  │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                        开发者路线（dev）                              │
│                                                                     │
│  变体: dev (DH_VARIANT=0)                                           │
│  前提: 无（开发者手动注入）                                           │
│  产物: 裸 dylib                                                     │
│  注入: DYLD_INSERT_LIBRARIES 或 insert_dylib                        │
│  门控: 无（手动注入 = 用户已明确意图）                                 │
│  用途: 本地开发调试、macOS 灰度测试                                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 二、能力边界对照表

| 维度 | trollstore（非越狱） | rootless/rootful/roothide（越狱） | dev |
|------|---------------------|----------------------------------|-----|
| **注入机制** | Mach-O patch（写 LC_LOAD_DYLIB） | Substrate/ElleKit 自动加载 | DYLD_INSERT_LIBRARIES |
| **注入载体** | 管理器 App 自身执行 patch | 设备注入框架读 filter plist | 环境变量 / 手动改 Mach-O |
| **管理器 App** | TrollStore 安装的 IPA，自包含 | deb 包内的 App，依赖 daemon | 无 |
| **daemon** | ❌ 无（App 直接操作文件系统） | ✅ dh_server（root, LaunchDaemon） | ❌ 无 |
| **门控方式** | 每 App 独立 Toggle（直接改/恢复二进制） | plist 总开关 + 目标 BundleId | 无门控 |
| **dylib 位置** | 复制到目标 App 的 .app/ bundle 内 | /Library/MobileSubstrate/DynamicLibraries/ | 任意路径 |
| **hook 能力** | fishhook(GOT) + ObjC swizzle | fishhook + swizzle + inline hook(二期) | fishhook + swizzle |
| **inline hook** | ❌ 不可能（无 AMFI 绕过） | ✅ 可能（越狱绕过 AMFI/CS） | ❌ |
| **文件系统** | TrollStore 权限（可写已安装 App） | root 权限（完全访问） | 开发机权限 |
| **签名处理** | TrollStore CoreTrust 绕过 | ldid 伪签名 + 越狱 AMFI 绕过 | 无需签名 |
| **打包格式** | IPA（通过 TrollStore 安装） | .deb（dpkg 安装） | 裸 dylib |
| **架构** | arm64 | arm64(rootless/rootful) / arm64e(roothide) | arm64 |
| **最低 iOS** | 14.0 | 15.0(rootless) / 13.0(rootful) / 15.0(roothide) | 14.0 |

---

## 三、TrollStore 变体实现方案（TrollFools 方案）

### 3.1 用户流程

```
1. 用户通过 TrollStore 安装 IOSDecryptHub.ipa
2. 打开 App → 看到已安装应用列表
3. 对目标 App 打开开关：
   a. 备份目标 App 原始 Mach-O 二进制
   b. 将 IOSDecryptHub.dylib 复制到目标 App 的 .app/ 目录
   c. Patch 目标 App 的 Mach-O：插入 LC_LOAD_DYLIB → @executable_path/IOSDecryptHub.dylib
   d. 目标 App 下次启动时自动加载 dylib
4. 对目标 App 关闭开关：
   a. 恢复备份的原始 Mach-O 二进制
   b. 删除 .app/ 目录中的 dylib
   c. 目标 App 恢复原样
```

### 3.2 技术要点

- **App 列表获取**：TrollStore App 有 `platform-application` entitlement，
  可读 `/var/containers/Bundle/Application/` 或使用 MobileInstallation API
- **Mach-O patch**：参考 TrollFools 开源实现（C 代码），
  支持 fat binary / 64-bit，插入/移除 LC_LOAD_DYLIB
- **备份/恢复**：原始二进制备份到 App 自身沙盒或目标 App bundle 内（如 `.dh_backup`）
- **dylib 编译**：`make VARIANT=trollstore`，DH_VARIANT=1，无门控，arm64
- **IPA 打包**：管理器 App + dylib 一起打包，Makefile 新增 target

### 3.3 绝对禁止

- ❌ 不得在 trollstore 变体中引用 daemon / dh_server 的任何代码或接口
- ❌ 不得在 trollstore 变体中读写 plist 偏好文件做门控
- ❌ 不得在 trollstore 变体中依赖 /var/jb 路径
- ❌ 不得在 trollstore 变体中使用 Substrate/ElleKit API
- ❌ 不得将越狱 deb 包的任何组件打入 trollstore IPA

---

## 四、越狱变体实现方案（现有架构，不变）

### 4.1 三件套架构

```
IOSDecryptHub.app (SwiftUI 前端)
    │ HTTP 127.0.0.1:29817
    ▼
dh_server (root daemon, LaunchDaemon)
    │ 写 plist
    ▼
<jbroot>/var/mobile/Library/Preferences/com.dh.iosdecrypthub.plist
    │ dylib 注入时读取（dh_prefs_should_activate）
    ▼
IOSDecryptHub.dylib (由 Substrate/ElleKit 注入目标 App)
```

### 4.2 门控逻辑（main.m）

```c
#if DH_VARIANT >= 2  // 越狱变体才走偏好门控
    读 DH_PREFS_PATH → DHEnabled + DHTargetBundleId
    无偏好文件 = 不注入（fail loud）
#else
    // dev / trollstore: 直接激活
    return YES;
#endif
```

### 4.3 绝对禁止

- ❌ 不得在越狱变体中使用 Mach-O patch 方式注入（那是 TrollStore 的方案）
- ❌ 不得在越狱变体中绕过 daemon 直接写 plist（App 沙盒无权限）
- ❌ 不得混淆三个越狱子变体的路径（rootful 无 /var/jb 前缀）

---

## 五、共享代码（dylib 核心引擎）

以下代码是 **所有变体共享** 的，编译同一份源码，通过 `DH_VARIANT` 宏区分行为：

```
src/core/       → fishhook, thunk, capability, 日志, 脱壳, 分析
src/hooks/      → 所有 hook 模块（crypto + behavior）
src/server/     → HTTP + MCP 服务 + UDP 发现
src/ui/         → 悬浮窗
```

**共享代码中的变体感知点**（仅有的几处）：
1. `dh_capability.c` → `dh_variant_current()` 返回编译期变体
2. `main.m` → `dh_prefs_should_activate()` 按 DH_VARIANT 决定是否读 plist
3. `dh_capability.c` → `dh_capability_bits()` 越狱变体可开 inline hook

**共享代码中不得出现的**：
- ❌ 不得出现 TrollStore 特有的 Mach-O patch 逻辑（那是管理器 App 的事）
- ❌ 不得出现 daemon 通信逻辑（那是管理器 App 的事）
- dylib 只负责：被加载 → 装 hook → 起服务 → 显示悬浮窗

---

## 六、目录与产物对照

| 目录/文件 | 归属 | 说明 |
|-----------|------|------|
| `src/` | 共享 | dylib 核心引擎（所有变体） |
| `app/` | **越狱专用** | 管理器 App（通过 daemon HTTP 通信） |
| `app-trollstore/`（待建） | **TrollStore 专用** | 管理器 App（直接 Mach-O patch） |
| `daemon/` | **越狱专用** | root daemon（dh_server） |
| `packaging/` | **越狱专用** | deb 打包资源 |
| `scripts/inject.sh` | dev/旧 trollstore | 手动 IPA 注入脚本（将被 app-trollstore 取代） |
| `scripts/pack_deb.sh` | **越狱专用** | deb 打包脚本 |
| `web/` | 共享 | Web 面板（编译为 C 头文件，嵌入 dylib） |
| `tests/` | 共享 | 集成测试 |

---

## 七、Makefile target 归属

| Target | 路线 | 说明 |
|--------|------|------|
| `make` / `make VARIANT=dev` | dev | 裸 dylib |
| `make VARIANT=trollstore` | TrollStore | dylib（将嵌入 IPA） |
| `make VARIANT=rootless/rootful/roothide` | 越狱 | dylib（将打入 deb） |
| `make ipa`（待建） | TrollStore | 编译 dylib + 管理器 App → 打包 IPA |
| `make app` | 越狱 | 管理器 App（SwiftUI, 依赖 daemon） |
| `make daemon` | 越狱 | root daemon |
| `make deb-*` / `make debs` | 越狱 | deb 打包 |
| `make mac` | dev | macOS 灰度 |
| `make sim` | dev | 模拟器 |
| `make test-mcp` | 共享 | 集成测试 |

---

## 八、检查清单（每次改代码前过一遍）

- [ ] 我改的代码属于哪条路线？（TrollStore / 越狱 / dev / 共享）
- [ ] 是否在共享代码中引入了特定路线的逻辑？
- [ ] TrollStore 代码是否引用了 daemon/plist/Substrate？→ 不允许
- [ ] 越狱代码是否引用了 Mach-O patch/TrollStore API？→ 不允许
- [ ] dylib 核心引擎是否保持了变体无关性（仅通过 DH_VARIANT 宏感知）？
- [ ] 新增的 Makefile target 是否归属正确的路线？
