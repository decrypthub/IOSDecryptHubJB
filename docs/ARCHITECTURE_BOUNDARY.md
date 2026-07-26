# IOSDecryptHub 架构边界文档（铁律）

> **本文档是所有开发的最高优先级参考。任何代码变更不得违反此文档定义的边界。**
> 最后更新：2026-07-26

---

## 一、设计原则

本项目 **只开发 TrollStore（巨魔）dylib**，不涉及任何越狱相关开发。

理由：
- 越狱的能力边界比巨魔大，但为了稳定性考虑，统一使用巨魔的 dylib 方案
- 越狱插件也只是将巨魔的 dylib 注入进去，无需单独维护越狱变体
- 一份代码、一套构建流程、一个产物，降低维护成本

---

## 二、两条路线

```
┌─────────────────────────────────────────────────────────────────────┐
│                        巨魔路线（TrollStore）                         │
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

## 三、能力边界

| 维度 | trollstore（巨魔） | dev（开发者） |
|------|-------------------|--------------|
| **注入机制** | Mach-O patch（写 LC_LOAD_DYLIB） | DYLD_INSERT_LIBRARIES / insert_dylib |
| **注入载体** | 管理器 App 自身执行 patch | 环境变量 / 手动重打包 |
| **权限要求** | TrollStore 签名（无 root） | 无 |
| **hook 引擎** | fishhook GOT + ObjC swizzle | fishhook GOT + ObjC swizzle |
| **inline hook** | ❌ 不支持（无 AMFI 绕过） | ❌ 不支持 |
| **门控** | App 内 Toggle（per-app） | 无（手动 = 明确意图） |
| **最低 iOS** | 14.0 | 14.0 |
| **架构** | arm64 | arm64 |

---

## 四、巨魔变体实现方案

### 4.1 架构

```
IOSDecryptHubTS.app (TrollStore 安装的管理器)
    │ 直接读写目标 App 的 Mach-O 二进制
    ▼
目标 App.app/目标二进制  ← 写入 LC_LOAD_DYLIB
目标 App.app/decrypt_helper.dylib  ← 拷贝 dylib
    │
    ▼ 目标 App 下次启动时自动加载 dylib
```

### 4.2 技术要点

- **App 列表获取**：TrollStore App 有 `platform-application` entitlement，
  可读 `/var/containers/Bundle/Application/` 或使用 MobileInstallation API
- **Mach-O patch**：参考 TrollFools 开源实现（C 代码），
  支持 fat binary / 64-bit，插入/移除 LC_LOAD_DYLIB
- **备份/恢复**：原始二进制备份到目标 App bundle 内（如 `.dh_backup`）
- **dylib 编译**：`make VARIANT=trollstore`，DH_VARIANT=1，arm64
- **IPA 打包**：`make ipa`，管理器 App + dylib 一起打包

### 4.3 绝对禁止

- ❌ 不得引用 daemon / dh_server 的任何代码或接口
- ❌ 不得读写 plist 偏好文件做门控
- ❌ 不得依赖 /var/jb 路径
- ❌ 不得使用 Substrate/ElleKit API
- ❌ 不得引入任何越狱相关代码或依赖

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

**共享代码中不得出现的**：
- ❌ 不得出现 TrollStore 特有的 Mach-O patch 逻辑（那是管理器 App 的事）
- ❌ 不得出现任何越狱相关逻辑（路径探测、Substrate、daemon 通信等）
- dylib 只负责：被加载 → 装 hook → 起服务 → 显示悬浮窗

---

## 六、目录与产物对照

| 目录/文件 | 归属 | 说明 |
|-----------|------|------|
| `src/` | 共享 | dylib 核心引擎（所有变体） |
| `app-trollstore/` | **TrollStore 专用** | 管理器 App（直接 Mach-O patch） |
| `scripts/inject.sh` | dev | 手动 IPA 注入脚本 |
| `web/` | 共享 | Web 面板（编译为 C 头文件，嵌入 dylib） |
| `tests/` | 共享 | 集成测试 |

---

## 七、Makefile target 归属

| Target | 路线 | 说明 |
|--------|------|------|
| `make` / `make VARIANT=dev` | dev | 裸 dylib |
| `make VARIANT=trollstore` | TrollStore | dylib（将嵌入 IPA） |
| `make ipa` | TrollStore | 编译 dylib + 管理器 App → 打包 IPA |
| `make mac` | dev | macOS 灰度 |
| `make sim` | dev | 模拟器 |
| `make test-mac` | dev | macOS 集成测试 |
| `make test-mcp` | 共享 | MCP 集成测试 |
| `make dist` | 共享 | 带版本号的发布产物 |

---

## 八、检查清单（每次改代码前过一遍）

- [ ] 是否引入了越狱相关代码？→ 不允许
- [ ] 是否引用了 daemon/plist/Substrate/ElleKit？→ 不允许
- [ ] 是否依赖了 /var/jb 或其他越狱路径？→ 不允许
- [ ] dylib 核心引擎是否保持了变体无关性（仅通过 DH_VARIANT 宏感知）？
- [ ] 新增的 Makefile target 是否归属正确的路线？
