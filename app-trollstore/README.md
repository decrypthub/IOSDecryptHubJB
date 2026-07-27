# IOSDecryptHub TrollStore 管理器

<div align="right">
  <b>中文</b> | <a href="./README.en.md">English</a>
</div>


> **非越狱方案** — 通过 TrollStore 安装，直接 patch 目标 App 的 Mach-O 二进制实现 dylib 注入。
> 参考 [TrollFools](https://github.com/Lessica/TrollFools) 开源方案。

## 用户流程

```
1. TrollStore 安装 IOSDecryptHubTS.ipa
2. 打开 App → 看到已安装应用列表
3. 目标 App 开关打开 → dylib 注入完成（重启目标 App 生效）
4. 开关关闭 → 恢复原始二进制
```

## 架构

```
┌─────────────────────────────────────────────────┐
│              IOSDecryptHubTS.app                 │
│              (TrollStore 安装)                   │
├─────────────────────────────────────────────────┤
│                                                 │
│  App.swift (SwiftUI)                            │
│    └─ AppListViewModel                          │
│         └─ DHInjector (ObjC)                    │
│              ├─ macho_patch.c (纯 C)            │
│              │   ├─ 插入 LC_LOAD_DYLIB          │
│              │   ├─ 移除 LC_LOAD_DYLIB          │
│              │   └─ 支持 fat/thin binary        │
│              ├─ LSApplicationWorkspace (私有API) │
│              │   └─ 枚举已安装 App              │
│              ├─ ldid (伪签名)                   │
│              ├─ ct_bypass (CoreTrust bypass)    │
│              └─ chown (改属主为 installd)       │
│                                                 │
│  内嵌资源:                                      │
│    decrypt_helper.dylib  (hook 引擎)            │
│    ct_bypass             (签名工具)             │
│    ldid                  (签名工具)             │
└─────────────────────────────────────────────────┘
```

## 注入流程

```
注入 (Toggle ON):
  1. kill 目标 App
  2. 备份主二进制 → <binary>.dh.bak
  3. 复制 decrypt_helper.dylib → 目标 .app/ 目录
  4. macho_patch: 插入 LC_LOAD_DYLIB (@executable_path/decrypt_helper.dylib)
  5. ldid -S (伪签名)
  6. ct_bypass -r -i <binary> -t <teamId> (CoreTrust bypass)
  7. chown 33:33 (installd 属主)

卸载 (Toggle OFF):
  1. kill 目标 App
  2. 恢复备份 (或 macho_patch 移除 LC_LOAD_DYLIB)
  3. 删除 dylib
  4. 重签名 + chown
```

## 构建

```bash
# 一键构建 IPA
make ipa

# 或手动
./app-trollstore/build_ipa.sh
```

产物: `build/trollstore/IOSDecryptHubTS_<version>.ipa`

## 文件说明

| 文件 | 说明 |
|------|------|
| `IOSDecryptHubTS/macho_patch.h/c` | Mach-O LC_LOAD_DYLIB 插入/移除 (纯 C, 支持 fat binary) |
| `IOSDecryptHubTS/DHInjector.h/m` | ObjC 注入引擎 (App 枚举 + 注入/卸载调度) |
| `IOSDecryptHubTS/LSApplicationWorkspace.h` | 私有 API 声明 (枚举已安装 App) |
| `IOSDecryptHubTS/App.swift` | SwiftUI 界面 (App 列表 + Toggle) |
| `IOSDecryptHubTS/BridgingHeader.h` | Swift ↔ ObjC 桥接 |
| `IOSDecryptHubTS/Info.plist` | App 配置 |
| `IOSDecryptHubTS/entitlements.plist` | TrollStore 权限 (沙盒绕过等) |
| `tools/` | 签名工具目录 (ct_bypass, ldid) |
| `build_ipa.sh` | 构建脚本 |

## ⚠️ 边界铁律

- **不得** 引用 daemon / dh_server 的任何代码或接口
- **不得** 读写 plist 偏好文件做门控
- **不得** 依赖 /var/jb 或任何越狱路径
- **不得** 使用 Substrate / ElleKit API
- **不得** 将越狱 deb 包的任何组件打入 IPA

详见 `docs/ARCHITECTURE_BOUNDARY.md`
