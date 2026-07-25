# TrollStore 工具目录

构建 IPA 时，此目录下的可执行文件会被自动打包进 App bundle。

## 需要的工具

| 工具 | 用途 | 来源 |
|------|------|------|
| `ct_bypass` | CoreTrust bypass 重签名 | [TrollStore 生态](https://github.com/opa334/TrollStore) |
| `ldid` | 伪签名 (生成 code signature) | `brew install ldid` 或 [ProcursusTeam/ldid](https://github.com/ProcursusTeam/ldid) |

## 获取方式

### 方法 1: 从 TrollFools IPA 提取
1. 下载 [TrollFools 最新 IPA](https://github.com/Lessica/TrollFools/releases)
2. 解压 IPA (改后缀为 .zip)
3. 从 `Payload/TrollFools.app/` 中复制 `ct_bypass` 和 `ldid` 到此目录

### 方法 2: 自行编译
- `ldid`: `brew install ldid` (macOS 版, 需交叉编译为 arm64-ios)
- `ct_bypass`: 从 TrollStore 源码编译

### 注意
- 工具必须是 **arm64 iOS** 二进制 (不是 macOS 版)
- 构建脚本会自动检测并打包此目录下的所有文件
- 如果工具缺失，App 仍可编译，但注入功能会降级（跳过签名步骤）
