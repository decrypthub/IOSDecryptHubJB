#!/usr/bin/env bash
# 通过 GitHub API 发布 release 并上传 dylib 资产 (纯 shell, 不依赖 python/jq)
# 用法: bash scripts/publish_release.sh <repo> <tag> <dylib_path>
set -euo pipefail

REPO="${1:-decrypthub/IOSDecryptHub}"
TAG="${2:-v1.1.0}"
DYLIB="${3:-decrypt_helper.dylib}"  # 内部构建产物名, 打包时重命名为 IOSDecryptHub.dylib
NOTES_PATH="${4:-}"

TOKEN=$(grep -oE 'https?://[^:]+:[^@]+@github\.com' "$HOME/.git-credentials" \
        | head -1 | sed -E 's|^https?://[^:]+:([^@]+)@.*|\1|')
if [ -z "$TOKEN" ]; then
    echo "❌ 没在 ~/.git-credentials 找到 github.com 的 token" >&2
    exit 1
fi

API="https://api.github.com/repos/$REPO"
UPLOAD="https://uploads.github.com/repos/$REPO"

# 用 perl 把 release notes 编码成 JSON 字符串 (转义换行/引号)
NOTES_FILE="$(mktemp)"
if [ -n "$NOTES_PATH" ] && [ -f "$NOTES_PATH" ]; then
    cat "$NOTES_PATH" > "$NOTES_FILE"
else
    cat > "$NOTES_FILE" <<'NOTES'
## IOSDecryptHub v1.0.0

> 基于 [fishhook](https://github.com/facebook/fishhook) 的 iOS 加解密 API 拦截工具,
> 把每次调用的 **算法 / Key / IV / 明文 / 密文 / 调用栈** 完整记录下来.

### 覆盖的算法 (44 个 API)

| 分类 | API |
|---|---|
| 摘要 | `CC_MD2/4/5`, `CC_SHA1/224/256/384/512` + 流式 `_Init/_Update/_Final` |
| HMAC | `CCHmac`, `CCHmacInit/Update/Final` |
| 对称 | `CCCrypt`, `CCCryptorCreate/CreateWithMode/Update/Final/Release` (AES/DES/3DES/RC4/RC2/CAST/Blowfish; ECB/CBC/CTR/CFB/OFB) |
| 非对称 | `SecKeyCreateSignature`, `SecKeyVerifySignature`, `SecKeyCreateEncryptedData`, `SecKeyCreateDecryptedData` |

### UI

* **悬浮窗** 只显示统计、Web 地址与基础控制 (暂停/清空), **绝不显示日志正文**.
* **Web 工作台**: 分类切换、关键字搜索、详情页 (Key/IV/明文/Hex/HexDump/输出/调用栈)、导出与配置均在浏览器完成.

### 用法

```bash
./scripts/inject.sh YourApp.ipa decrypt_helper.dylib  # 或 make VARIANT=trollstore 后用产物
```

或自己构建:

```bash
# macOS
make

# Linux / WSL
bash scripts/wsl_setup_toolchain.sh   # 一次性, 无需 sudo
source ~/dh-cross/env.sh
make linux
```

### 已知限制

* 流式 Init/Update 但永不 Final 的会话会在内存表里留下状态 (轻微泄漏).
* 日志文件无大小封顶, 长跑请定期 "清空".
* CC_MD2 / CC_MD4 在新 SDK 已 deprecated, 但运行时符号仍在, hook 正常工作.
NOTES
fi

# 用 perl 一次性把 notes 转成 JSON 字符串字面量 (含双引号)
BODY_JSON=$(perl -0777 -ne '
    s/\\/\\\\/g;
    s/"/\\"/g;
    s/\n/\\n/g;
    s/\r/\\r/g;
    s/\t/\\t/g;
    print "\"$_\"";
' "$NOTES_FILE")
rm -f "$NOTES_FILE"

PAYLOAD_FILE="$(mktemp)"
cat > "$PAYLOAD_FILE" <<EOF
{
  "tag_name": "$TAG",
  "name": "IOSDecryptHub $TAG",
  "body": $BODY_JSON,
  "draft": false,
  "prerelease": false
}
EOF

echo "[*] 创建 release $TAG ..."
RESP_FILE="$(mktemp)"
curl -sS -X POST "$API/releases" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    --data-binary "@$PAYLOAD_FILE" \
    -o "$RESP_FILE"

# 简单 grep 提取
RELEASE_ID=$(grep -oE '"id":\s*[0-9]+' "$RESP_FILE" | head -1 | grep -oE '[0-9]+')
HTML_URL=$(grep -oE '"html_url":\s*"[^"]+"' "$RESP_FILE" | head -1 | sed -E 's|.*"html_url":\s*"([^"]+)".*|\1|')
if [ -z "$RELEASE_ID" ]; then
    echo "❌ 创建 release 失败:"
    head -50 "$RESP_FILE"
    exit 1
fi
echo "✅ release 已创建 id=$RELEASE_ID"
echo "    $HTML_URL"

echo "[*] 上传 dylib 资产 ($(stat -c%s "$DYLIB" 2>/dev/null || stat -f%z "$DYLIB") bytes) ..."
ASSET_RESP_FILE="$(mktemp)"
curl -sS -X POST \
    "$UPLOAD/releases/$RELEASE_ID/assets?name=$(basename "$DYLIB")" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$DYLIB" \
    -o "$ASSET_RESP_FILE"
ASSET_URL=$(grep -oE '"browser_download_url":\s*"[^"]+"' "$ASSET_RESP_FILE" | head -1 | sed -E 's|.*"browser_download_url":\s*"([^"]+)".*|\1|')
if [ -z "$ASSET_URL" ]; then
    echo "❌ 上传 dylib 失败:"
    head -30 "$ASSET_RESP_FILE"
    exit 1
fi
echo "✅ dylib 已上传:"
echo "    $ASSET_URL"
rm -f "$PAYLOAD_FILE" "$RESP_FILE" "$ASSET_RESP_FILE"

echo
echo "🎉 Release 完成:"
echo "    $HTML_URL"
