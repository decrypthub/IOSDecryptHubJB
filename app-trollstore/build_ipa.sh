#!/bin/bash
# IOSDecryptHub TrollStore IPA 一键构建
#
# 用法: make ipa  (或 ./app-trollstore/build_ipa.sh)
#
# 全自动流程:
#   1. 自动下载签名工具 (ct_bypass / ldid, 从 TrollFools release 提取)
#   2. make VARIANT=trollstore → 编译 dylib (arm64)
#   3. swiftc 编译管理器 App (SwiftUI + ObjC 混编)
#   4. 组装 .app bundle (dylib + 工具 + Info.plist)
#   5. ldid 签名 (带 entitlements)
#   6. 打包 IPA → build/trollstore/IOSDecryptHubTS_<version>.ipa
#
# 产物用 TrollStore 打开即装, 开箱即用。
#
# ⚠️ 本脚本属于 TrollStore 变体, 不涉及 daemon/deb/plist 门控。

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_SRC="$ROOT/app-trollstore/IOSDecryptHubTS"
TOOLS_DIR="$ROOT/app-trollstore/tools"

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
SWIFTC="$(xcrun --find swiftc)"
LDID="$(command -v ldid || true)"
ARCH="arm64"
MIN_IOS="14.0"

VERSION="$(grep -m1 '^VERSION' "$ROOT/Makefile" | sed 's/.*:=[[:space:]]*//')"

OUT_DIR="$ROOT/build/trollstore"
APP_BUNDLE="$OUT_DIR/Payload/IOSDecryptHubTS.app"

echo "╔══════════════════════════════════════════════════╗"
echo "║   IOSDecryptHub TrollStore IPA 一键构建         ║"
echo "║   版本: v${VERSION}                              ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ================================================================
# 0. 自动获取签名工具 (ct_bypass + ldid iOS arm64 版)
# ================================================================
fetch_tools() {
    # 检查工具是否已存在
    if [ -f "$TOOLS_DIR/ct_bypass" ] && [ -f "$TOOLS_DIR/ldid" ]; then
        echo "    ✅ 签名工具已就绪, 跳过下载"
        return 0
    fi

    echo "    📦 签名工具缺失, 从 TrollFools release 自动获取..."
    mkdir -p "$TOOLS_DIR"

    # 从 GitHub API 获取最新 TrollFools release
    local API_URL="https://api.github.com/repos/Lessica/TrollFools/releases/latest"
    local IPA_URL=""

    echo "    → 查询 TrollFools 最新 release..."
    local RELEASE_JSON
    RELEASE_JSON=$(curl -sL --connect-timeout 10 "$API_URL" 2>/dev/null) || true

    if [ -n "$RELEASE_JSON" ]; then
        # 提取 .ipa 下载链接
        IPA_URL=$(echo "$RELEASE_JSON" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for asset in data.get('assets', []):
        name = asset.get('name', '')
        if name.endswith('.ipa'):
            print(asset['browser_download_url'])
            break
except: pass
" 2>/dev/null) || true
    fi

    if [ -z "$IPA_URL" ]; then
        echo "    ⚠️ 无法自动获取 TrollFools IPA (网络问题或 API 限流)"
        echo "    → 请手动下载: https://github.com/Lessica/TrollFools/releases"
        echo "    → 解压 IPA, 将 ct_bypass 和 ldid 复制到: $TOOLS_DIR/"
        echo "    → 然后重新运行 make ipa"
        echo ""
        echo "    继续构建 (无签名工具, App 可编译但注入功能受限)..."
        return 0
    fi

    echo "    → 下载: $(basename "$IPA_URL")"
    local TMP_DIR
    TMP_DIR=$(mktemp -d)
    trap "rm -rf '$TMP_DIR'" RETURN

    curl -sL --connect-timeout 30 -o "$TMP_DIR/TrollFools.ipa" "$IPA_URL" || {
        echo "    ⚠️ 下载失败, 请手动获取工具"
        return 0
    }

    # 解压 IPA (就是 zip)
    cd "$TMP_DIR"
    unzip -qo TrollFools.ipa -d extracted 2>/dev/null || {
        echo "    ⚠️ 解压失败"
        cd "$ROOT"
        return 0
    }

    # 从 TrollFools.app 中提取工具
    local TF_APP
    TF_APP=$(find extracted/Payload -maxdepth 1 -name "*.app" -type d | head -1)

    if [ -z "$TF_APP" ]; then
        echo "    ⚠️ IPA 中未找到 .app"
        cd "$ROOT"
        return 0
    fi

    local FOUND=0
    for tool in ct_bypass ldid; do
        if [ -f "$TF_APP/$tool" ]; then
            cp "$TF_APP/$tool" "$TOOLS_DIR/$tool"
            chmod 755 "$TOOLS_DIR/$tool"
            echo "    ✅ 提取: $tool"
            FOUND=$((FOUND + 1))
        fi
    done

    cd "$ROOT"

    if [ "$FOUND" -eq 0 ]; then
        echo "    ⚠️ TrollFools IPA 中未找到签名工具"
    else
        echo "    ✅ 签名工具就绪 ($FOUND 个)"
    fi
}

echo "==> [0/5] 检查签名工具..."
fetch_tools
echo ""

# ================================================================
# 1. 编译 dylib
# ================================================================
echo "==> [1/5] 编译 dylib (VARIANT=trollstore, $ARCH)..."
make -C "$ROOT" -B VARIANT=trollstore all
DYLIB="$ROOT/decrypt_helper.dylib"
if [ ! -f "$DYLIB" ]; then
    echo "❌ dylib 编译失败"; exit 1
fi
echo "    ✅ $(du -h "$DYLIB" | cut -f1)"
echo ""

# ================================================================
# 2. 编译 App
# ================================================================
echo "==> [2/5] 编译管理器 App (SwiftUI + ObjC)..."
mkdir -p "$OUT_DIR"

# ObjC / C 源文件 → .o
OBJC_OBJS=()
for src in "$APP_SRC"/*.m "$APP_SRC"/*.c; do
    [ -f "$src" ] || continue
    obj="$OUT_DIR/$(basename "${src%.*}").o"
    echo "    CC $(basename "$src")"
    xcrun clang \
        -target "${ARCH}-apple-ios${MIN_IOS}" \
        -isysroot "$SDK" \
        -ObjC -fobjc-arc \
        -Wall -Wno-deprecated-declarations \
        -I"$APP_SRC" \
        -O \
        -c "$src" -o "$obj"
    OBJC_OBJS+=("$obj")
done

# Swift + 链接
echo "    SWIFT App.swift"
"$SWIFTC" \
    -parse-as-library \
    -target "${ARCH}-apple-ios${MIN_IOS}" \
    -sdk "$SDK" \
    -import-objc-header "$APP_SRC/BridgingHeader.h" \
    -I"$APP_SRC" \
    -framework SwiftUI \
    -framework UIKit \
    -framework Foundation \
    -framework Security \
    -O \
    -o "$OUT_DIR/IOSDecryptHubTS" \
    "$APP_SRC/App.swift" \
    "${OBJC_OBJS[@]}"

echo "    ✅ 编译完成"
echo ""

# ================================================================
# 3. 组装 .app bundle
# ================================================================
echo "==> [3/5] 组装 .app bundle..."
mkdir -p "$APP_BUNDLE"

# 主二进制
cp "$OUT_DIR/IOSDecryptHubTS" "$APP_BUNDLE/"

# Info.plist (注入版本号)
sed "s/1.23.0/$VERSION/" "$APP_SRC/Info.plist" > "$APP_BUNDLE/Info.plist"

# 内嵌 dylib
cp "$DYLIB" "$APP_BUNDLE/decrypt_helper.dylib"
echo "    + decrypt_helper.dylib"

# 签名工具
TOOL_COUNT=0
if [ -d "$TOOLS_DIR" ]; then
    for tool in "$TOOLS_DIR"/ct_bypass "$TOOLS_DIR"/ldid; do
        [ -f "$tool" ] || continue
        cp "$tool" "$APP_BUNDLE/$(basename "$tool")"
        chmod 755 "$APP_BUNDLE/$(basename "$tool")"
        echo "    + $(basename "$tool")"
        TOOL_COUNT=$((TOOL_COUNT + 1))
    done
fi
if [ "$TOOL_COUNT" -eq 0 ]; then
    echo "    ⚠️ 无签名工具 (注入时无法重签名, 请参考 tools/README.md)"
fi

# App 图标
[ -f "$APP_SRC/AppIcon60x60@2x.png" ] && cp "$APP_SRC/AppIcon60x60@2x.png" "$APP_BUNDLE/"

# 公众号关注物料
if [ -f "$ROOT/web/wechat-follow.png" ]; then
    cp "$ROOT/web/wechat-follow.png" "$APP_BUNDLE/"
    echo "    + wechat-follow.png"
fi

# 清理中间产物
for obj in "${OBJC_OBJS[@]}"; do [ -f "$obj" ] && unlink "$obj"; done
[ -f "$OUT_DIR/IOSDecryptHubTS" ] && unlink "$OUT_DIR/IOSDecryptHubTS"

echo "    ✅ bundle 就绪"
echo ""

# ================================================================
# 4. 签名
# ================================================================
echo "==> [4/5] 签名..."
if [ -n "$LDID" ]; then
    "$LDID" -S"$APP_SRC/entitlements.plist" "$APP_BUNDLE/IOSDecryptHubTS"
    "$LDID" -S "$APP_BUNDLE/decrypt_helper.dylib"
    for tool in "$APP_BUNDLE"/ct_bypass "$APP_BUNDLE"/ldid; do
        [ -f "$tool" ] && "$LDID" -S "$tool"
    done
    echo "    ✅ ldid 签名完成 (entitlements 已注入)"
else
    echo "    ⚠️ macOS ldid 未安装 (brew install ldid), 跳过构建签名"
    echo "       TrollStore 安装时会自动重签, 不影响使用"
fi
echo ""

# ================================================================
# 5. 打包 IPA
# ================================================================
echo "==> [5/5] 打包 IPA..."
IPA="$OUT_DIR/IOSDecryptHubTS_${VERSION}.ipa"
# 先删旧的
[ -f "$IPA" ] && unlink "$IPA"
(cd "$OUT_DIR" && zip -qr "$IPA" Payload/)

IPA_SIZE=$(du -h "$IPA" | cut -f1)
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║   ✅ 构建完成!                                  ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║                                                ║"
echo "║   📦 $IPA"
echo "║   📏 $IPA_SIZE"
echo "║                                                ║"
echo "║   安装方式:                                    ║"
echo "║   1. 把 IPA 传到 iPhone                        ║"
echo "║   2. 用 TrollStore 打开 → 安装                 ║"
echo "║   3. 桌面出现 IOSDecryptHub → 打开即用         ║"
echo "║                                                ║"
echo "╚══════════════════════════════════════════════════╝"
