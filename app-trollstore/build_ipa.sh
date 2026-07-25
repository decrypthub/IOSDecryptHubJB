#!/bin/bash
# 构建 IOSDecryptHub TrollStore IPA (非越狱, 无需 Xcode 工程)
#
# 用法: ./app-trollstore/build_ipa.sh
#
# 产物: build/trollstore/IOSDecryptHubTS.ipa
#
# 流程:
#   1. make VARIANT=trollstore → 编译 dylib (arm64)
#   2. swiftc 编译管理器 App (SwiftUI + ObjC 混编)
#   3. 组装 .app bundle (dylib + 工具 + Info.plist)
#   4. ldid 签名 (带 entitlements)
#   5. 打包 IPA (Payload/ 结构)
#
# 依赖: Xcode CLI tools, ldid (brew install ldid)
# 可选: ct_bypass (放入 app-trollstore/tools/ 目录, 自动打包进 App)
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

# 版本号从 Makefile 读取
VERSION="$(grep -m1 '^VERSION' "$ROOT/Makefile" | sed 's/.*:=[[:space:]]*//')"

OUT_DIR="$ROOT/build/trollstore"
APP_BUNDLE="$OUT_DIR/Payload/IOSDecryptHubTS.app"

echo "==> IOSDecryptHub TrollStore IPA (v${VERSION})"
echo "    SDK: $SDK"
echo "    Arch: $ARCH, Min iOS: $MIN_IOS"

# ---- 1. 编译 dylib ----
echo ""
echo "==> [1/5] 编译 dylib (VARIANT=trollstore)..."
make -C "$ROOT" VARIANT=trollstore
DYLIB="$ROOT/decrypt_helper.dylib"
if [ ! -f "$DYLIB" ]; then
    echo "❌ dylib 编译失败"; exit 1
fi
echo "    dylib: $(du -h "$DYLIB" | cut -f1)"

# ---- 2. 编译 App ----
echo ""
echo "==> [2/5] 编译管理器 App (SwiftUI + ObjC)..."
mkdir -p "$OUT_DIR"

# ObjC 源文件先编译为 .o
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

# Swift 编译 + 链接 ObjC .o
echo "    SWIFT App.swift + link"
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

# ---- 3. 组装 .app bundle ----
echo ""
echo "==> [3/5] 组装 .app bundle..."
mkdir -p "$APP_BUNDLE"

# 主二进制
cp "$OUT_DIR/IOSDecryptHubTS" "$APP_BUNDLE/"

# Info.plist (替换版本号)
sed "s/1.23.0/$VERSION/" "$APP_SRC/Info.plist" > "$APP_BUNDLE/Info.plist"

# 内嵌 dylib
cp "$DYLIB" "$APP_BUNDLE/decrypt_helper.dylib"
echo "    + decrypt_helper.dylib"

# 签名工具 (如果存在)
if [ -d "$TOOLS_DIR" ]; then
    for tool in "$TOOLS_DIR"/*; do
        [ -f "$tool" ] || continue
        cp "$tool" "$APP_BUNDLE/$(basename "$tool")"
        chmod 755 "$APP_BUNDLE/$(basename "$tool")"
        echo "    + $(basename "$tool")"
    done
else
    echo "    ⚠️ tools/ 目录不存在, 跳过 ct_bypass/ldid 打包"
    echo "       请将 ct_bypass 和 ldid 放入: $TOOLS_DIR/"
fi

# App 图标 (如果有)
if [ -f "$APP_SRC/AppIcon60x60@2x.png" ]; then
    cp "$APP_SRC/AppIcon60x60@2x.png" "$APP_BUNDLE/"
fi

# 清理 .o 文件
for obj in "${OBJC_OBJS[@]}"; do
    [ -f "$obj" ] && unlink "$obj"
done
[ -f "$OUT_DIR/IOSDecryptHubTS" ] && unlink "$OUT_DIR/IOSDecryptHubTS"

# ---- 4. 签名 ----
echo ""
echo "==> [4/5] 签名 (ldid + entitlements)..."
if [ -n "$LDID" ]; then
    # 对主二进制签名 (带 entitlements)
    "$LDID" -S"$APP_SRC/entitlements.plist" "$APP_BUNDLE/IOSDecryptHubTS"
    # 对内嵌 dylib 签名
    "$LDID" -S "$APP_BUNDLE/decrypt_helper.dylib"
    # 对工具签名
    for tool in "$APP_BUNDLE"/ct_bypass "$APP_BUNDLE"/ldid; do
        [ -f "$tool" ] && "$LDID" -S "$tool"
    done
    echo "    ✅ ldid 签名完成"
else
    echo "    ⚠️ ldid 未找到, 跳过签名 (TrollStore 安装时会重签)"
fi

# ---- 5. 打包 IPA ----
echo ""
echo "==> [5/5] 打包 IPA..."
IPA="$OUT_DIR/IOSDecryptHubTS_${VERSION}.ipa"
(cd "$OUT_DIR" && zip -qr "$IPA" Payload/)
echo ""
echo "✅ 完成: $IPA ($(du -h "$IPA" | cut -f1))"
echo ""
echo "   安装方式: 用 TrollStore 打开此 IPA"
echo "   或 URL Scheme: apple-magnifier://install?url=<IPA的URL>"
