#!/bin/bash
# 构建 DecryptHelper 管理器 App (越狱设备用, 无需 Xcode 工程)
# 用法: ./app/build_app.sh [roothide|rootless|rootful]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_SRC="$ROOT/app/DecryptHelperManager"
VARIANT="${1:-roothide}"

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
CC="$(xcrun --find swiftc)"
LDID="$(command -v ldid || true)"

# 架构: roothide=arm64e, 其他=arm64
case "$VARIANT" in
    roothide) ARCH="arm64e"; MIN_IOS="15.0" ;;
    rootless) ARCH="arm64";  MIN_IOS="15.0" ;;
    rootful)  ARCH="arm64";  MIN_IOS="14.0" ;;
    *) echo "用法: $0 [roothide|rootless|rootful]"; exit 1 ;;
esac

OUT_DIR="$ROOT/build/app"
APP_BUNDLE="$OUT_DIR/DecryptHelper.app"
mkdir -p "$APP_BUNDLE"

echo "==> 编译 DecryptHelper 管理器 ($VARIANT, $ARCH)"
"$CC" \
    -target "${ARCH}-apple-ios${MIN_IOS}" \
    -sdk "$SDK" \
    -framework SwiftUI \
    -framework UIKit \
    -framework Foundation \
    -framework CoreGraphics \
    -O \
    -o "$APP_BUNDLE/DecryptHelperManager" \
    "$APP_SRC/DecryptHelperApp.swift" \
    "$APP_SRC/PrivateAPIs.swift" \
    "$APP_SRC/MainView.swift"

echo "==> 组装 .app bundle"
cp "$APP_SRC/Info.plist" "$APP_BUNDLE/"
cp "$APP_SRC/AppIcon60x60@2x.png" "$APP_BUNDLE/" 2>/dev/null || true

echo "==> 伪签名 (ldid)"
if [ -n "$LDID" ]; then
    "$LDID" -S"$APP_SRC/entitlements.plist" "$APP_BUNDLE/DecryptHelperManager"
else
    echo "⚠️  ldid 未找到, 跳过签名"
fi

echo "✅ App 构建完成: $APP_BUNDLE"
echo "   安装到设备: /var/jb/Applications/DecryptHelper.app (roothide/rootless)"
echo "   或:         /Applications/DecryptHelper.app (rootful)"
