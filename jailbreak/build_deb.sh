#!/bin/bash
# build_deb.sh — 构建 IOSDecryptHub 越狱 deb 包（三端）
#
# 用法:
#   ./jailbreak/build_deb.sh              # 构建全部三端
#   ./jailbreak/build_deb.sh rootless     # 仅 rootless
#   ./jailbreak/build_deb.sh roothide     # 仅 roothide
#   ./jailbreak/build_deb.sh rootful      # 仅 rootful
#
# 前提:
#   - macOS + Xcode (xcrun)
#   - dpkg-deb (brew install dpkg) 或 ldid
#
# 产物: build/deb/ 下三个 .deb 文件

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build/deb"
VERSION=$(grep '^VERSION' "$PROJECT_DIR/Makefile" | head -1 | sed 's/.*:= *//')
PKG_NAME="com.iosdecrypthub.jailbreak"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[*]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# ---------- 检查依赖 ----------
command -v dpkg-deb >/dev/null 2>&1 || error "需要 dpkg-deb (brew install dpkg)"
command -v xcrun >/dev/null 2>&1 || error "需要 Xcode (xcrun)"

# ---------- 编译主 dylib (jailbreak 变体) ----------
info "编译主 dylib (VARIANT=jailbreak)..."
make -C "$PROJECT_DIR" VARIANT=jailbreak clean all

# ---------- 编译加载器 ----------
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
CC=$(xcrun --find clang)
LOADER_SRC="$SCRIPT_DIR/src/loader.m"
LOADER_OUT="$BUILD_DIR/_loader/IOSDecryptHubLoader.dylib"

info "编译越狱加载器..."
mkdir -p "$(dirname "$LOADER_OUT")"
$CC -arch arm64 -isysroot "$SDK" -miphoneos-version-min=14.0 \
    -dynamiclib -install_name /usr/lib/IOSDecryptHub/IOSDecryptHubLoader.dylib \
    -ObjC -fobjc-arc -Wall -O2 \
    -framework Foundation \
    "$LOADER_SRC" -o "$LOADER_OUT"

# ---------- 编译 PreferenceBundle ----------
PREFS_SRC="$SCRIPT_DIR/prefs/IOSDecryptHubPrefsListController.m"
PREFS_BUNDLE="$BUILD_DIR/_prefs/IOSDecryptHubPrefs.bundle"

info "编译设置面板..."
mkdir -p "$PREFS_BUNDLE"
$CC -arch arm64 -isysroot "$SDK" -miphoneos-version-min=14.0 \
    -bundle \
    -ObjC -fobjc-arc -Wall -O2 \
    -framework Foundation -framework UIKit \
    -undefined dynamic_lookup \
    "$PREFS_SRC" -o "$PREFS_BUNDLE/IOSDecryptHubPrefs"
cp "$SCRIPT_DIR/prefs/Info.plist" "$PREFS_BUNDLE/"
cp "$SCRIPT_DIR/prefs/Root.plist" "$PREFS_BUNDLE/"

# ---------- 打包函数 ----------
build_variant() {
    local VARIANT="$1"
    local PREFIX="$2"
    local DEPENDS="$3"

    local STAGE="$BUILD_DIR/stage-$VARIANT"
    local DEB_OUT="$BUILD_DIR/${PKG_NAME}_${VERSION}_${VARIANT}.deb"

    info "打包 $VARIANT ..."
    rm -rf "$STAGE"
    mkdir -p "$STAGE/DEBIAN"
    mkdir -p "$STAGE/${PREFIX}/Library/MobileSubstrate/DynamicLibraries"
    mkdir -p "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub"
    mkdir -p "$STAGE/${PREFIX}/Library/PreferenceBundles"
    mkdir -p "$STAGE/${PREFIX}/Library/PreferenceLoader/Preferences"

    # control
    cat > "$STAGE/DEBIAN/control" << CTRL
Package: ${PKG_NAME}
Name: IOSDecryptHub
Version: ${VERSION}
Architecture: iphoneos-arm
Description: iOS runtime security analysis tool (dylib injection via jailbreak)
Maintainer: IOSDecryptHub
Author: IOSDecryptHub
Section: Tweaks
Depends: firmware (>= 14.0), ${DEPENDS}
Conflicts: com.iosdecrypthub.trollstore
CTRL

    # 加载器 + Filter
    cp "$LOADER_OUT" "$STAGE/${PREFIX}/Library/MobileSubstrate/DynamicLibraries/IOSDecryptHubLoader.dylib"
    cp "$SCRIPT_DIR/Filter.plist" "$STAGE/${PREFIX}/Library/MobileSubstrate/DynamicLibraries/IOSDecryptHubLoader.plist"

    # 主 dylib
    cp "$PROJECT_DIR/decrypt_helper.dylib" "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub/decrypt_helper.dylib"

    # 设置面板
    cp -R "$PREFS_BUNDLE" "$STAGE/${PREFIX}/Library/PreferenceBundles/"
    cp "$SCRIPT_DIR/prefs/entry.plist" "$STAGE/${PREFIX}/Library/PreferenceLoader/Preferences/IOSDecryptHubPrefs.plist"

    # 构建 deb
    dpkg-deb --build --root-owner-group "$STAGE" "$DEB_OUT" >/dev/null 2>&1
    info "✅ $DEB_OUT ($(du -h "$DEB_OUT" | cut -f1))"
}

# ---------- 构建目标 ----------
TARGETS="${1:-all}"

mkdir -p "$BUILD_DIR"

case "$TARGETS" in
    rootless)
        build_variant "rootless" "/var/jb" "mobilesubstrate (>= 0.9.5000), applist (>= 1.5)"
        ;;
    roothide)
        build_variant "roothide" "/var/jb" "mobilesubstrate (>= 0.9.5000), applist (>= 1.5)"
        ;;
    rootful)
        build_variant "rootful" "" "mobilesubstrate (>= 0.9.5000), applist (>= 1.5)"
        ;;
    all)
        build_variant "rootless" "/var/jb" "mobilesubstrate (>= 0.9.5000), applist (>= 1.5)"
        build_variant "roothide" "/var/jb" "mobilesubstrate (>= 0.9.5000), applist (>= 1.5)"
        build_variant "rootful" "" "mobilesubstrate (>= 0.9.5000), applist (>= 1.5)"
        ;;
    *)
        error "未知目标: $TARGETS (可选: rootless / roothide / rootful / all)"
        ;;
esac

info "全部完成! 产物在: $BUILD_DIR/"
ls -lh "$BUILD_DIR"/*.deb 2>/dev/null || true
