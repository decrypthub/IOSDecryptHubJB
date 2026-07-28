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
command -v ldid >/dev/null 2>&1 || error "需要 ldid (brew install ldid)"

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
    local ARCHITECTURE="$4"

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
Architecture: ${ARCHITECTURE}
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
    cp "$SCRIPT_DIR/enabledBundles.default.plist" \
        "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub/enabledBundles.default.plist"

    # 主门控配置不作为 dpkg conffile 打包，避免升级覆盖用户选择。postinst 在干净安装时
    # 创建，在旧版升级时从 /var/mobile/Library/Preferences 自动迁移。
    cat > "$STAGE/DEBIAN/postinst" << POSTINST
#!/bin/sh
set -e
CONFIG_DIR="${PREFIX}/usr/lib/IOSDecryptHub/config"
CONFIG_PATH="\$CONFIG_DIR/enabledBundles.plist"
DEFAULT_PATH="${PREFIX}/usr/lib/IOSDecryptHub/enabledBundles.default.plist"
LEGACY_PATH="/var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist"
mkdir -p "\$CONFIG_DIR"
if [ ! -f "\$CONFIG_PATH" ]; then
    if [ -f "\$LEGACY_PATH" ]; then
        cp "\$LEGACY_PATH" "\$CONFIG_PATH"
    else
        cp "\$DEFAULT_PATH" "\$CONFIG_PATH"
    fi
fi
chown mobile:mobile "\$CONFIG_DIR" "\$CONFIG_PATH" 2>/dev/null || true
chmod 0755 "\$CONFIG_DIR"
chmod 0644 "\$CONFIG_PATH"
exit 0
POSTINST
    chmod 0755 "$STAGE/DEBIAN/postinst"

    # 设置面板
    cp -R "$PREFS_BUNDLE" "$STAGE/${PREFIX}/Library/PreferenceBundles/"
    cp "$SCRIPT_DIR/prefs/entry.plist" "$STAGE/${PREFIX}/Library/PreferenceLoader/Preferences/IOSDecryptHubPrefs.plist"

    # 越狱环境仍要求可加载 Mach-O 具备 ad-hoc 签名。
    ldid -S "$STAGE/${PREFIX}/Library/MobileSubstrate/DynamicLibraries/IOSDecryptHubLoader.dylib"
    ldid -S "$STAGE/${PREFIX}/usr/lib/IOSDecryptHub/decrypt_helper.dylib"
    ldid -S "$STAGE/${PREFIX}/Library/PreferenceBundles/IOSDecryptHubPrefs.bundle/IOSDecryptHubPrefs"

    # 构建 deb
    dpkg-deb --build --root-owner-group "$STAGE" "$DEB_OUT" >/dev/null 2>&1

    # 发布包必须能在干净环境中由包管理器完整解析，禁止依赖设备侧手工补文件。
    local ACTUAL_ARCH
    local ACTUAL_DEPENDS
    local PACKAGE_CONTENTS
    ACTUAL_ARCH=$(dpkg-deb -f "$DEB_OUT" Architecture)
    ACTUAL_DEPENDS=$(dpkg-deb -f "$DEB_OUT" Depends)
    PACKAGE_CONTENTS=$(dpkg-deb -c "$DEB_OUT")
    [ "$ACTUAL_ARCH" = "$ARCHITECTURE" ] || error "$VARIANT 架构错误: $ACTUAL_ARCH"
    case "$ACTUAL_DEPENDS" in
        *"preferenceloader (>= 2.2.6)"*) ;;
        *) error "$VARIANT 缺少 PreferenceLoader 运行时依赖" ;;
    esac
    case "$PACKAGE_CONTENTS" in
        *"/PreferenceLoader/Preferences/IOSDecryptHubPrefs.plist"*) ;;
        *) error "$VARIANT 缺少设置入口" ;;
    esac
    case "$PACKAGE_CONTENTS" in
        *"/usr/lib/IOSDecryptHub/enabledBundles.default.plist"*) ;;
        *) error "$VARIANT 缺少内置门控配置模板" ;;
    esac
    grep -q '<string>com.apple.UIKit</string>' \
        "$STAGE/${PREFIX}/Library/MobileSubstrate/DynamicLibraries/IOSDecryptHubLoader.plist" \
        || error "$VARIANT 的 MobileLoader 过滤器未覆盖 UIKit App"

    info "✅ $DEB_OUT ($(du -h "$DEB_OUT" | cut -f1))"
}

# ---------- 构建目标 ----------
TARGETS="${1:-all}"

mkdir -p "$BUILD_DIR"

case "$TARGETS" in
    rootless)
        build_variant "rootless" "/var/jb" "mobilesubstrate (>= 0.9.5000), preferenceloader (>= 2.2.6)" "iphoneos-arm64"
        ;;
    roothide)
        build_variant "roothide" "/var/jb" "mobilesubstrate (>= 0.9.5000), preferenceloader (>= 2.2.6)" "iphoneos-arm64"
        ;;
    rootful)
        build_variant "rootful" "" "mobilesubstrate (>= 0.9.5000), preferenceloader (>= 2.2.6)" "iphoneos-arm"
        ;;
    all)
        build_variant "rootless" "/var/jb" "mobilesubstrate (>= 0.9.5000), preferenceloader (>= 2.2.6)" "iphoneos-arm64"
        build_variant "roothide" "/var/jb" "mobilesubstrate (>= 0.9.5000), preferenceloader (>= 2.2.6)" "iphoneos-arm64"
        build_variant "rootful" "" "mobilesubstrate (>= 0.9.5000), preferenceloader (>= 2.2.6)" "iphoneos-arm"
        ;;
    *)
        error "未知目标: $TARGETS (可选: rootless / roothide / rootful / all)"
        ;;
esac

info "全部完成! 产物在: $BUILD_DIR/"
ls -lh "$BUILD_DIR"/*.deb 2>/dev/null || true
