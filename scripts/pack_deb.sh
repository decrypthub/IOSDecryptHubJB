#!/bin/bash
# 越狱变体 .deb 打包 —— 一份源码, 按 variant 产出 rootless / rootful / roothide 三种包。
#
# 用法:
#   ./scripts/pack_deb.sh rootless     # arm64, 装到 /var/jb
#   ./scripts/pack_deb.sh rootful      # arm64, 装到 /
#   ./scripts/pack_deb.sh roothide     # arm64e, 装到 /var/jb
#
# 原理: 我们的核心引擎是纯 fishhook + ObjC runtime, 不链接 Substrate/ElleKit 的 API,
# 所以越狱包只需 [dylib + filter plist + control], 由设备上的注入器(ElleKit/libhooker/
# MobileSubstrate 任一)读 plist 自动注入。dm.pl(Theos 自带)封包, 无需系统 dpkg-deb。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VARIANT="${1:-}"
DM="${THEOS:-/opt/theos}/bin/dm.pl"
LDID="$(command -v ldid || true)"

# VERSION 单一真相源 = Makefile 顶部。
VERSION="$(grep -m1 '^VERSION' Makefile | sed 's/.*:=[[:space:]]*//')"

case "$VARIANT" in
    rootless)  JBROOT="/var/jb"; DEB_ARCH="iphoneos-arm64"; DEPENDS="ellekit | mobilesubstrate" ;;
    rootful)   JBROOT="";        DEB_ARCH="iphoneos-arm";   DEPENDS="mobilesubstrate" ;;
    roothide)  JBROOT="/var/jb"; DEB_ARCH="iphoneos-arm64e"; DEPENDS="ellekit" ;;
    *) echo "用法: $0 <rootless|rootful|roothide>"; exit 1 ;;
esac

[ -x "$DM" ] || { echo "❌ 缺 dm.pl ($DM)。装 Theos 或 export THEOS=/path/to/theos"; exit 1; }
[ -n "$LDID" ] || { echo "❌ 缺 ldid (brew install ldid)"; exit 1; }

echo "==> 编译 $VARIANT 变体 dylib (VERSION=$VERSION)"
make -s clean >/dev/null 2>&1 || true
make -s VARIANT="$VARIANT"

echo "==> 伪签名 (ldid -S)"
"$LDID" -S decrypt_helper.dylib

# ---- 构造 .deb layout ----
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
DYLIB_DIR="$STAGE${JBROOT}/Library/MobileSubstrate/DynamicLibraries"
mkdir -p "$DYLIB_DIR" "$STAGE/DEBIAN"

# dylib 与 plist 同名 (MobileSubstrate 约定: 同前缀配对)。
cp decrypt_helper.dylib          "$DYLIB_DIR/DecryptHelper.dylib"
cp packaging/DecryptHelper.plist "$DYLIB_DIR/DecryptHelper.plist"

# PreferenceLoader 设置面板 (Settings 里的注入开关)
PREFS_DIR="$STAGE${JBROOT}/Library/PreferenceLoader/Preferences"
mkdir -p "$PREFS_DIR"
cp packaging/DecryptHelper-prefs.plist "$PREFS_DIR/DecryptHelper.plist"

# 管理器 App (桌面图标, 选择注入目标)
if [ -d "build/app/DecryptHelper.app" ]; then
    APP_DIR="$STAGE${JBROOT}/Applications"
    mkdir -p "$APP_DIR"
    cp -R build/app/DecryptHelper.app "$APP_DIR/"
    echo "  + 管理器 App 已包含"
fi

# root daemon: HTTP API 服务 (枚举 App / 读写偏好)
if [ -f "build/daemon/dh_server" ]; then
    HELPER_DIR="$STAGE${JBROOT}/usr/bin"
    mkdir -p "$HELPER_DIR"
    cp build/daemon/dh_server "$HELPER_DIR/dh_server"
    chmod 755 "$HELPER_DIR/dh_server"
    # helper 脚本 (生成 App 列表 JSON)
    cp app/dh_listapps.sh "$HELPER_DIR/dh_listapps"
    chmod 755 "$HELPER_DIR/dh_listapps"
    # LaunchDaemon: 开机自启 + 崩溃重拉
    DAEMON_DIR="$STAGE${JBROOT}/Library/LaunchDaemons"
    mkdir -p "$DAEMON_DIR"
    # LaunchDaemon plist 中的路径按变体替换 (rootful 无 /var/jb 前缀)
    sed "s|/var/jb/usr/bin|${JBROOT}/usr/bin|g" packaging/com.dh.server.plist > "$DAEMON_DIR/com.dh.server.plist"
    echo "  + dh_server daemon + LaunchDaemon 已包含"
fi

# control: 模板占位符替换。
sed -e "s/@VERSION@/$VERSION/" \
    -e "s/@ARCH@/$DEB_ARCH/" \
    -e "s/@VARIANT@/$VARIANT/" \
    -e "s/@DEPENDS@/$DEPENDS/" \
    packaging/control.tmpl > "$STAGE/DEBIAN/control"

# ---- 封包 ----
OUT="decrypt_helper_${VARIANT}_${VERSION}.deb"
"$DM" -Zgzip -b "$STAGE" "$OUT"
echo "✅ 打包完成: $OUT  ($(du -h "$OUT" | cut -f1))"
