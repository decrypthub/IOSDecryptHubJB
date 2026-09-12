#!/bin/bash
# 一键编译并部署到 iOS 模拟器 (sim_uitest + decrypt_helper.sim.dylib)
#
# 用法:
#   ./scripts/sim_install.sh              # 编译 + 安装到已启动的模拟器 + 启动 App
#   ./scripts/sim_install.sh --open       # 同上, 并打开 http://127.0.0.1:8088
#   ./scripts/sim_install.sh --no-build   # 跳过编译, 用现有产物重装
#   ./scripts/sim_install.sh --device UDID
#   ./scripts/sim_install.sh --no-launch  # 只安装不启动
#
# 依赖: Xcode (iphonesimulator SDK), insert_dylib (brew install insert_dylib)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BUNDLE_ID="com.taisuii.cryptotesthost"
APP_NAME="CryptoTestHost"
DYLIB_NAME="decrypt_helper.sim.dylib"
BUILD_DIR="$ROOT/build/sim"
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"
MIN_IOS="14.0"

DO_BUILD=1
DO_LAUNCH=1
DO_OPEN=0
DEVICE="booted"

usage() {
    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage 0 ;;
        --no-build) DO_BUILD=0; shift ;;
        --no-launch) DO_LAUNCH=0; shift ;;
        --open) DO_OPEN=1; shift ;;
        --device) DEVICE="${2:?缺少 --device 参数}"; shift 2 ;;
        *) echo "未知参数: $1"; usage 1 ;;
    esac
done

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || { echo "❌ 未找到 $1"; exit 1; }
}

need_cmd xcrun
need_cmd insert_dylib

SIM_SDK="$(xcrun --sdk iphonesimulator --show-sdk-path 2>/dev/null || true)"
if [[ -z "$SIM_SDK" ]]; then
    echo "❌ 未找到 iPhoneSimulator SDK, 请安装 Xcode"
    exit 1
fi

CC="$(xcrun --find clang)"
ARCH="$(uname -m)"
TARGET="-target ${ARCH}-apple-ios${MIN_IOS}-simulator"

if [[ "$DEVICE" == "booted" ]]; then
    if ! xcrun simctl list devices booted 2>/dev/null | grep -q "(Booted)"; then
        echo "[*] 没有已启动的模拟器, 正在启动默认设备..."
        DEFAULT_UDID="$(xcrun simctl list devices available -j \
            | python3 -c "import json,sys; d=json.load(sys.stdin); \
devs=[x for r in d.get('devices',{}).values() for x in r if x.get('isAvailable') and 'iPhone' in x.get('name','')]; \
print(devs[0]['udid'] if devs else '')")"
        if [[ -z "$DEFAULT_UDID" ]]; then
            echo "❌ 没有可用的 iPhone 模拟器"
            exit 1
        fi
        xcrun simctl boot "$DEFAULT_UDID" 2>/dev/null || true
        open -a Simulator
        DEVICE="$DEFAULT_UDID"
    fi
fi

if [[ "$DO_BUILD" -eq 1 ]]; then
    echo "[*] 编译 $DYLIB_NAME ..."
    make sim

    echo "[*] 编译测试 App ($APP_NAME) ..."
    rm -rf "$BUILD_DIR"
    mkdir -p "$APP_BUNDLE"

    "$CC" $TARGET -isysroot "$SIM_SDK" \
        -fobjc-arc -ObjC \
        -framework UIKit -framework Foundation -framework Security -framework AdSupport \
        sim_uitest/main.m -o "$APP_BUNDLE/$APP_NAME"

    cp sim_uitest/Info.plist "$APP_BUNDLE/"
    cp sim_uitest/AppIcon60x60@2x.png "$APP_BUNDLE/"
    cp "$DYLIB_NAME" "$APP_BUNDLE/"

    echo "[*] 注入 $DYLIB_NAME ..."
    insert_dylib --strip-codesig --inplace \
        "@executable_path/$DYLIB_NAME" "$APP_BUNDLE/$APP_NAME"

    codesign -s - --force --deep "$APP_BUNDLE"
else
    if [[ ! -d "$APP_BUNDLE" ]]; then
        echo "❌ 未找到 $APP_BUNDLE, 去掉 --no-build 重新编译"
        exit 1
    fi
fi

echo "[*] 安装到模拟器 ($DEVICE) ..."
# simctl 安装服务无法从外置磁盘路径创建传输 promise(IXErrorDomain code=2),
# 先中转到本地临时目录再安装。
STAGE_DIR="${TMPDIR:-/tmp}/dhsim-stage"
rm -rf "$STAGE_DIR" && mkdir -p "$STAGE_DIR"
cp -R "$APP_BUNDLE" "$STAGE_DIR/"
xcrun simctl install "$DEVICE" "$STAGE_DIR/$APP_NAME.app"

if [[ "$DO_LAUNCH" -eq 1 ]]; then
    echo "[*] 启动 $BUNDLE_ID ..."
    xcrun simctl launch "$DEVICE" "$BUNDLE_ID" >/dev/null
    sleep 1
    if curl -sf --max-time 2 http://127.0.0.1:8088/api/stats >/dev/null 2>&1; then
        echo "✅ Web 面板: http://127.0.0.1:8088"
    else
        echo "⚠️  App 已启动, Web 服务可能仍在初始化 — 稍后打开 http://127.0.0.1:8088"
    fi
    if [[ "$DO_OPEN" -eq 1 ]]; then
        open "http://127.0.0.1:8088"
    fi
else
    echo "✅ 已安装: $APP_BUNDLE"
fi
