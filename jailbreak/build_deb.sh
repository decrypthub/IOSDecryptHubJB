#!/bin/bash
# 私有仓入口：编译闭源 dylib → 放入开源越狱仓 vendor → 调用开源打包脚本
#
# 用法与原先相同:
#   ./jailbreak/build_deb.sh [all|rootless|roothide]
#
# 越狱加载器 / 设置面板源码已迁至工作区并列仓库 IOSDecryptHubJB。

set -euo pipefail

if [ "$#" -gt 1 ]; then
    echo "[x] 用法: $0 [all|rootless|roothide]" >&2
    exit 1
fi

TARGET="${1:-all}"
case "$TARGET" in
    all|rootless|roothide) ;;
    *)
        echo "[x] 未知目标: $TARGET (可选: all / rootless / roothide)" >&2
        exit 1
        ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PRIVATE_DIR="$(dirname "$SCRIPT_DIR")"
WORKSPACE="$(dirname "$PRIVATE_DIR")"
JB_DIR="${DH_JB_DIR:-$WORKSPACE/IOSDecryptHubJB}"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
info()  { echo -e "${GREEN}[*]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

[ -d "$JB_DIR" ] || error "找不到开源越狱仓: $JB_DIR
请把 IOSDecryptHubJB 放在工作区根目录，或设置 DH_JB_DIR。"
[ -x "$JB_DIR/build_deb.sh" ] || chmod +x "$JB_DIR/build_deb.sh"

VERSION=$(grep '^VERSION' "$PRIVATE_DIR/Makefile" | head -1 | sed 's/.*:= *//')
[ -n "$VERSION" ] || error "无法读取私有仓 Makefile VERSION"

info "同步版本号 $VERSION → IOSDecryptHubJB/Makefile"
sed -i '' "s/^VERSION := .*/VERSION := $VERSION/" "$JB_DIR/Makefile"
grep -q "^VERSION := $VERSION$" "$JB_DIR/Makefile" \
    || error "无法把版本号写入 $JB_DIR/Makefile"

stage_engine() {
    local VARIANT="$1"
    local ARCHS="$2"
    local DEST="$JB_DIR/vendor/dylib/$VARIANT/decrypt_helper.dylib"
    info "编译闭源 dylib (VARIANT=rootless, archs=$ARCHS) → vendor/$VARIANT"
    make -C "$PRIVATE_DIR" -B VARIANT=rootless ARCHS="$ARCHS" all
    [ -f "$PRIVATE_DIR/decrypt_helper.dylib" ] || error "dylib 编译失败"
    mkdir -p "$(dirname "$DEST")"
    cp "$PRIVATE_DIR/decrypt_helper.dylib" "$DEST"
}

case "$TARGET" in
    all)
        stage_engine "rootless" "arm64"
        stage_engine "roothide" "arm64 arm64e"
        ;;
    rootless)
        stage_engine "rootless" "arm64"
        ;;
    roothide)
        stage_engine "roothide" "arm64 arm64e"
        ;;
esac

info "调用开源仓打包: $JB_DIR/build_deb.sh $TARGET"
"$JB_DIR/build_deb.sh" "$TARGET"

mkdir -p "$PRIVATE_DIR/build/deb"
cp -f "$JB_DIR/build/deb/"*.deb "$PRIVATE_DIR/build/deb/"
info "deb 已同步回私有仓 build/deb/"
ls -lh "$PRIVATE_DIR/build/deb/"*.deb 2>/dev/null || true
