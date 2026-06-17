#!/usr/bin/env bash
# 解密助手 - WSL 交叉编译工具链一键准备 (无需 sudo, 全部装在 ~/dh-cross)
#
# 内容:
#   1. kabiroberai/swift-toolchain-linux  (含 clang + lld + Apple target 支持)
#   2. theos/sdks  iPhoneOS16.5.sdk
#   3. ProcursusTeam/ldid                (用于签名 dylib)
#
# 用法:
#   bash scripts/wsl_setup_toolchain.sh
#   source ~/dh-cross/env.sh
#   make linux

set -euo pipefail

ROOT="${DH_CROSS_ROOT:-$HOME/dh-cross}"
mkdir -p "$ROOT"
cd "$ROOT"

# 探测发行版选择哪个 swift-toolchain
. /etc/os-release || true
UB_VER="${VERSION_ID:-22.04}"
case "$UB_VER" in
  18.*) UB=18.04 ;;
  20.*) UB=20.04 ;;
  *)    UB=22.04 ;;
esac

TC_URL="https://github.com/kabiroberai/swift-toolchain-linux/releases/download/v2.3.0/swift-5.8-ubuntu${UB}.tar.xz"
SDK_URL="https://github.com/theos/sdks/releases/download/master-146e41f/iPhoneOS16.5.sdk.tar.xz"
LDID_URL="https://github.com/ProcursusTeam/ldid/releases/download/v2.1.5-procursus7/ldid_linux_x86_64"

echo "[*] Toolchain: $TC_URL"
echo "[*] SDK     : $SDK_URL"
echo "[*] ldid    : $LDID_URL"
echo "[*] 安装到  : $ROOT"
echo

# 1. swift toolchain
if [ ! -d "$ROOT/toolchain" ]; then
    echo "[1/3] 下载 swift toolchain..."
    curl -fL --progress-bar -o swift.tar.xz "$TC_URL"
    mkdir -p toolchain
    echo "[1/3] 解压 toolchain..."
    tar -xJf swift.tar.xz -C toolchain --strip-components=1
    rm swift.tar.xz
else
    echo "[1/3] toolchain 已存在, 跳过"
fi

# 2. iPhoneOS SDK
if [ ! -d "$ROOT/sdks/iPhoneOS16.5.sdk" ]; then
    echo "[2/3] 下载 iPhoneOS SDK..."
    mkdir -p sdks
    curl -fL --progress-bar -o sdk.tar.xz "$SDK_URL"
    echo "[2/3] 解压 SDK..."
    tar -xJf sdk.tar.xz -C sdks
    rm sdk.tar.xz
else
    echo "[2/3] SDK 已存在, 跳过"
fi

# 3. ldid
if [ ! -x "$ROOT/bin/ldid" ]; then
    echo "[3/3] 下载 ldid..."
    mkdir -p bin
    curl -fL -o bin/ldid "$LDID_URL"
    chmod +x bin/ldid
else
    echo "[3/3] ldid 已存在, 跳过"
fi

# env.sh
cat > "$ROOT/env.sh" <<EOF
# source me before \`make linux\`
export DH_CROSS_ROOT="$ROOT"
export IOS_SDK="\$DH_CROSS_ROOT/sdks/iPhoneOS16.5.sdk"
export CROSS_CC="\$DH_CROSS_ROOT/toolchain/iphone/bin/clang"
# iphone/bin 优先 (含 cctools 的 ld), host/bin 提供 lld 等
export PATH="\$DH_CROSS_ROOT/bin:\$DH_CROSS_ROOT/toolchain/iphone/bin:\$DH_CROSS_ROOT/toolchain/host/bin:\$PATH"
EOF

echo
echo "✅ 准备完成. 启用环境:"
echo "    source $ROOT/env.sh"
echo "然后:"
echo "    make linux"
