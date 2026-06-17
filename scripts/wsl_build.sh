#!/usr/bin/env bash
# 解密助手 - 在 WSL 里用 swift-toolchain 交叉编译 (跳过 make, 直接 clang)
set -euo pipefail
source "$HOME/dh-cross/env.sh"
cd /mnt/c/Users/diiho/Claude/finshhook-plugin
echo "CC : $CROSS_CC"
echo "SDK: $IOS_SDK"

SRCS=(
  src/fishhook.c
  src/log_store.m
  src/hook_digest.m
  src/hook_hmac.m
  src/hook_symmetric.m
  src/hook_asymmetric.m
  src/ui_float.m
  src/ui_logview.m
  src/main.m
)

OUT=decrypt_helper.dylib
"$CROSS_CC" \
  -target arm64-apple-ios14.0 \
  -isysroot "$IOS_SDK" \
  -dynamiclib \
  -install_name "@executable_path/$OUT" \
  -ObjC -fobjc-arc \
  -Wall -Wno-deprecated-declarations -Wno-nullability-completeness \
  -Os \
  -framework Foundation -framework UIKit -framework CoreGraphics -framework Security \
  "${SRCS[@]}" -o "$OUT"

echo "[*] linked $OUT"
file "$OUT" || true
ldid -S "$OUT" && echo "[*] ldid -S 完成"
ls -l "$OUT"
