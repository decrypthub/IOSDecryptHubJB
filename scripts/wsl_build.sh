#!/usr/bin/env bash
# IOSDecryptHub - 在 WSL 里用 swift-toolchain 交叉编译 (跳过 make, 直接 clang)
set -euo pipefail
source "$HOME/dh-cross/env.sh"
cd /mnt/c/Users/diiho/Claude/finshhook-plugin
echo "CC : $CROSS_CC"
echo "SDK: $IOS_SDK"

SRCS=(
  src/core/fishhook.c
  src/core/dh_health.c
  src/core/log_store.m
  src/hooks/crypto/hook_digest.m
  src/hooks/crypto/hook_hmac.m
  src/hooks/crypto/hook_symmetric.m
  src/hooks/crypto/hook_asymmetric.m
  src/hooks/crypto/hook_kdf.m
  src/hooks/behavior/hook_network.m
  src/hooks/behavior/hook_file.m
  src/hooks/behavior/hook_system.m
  src/server/http_server.m
  src/ui/ui_float.m
  src/ui/ui_logview.m
  src/core/main.m
)

OUT=decrypt_helper.dylib
"$CROSS_CC" \
  -target arm64-apple-ios14.0 \
  -isysroot "$IOS_SDK" \
  -dynamiclib \
  -install_name "@executable_path/$OUT" \
  -Xlinker -current_version -Xlinker 1.5.0 \
  -Xlinker -compatibility_version -Xlinker 1.0.0 \
  -ObjC -fobjc-arc \
  -Wall -Wno-deprecated-declarations -Wno-nullability-completeness \
  -Os \
  -Isrc/core -Isrc/server -Isrc/ui \
  -framework Foundation -framework UIKit -framework CoreGraphics -framework Security \
  "${SRCS[@]}" -o "$OUT"

echo "[*] linked $OUT"
file "$OUT" || true
ldid -S "$OUT" && echo "[*] ldid -S 完成"
ls -l "$OUT"
