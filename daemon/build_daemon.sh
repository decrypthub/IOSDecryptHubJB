#!/bin/bash
# 构建 dh_server daemon (root 权限 HTTP API 服务)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
OUT="$ROOT/build/daemon"
mkdir -p "$OUT"

echo "==> 编译 dh_server daemon (arm64e)"
xcrun clang -arch arm64e -isysroot "$SDK" -miphoneos-version-min=15.0 \
    -framework Foundation \
    -fobjc-arc -O2 \
    -o "$OUT/dh_server" \
    "$ROOT/daemon/dh_server.m"

LDID="$(command -v ldid || true)"
[ -n "$LDID" ] && "$LDID" -S "$OUT/dh_server"
echo "✅ daemon: $OUT/dh_server ($(du -h "$OUT/dh_server" | cut -f1))"
