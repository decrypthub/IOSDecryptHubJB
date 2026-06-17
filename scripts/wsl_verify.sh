#!/usr/bin/env bash
set -euo pipefail
source "$HOME/dh-cross/env.sh"
cd /mnt/c/Users/diiho/Claude/finshhook-plugin

NM="$DH_CROSS_ROOT/toolchain/host/bin/llvm-nm"
OTOOL_CANDIDATES=(
    "$DH_CROSS_ROOT/toolchain/iphone/bin/otool"
    "$DH_CROSS_ROOT/toolchain/host/bin/llvm-otool"
    "$DH_CROSS_ROOT/toolchain/host/bin/llvm-objdump"
)
OTOOL=""
for c in "${OTOOL_CANDIDATES[@]}"; do [ -x "$c" ] && OTOOL="$c" && break; done

echo "=== dylib info ==="
file decrypt_helper.dylib
ls -lh decrypt_helper.dylib

echo
echo "=== undefined symbols we expect to hook ==="
"$NM" -u decrypt_helper.dylib | grep -E "CC_(MD|SHA)|CCHmac|CCCrypt|SecKey" | sort -u || echo "(none found)"

echo
echo "=== load commands ==="
if [ -n "$OTOOL" ]; then
    "$OTOOL" --macho-load-commands decrypt_helper.dylib 2>/dev/null | head -40 || \
    "$OTOOL" -l decrypt_helper.dylib 2>/dev/null | head -40 || \
    echo "(can't dump load commands)"
fi
