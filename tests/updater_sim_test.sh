#!/bin/bash
# macOS 本地仿真：真实 daemon 拒绝旧安装/回滚，启动脚本保留请求且不覆盖引擎。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/dhupd.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
ENGINE="$WORK/home/usr/lib/IOSDecryptHub"
MOBILE="$WORK/mobile"
PREFS="$MOBILE/Library/Preferences"
REQUEST="$PREFS/com.iosdecrypthub.updater.request.plist"
STATE="$PREFS/com.iosdecrypthub.updater.state.plist"
mkdir -p "$ENGINE/config" "$PREFS" "$WORK/home/var/log" "$WORK/home/var/cache/com.iosdecrypthub"
cp /usr/bin/true "$ENGINE/decrypt_helper.dylib"
printf stale > "$WORK/home/var/cache/com.iosdecrypthub/decrypt_helper.dylib.new"
printf stale > "$ENGINE/decrypt_helper.dylib.bak"
BEFORE="$(shasum -a 256 "$ENGINE/decrypt_helper.dylib")"
sed "s#/var/mobile#$MOBILE#g" "$ROOT/src/dh_shared.h" > "$WORK/dh_shared.h"
cp "$ROOT/daemon/main.m" "$WORK/main.m"
xcrun clang -fobjc-arc -Wall -I"$ROOT/src" -framework Foundation "$WORK/main.m" -o "$ENGINE/IOSDecryptHubUpdated"
sed "s#/var/mobile#$MOBILE#g" "$ROOT/daemon/updated.sh" > "$ENGINE/updated.sh"
write_plist() {
    printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' "<plist version=\"1.0\">$2</plist>" > "$1"
}
get() { /usr/libexec/PlistBuddy -c "Print :$2" "$1"; }
for ACTION in install rollback; do
    # 新鲜检查时间避免测试访问网络；旧请求携带恶意 URL 也不会被使用。
    write_plist "$STATE" "<dict><key>lastCheck</key><real>$(date +%s)</real></dict>"
    write_plist "$REQUEST" "<dict><key>action</key><string>$ACTION</string><key>url</key><string>http://127.0.0.1:1/untrusted</string></dict>"
    "$ENGINE/IOSDecryptHubUpdated"
    [ "$(get "$STATE" lastOp:kind)" = "$ACTION" ]
    [ "$(get "$STATE" lastOp:result)" = error ]
    get "$STATE" lastOp:error | grep -q '包管理器'
    [ "$(get "$REQUEST" action)" = none ]
    [ "$BEFORE" = "$(shasum -a 256 "$ENGINE/decrypt_helper.dylib")" ]
    echo "PASS: daemon rejects $ACTION and preserves package engine"
done
# 测试启动脚本：真实请求不能被同路径 cp/rm 清除，旧 .new / .bak 不得覆盖。
write_plist "$REQUEST" '<dict><key>action</key><string>install</string></dict>'
sh "$ENGINE/updated.sh"
[ "$(get "$STATE" lastOp:kind)" = install ]
[ "$(get "$STATE" lastOp:result)" = error ]
[ "$(get "$REQUEST" lastAction)" = install ]
[ "$BEFORE" = "$(shasum -a 256 "$ENGINE/decrypt_helper.dylib")" ]
echo 'PASS: launch wrapper delivers request without applying stale staging or backup'
