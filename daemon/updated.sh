#!/bin/sh
# launchd 入口。rootHide 下直接 Program=jb 路径会 exit 78，
# postinst 改成 /bin/sh 执行本脚本。
# 签过名的 daemon 对 /usr/lib/IOSDecryptHub 是 EPERM；本脚本负责把
# 配置和请求转交给 daemon；引擎安装仅由 dpkg 负责。
set -e
DIR=$(dirname "$0")
JBROOT=$(cd "$DIR/../../.." 2>/dev/null && pwd)
DAEMON="$DIR/IOSDecryptHubUpdated"

# 沙盒目标读不到 /var/mobile/.../loader.plist；jb 这份才是注入门。
# rootHide 上签过名的 daemon 写 /usr/lib 是 EPERM，这里用 /bin/sh 拷。
sync_enabled() {
    PREFS="/var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist"
    CFGDIR="$DIR/config"
    CFG="$CFGDIR/enabledBundles.plist"
    mkdir -p "$CFGDIR" 2>/dev/null || true
    if [ -f "$PREFS" ]; then
        cp "$PREFS" "$CFG" 2>/dev/null || true
        chmod 0666 "$CFG" 2>/dev/null || true
        chmod 0777 "$CFGDIR" 2>/dev/null || true
        chown mobile:mobile "$CFGDIR" "$CFG" 2>/dev/null || true
    fi
}

sync_request() {
    REQ_REAL="/var/mobile/Library/Preferences/com.iosdecrypthub.updater.request.plist"
    for REQ_SRC in \
        "$JBROOT/var/mobile/Library/Preferences/com.iosdecrypthub.updater.request.plist" \
        "$JBROOT/var/mobile/Library/Caches/com.iosdecrypthub/updater.request.plist" \
        "/var/mobile/Library/Caches/com.iosdecrypthub/updater.request.plist" \
        "/var/mobile/Library/Preferences/com.iosdecrypthub.updater.request.plist" \
        "$DIR/config/updater.request.plist"; do
        [ -f "$REQ_SRC" ] || continue
        if grep -q '<key>action</key><string>none</string>' "$REQ_SRC" 2>/dev/null; then
            rm -f "$REQ_SRC" 2>/dev/null || true
            continue
        fi
        if [ "$REQ_SRC" != "$REQ_REAL" ]; then
            cp "$REQ_SRC" "$REQ_REAL" 2>/dev/null || continue
        fi
        chown mobile:mobile "$REQ_REAL" 2>/dev/null || true
        chmod 0644 "$REQ_REAL" 2>/dev/null || true
        [ "$REQ_SRC" = "$REQ_REAL" ] || rm -f "$REQ_SRC" 2>/dev/null || true
        return 0
    done
}

sync_state() {
    SRC="$JBROOT/var/log/com.iosdecrypthub.updater.state.plist"
    DST="$DIR/state.plist"
    [ -f "$SRC" ] || return 0
    cp "$SRC" "$DST" 2>/dev/null || true
    chmod 0644 "$DST" 2>/dev/null || true
}

sync_enabled
sync_request

# 整包由 dpkg 管理；不执行旧 staging 引擎覆盖或交换备份。
"$DAEMON"
sync_state
sync_enabled
