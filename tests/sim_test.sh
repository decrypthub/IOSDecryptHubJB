#!/bin/bash

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RESULT_DIR="${DH_TEST_RESULTS_DIR:-$ROOT/build/test-results/sim-$(date +%Y%m%d-%H%M%S)-$$}"
mkdir -p "$RESULT_DIR"
# shellcheck source=tests/test_helpers.sh
source "$ROOT/tests/test_helpers.sh"

BUNDLE_ID="com.taisuii.cryptotesthost"
DEVICE="${DH_SIM_DEVICE:-booted}"
PASS=0
FAIL=0
ECHO_PID=""

ok(){ printf '  [PASS] %s\n' "$1"; PASS=$((PASS + 1)); }
ng(){ printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL + 1)); }
eq(){ if [[ "$1" = "$2" ]]; then ok "$3"; else ng "$3 (期望=$2 实得=$1)"; fi; }
ge(){ if [[ "${1:-x}" -ge "$2" ]] 2>/dev/null; then ok "$3"; else ng "$3 (期望>=$2 实得=${1:-空})"; fi; }

cleanup(){
    xcrun simctl terminate "$DEVICE" "$BUNDLE_ID" >/dev/null 2>&1 || true
    if [[ -n "$ECHO_PID" ]]; then
        kill "$ECHO_PID" >/dev/null 2>&1 || true
        wait "$ECHO_PID" 2>/dev/null || true
    fi
}
finalize(){
    local exit_code="$1"
    trap - EXIT
    if [[ "$exit_code" -ne 0 && "$FAIL" -eq 0 ]]; then ng "模拟器测试异常终止 (exit=$exit_code)"; fi
    dh_write_results "sim-e2e" "$PASS" "$FAIL" "sim"
    cleanup
    printf '[results] %s\n' "$RESULT_DIR"
    exit "$exit_code"
}
trap 'finalize $?' EXIT

for command in xcrun insert_dylib jq curl; do
    command -v "$command" >/dev/null || { echo "缺少命令: $command"; exit 2; }
done

echo "[build] 编译并安装模拟器测试 App"
./scripts/sim_install.sh --device "$DEVICE" --no-launch >"$RESULT_DIR/build-install.log" 2>&1 || {
    echo "模拟器构建/安装失败，见 $RESULT_DIR/build-install.log"
    exit 1
}

cleanup
echo "[echo] 启动本地 HTTP/WebSocket 回显服务"
python3 tests/net_echo_server.py --port 8099 --ws >"$RESULT_DIR/echo.log" 2>&1 &
ECHO_PID=$!
for _ in $(seq 1 50); do
    curl -sf --max-time 1 http://127.0.0.1:8099/echo >/dev/null 2>&1 && break
    sleep 0.1
done
echo "[launch] 使用 DH_AUTOTEST=1 启动 $BUNDLE_ID"
SIMCTL_CHILD_DH_AUTOTEST=1 SIMCTL_CHILD_DH_WEBKIT_PROBE=1 \
    xcrun simctl launch "$DEVICE" "$BUNDLE_ID" >"$RESULT_DIR/launch.log" 2>&1 || exit 1

PORT=$(dh_find_http_for_bundle "$BUNDLE_ID" 30) || {
    echo "未找到 $BUNDLE_ID 的 HTTP 服务"
    exit 1
}
MCP="http://127.0.0.1:$PORT/api/mcp"
mc(){ curl -sf --max-time 15 -X POST "$MCP" -H 'Content-Type: application/json' -d "$1"; }

echo "[server] port=${PORT}，轮询自动场景事件"
ready=0
for ((i = 0; i < 100; i++)); do
    mc '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_stats","arguments":{}}}' \
        > "$RESULT_DIR/stats.json" || true
    digest=$(jq -r '.result.structuredContent.byCategory.digest // 0' "$RESULT_DIR/stats.json" 2>/dev/null || echo 0)
    sym=$(jq -r '.result.structuredContent.byCategory.sym // 0' "$RESULT_DIR/stats.json" 2>/dev/null || echo 0)
    file=$(jq -r '.result.structuredContent.byCategory.file // 0' "$RESULT_DIR/stats.json" 2>/dev/null || echo 0)
    if [[ "$digest" -ge 2 && "$sym" -ge 1 && "$file" -ge 5 ]]; then ready=1; break; fi
    sleep 0.2
done

eq "$ready" "1" "自动场景在超时前完成"
eq "$(jq -r '.result.structuredContent.process.bundleId' "$RESULT_DIR/stats.json")" "$BUNDLE_ID" "连接到正确测试 App"
ge "$(jq -r '.result.structuredContent.byCategory.digest // 0' "$RESULT_DIR/stats.json")" 2 "摘要事件 >= 2"
ge "$(jq -r '.result.structuredContent.byCategory.hmac // 0' "$RESULT_DIR/stats.json")" 1 "HMAC 事件 >= 1"
ge "$(jq -r '.result.structuredContent.byCategory.sym // 0' "$RESULT_DIR/stats.json")" 1 "对称加密事件 >= 1"
ge "$(jq -r '.result.structuredContent.byCategory.file // 0' "$RESULT_DIR/stats.json")" 5 "文件事件 >= 5"
ge "$(jq -r '.result.structuredContent.byCategory.net // 0' "$RESULT_DIR/stats.json")" 1 "回环网络事件 >= 1"

mc '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_events","arguments":{"category":"net","limit":10}}}' \
    > "$RESULT_DIR/network-events.json"
ge "$(jq -r '.result.structuredContent.matched // 0' "$RESULT_DIR/network-events.json")" 1 "存在网络事件明细"
NET_SEQ=$(jq -r '.result.structuredContent.events[0].seq // 0' "$RESULT_DIR/network-events.json")
mc "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"get_event\",\"arguments\":{\"seq\":$NET_SEQ}}}" \
    > "$RESULT_DIR/network-event-detail.json"
eq "$(jq -r '(.result.structuredContent.detail // "")|contains("127.0.0.1")' "$RESULT_DIR/network-event-detail.json")" \
    "true" "网络测试只访问本机回环地址"

echo "[webkit] 轮询 WKWebView 宿主侧事件"
webkit_ready=0
for ((i = 0; i < 80; i++)); do
    mc '{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"query_events","arguments":{"category":"net","query":"WEBKIT","limit":100}}}' \
        > "$RESULT_DIR/webkit-events.json" || true
    if jq -e '[.result.structuredContent.events[] | select(.algorithm=="WEBKIT") | .operation] as $ops |
        ["navigate","evaluateJavaScript","jsBridge","message","cookie.set","cookie.get",
         "scheme.register","scheme.start"] |
        all(. as $op | $ops | index($op) != null)' "$RESULT_DIR/webkit-events.json" >/dev/null 2>&1; then
        webkit_ready=1
        break
    fi
    sleep 0.2
done
eq "$webkit_ready" "1" "WebKit 宿主侧事件已产生"
for op in navigate evaluateJavaScript jsBridge message cookie.set cookie.get scheme.register scheme.start; do
    eq "$(jq -r --arg op "$op" '[.result.structuredContent.events[] | select(.algorithm=="WEBKIT" and .operation==$op)] | length > 0' "$RESULT_DIR/webkit-events.json")" \
        "true" "WebKit 事件包含 $op"
done

echo "[webkit-probe] 轮询 JS 网络探针事件"
probe_ready=0
for ((i = 0; i < 100; i++)); do
    mc '{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"query_events","arguments":{"category":"net","query":"WEBKIT-PROBE","limit":100}}}' \
        > "$RESULT_DIR/webkit-probe-events.json" || true
    if jq -e '[.result.structuredContent.events[] | select(.algorithm=="WEBKIT-PROBE") | .operation] as $ops |
        ["fetch.request","fetch.response","xhr.request","xhr.response","websocket.open",
         "websocket.send","websocket.recv","beacon"] |
        all(. as $op | $ops | index($op) != null)' "$RESULT_DIR/webkit-probe-events.json" >/dev/null 2>&1; then
        probe_ready=1
        break
    fi
    sleep 0.2
done
eq "$probe_ready" "1" "WebKit JS 网络探针事件已产生"
for op in fetch.request fetch.response xhr.request xhr.response websocket.open websocket.send websocket.recv beacon; do
    eq "$(jq -r --arg op "$op" '[.result.structuredContent.events[] | select(.algorithm=="WEBKIT-PROBE" and .operation==$op)] | length > 0' "$RESULT_DIR/webkit-probe-events.json")" \
        "true" "WebKit JS 探针包含 $op"
done
eq "$(jq -r '[.result.structuredContent.events[] | select(.algorithm=="WEBKIT-PROBE" and ((.preview // "") | contains("DH_WK_XHR_BODY_001")))] | length > 0' "$RESULT_DIR/webkit-probe-events.json")" \
    "true" "XHR 请求体进入探针事件"
eq "$(jq -r '[.result.structuredContent.events[] | select(.algorithm=="WEBKIT-PROBE" and ((.preview // "") | contains("DH_WK_WS_001")))] | length > 0' "$RESULT_DIR/webkit-probe-events.json")" \
    "true" "WebSocket 帧进入探针事件"

mc '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_diag","arguments":{}}}' \
    > "$RESULT_DIR/diagnostics.json"
eq "$(jq -r '.result.isError' "$RESULT_DIR/diagnostics.json")" "false" "诊断信息可导出"

# 单独触发复合文件生命周期。为避开 simctl openurl 的系统确认框(无人值守下 URL
# 永远送不到 App), 改用 DH_TRIGGER 环境变量重启触发, 与 DH_AUTOTEST 同通道。
mc '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"clear_events","arguments":{"category":"file"}}}' >/dev/null
echo "[trigger] 重启并用 DH_TRIGGER 触发 baseline.file.lifecycle"
xcrun simctl terminate "$DEVICE" "$BUNDLE_ID" >/dev/null 2>&1 || true
SIMCTL_CHILD_DH_TRIGGER=baseline.file.lifecycle xcrun simctl launch "$DEVICE" "$BUNDLE_ID" >"$RESULT_DIR/relaunch.log" 2>&1 || exit 1
PORT=$(dh_find_http_for_bundle "$BUNDLE_ID" 30) || {
    echo "重启后未找到 $BUNDLE_ID 的 HTTP 服务"
    exit 1
}
MCP="http://127.0.0.1:$PORT/api/mcp"
file_lifecycle_ready=0
for ((i = 0; i < 50; i++)); do
    mc '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"query_events","arguments":{"category":"file","limit":100}}}' \
        > "$RESULT_DIR/file-lifecycle.json" || true
    if jq -e '[.result.structuredContent.events[].algorithm] as $algorithms |
        ["open","write","read","rename","unlink"] |
        all(. as $name | $algorithms | index($name) != null)' \
        "$RESULT_DIR/file-lifecycle.json" >/dev/null 2>&1; then
        file_lifecycle_ready=1
        break
    fi
    sleep 0.2
done
eq "$file_lifecycle_ready" "1" "复合文件场景包含 open/write/read/rename/unlink"

printf '模拟器结果: PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
