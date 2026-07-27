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

ok(){ printf '  [PASS] %s\n' "$1"; PASS=$((PASS + 1)); }
ng(){ printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL + 1)); }
eq(){ if [[ "$1" = "$2" ]]; then ok "$3"; else ng "$3 (期望=$2 实得=$1)"; fi; }
ge(){ if [[ "${1:-x}" -ge "$2" ]] 2>/dev/null; then ok "$3"; else ng "$3 (期望>=$2 实得=${1:-空})"; fi; }

cleanup(){ xcrun simctl terminate "$DEVICE" "$BUNDLE_ID" >/dev/null 2>&1 || true; }
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
echo "[launch] 使用 DH_AUTOTEST=1 启动 $BUNDLE_ID"
SIMCTL_CHILD_DH_AUTOTEST=1 xcrun simctl launch "$DEVICE" "$BUNDLE_ID" >"$RESULT_DIR/launch.log" 2>&1 || exit 1

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
    if [[ "$digest" -ge 2 && "$sym" -ge 1 && "$file" -ge 3 ]]; then ready=1; break; fi
    sleep 0.2
done

eq "$ready" "1" "自动场景在超时前完成"
eq "$(jq -r '.result.structuredContent.process.bundleId' "$RESULT_DIR/stats.json")" "$BUNDLE_ID" "连接到正确测试 App"
ge "$(jq -r '.result.structuredContent.byCategory.digest // 0' "$RESULT_DIR/stats.json")" 2 "摘要事件 >= 2"
ge "$(jq -r '.result.structuredContent.byCategory.hmac // 0' "$RESULT_DIR/stats.json")" 1 "HMAC 事件 >= 1"
ge "$(jq -r '.result.structuredContent.byCategory.sym // 0' "$RESULT_DIR/stats.json")" 1 "对称加密事件 >= 1"
ge "$(jq -r '.result.structuredContent.byCategory.file // 0' "$RESULT_DIR/stats.json")" 3 "文件事件 >= 3"
ge "$(jq -r '.result.structuredContent.byCategory.net // 0' "$RESULT_DIR/stats.json")" 1 "回环网络事件 >= 1"

mc '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_events","arguments":{"category":"net","limit":10}}}' \
    > "$RESULT_DIR/network-events.json"
ge "$(jq -r '.result.structuredContent.matched // 0' "$RESULT_DIR/network-events.json")" 1 "存在网络事件明细"
NET_SEQ=$(jq -r '.result.structuredContent.events[0].seq // 0' "$RESULT_DIR/network-events.json")
mc "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"get_event\",\"arguments\":{\"seq\":$NET_SEQ}}}" \
    > "$RESULT_DIR/network-event-detail.json"
eq "$(jq -r '(.result.structuredContent.detail // "")|contains("127.0.0.1")' "$RESULT_DIR/network-event-detail.json")" \
    "true" "网络测试只访问本机回环地址"

mc '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_diag","arguments":{}}}' \
    > "$RESULT_DIR/diagnostics.json"
eq "$(jq -r '.result.isError' "$RESULT_DIR/diagnostics.json")" "false" "诊断信息可导出"

printf '模拟器结果: PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
