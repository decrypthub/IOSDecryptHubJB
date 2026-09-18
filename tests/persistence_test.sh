#!/bin/bash
# 持久化回载 E2E:
#   第一轮生成事件 -> SIGKILL(模拟闪退) -> 第二轮启动
#   -> 校验结构化日志(journal)把最近事件回载到内存, 且同 seq 内容一致。
# 用法: make test-persistence

set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RESULT_DIR="${DH_TEST_RESULTS_DIR:-$ROOT/build/test-results/persistence-$(date +%Y%m%d-%H%M%S)-$$}"
mkdir -p "$RESULT_DIR"
# shellcheck source=tests/test_helpers.sh
source "$ROOT/tests/test_helpers.sh"
exec 2> >(tee "$RESULT_DIR/stderr.log" >&2)

PASS=0; FAIL=0
ok(){ printf '  \033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); printf 'PASS\t%s\n' "$1" >> "$RESULT_DIR/assertions.tsv"; }
ng(){ printf '  \033[31m✗\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); printf 'FAIL\t%s\n' "$1" >> "$RESULT_DIR/assertions.tsv"; }
eq(){ if [[ "$1" = "$2" ]]; then ok "$3"; else ng "$3  (期望=$2 实得=$1)"; fi; }
ge(){ if [[ "${1:-x}" -ge "$2" ]] 2>/dev/null; then ok "$3"; else ng "$3  (期望>=$2 实得=${1:-空})"; fi; }

HOST1=""; HOST2=""
cleanup(){
  local p
  for p in "$HOST1" "$HOST2"; do
    [[ -n "$p" ]] || continue
    kill -9 "$p" 2>/dev/null || true
    wait "$p" 2>/dev/null || true
  done
}
finalize(){
  local exit_code="$1"
  trap - EXIT
  if [[ "$exit_code" -ne 0 && "$FAIL" -eq 0 ]]; then ng "测试运行器异常终止 (exit=$exit_code)"; fi
  dh_write_results "persistence" "$PASS" "$FAIL" "mac"
  cleanup
  printf '[results] %s\n' "$RESULT_DIR"
  exit "$exit_code"
}
trap 'finalize $?' EXIT

command -v jq >/dev/null || { echo "需要 jq"; exit 2; }
: > "$RESULT_DIR/assertions.tsv"

export DH_LOG_DIR="$RESULT_DIR/docs"
mkdir -p "$DH_LOG_DIR"

echo "[build] mac dylib + exercise_runner"
make mac >"$RESULT_DIR/build.log" 2>&1 || { echo "mac dylib 构建失败, 见 $RESULT_DIR/build.log"; exit 1; }
make tests/exercise_runner >>"$RESULT_DIR/build.log" 2>&1 || { echo "runner 构建失败"; exit 1; }

HOST_PID=""; PORT=""; MCP=""
start_host(){
  local log="$1"
  : > "$log"
  DYLD_INSERT_LIBRARIES=./decrypt_helper.mac.dylib ./tests/exercise_runner --all --timeout 180 >"$log" 2>&1 &
  HOST_PID=$!
  PORT=$(dh_wait_for_http "$log" "$HOST_PID" 20) || return 1
  dh_wait_for_marker "$log" "SCENARIOS_COMPLETE" 30 || return 1
  MCP="http://127.0.0.1:$PORT/api/mcp"
  return 0
}
mc(){ curl -sf --max-time 15 -X POST "$MCP" -H 'Content-Type: application/json' -d "$1"; }

echo ""; echo "== 第一轮: 生成事件 =="
if start_host "$RESULT_DIR/host1.log"; then HOST1=$HOST_PID; else ng "第一轮宿主启动失败"; exit 1; fi
mc '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_stats","arguments":{}}}' >"$RESULT_DIR/stats1.json"
mc '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_events","arguments":{"category":"digest","query":"SHA256","limit":1}}}' >"$RESULT_DIR/digest1.json"
SEQ1=$(jq -r '.result.structuredContent.events[0].seq // empty' "$RESULT_DIR/digest1.json" 2>/dev/null)
[[ -n "$SEQ1" ]] && ok "第一轮捕获 SHA256 事件 (seq=$SEQ1)" || ng "第一轮未捕获 SHA256 事件"
mc "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"get_event\",\"arguments\":{\"seq\":${SEQ1:-0}}}}" >"$RESULT_DIR/event1.json"
OUT1=$(jq -r '.result.structuredContent.outputHex // empty' "$RESULT_DIR/event1.json" 2>/dev/null)
[[ -n "$OUT1" ]] && ok "第一轮事件有 outputHex" || ng "第一轮事件缺少 outputHex"
sleep 1   # 高价值事件逐条落盘; 再等一轮批量 flush
JOURNAL="$DH_LOG_DIR/decrypt_helper.journal"
[[ -s "$JOURNAL" ]] && ok "结构化事件日志已写入 ($(stat -f%z "$JOURNAL" 2>/dev/null || echo 0) bytes)" || ng "结构化事件日志为空"

echo ""; echo "== SIGKILL 模拟闪退, 第二轮校验回载 =="
kill -9 "$HOST1" 2>/dev/null || true
wait "$HOST1" 2>/dev/null || true
HOST1=""
if start_host "$RESULT_DIR/host2.log"; then HOST2=$HOST_PID; else ng "第二轮宿主启动失败"; exit 1; fi
mc '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_stats","arguments":{}}}' >"$RESULT_DIR/stats2.json"
RESTORED=$(jq -r '.result.structuredContent.pipeline.restoredEvents // 0' "$RESULT_DIR/stats2.json" 2>/dev/null)
ge "${RESTORED:-0}" 1 "重启后回载事件数 >= 1 (实得 $RESTORED)"
TOTAL2=$(jq -r '.result.structuredContent.total // 0' "$RESULT_DIR/stats2.json" 2>/dev/null)
ge "${TOTAL2:-0}" "${SEQ1:-0}" "重启后 seq 计数不回退 (total=$TOTAL2 seq1=$SEQ1)"
mc "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"get_event\",\"arguments\":{\"seq\":${SEQ1:-0}}}}" >"$RESULT_DIR/event2.json"
OUT2=$(jq -r '.result.structuredContent.outputHex // empty' "$RESULT_DIR/event2.json" 2>/dev/null)
eq "$OUT2" "$OUT1" "重启后同 seq 事件内容一致"

echo ""; echo "== 第二次强杀重启: 防重复/损坏 =="
kill -9 "$HOST2" 2>/dev/null || true
wait "$HOST2" 2>/dev/null || true
HOST2=""
if start_host "$RESULT_DIR/host3.log"; then HOST2=$HOST_PID; else ng "第三轮宿主启动失败"; exit 1; fi
mc '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"get_stats","arguments":{}}}' >"$RESULT_DIR/stats3.json"
RESTORED3=$(jq -r '.result.structuredContent.pipeline.restoredEvents // 0' "$RESULT_DIR/stats3.json" 2>/dev/null)
ge "${RESTORED3:-0}" 1 "二次重启仍能回载事件 (实得 $RESTORED3)"
mc "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"get_event\",\"arguments\":{\"seq\":${SEQ1:-0}}}}" >"$RESULT_DIR/event3.json"
OUT3=$(jq -r '.result.structuredContent.outputHex // empty' "$RESULT_DIR/event3.json" 2>/dev/null)
eq "$OUT3" "$OUT1" "二次重启后事件内容仍一致"

printf '\n结果: \033[32mPASS=%d\033[0m \033[31mFAIL=%d\033[0m\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
