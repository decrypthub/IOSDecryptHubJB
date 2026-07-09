#!/bin/bash
# MCP / analysis / correlate / auth 集成测试。
# 注入 mac dylib 到 exercise_runner(生成 crypto+网络事件并常驻), 驱动真实 HTTP/MCP 端点断言。
# 用法: make test-mcp   (或直接 ./tests/mcp_test.sh)
# 全部通过 exit 0, 有失败 exit 1。

set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"

PASS=0; FAIL=0
ok(){ printf '  \033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
ng(){ printf '  \033[31m✗\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
eq(){ if [ "$1" = "$2" ]; then ok "$3"; else ng "$3  (期望=$2 实得=$1)"; fi; }
ge(){ if [ "${1:-x}" -ge "$2" ] 2>/dev/null; then ok "$3"; else ng "$3  (期望>=$2 实得=${1:-空})"; fi; }

command -v jq >/dev/null || { echo "需要 jq"; exit 2; }

echo "[build] mac dylib + exercise_runner"
make mac >/tmp/dh_build.log 2>&1 || { echo "mac dylib 构建失败, 见 /tmp/dh_build.log"; exit 1; }
make tests/exercise_runner >>/tmp/dh_build.log 2>&1 || { echo "runner 构建失败"; exit 1; }

# 全新 token(删旧的, 让 dylib 重新生成), 干净起宿主
rm -f "$HOME/Documents/.dh_token.conf"
DYLD_INSERT_LIBRARIES=./decrypt_helper.mac.dylib ./tests/exercise_runner >/tmp/dh_test_host.log 2>&1 &
HOST=$!
trap 'kill $HOST 2>/dev/null' EXIT
echo "[host] PID $HOST, 等事件生成 + 网络完成 (5s)"
sleep 5

PORT=$(grep -oE 'http://[0-9.]+:[0-9]+' /tmp/dh_test_host.log | head -1 | grep -oE '[0-9]+$'); PORT=${PORT:-8088}
TOK=$(cat "$HOME/Documents/.dh_token.conf" 2>/dev/null)
U="http://127.0.0.1:$PORT"; MCP="$U/api/mcp?token=$TOK"
mc(){ curl -s -X POST "$MCP" -H "Content-Type: application/json" -d "$1"; }
echo "[server] port=$PORT token=$TOK"

echo ""; echo "== 认证 =="
eq "$(curl -s -o /dev/null -w '%{http_code}' "$U/api/stats")"           "401" "无令牌 → 401"
eq "$(curl -s -o /dev/null -w '%{http_code}' "$U/api/stats?token=000000")" "401" "错令牌 → 401"
eq "$(curl -s -o /dev/null -w '%{http_code}' "$U/api/stats?token=$TOK")"  "200" "正确令牌 → 200"
eq "$(curl -s -o /dev/null -w '%{http_code}' "$U/")"                     "200" "HTML 外壳免鉴权 → 200"
eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$U/api/mcp" -d '{}')" "401" "MCP 无令牌 → 401"

echo ""; echo "== MCP 协议 + 反汇编 (analysis) =="
ge "$(mc '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq '.result.tools|length')" 30 "tools/list ≥30 工具"
eq "$(mc '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"disassemble","arguments":{"bytes":"fd7bbfa9","arch":"arm64"}}}' | jq -r '.result.structuredContent.instructions[0].mnemonic')" "stp" "disassemble fd7bbfa9 → stp"
eq "$(mc '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"disassemble","arguments":{"bytes":"c0 03 5f d6","arch":"arm64"}}}' | jq -r '.result.structuredContent.instructions[0].mnemonic')" "ret" "disassemble 带空格 hex → ret (DHDataFromHex 容错)"

echo ""; echo "== 取证查询 =="
mc '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_stats","arguments":{}}}' > /tmp/dh_stats.json
eq "$(jq -r '.result.structuredContent.byCategory | has("net")' /tmp/dh_stats.json)" "true" "get_stats.byCategory 含 net (分类表)"
eq "$(jq -r '.result.structuredContent.byCategory | has("keychain")' /tmp/dh_stats.json)" "true" "get_stats.byCategory 含 keychain"
mc '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"query_events","arguments":{"category":"digest","query":"SHA256","limit":1}}}' > /tmp/dh_dig.json
ge "$(jq '.result.structuredContent.matched' /tmp/dh_dig.json)" 1 "query_events digest SHA256 ≥1"
DSEQ=$(jq -r '.result.structuredContent.events[0].seq // empty' /tmp/dh_dig.json)
mc "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"get_event\",\"arguments\":{\"seq\":${DSEQ:-0}}}}" > /tmp/dh_ev.json
OH=$(jq -r '.result.structuredContent.outputHex // empty' /tmp/dh_ev.json)
eq "$([ -n "$OH" ] && echo yes)" "yes" "get_event 返回 outputHex"
# output_hex 反查应命中自身
mc "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"query_events\",\"arguments\":{\"output_hex\":\"$OH\"}}}" > /tmp/dh_rev.json
ge "$(jq '.result.structuredContent.matched' /tmp/dh_rev.json)" 1 "output_hex 反查命中"
eq "$(jq --arg s "$DSEQ" 'any(.result.structuredContent.events[]; (.seq|tostring)==$s)' /tmp/dh_rev.json)" "true" "反查结果含原 seq"

echo ""; echo "== correlate_request 闭环 (X-Validator=base64(SHA256)) =="
mc '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"query_events","arguments":{"category":"net","limit":1}}}' > /tmp/dh_net.json
NSEQ=$(jq -r '.result.structuredContent.events[0].seq // empty' /tmp/dh_net.json)
if [ -n "$NSEQ" ]; then
  mc "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"correlate_request\",\"arguments\":{\"net_seq\":$NSEQ,\"window_ms\":3000}}}" > /tmp/dh_cor.json
  eq "$(jq -r '.result.structuredContent.match.validatorOutputFound' /tmp/dh_cor.json)" "true" "correlate match=true"
  eq "$(jq -r '.result.structuredContent.match.matchedAlgorithm' /tmp/dh_cor.json)" "SHA256" "命中算法=SHA256"
  eq "$(jq -r '.result.structuredContent.match.matchedHeader' /tmp/dh_cor.json)" "X-Validator" "命中头=X-Validator"
else
  ng "无 net 事件, correlate 无法测 (网络探针可能未落库)"
fi

echo ""; echo "== 诊断 =="
eq "$(mc '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"get_diag","arguments":{"board":"general"}}}' | jq -r '.result.structuredContent.diag|test("hook")')" "true" "get_diag 含 hook 时间线"

echo ""
printf '结果: \033[32mPASS=%d\033[0m \033[31mFAIL=%d\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
