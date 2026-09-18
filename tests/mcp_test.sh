#!/bin/bash
# MCP / analysis / correlate / auth 集成测试。
# 注入 mac dylib 到 exercise_runner(生成 crypto+网络事件并常驻), 驱动真实 HTTP/MCP 端点断言。
# 用法: make test-mcp   (或直接 ./tests/mcp_test.sh)
# 全部通过 exit 0, 有失败 exit 1。

set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RESULT_DIR="${DH_TEST_RESULTS_DIR:-$ROOT/build/test-results/mcp-$(date +%Y%m%d-%H%M%S)-$$}"
mkdir -p "$RESULT_DIR"
# shellcheck source=tests/test_helpers.sh
source "$ROOT/tests/test_helpers.sh"
exec 2> >(tee "$RESULT_DIR/stderr.log" >&2)

PASS=0; FAIL=0
ok(){
  if [[ -z "${1:-}" ]]; then ng "断言名称不能为空"; return; fi
  printf '  \033[32m✓\033[0m %s\n' "$1"
  printf 'PASS\t%s\n' "$1" >> "$RESULT_DIR/assertions.tsv"
  PASS=$((PASS+1))
}
ng(){
  local label="${1:-未命名断言失败}"
  printf '  \033[31m✗\033[0m %s\n' "$label"
  printf 'FAIL\t%s\n' "$label" >> "$RESULT_DIR/assertions.tsv"
  FAIL=$((FAIL+1))
}
eq(){
  if [[ $# -ne 3 || -z "${3:-}" ]]; then ng "eq 断言参数无效"; return; fi
  if [[ "$1" = "$2" ]]; then ok "$3"; else ng "$3  (期望=$2 实得=$1)"; fi
}
ge(){
  if [[ $# -ne 3 || -z "${3:-}" ]]; then ng "ge 断言参数无效"; return; fi
  if [[ "${1:-x}" -ge "$2" ]] 2>/dev/null; then ok "$3"; else ng "$3  (期望>=$2 实得=${1:-空})"; fi
}

HOST=""; HOST2=""; HOST3=""
cleanup(){
  local pid
  for pid in "$HOST" "$HOST2" "$HOST3"; do
    [[ -n "$pid" ]] || continue
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
}
finalize(){
  local exit_code="$1"
  trap - EXIT
  if [[ "$exit_code" -ne 0 && "$FAIL" -eq 0 ]]; then
    ng "测试运行器异常终止 (exit=$exit_code)"
  fi
  dh_write_results "mcp-e2e" "$PASS" "$FAIL" "mac"
  cleanup
  printf '[results] %s\n' "$RESULT_DIR"
  exit "$exit_code"
}
trap 'finalize $?' EXIT

command -v jq >/dev/null || { echo "需要 jq"; exit 2; }
: > "$RESULT_DIR/assertions.tsv"

echo "[build] mac dylib + exercise_runner"
make mac >"$RESULT_DIR/build.log" 2>&1 || { echo "mac dylib 构建失败, 见 "$RESULT_DIR/build.log""; exit 1; }
make tests/exercise_runner >>"$RESULT_DIR/build.log" 2>&1 || { echo "runner 构建失败"; exit 1; }

echo "[echo] 启动本地 WebSocket 回显服务"
python3 tests/net_echo_server.py --port 8099 --ws >"$RESULT_DIR/echo.log" 2>&1 &
HOST2=$!
for _ in $(seq 1 50); do
  curl -sf --max-time 1 http://127.0.0.1:8099/echo >/dev/null 2>&1 && break
  sleep 0.1
done

DYLD_INSERT_LIBRARIES=./decrypt_helper.mac.dylib ./tests/exercise_runner --all --timeout 180 >"$RESULT_DIR/host.log" 2>&1 &
HOST=$!
echo "[host] PID $HOST, 轮询服务与场景完成标记"

PORT=$(dh_wait_for_http "$RESULT_DIR/host.log" "$HOST" 20) || {
  echo "宿主 HTTP 服务未就绪，见 "$RESULT_DIR/host.log""
  exit 1
}
dh_wait_for_marker "$RESULT_DIR/host.log" "SCENARIOS_COMPLETE" 20 || {
  echo "宿主场景未完成，见 $RESULT_DIR/host.log"
  exit 1
}
U="http://127.0.0.1:$PORT"; MCP="$U/api/mcp"
mc(){ curl -sf --max-time 15 -X POST "$MCP" -H "Content-Type: application/json" -d "$1"; }
echo "[server] port=$PORT (无鉴权)"

echo ""; echo "== 无鉴权直连 (局域网自用, 已移除 token) =="
eq "$(curl -s -o /dev/null -w '%{http_code}' "$U/api/stats")"              "200" "/api/stats 直连 → 200"
eq "$(curl -s -o /dev/null -w '%{http_code}' "$U/")"                       "200" "HTML 外壳 → 200"
eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$U/api/mcp" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')" "200" "MCP 直连 → 200"

echo ""; echo "== MCP 协议 + 反汇编 (analysis) =="
mc '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' > "$RESULT_DIR/tools.json"
eq "$(jq -r '[.result.tools[].name] as $names |
    ["get_capabilities","disassemble","objc_resolve_imp","find_objc_methods","list_loaded_images","find_xrefs","find_string_refs",
     "find_selector_refs","find_function_refs","list_functions","get_stats","query_events",
     "correlate_request","get_event","export_events","get_diag","get_capture_coverage",
     "get_webkit_probe","set_webkit_probe","hook_import","hook_method","unhook"] |
    all(. as $name | $names | index($name) != null)' "$RESULT_DIR/tools.json")" \
    "true" "tools/list 包含关键兼容工具集合"
mc '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"disassemble","arguments":{"bytes":"fd7bbfa9","arch":"arm64"}}}' > "$RESULT_DIR/dh_disasm_stp.json"
eq "$(jq -r '.result.structuredContent.instructions[0].mnemonic' "$RESULT_DIR/dh_disasm_stp.json")" "stp" "disassemble fd7bbfa9 → stp"
eq "$(jq -r '.result.structuredContent.instructions[0].operands[0].type' "$RESULT_DIR/dh_disasm_stp.json")" "register" "结构化 operand 标记寄存器"
eq "$(jq -r '.result.structuredContent.instructions[0].operands[2].type' "$RESULT_DIR/dh_disasm_stp.json")" "memory" "结构化 operand 标记内存引用"
eq "$(jq -r '.result.structuredContent.instructions[0].operands[2].base' "$RESULT_DIR/dh_disasm_stp.json")" "sp" "内存 operand 返回基址寄存器"

mc '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"disassemble","arguments":{"bytes":"c0 03 5f d6","arch":"arm64"}}}' > "$RESULT_DIR/dh_disasm_ret.json"
eq "$(jq -r '.result.structuredContent.instructions[0].mnemonic' "$RESULT_DIR/dh_disasm_ret.json")" "ret" "disassemble 带空格 hex → ret (DHDataFromHex 容错)"
eq "$(jq -r '.result.structuredContent.instructions[0].groups|index("return")!=null' "$RESULT_DIR/dh_disasm_ret.json")" "true" "结构化分组识别 return"

# movz x0,#0x1234; movk x0,#0x5678,lsl#16 → 0x56781234。仅在线性流内拼接，不跨分支。
mc '{"jsonrpc":"2.0","id":48,"method":"tools/call","params":{"name":"disassemble","arguments":{"bytes":"804682d200cf aaf2","arch":"arm64"}}}' > "$RESULT_DIR/dh_disasm_const.json"
eq "$(jq -r '.result.structuredContent.instructions[1].constant_build.value' "$RESULT_DIR/dh_disasm_const.json")" "0x0000000056781234" "MOVZ/MOVK 拼接 64 位常量"
eq "$(jq -r '.result.structuredContent.instructions[1].constant_build.complete' "$RESULT_DIR/dh_disasm_const.json")" "true" "MOVZ 起始的常量链标记完整"
eq "$(jq -r '.result.structuredContent.instructions[1].constant_build.instruction_count' "$RESULT_DIR/dh_disasm_const.json")" "2" "常量结果保留指令链长度"

# resolve_symbol 参数统一 + 中间地址自动归一到函数入口。
MAIN_INFO=$(mc '{"jsonrpc":"2.0","id":46,"method":"tools/call","params":{"name":"resolve_symbol","arguments":{"symbol":"main"}}}')
MAIN_ADDR=$(jq -r '.result.structuredContent.address' <<<"$MAIN_INFO")
eq "$(jq -r '.result.structuredContent.symbol' <<<"$MAIN_INFO")" "main" "resolve_symbol 首选 symbol 参数"
MAIN_INTERIOR=$(printf '0x%x' "$((MAIN_ADDR + 4))")
mc "{\"jsonrpc\":\"2.0\",\"id\":47,\"method\":\"tools/call\",\"params\":{\"name\":\"disassemble_function\",\"arguments\":{\"address\":\"$MAIN_INTERIOR\",\"max_bytes\":256}}}" > "$RESULT_DIR/dh_disasm_func.json"
eq "$(jq -r '.result.structuredContent.resolved_start' "$RESULT_DIR/dh_disasm_func.json")" "$MAIN_ADDR" "函数中间地址自动归一到 main 入口"
eq "$(jq -r '.result.structuredContent.requested_offset' "$RESULT_DIR/dh_disasm_func.json")" "4" "返回调用点相对函数入口偏移"
eq "$(jq -r '.result.structuredContent.boundary_source' "$RESULT_DIR/dh_disasm_func.json")" "lc_function_starts" "函数边界来自 LC_FUNCTION_STARTS"
eq "$(jq -r '.result.structuredContent.instructions[0].address' "$RESULT_DIR/dh_disasm_func.json")" "$MAIN_ADDR" "反汇编从真实函数入口开始"

echo ""; echo "== 完整 dyld 镜像地图 =="
mc '{"jsonrpc":"2.0","id":38,"method":"tools/call","params":{"name":"list_loaded_images","arguments":{"query":"decrypt_helper.mac","include_system":false}}}' > "$RESULT_DIR/dh_images.json"
ge "$(jq '.result.structuredContent.total' "$RESULT_DIR/dh_images.json")" 1 "完整镜像地图可找到注入 dylib"
eq "$(jq -r '.result.structuredContent.images[0].scope!="system"' "$RESULT_DIR/dh_images.json")" "true" "注入 dylib 不误标为 system"
eq "$(jq -r '.result.structuredContent.images[0].load_address|test("^0x")' "$RESULT_DIR/dh_images.json")" "true" "镜像带 load_address"
eq "$(jq -r '.result.structuredContent.images[0].text_size>0' "$RESULT_DIR/dh_images.json")" "true" "镜像带可执行范围"
eq "$(mc '{"jsonrpc":"2.0","id":39,"method":"tools/call","params":{"name":"list_loaded_images","arguments":{"offset":-1}}}' | jq -r '.result.isError')" "true" "镜像分页拒绝负 offset"

echo ""; echo "== 取证查询 =="
mc '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_stats","arguments":{}}}' > "$RESULT_DIR/dh_stats.json"
eq "$(jq -r '.result.structuredContent.byCategory | has("net")' "$RESULT_DIR/dh_stats.json")" "true" "get_stats.byCategory 含 net (分类表)"
eq "$(jq -r '.result.structuredContent.byCategory | has("keychain")' "$RESULT_DIR/dh_stats.json")" "true" "get_stats.byCategory 含 keychain"
mc '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"query_events","arguments":{"category":"digest","query":"SHA256","limit":1}}}' > "$RESULT_DIR/dh_dig.json"
ge "$(jq '.result.structuredContent.matched' "$RESULT_DIR/dh_dig.json")" 1 "query_events digest SHA256 ≥1"
DSEQ=$(jq -r '.result.structuredContent.events[0].seq // empty' "$RESULT_DIR/dh_dig.json")
mc "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"get_event\",\"arguments\":{\"seq\":${DSEQ:-0}}}}" > "$RESULT_DIR/dh_ev.json"
OH=$(jq -r '.result.structuredContent.outputHex // empty' "$RESULT_DIR/dh_ev.json")
eq "$([ -n "$OH" ] && echo yes)" "yes" "get_event 返回 outputHex"

mc '{"jsonrpc":"2.0","id":49,"method":"tools/call","params":{"name":"export_events","arguments":{"category":"digest","limit":1,"max_blob_bytes":8}}}' > "$RESULT_DIR/dh_export.json"
eq "$(jq -r '.result.structuredContent.format' "$RESULT_DIR/dh_export.json")" "iosdecrypthub.events.v1" "export_events 返回稳定格式标识"
eq "$(jq -r '.result.structuredContent.order' "$RESULT_DIR/dh_export.json")" "seq_ascending" "事件导出按 seq 升序"
eq "$(jq -r '.result.structuredContent.events|length' "$RESULT_DIR/dh_export.json")" "1" "事件导出遵守分页 limit"
eq "$(jq -r '.result.structuredContent.events[0] | (.inputHex|length)<=16 and (has("inputDump")|not)' "$RESULT_DIR/dh_export.json")" "true" "批量导出限制 blob 且默认不重复 hexdump"
eq "$(jq -r '.result.structuredContent.events[0] | if .input>8 then .inputTruncated==true else (has("inputTruncated")|not) end' "$RESULT_DIR/dh_export.json")" "true" "blob 截断标记与原始长度一致"
eq "$(jq -r '.result.structuredContent.events[0].callStackFrames|type' "$RESULT_DIR/dh_export.json")" "array" "批量导出包含结构化调用栈"

mc '{"jsonrpc":"2.0","id":50,"method":"tools/call","params":{"name":"export_events","arguments":{"limit":1,"max_blob_bytes":0}}}' > "$RESULT_DIR/dh_export_page1.json"
EXPORT_NEXT=$(jq -r '.result.structuredContent.cursor.next_after_seq // empty' "$RESULT_DIR/dh_export_page1.json")
EXPORT_UNTIL=$(jq -r '.result.structuredContent.cursor.snapshot_until_seq' "$RESULT_DIR/dh_export_page1.json")
eq "$(jq -r '.result.structuredContent.cursor.has_more' "$RESULT_DIR/dh_export_page1.json")" "true" "多事件导出返回下一页游标"
mc "{\"jsonrpc\":\"2.0\",\"id\":51,\"method\":\"tools/call\",\"params\":{\"name\":\"export_events\",\"arguments\":{\"after_seq\":${EXPORT_NEXT:-0},\"until_seq\":${EXPORT_UNTIL:-0},\"limit\":1,\"max_blob_bytes\":0}}}" > "$RESULT_DIR/dh_export_page2.json"
eq "$(jq --argjson prev "${EXPORT_NEXT:-0}" '.result.structuredContent.events[0].seq>$prev' "$RESULT_DIR/dh_export_page2.json")" "true" "下一页从 after_seq 之后继续"
eq "$(jq -r '.result.structuredContent.cursor.snapshot_until_seq' "$RESULT_DIR/dh_export_page2.json")" "$EXPORT_UNTIL" "分页复用同一快照上界"
# output_hex 反查应命中自身
mc "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"query_events\",\"arguments\":{\"output_hex\":\"$OH\"}}}" > "$RESULT_DIR/dh_rev.json"
ge "$(jq '.result.structuredContent.matched' "$RESULT_DIR/dh_rev.json")" 1 "output_hex 反查命中"
eq "$(jq --arg s "$DSEQ" 'any(.result.structuredContent.events[]; (.seq|tostring)==$s)' "$RESULT_DIR/dh_rev.json")" "true" "反查结果含原 seq"

echo ""; echo "== correlate_request 闭环 (X-Validator=base64(SHA256)) =="
mc '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"query_events","arguments":{"category":"net","query":"X-Validator","limit":1}}}' > "$RESULT_DIR/dh_net.json"
NSEQ=$(jq -r '.result.structuredContent.events[0].seq // empty' "$RESULT_DIR/dh_net.json")
if [ -n "$NSEQ" ]; then
  mc "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"correlate_request\",\"arguments\":{\"net_seq\":$NSEQ,\"window_ms\":3000}}}" > "$RESULT_DIR/dh_cor.json"
  eq "$(jq -r '.result.structuredContent.match.validatorOutputFound' "$RESULT_DIR/dh_cor.json")" "true" "correlate match=true"
  eq "$(jq -r '.result.structuredContent.match.matchedAlgorithm' "$RESULT_DIR/dh_cor.json")" "SHA256" "命中算法=SHA256"
  eq "$(jq -r '.result.structuredContent.match.matchedHeader' "$RESULT_DIR/dh_cor.json")" "X-Validator" "命中头=X-Validator"
else
  ng "无 net 事件, correlate 无法测 (网络探针可能未落库)"
fi

echo ""; echo "== 通用 BSD socket 明文抓取 =="
mc '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"query_events","arguments":{"category":"net","query":"/api/stats","limit":50}}}' > "$RESULT_DIR/dh_socket.json"
eq "$(jq -r '[.result.structuredContent.events[] | select(.algorithm=="SOCKET" and ((.preview // "") | contains("GET /api/stats")))] | length > 0' "$RESULT_DIR/dh_socket.json")" "true" "raw socket send 被通用层记录"
eq "$(jq -r '[.result.structuredContent.events[] | select(.algorithm=="SOCKET" and .operation=="send" and ((.preview // "") | contains("GET /api/stats")))] | length > 0' "$RESULT_DIR/dh_socket.json")" "true" "raw socket 请求行进入 input 预览"

echo ""; echo "== WebSocket 帧抓取 =="
mc '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"query_events","arguments":{"category":"net","query":"DH_WS_FIXTURE_001","limit":20}}}' > "$RESULT_DIR/dh_ws.json"
eq "$(jq -r '[.result.structuredContent.events[] | select(.algorithm=="WS" and .operation=="send")] | length > 0' "$RESULT_DIR/dh_ws.json")" "true" "WebSocket send 帧被记录"
eq "$(jq -r '[.result.structuredContent.events[] | select(.algorithm=="WS" and .operation=="recv")] | length > 0' "$RESULT_DIR/dh_ws.json")" "true" "WebSocket recv 帧被记录"

echo ""; echo "== Network.framework 明文抓取 =="
mc '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"query_events","arguments":{"category":"net","query":"/echo","limit":50}}}' > "$RESULT_DIR/dh_nw.json"
eq "$(jq -r '[.result.structuredContent.events[] | select(.algorithm=="NW" and .operation=="send")] | length > 0' "$RESULT_DIR/dh_nw.json")" "true" "nw_connection_send 明文被记录"
eq "$(jq -r '[.result.structuredContent.events[] | select(.algorithm=="NW" and .operation=="recv" and ((.preview // "") | contains("HTTP/")))] | length > 0' "$RESULT_DIR/dh_nw.json")" "true" "nw_connection_receive 明文被记录"

echo ""; echo "== find_xrefs (tier-1 直接 BL 调用引用) =="
# import stub 正例: runner 直接调 printf 多次, 应经 __stubs → GOT → dladdr 还原成 printf
mc '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"find_xrefs","arguments":{"symbol":"printf","max_results":50}}}' > "$RESULT_DIR/dh_xref.json"
ge "$(jq '.result.structuredContent.count' "$RESULT_DIR/dh_xref.json")" 1 "find_xrefs printf ≥1 调用点"
eq "$(jq -r '.result.structuredContent.results[0].kind' "$RESULT_DIR/dh_xref.json")" "call_import_stub" "printf 归类 call_import_stub"
eq "$(jq -r '.result.structuredContent.results[0].resolved_name' "$RESULT_DIR/dh_xref.json")" "printf" "stub 还原出 printf"
eq "$(jq -r '.result.structuredContent.scan.scan_offset' "$RESULT_DIR/dh_xref.json")" "0" "xref 返回扫描 offset"
eq "$(jq -r '.result.structuredContent.scan.bytes_read>0' "$RESULT_DIR/dh_xref.json")" "true" "xref 返回实际读取字节数"
eq "$(jq -r '.result.structuredContent.scan.unreadable_pages' "$RESULT_DIR/dh_xref.json")" "0" "测试镜像无不可读页"
# tier-1.5 归属: 有符号 → main+off, 并带 from_func_start / vmaddr
eq "$(jq -r '.result.structuredContent.results[0].from_func|test("^main\\+0x")' "$RESULT_DIR/dh_xref.json")" "true" "printf 调用点归属到 main+off"
eq "$(jq -r '.result.structuredContent.results[0].from_func_start|test("^0x")' "$RESULT_DIR/dh_xref.json")" "true" "带 from_func_start"
eq "$(jq -r '.result.structuredContent.results[0].from_func_vmaddr|test("^0x")' "$RESULT_DIR/dh_xref.json")" "true" "带 from_func_vmaddr(稳定 ID)"
# objc_stub 路径: objc_msgSend$sel 降级 stub, 前缀匹配 objc_msgSend
mc '{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"find_xrefs","arguments":{"symbol":"objc_msgSend","max_results":50}}}' > "$RESULT_DIR/dh_xref2.json"
ge "$(jq '.result.structuredContent.count' "$RESULT_DIR/dh_xref2.json")" 1 "find_xrefs objc_msgSend ≥1 调用点"
eq "$(jq -r 'any(.result.structuredContent.results[]; .kind=="call_objc_stub")' "$RESULT_DIR/dh_xref2.json")" "true" "含 call_objc_stub"
# 缺参防御
eq "$(mc '{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"find_xrefs","arguments":{}}}' | jq -r '.result.isError')" "true" "无 symbol/address → isError"
# 显式小窗口验证分页诊断；命中数不作为断言，避免依赖 printf 在 __text 的具体位置。
mc '{"jsonrpc":"2.0","id":40,"method":"tools/call","params":{"name":"find_xrefs","arguments":{"symbol":"printf","scan_size":64}}}' > "$RESULT_DIR/dh_xref_page.json"
eq "$(jq -r '.result.structuredContent.scan.scan_size' "$RESULT_DIR/dh_xref_page.json")" "64" "scan_size 控制单页字节数"
eq "$(jq -r '.result.structuredContent.scan.has_more' "$RESULT_DIR/dh_xref_page.json")" "true" "小窗口提示 has_more"
eq "$(jq -r '.result.structuredContent.scan.next_scan_offset' "$RESULT_DIR/dh_xref_page.json")" "64" "返回下一页 scan_offset"
eq "$(jq -r '.result.structuredContent.truncated' "$RESULT_DIR/dh_xref_page.json")" "true" "未覆盖完整 __text 时 truncated=true"
eq "$(mc '{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{"name":"find_xrefs","arguments":{"symbol":"printf","scan_offset":999999999}}}' | jq -r '.result.isError')" "true" "越界 scan_offset → isError"

echo ""; echo "== objc_resolve_imp (selector -> 当前运行时 IMP) =="
# 类名路径: 实例方法 -> IMP + dladdr 符号
mc '{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"objc_resolve_imp","arguments":{"class":"NSObject","selector":"description"}}}' > "$RESULT_DIR/dh_imp.json"
eq "$(jq -r '.result.structuredContent.found' "$RESULT_DIR/dh_imp.json")" "true" "resolve NSObject -description found"
eq "$(jq -r '.result.structuredContent.imp|test("^0x")' "$RESULT_DIR/dh_imp.json")" "true" "返回 imp 地址"
eq "$(jq -r '.result.structuredContent.current_imp==.result.structuredContent.imp' "$RESULT_DIR/dh_imp.json")" "true" "兼容 imp 与 current_imp 一致"
eq "$(jq -r '.result.structuredContent.imp_semantics' "$RESULT_DIR/dh_imp.json")" "current_runtime_implementation" "IMP 语义明确为当前实现"
eq "$(jq -r '.result.structuredContent.original_imp_known' "$RESULT_DIR/dh_imp.json")" "false" "不宣称恢复第三方 swizzle 前 IMP"
eq "$(jq -r '.result.structuredContent.symbol|test("description")' "$RESULT_DIR/dh_imp.json")" "true" "dladdr 符号含 description"
# 交叉验证: imp 喂 symbolicate 应还原同名符号
RIMP=$(jq -r '.result.structuredContent.imp' "$RESULT_DIR/dh_imp.json")
mc "{\"jsonrpc\":\"2.0\",\"id\":31,\"method\":\"tools/call\",\"params\":{\"name\":\"symbolicate\",\"arguments\":{\"address\":\"$RIMP\"}}}" > "$RESULT_DIR/dh_symbolicate.json"
eq "$(jq -r '(.result.structuredContent.symbol // "")|test("description")' "$RESULT_DIR/dh_symbolicate.json")" "true" "imp→symbolicate 交叉一致"
# 类方法路径: 元类解析
eq "$(mc '{"jsonrpc":"2.0","id":32,"method":"tools/call","params":{"name":"objc_resolve_imp","arguments":{"class":"NSString","selector":"string","method_type":"class"}}}' | jq -r '.result.structuredContent.method_type')" "class" "类方法 method_type=class"
# 继承: 子类查方法, 声明类回溯到父类
eq "$(mc '{"jsonrpc":"2.0","id":33,"method":"tools/call","params":{"name":"objc_resolve_imp","arguments":{"class":"NSMutableString","selector":"length"}}}' | jq -r '.result.structuredContent.resolving_class')" "NSString" "继承方法归属父类 NSString"
# 不存在 selector -> found:false
eq "$(mc '{"jsonrpc":"2.0","id":34,"method":"tools/call","params":{"name":"objc_resolve_imp","arguments":{"class":"NSObject","selector":"dhNoSuchSelXYZ:"}}}' | jq -r '.result.structuredContent.found')" "false" "未知 selector → found:false"
# object 路径安全: 坏指针不崩宿主, 干净报错
eq "$(mc '{"jsonrpc":"2.0","id":35,"method":"tools/call","params":{"name":"objc_resolve_imp","arguments":{"object":"0x1","selector":"length"}}}' | jq -r '.result.isError')" "true" "坏 object 地址 → isError(不崩)"
# 缺参防御
eq "$(mc '{"jsonrpc":"2.0","id":36,"method":"tools/call","params":{"name":"objc_resolve_imp","arguments":{"class":"NSObject"}}}' | jq -r '.result.isError')" "true" "无 selector → isError"
eq "$(mc '{"jsonrpc":"2.0","id":37,"method":"tools/call","params":{"name":"objc_resolve_imp","arguments":{"selector":"length"}}}' | jq -r '.result.isError')" "true" "无 class/object → isError"

echo ""; echo "== find_objc_methods (运行时 ObjC 实体查询) =="
mc '{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"find_objc_methods","arguments":{"class":"NSObject","selector":"description","match":"exact","method_type":"instance"}}}' > "$RESULT_DIR/dh_methods.json"
ge "$(jq '.result.structuredContent.total' "$RESULT_DIR/dh_methods.json")" 1 "NSObject 声明 description"
eq "$(jq -r '.result.structuredContent.methods[0].selector' "$RESULT_DIR/dh_methods.json")" "description" "方法实体返回 selector"
eq "$(jq -r '.result.structuredContent.methods[0].current_imp|test("^0x")' "$RESULT_DIR/dh_methods.json")" "true" "方法实体返回 current_imp"
eq "$(jq -r '.result.structuredContent.methods[0].declared' "$RESULT_DIR/dh_methods.json")" "true" "明确只列自身声明方法"
eq "$(jq -r '.result.structuredContent.methods[0]|has("class_image") and has("imp_image")' "$RESULT_DIR/dh_methods.json")" "true" "同时返回 class/IMP 镜像"
eq "$(mc '{"jsonrpc":"2.0","id":43,"method":"tools/call","params":{"name":"find_objc_methods","arguments":{"class":"NSObject","offset":1,"limit":1}}}' | jq '.result.structuredContent.shown')" "1" "ObjC 方法查询支持分页"
eq "$(mc '{"jsonrpc":"2.0","id":44,"method":"tools/call","params":{"name":"find_objc_methods","arguments":{}}}' | jq -r '.result.isError')" "true" "ObjC 方法查询拒绝无过滤全扫"
eq "$(mc '{"jsonrpc":"2.0","id":45,"method":"tools/call","params":{"name":"find_objc_methods","arguments":{"class":"MCPServer","selector":"handleMessage:","match":"exact","method_type":"class"}}}' | jq -r '.result.structuredContent.methods[0].imp_image|test("decrypt_helper\\.mac\\.dylib")')" "true" "隐藏策略下仍恢复 DecryptHub IMP 真实镜像名"

echo ""; echo "== find_xrefs tier-1.5: strip 目标归属到 sub_xxx =="
# strip 掉本地符号后 dladdr 失效, 应经 LC_FUNCTION_STARTS 归属到 sub_<runtime>+off。
cp tests/exercise_runner "$RESULT_DIR/dh_er_stripped" && strip "$RESULT_DIR/dh_er_stripped" 2>/dev/null
eq "$(otool -l "$RESULT_DIR/dh_er_stripped" 2>/dev/null | grep -c FUNCTION_STARTS)" "1" "strip 后 LC_FUNCTION_STARTS 保留"
DYLD_INSERT_LIBRARIES=./decrypt_helper.mac.dylib "$RESULT_DIR/dh_er_stripped" --all --timeout 180 >"$RESULT_DIR/dh_host2.log" 2>&1 &
HOST2=$!
P2=$(dh_wait_for_http "$RESULT_DIR/dh_host2.log" "$HOST2" 20) || {
  ng "strip 宿主 HTTP 服务未就绪"
  P2=8088
}
curl -sf --max-time 15 -X POST "http://127.0.0.1:$P2/api/mcp" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"find_xrefs","arguments":{"symbol":"printf","max_results":5}}}' > "$RESULT_DIR/dh_xref3.json"
ge "$(jq '.result.structuredContent.count' "$RESULT_DIR/dh_xref3.json")" 1 "strip 目标 printf ≥1 调用点"
eq "$(jq -r '.result.structuredContent.results[0].from_func|test("^sub_[0-9a-f]+\\+0x")' "$RESULT_DIR/dh_xref3.json")" "true" "strip 后归属到 sub_xxx+off"
eq "$(jq -r '.result.structuredContent.results[0].resolved_name' "$RESULT_DIR/dh_xref3.json")" "printf" "strip 后 import 仍还原 printf"
# tier-3A 在 strip 下: 调 printf 的函数(strip 后 = sub_xxx)的内部 callees 应归属到 sub_xxx 且带稳定 vmaddr
FSTART=$(jq -r '.result.structuredContent.results[0].from_func_start' "$RESULT_DIR/dh_xref3.json")
curl -sf --max-time 15 -X POST "http://127.0.0.1:$P2/api/mcp" -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"find_function_refs\",\"arguments\":{\"target\":\"$FSTART\",\"direction\":\"callees\",\"max_results\":40}}}" > "$RESULT_DIR/dh_fref_s.json"
ge "$(jq '.result.structuredContent.count' "$RESULT_DIR/dh_fref_s.json")" 1 "strip: 内部 callees ≥1"
eq "$(jq -r '[.result.structuredContent.results[].to_func]|all(test("^sub_"))' "$RESULT_DIR/dh_fref_s.json")" "true" "strip 下 callees 归属到 sub_xxx"
eq "$(jq -r '.result.structuredContent.results[0].to_func_vmaddr|test("^0x")' "$RESULT_DIR/dh_fref_s.json")" "true" "strip 下带 to_func_vmaddr(稳定 ID)"
# tier-3B: strip 下 list_functions 仍列出函数(LC_FUNCTION_STARTS), 但名字退化成 sub_xxx
curl -sf --max-time 15 -X POST "http://127.0.0.1:$P2/api/mcp" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_functions","arguments":{"limit":100}}}' > "$RESULT_DIR/dh_lf_s.json"
ge "$(jq '.result.structuredContent.total' "$RESULT_DIR/dh_lf_s.json")" 5 "strip: list_functions total ≥5"
eq "$(jq -r '[.result.structuredContent.functions[]|select(.has_symbol==false)]|length>0' "$RESULT_DIR/dh_lf_s.json")" "true" "strip 下含 sub_xxx(has_symbol=false)"
# strip 地址即使 dladdr 能找到远处导出符号，也必须以 FUNCTION_STARTS 的 synthetic 函数为准。
curl -sf --max-time 15 -X POST "http://127.0.0.1:$P2/api/mcp" -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"symbolicate\",\"arguments\":{\"address\":\"$FSTART\"}}}" > "$RESULT_DIR/dh_sym_s.json"
eq "$(jq -r '.result.structuredContent.symbol_source' "$RESULT_DIR/dh_sym_s.json")" "lc_function_starts" "strip 地址拒绝最近导出伪符号"
eq "$(jq -r '.result.structuredContent.confidence' "$RESULT_DIR/dh_sym_s.json")" "high" "FUNCTION_STARTS 归属为高置信"
eq "$(jq -r '.result.structuredContent.symbol|test("^sub_[0-9a-f]+$")' "$RESULT_DIR/dh_sym_s.json")" "true" "strip symbolicate 返回 synthetic sub_xxx"
eq "$(jq -r '.result.structuredContent.function_start' "$RESULT_DIR/dh_sym_s.json")" "$FSTART" "symbolicate 返回真实函数入口"
kill $HOST2 2>/dev/null; wait $HOST2 2>/dev/null   # 同步收尸, 免 job-control 打印 Terminated

echo ""; echo "== find_string_refs (tier-2A: direct + 归属 + 无误报) =="
# direct: ADRP+ADD → __cstring; runner 用 printf 打了带 "AES" 的格式串
mc '{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"find_string_refs","arguments":{"string":"AES","max_results":20}}}' > "$RESULT_DIR/dh_sref.json"
ge "$(jq '.result.structuredContent.count' "$RESULT_DIR/dh_sref.json")" 1 "find_string_refs AES ≥1 引用"
eq "$(jq -r '.result.structuredContent.results[0].indirect' "$RESULT_DIR/dh_sref.json")" "false" "direct ref indirect=false"
eq "$(jq -r '.result.structuredContent.results[0].section|test("__cstring")' "$RESULT_DIR/dh_sref.json")" "true" "命中 __TEXT,__cstring"
eq "$(jq -r '.result.structuredContent.results[0].instruction|test("^add ")' "$RESULT_DIR/dh_sref.json")" "true" "指令是 ADRP+ADD 的 add"
eq "$(jq -r '.result.structuredContent.results[0].from_func!=null' "$RESULT_DIR/dh_sref.json")" "true" "ref_site 有函数归属"
# address 模式: 用命中的 string_addr 反查, 应对上
SADDR=$(jq -r '.result.structuredContent.results[0].string_addr' "$RESULT_DIR/dh_sref.json")
mc "{\"jsonrpc\":\"2.0\",\"id\":15,\"method\":\"tools/call\",\"params\":{\"name\":\"find_string_refs\",\"arguments\":{\"address\":\"$SADDR\"}}}" > "$RESULT_DIR/dh_sref_a.json"
ge "$(jq '.result.structuredContent.count' "$RESULT_DIR/dh_sref_a.json")" 1 "address 模式反查命中 ($SADDR)"
# 无误报: 不存在的子串
eq "$(mc '{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"find_string_refs","arguments":{"string":"ZZZ_NOPE_QWERTY_XYZZY"}}}' | jq '.result.structuredContent.count')" "0" "不存在子串 → 0(不误把立即数当串)"
# 缺参防御
eq "$(mc '{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"find_string_refs","arguments":{}}}' | jq -r '.result.isError')" "true" "无 string/address → isError"

echo ""; echo "== find_selector_refs (tier-2B path B: __objc_stubs) =="
# 默认 runner 走 __objc_stubs; dataWithBytes:length: 应作为 objc_stub 调用点命中
mc '{"jsonrpc":"2.0","id":18,"method":"tools/call","params":{"name":"find_selector_refs","arguments":{"selector":"dataWithBytes:length:"}}}' > "$RESULT_DIR/dh_selr.json"
ge "$(jq '.result.structuredContent.count' "$RESULT_DIR/dh_selr.json")" 1 "find_selector_refs dataWithBytes:length: ≥1"
eq "$(jq -r '.result.structuredContent.results[0].target_kind' "$RESULT_DIR/dh_selr.json")" "objc_stub" "path B kind=objc_stub"
eq "$(jq -r '.result.structuredContent.results[0].selector_source' "$RESULT_DIR/dh_selr.json")" "__objc_stubs" "selector_source=__objc_stubs"
eq "$(jq -r '.result.structuredContent.results[0].from_func!=null' "$RESULT_DIR/dh_selr.json")" "true" "call_site 有函数归属"
# 无误报: "bytes" 既是 cstring 又是 selector; selector_ref 只应报真正的 objc 调用点(不含 cstring)
mc '{"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"find_selector_refs","arguments":{"selector":"bytes"}}}' > "$RESULT_DIR/dh_selb.json"
eq "$(jq -r '[.result.structuredContent.results[]|.target_kind]|unique|.[]' "$RESULT_DIR/dh_selb.json")" "objc_stub" "bytes 只命中 objc 调用(cstring 不误报)"
# 不存在 selector → 0
eq "$(mc '{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"find_selector_refs","arguments":{"selector":"nonexistentSelectorXYZ:"}}}' | jq '.result.structuredContent.count')" "0" "不存在 selector → 0"
# 缺参防御
eq "$(mc '{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"find_selector_refs","arguments":{}}}' | jq -r '.result.isError')" "true" "无 selector → isError"

echo ""; echo "== find_function_refs (tier-3A: 内部调用图) =="
MAINA=$(mc '{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"resolve_symbol","arguments":{"name":"main"}}}' | jq -r '.result.structuredContent.address')
mc "{\"jsonrpc\":\"2.0\",\"id\":23,\"method\":\"tools/call\",\"params\":{\"name\":\"find_function_refs\",\"arguments\":{\"target\":\"$MAINA\",\"direction\":\"callees\",\"max_results\":40}}}" > "$RESULT_DIR/dh_fref.json"
ge "$(jq '.result.structuredContent.count' "$RESULT_DIR/dh_fref.json")" 1 "callees of main ≥1 内部调用"
eq "$(jq -r '[.result.structuredContent.results[].to_func]|any(test("^test_"))' "$RESULT_DIR/dh_fref.json")" "true" "callees 含内部 test_* 函数"
eq "$(jq -r '[.result.structuredContent.results[].to_func]|any(test("printf"))' "$RESULT_DIR/dh_fref.json")" "false" "callees 不含 import stub printf(排除 stub)"
eq "$(jq -r '.result.structuredContent.results[0].relation' "$RESULT_DIR/dh_fref.json")" "callee" "relation=callee"
# callers 方向: 取 test_network 入口, 查谁调用它
NETS=$(jq -r '.result.structuredContent.results[]|select(.to_func|startswith("test_network"))|.to_func_start' "$RESULT_DIR/dh_fref.json" | head -1)
mc "{\"jsonrpc\":\"2.0\",\"id\":24,\"method\":\"tools/call\",\"params\":{\"name\":\"find_function_refs\",\"arguments\":{\"target\":\"$NETS\",\"direction\":\"callers\"}}}" > "$RESULT_DIR/dh_fref2.json"
ge "$(jq '.result.structuredContent.count' "$RESULT_DIR/dh_fref2.json")" 1 "callers of test_network ≥1"
eq "$(jq -r '.result.structuredContent.results[0].from_func|test("^main")' "$RESULT_DIR/dh_fref2.json")" "true" "test_network 的调用者是 main"
eq "$(jq -r '.result.structuredContent.results[0].relation' "$RESULT_DIR/dh_fref2.json")" "caller" "relation=caller"
# test_network 只做 objc/import 调用 → 内部 callees 为空(排除 objc_stub/stub)
mc "{\"jsonrpc\":\"2.0\",\"id\":25,\"method\":\"tools/call\",\"params\":{\"name\":\"find_function_refs\",\"arguments\":{\"target\":\"$NETS\",\"direction\":\"callees\"}}}" > "$RESULT_DIR/dh_fref3.json"
eq "$(jq '.result.structuredContent.count' "$RESULT_DIR/dh_fref3.json")" "0" "test_network 内部 callees=0(objc_stub/import 不算内部)"
# 缺参 / 无法归属
eq "$(mc '{"jsonrpc":"2.0","id":26,"method":"tools/call","params":{"name":"find_function_refs","arguments":{}}}' | jq -r '.result.isError')" "true" "无 target → isError"
eq "$(mc '{"jsonrpc":"2.0","id":27,"method":"tools/call","params":{"name":"find_function_refs","arguments":{"target":"0x1"}}}' | jq -r '.result.isError')" "true" "无法归属地址 → isError"

echo ""; echo "== list_functions (tier-3B: 函数清单) =="
mc '{"jsonrpc":"2.0","id":28,"method":"tools/call","params":{"name":"list_functions","arguments":{"limit":100}}}' > "$RESULT_DIR/dh_lf.json"
ge "$(jq '.result.structuredContent.total' "$RESULT_DIR/dh_lf.json")" 5 "list_functions total ≥5"
eq "$(jq -r '[.result.structuredContent.functions[]|select(.name=="main")]|length>0' "$RESULT_DIR/dh_lf.json")" "true" "含 main 函数"
eq "$(jq -r '[.result.structuredContent.functions[]|select(.name=="main")][0].has_symbol' "$RESULT_DIR/dh_lf.json")" "true" "main has_symbol=true"
eq "$(jq -r '[.result.structuredContent.functions[]|select(.name=="main")][0]|(.vmaddr|test("^0x")) and (.size>0)' "$RESULT_DIR/dh_lf.json")" "true" "main 带 vmaddr 与 size>0"
# query 过滤
eq "$(jq -r '[.result.structuredContent.functions[]|.name]|all(test("test_"))' <(mc '{"jsonrpc":"2.0","id":29,"method":"tools/call","params":{"name":"list_functions","arguments":{"query":"test_"}}}'))" "true" "query=test_ 全部含 test_"
# 分页: offset 生效
eq "$(mc '{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"list_functions","arguments":{"query":"test_","offset":2,"limit":2}}}' | jq '.result.structuredContent.shown')" "2" "分页 shown=2"

echo ""; echo "== find_string_refs indirect (经典 selref → SEL) =="
# 用 -fno-objc-msgsend-selector-stubs 强制经典 adrp+ldr selref 模式, 触发间接引用
CLSDK=$(xcrun --sdk macosx --show-sdk-path 2>/dev/null)
xcrun --find clang >/dev/null 2>&1 && "$(xcrun --find clang)" -arch arm64 -isysroot "$CLSDK" \
  -mmacosx-version-min=11.0 -ObjC -fobjc-arc -O0 -fno-objc-msgsend-selector-stubs \
  -framework Foundation -framework CoreFoundation -framework Security -framework Network \
  tests/exercise_runner.m -o "$RESULT_DIR/dh_er_classic" >"$RESULT_DIR/dh_classic_build.log" 2>&1
if [ -x "$RESULT_DIR/dh_er_classic" ]; then
  eq "$(otool -l "$RESULT_DIR/dh_er_classic" 2>/dev/null | grep -c 'sectname __objc_stubs')" "0" "classic 变体无 __objc_stubs"
  DYLD_INSERT_LIBRARIES=./decrypt_helper.mac.dylib "$RESULT_DIR/dh_er_classic" --all --timeout 180 >"$RESULT_DIR/dh_host3.log" 2>&1 &
  HOST3=$!
  P3=$(dh_wait_for_http "$RESULT_DIR/dh_host3.log" "$HOST3" 20) || {
    ng "classic 宿主 HTTP 服务未就绪"
    P3=8088
  }
  curl -sf --max-time 15 -X POST "http://127.0.0.1:$P3/api/mcp" -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"find_string_refs","arguments":{"string":"dataWithBytes","max_results":5}}}' > "$RESULT_DIR/dh_sref2.json"
  ge "$(jq '.result.structuredContent.count' "$RESULT_DIR/dh_sref2.json")" 1 "indirect: selector dataWithBytes ≥1 引用"
  eq "$(jq -r 'any(.result.structuredContent.results[]; .indirect==true)' "$RESULT_DIR/dh_sref2.json")" "true" "含 indirect=true(经 selref)"
  eq "$(jq -r '[.result.structuredContent.results[]|select(.indirect==true)][0].string|test("dataWithBytes")' "$RESULT_DIR/dh_sref2.json")" "true" "间接读出 selector 名"
  # 同一 classic 宿主验 find_selector_refs path A (selref + blr objc_msgSend)
  curl -sf --max-time 15 -X POST "http://127.0.0.1:$P3/api/mcp" -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find_selector_refs","arguments":{"selector":"dataWithBytes:length:"}}}' > "$RESULT_DIR/dh_selr3.json"
  ge "$(jq '.result.structuredContent.count' "$RESULT_DIR/dh_selr3.json")" 1 "path A: classic selref ≥1 调用点"
  eq "$(jq -r '.result.structuredContent.results[0].target_kind' "$RESULT_DIR/dh_selr3.json")" "objc_msgsend" "path A kind=objc_msgsend"
  eq "$(jq -r '.result.structuredContent.results[0].selector_source' "$RESULT_DIR/dh_selr3.json")" "__objc_selrefs" "selector_source=__objc_selrefs"
  eq "$(jq -r '.result.structuredContent.results[0].selector_load_site!=null' "$RESULT_DIR/dh_selr3.json")" "true" "带 selector_load_site"
  eq "$(jq -r '.result.structuredContent.results[0].selector_slot!=null' "$RESULT_DIR/dh_selr3.json")" "true" "带 selector_slot(__objc_selrefs)"
  kill $HOST3 2>/dev/null; wait $HOST3 2>/dev/null
else
  ng "classic 变体编译失败, 跳过 indirect 验证 (见 $RESULT_DIR/dh_classic_build.log)"
fi

echo ""; echo "== 诊断 =="
mc '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"get_diag","arguments":{"board":"general"}}}' > "$RESULT_DIR/diagnostics.json"
eq "$(jq -r '.result.structuredContent.diag|test("hook")' "$RESULT_DIR/diagnostics.json")" "true" "get_diag 含 hook 时间线"
mc '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"get_capture_coverage","arguments":{}}}' > "$RESULT_DIR/coverage.json"
eq "$(jq -r '.result.structuredContent.layers|type' "$RESULT_DIR/coverage.json")" "array" "覆盖自检返回 layers 数组"
eq "$(jq -r '.result.structuredContent.blind_spots|type' "$RESULT_DIR/coverage.json")" "array" "覆盖自检返回 blind_spots 数组"
eq "$(jq -r '[.result.structuredContent.layers[].layer]|index("NSURLSession (ObjC)")!=null' "$RESULT_DIR/coverage.json")" "true" "覆盖自检包含 NSURLSession 层"
mc '{"jsonrpc":"2.0","id":70,"method":"tools/call","params":{"name":"get_webkit_probe","arguments":{}}}' > "$RESULT_DIR/webkit_probe_get.json"
eq "$(jq -r '.result.structuredContent.enabled' "$RESULT_DIR/webkit_probe_get.json")" "false" "WebKit JS 探针默认关闭"
mc '{"jsonrpc":"2.0","id":71,"method":"tools/call","params":{"name":"set_webkit_probe","arguments":{"enabled":true,"redact":true,"allow":["example.com"]}}}' > "$RESULT_DIR/webkit_probe_set.json"
eq "$(jq -r '.result.structuredContent.enabled' "$RESULT_DIR/webkit_probe_set.json")" "true" "WebKit JS 探针可开启"
eq "$(jq -r '.result.structuredContent.allow[0]' "$RESULT_DIR/webkit_probe_set.json")" "example.com" "WebKit JS 探针 allowlist 生效"
mc '{"jsonrpc":"2.0","id":72,"method":"tools/call","params":{"name":"set_webkit_probe","arguments":{"redact":false,"deny":["127.0.0.1"]}}}' > "$RESULT_DIR/webkit_probe_filter.json"
eq "$(jq -r '.result.structuredContent.redact' "$RESULT_DIR/webkit_probe_filter.json")" "false" "WebKit JS 探针 redact 可关闭"
eq "$(jq -r '.result.structuredContent.deny[0]' "$RESULT_DIR/webkit_probe_filter.json")" "127.0.0.1" "WebKit JS 探针 denylist 生效"
mc '{"jsonrpc":"2.0","id":73,"method":"tools/call","params":{"name":"set_webkit_probe","arguments":{"enabled":false,"redact":true,"allow":[],"deny":[]}}}' >/dev/null
mc '{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"get_diag","arguments":{"board":"sys"}}}' > "$RESULT_DIR/diag_sys.json"
eq "$(jq -r '.result.structuredContent.diag|test("heavy tool")' "$RESULT_DIR/diag_sys.json")" "true" "get_diag(sys) 含重活审计(崩溃可归因)"

echo ""; echo "== 动态 hook + 参数反引用 =="
# import 侧: 只验证能装 + describe_args 生效(是否命中取决于宿主是否真的调这个符号)
mc '{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"hook_import","arguments":{"symbol":"getenv","label":"t-cstr","describe_args":true}}}' > "$RESULT_DIR/hook_import.json"
eq "$(jq -r '.result.structuredContent.slot>=0 and .result.structuredContent.describe_args' "$RESULT_DIR/hook_import.json")" "true" "hook_import(describe_args) 安装并启用"
# method 侧: 挂 NSFileManager 的目录列举, 再用 list_files 主动触发 —— 确定性验证「参数内容被记录」
mc '{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"hook_method","arguments":{"class":"NSFileManager","selector":"contentsOfDirectoryAtPath:error:","describe_args":true}}}' > "$RESULT_DIR/hook_method.json"
eq "$(jq -r '.result.structuredContent.slot>=0 and .result.structuredContent.describe_args' "$RESULT_DIR/hook_method.json")" "true" "hook_method(describe_args) 安装并启用"
mc '{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"list_files","arguments":{"path":"Documents"}}}' > /dev/null
sleep 1
mc '{"jsonrpc":"2.0","id":23,"method":"tools/call","params":{"name":"query_events","arguments":{"category":"other","limit":50}}}' > "$RESULT_DIR/hook_events.json"
eq "$(jq -r '[.result.structuredContent.events[].detail // ""] | any(contains("arg0 ="))' "$RESULT_DIR/hook_events.json")" "true" "method hook 记录了参数内容(反引用生效)"

if grep -Eq '^(jq:|curl:)' "$RESULT_DIR/stderr.log"; then
  ng "测试过程中没有 jq/curl 执行错误"
else
  ok "测试过程中没有 jq/curl 执行错误"
fi

echo ""
printf '结果: \033[32mPASS=%d\033[0m \033[31mFAIL=%d\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
