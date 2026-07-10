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

DYLD_INSERT_LIBRARIES=./decrypt_helper.mac.dylib ./tests/exercise_runner >/tmp/dh_test_host.log 2>&1 &
HOST=$!
trap 'kill $HOST 2>/dev/null' EXIT
echo "[host] PID $HOST, 等事件生成 + 网络完成 (5s)"
sleep 5

PORT=$(grep -oE 'http://[0-9.]+:[0-9]+' /tmp/dh_test_host.log | head -1 | grep -oE '[0-9]+$'); PORT=${PORT:-8088}
U="http://127.0.0.1:$PORT"; MCP="$U/api/mcp"
mc(){ curl -s -X POST "$MCP" -H "Content-Type: application/json" -d "$1"; }
echo "[server] port=$PORT (无鉴权)"

echo ""; echo "== 无鉴权直连 (局域网自用, 已移除 token) =="
eq "$(curl -s -o /dev/null -w '%{http_code}' "$U/api/stats")"              "200" "/api/stats 直连 → 200"
eq "$(curl -s -o /dev/null -w '%{http_code}' "$U/")"                       "200" "HTML 外壳 → 200"
eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$U/api/mcp" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')" "200" "MCP 直连 → 200"

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

echo ""; echo "== find_xrefs (tier-1 直接 BL 调用引用) =="
# import stub 正例: runner 直接调 printf 多次, 应经 __stubs → GOT → dladdr 还原成 printf
mc '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"find_xrefs","arguments":{"symbol":"printf","max_results":50}}}' > /tmp/dh_xref.json
ge "$(jq '.result.structuredContent.count' /tmp/dh_xref.json)" 1 "find_xrefs printf ≥1 调用点"
eq "$(jq -r '.result.structuredContent.results[0].kind' /tmp/dh_xref.json)" "call_import_stub" "printf 归类 call_import_stub"
eq "$(jq -r '.result.structuredContent.results[0].resolved_name' /tmp/dh_xref.json)" "printf" "stub 还原出 printf"
# tier-1.5 归属: 有符号 → main+off, 并带 from_func_start / vmaddr
eq "$(jq -r '.result.structuredContent.results[0].from_func|test("^main\\+0x")' /tmp/dh_xref.json)" "true" "printf 调用点归属到 main+off"
eq "$(jq -r '.result.structuredContent.results[0].from_func_start|test("^0x")' /tmp/dh_xref.json)" "true" "带 from_func_start"
eq "$(jq -r '.result.structuredContent.results[0].from_func_vmaddr|test("^0x")' /tmp/dh_xref.json)" "true" "带 from_func_vmaddr(稳定 ID)"
# objc_stub 路径: objc_msgSend$sel 降级 stub, 前缀匹配 objc_msgSend
mc '{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"find_xrefs","arguments":{"symbol":"objc_msgSend","max_results":50}}}' > /tmp/dh_xref2.json
ge "$(jq '.result.structuredContent.count' /tmp/dh_xref2.json)" 1 "find_xrefs objc_msgSend ≥1 调用点"
eq "$(jq -r 'any(.result.structuredContent.results[]; .kind=="call_objc_stub")' /tmp/dh_xref2.json)" "true" "含 call_objc_stub"
# 缺参防御
eq "$(mc '{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"find_xrefs","arguments":{}}}' | jq -r '.result.isError')" "true" "无 symbol/address → isError"

echo ""; echo "== find_xrefs tier-1.5: strip 目标归属到 sub_xxx =="
# strip 掉本地符号后 dladdr 失效, 应经 LC_FUNCTION_STARTS 归属到 sub_<runtime>+off。
cp tests/exercise_runner /tmp/dh_er_stripped && strip /tmp/dh_er_stripped 2>/dev/null
eq "$(otool -l /tmp/dh_er_stripped 2>/dev/null | grep -c FUNCTION_STARTS)" "1" "strip 后 LC_FUNCTION_STARTS 保留"
rm -f "$HOME/Documents/.dh_token.conf"
DYLD_INSERT_LIBRARIES=./decrypt_helper.mac.dylib /tmp/dh_er_stripped >/tmp/dh_host2.log 2>&1 &
HOST2=$!; sleep 3
P2=$(grep -oE 'http://[0-9.]+:[0-9]+' /tmp/dh_host2.log | head -1 | grep -oE '[0-9]+$'); P2=${P2:-8088}
T2=$(cat "$HOME/Documents/.dh_token.conf" 2>/dev/null)
curl -s -X POST "http://127.0.0.1:$P2/api/mcp?token=$T2" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"find_xrefs","arguments":{"symbol":"printf","max_results":5}}}' > /tmp/dh_xref3.json
ge "$(jq '.result.structuredContent.count' /tmp/dh_xref3.json)" 1 "strip 目标 printf ≥1 调用点"
eq "$(jq -r '.result.structuredContent.results[0].from_func|test("^sub_[0-9a-f]+\\+0x")' /tmp/dh_xref3.json)" "true" "strip 后归属到 sub_xxx+off"
eq "$(jq -r '.result.structuredContent.results[0].resolved_name' /tmp/dh_xref3.json)" "printf" "strip 后 import 仍还原 printf"
# tier-3A 在 strip 下: 调 printf 的函数(strip 后 = sub_xxx)的内部 callees 应归属到 sub_xxx 且带稳定 vmaddr
FSTART=$(jq -r '.result.structuredContent.results[0].from_func_start' /tmp/dh_xref3.json)
curl -s --max-time 15 -X POST "http://127.0.0.1:$P2/api/mcp?token=$T2" -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"find_function_refs\",\"arguments\":{\"target\":\"$FSTART\",\"direction\":\"callees\",\"max_results\":40}}}" > /tmp/dh_fref_s.json
ge "$(jq '.result.structuredContent.count' /tmp/dh_fref_s.json)" 1 "strip: 内部 callees ≥1"
eq "$(jq -r '[.result.structuredContent.results[].to_func]|all(test("^sub_"))' /tmp/dh_fref_s.json)" "true" "strip 下 callees 归属到 sub_xxx"
eq "$(jq -r '.result.structuredContent.results[0].to_func_vmaddr|test("^0x")' /tmp/dh_fref_s.json)" "true" "strip 下带 to_func_vmaddr(稳定 ID)"
# tier-3B: strip 下 list_functions 仍列出函数(LC_FUNCTION_STARTS), 但名字退化成 sub_xxx
curl -s --max-time 15 -X POST "http://127.0.0.1:$P2/api/mcp?token=$T2" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_functions","arguments":{"limit":100}}}' > /tmp/dh_lf_s.json
ge "$(jq '.result.structuredContent.total' /tmp/dh_lf_s.json)" 5 "strip: list_functions total ≥5"
eq "$(jq -r '[.result.structuredContent.functions[]|select(.has_symbol==false)]|length>0' /tmp/dh_lf_s.json)" "true" "strip 下含 sub_xxx(has_symbol=false)"
kill $HOST2 2>/dev/null; wait $HOST2 2>/dev/null   # 同步收尸, 免 job-control 打印 Terminated

echo ""; echo "== find_string_refs (tier-2A: direct + 归属 + 无误报) =="
# direct: ADRP+ADD → __cstring; runner 用 printf 打了带 "AES" 的格式串
mc '{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"find_string_refs","arguments":{"string":"AES","max_results":20}}}' > /tmp/dh_sref.json
ge "$(jq '.result.structuredContent.count' /tmp/dh_sref.json)" 1 "find_string_refs AES ≥1 引用"
eq "$(jq -r '.result.structuredContent.results[0].indirect' /tmp/dh_sref.json)" "false" "direct ref indirect=false"
eq "$(jq -r '.result.structuredContent.results[0].section|test("__cstring")' /tmp/dh_sref.json)" "true" "命中 __TEXT,__cstring"
eq "$(jq -r '.result.structuredContent.results[0].instruction|test("^add ")' /tmp/dh_sref.json)" "true" "指令是 ADRP+ADD 的 add"
eq "$(jq -r '.result.structuredContent.results[0].from_func!=null' /tmp/dh_sref.json)" "true" "ref_site 有函数归属"
# address 模式: 用命中的 string_addr 反查, 应对上
SADDR=$(jq -r '.result.structuredContent.results[0].string_addr' /tmp/dh_sref.json)
mc "{\"jsonrpc\":\"2.0\",\"id\":15,\"method\":\"tools/call\",\"params\":{\"name\":\"find_string_refs\",\"arguments\":{\"address\":\"$SADDR\"}}}" > /tmp/dh_sref_a.json
ge "$(jq '.result.structuredContent.count' /tmp/dh_sref_a.json)" 1 "address 模式反查命中 ($SADDR)"
# 无误报: 不存在的子串
eq "$(mc '{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"find_string_refs","arguments":{"string":"ZZZ_NOPE_QWERTY_XYZZY"}}}' | jq '.result.structuredContent.count')" "0" "不存在子串 → 0(不误把立即数当串)"
# 缺参防御
eq "$(mc '{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"find_string_refs","arguments":{}}}' | jq -r '.result.isError')" "true" "无 string/address → isError"

echo ""; echo "== find_selector_refs (tier-2B path B: __objc_stubs) =="
# 默认 runner 走 __objc_stubs; dataWithBytes:length: 应作为 objc_stub 调用点命中
mc '{"jsonrpc":"2.0","id":18,"method":"tools/call","params":{"name":"find_selector_refs","arguments":{"selector":"dataWithBytes:length:"}}}' > /tmp/dh_selr.json
ge "$(jq '.result.structuredContent.count' /tmp/dh_selr.json)" 1 "find_selector_refs dataWithBytes:length: ≥1"
eq "$(jq -r '.result.structuredContent.results[0].target_kind' /tmp/dh_selr.json)" "objc_stub" "path B kind=objc_stub"
eq "$(jq -r '.result.structuredContent.results[0].selector_source' /tmp/dh_selr.json)" "__objc_stubs" "selector_source=__objc_stubs"
eq "$(jq -r '.result.structuredContent.results[0].from_func!=null' /tmp/dh_selr.json)" "true" "call_site 有函数归属"
# 无误报: "bytes" 既是 cstring 又是 selector; selector_ref 只应报真正的 objc 调用点(不含 cstring)
mc '{"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"find_selector_refs","arguments":{"selector":"bytes"}}}' > /tmp/dh_selb.json
eq "$(jq -r '[.result.structuredContent.results[]|.target_kind]|unique|.[]' /tmp/dh_selb.json)" "objc_stub" "bytes 只命中 objc 调用(cstring 不误报)"
# 不存在 selector → 0
eq "$(mc '{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"find_selector_refs","arguments":{"selector":"nonexistentSelectorXYZ:"}}}' | jq '.result.structuredContent.count')" "0" "不存在 selector → 0"
# 缺参防御
eq "$(mc '{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"find_selector_refs","arguments":{}}}' | jq -r '.result.isError')" "true" "无 selector → isError"

echo ""; echo "== find_function_refs (tier-3A: 内部调用图) =="
MAINA=$(mc '{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"resolve_symbol","arguments":{"name":"main"}}}' | jq -r '.result.structuredContent.address')
mc "{\"jsonrpc\":\"2.0\",\"id\":23,\"method\":\"tools/call\",\"params\":{\"name\":\"find_function_refs\",\"arguments\":{\"target\":\"$MAINA\",\"direction\":\"callees\",\"max_results\":40}}}" > /tmp/dh_fref.json
ge "$(jq '.result.structuredContent.count' /tmp/dh_fref.json)" 1 "callees of main ≥1 内部调用"
eq "$(jq -r '[.result.structuredContent.results[].to_func]|any(test("^test_"))' /tmp/dh_fref.json)" "true" "callees 含内部 test_* 函数"
eq "$(jq -r '[.result.structuredContent.results[].to_func]|any(test("printf"))' /tmp/dh_fref.json)" "false" "callees 不含 import stub printf(排除 stub)"
eq "$(jq -r '.result.structuredContent.results[0].relation' /tmp/dh_fref.json)" "callee" "relation=callee"
# callers 方向: 取 test_network 入口, 查谁调用它
NETS=$(jq -r '.result.structuredContent.results[]|select(.to_func|startswith("test_network"))|.to_func_start' /tmp/dh_fref.json | head -1)
mc "{\"jsonrpc\":\"2.0\",\"id\":24,\"method\":\"tools/call\",\"params\":{\"name\":\"find_function_refs\",\"arguments\":{\"target\":\"$NETS\",\"direction\":\"callers\"}}}" > /tmp/dh_fref2.json
ge "$(jq '.result.structuredContent.count' /tmp/dh_fref2.json)" 1 "callers of test_network ≥1"
eq "$(jq -r '.result.structuredContent.results[0].from_func|test("^main")' /tmp/dh_fref2.json)" "true" "test_network 的调用者是 main"
eq "$(jq -r '.result.structuredContent.results[0].relation' /tmp/dh_fref2.json)" "caller" "relation=caller"
# test_network 只做 objc/import 调用 → 内部 callees 为空(排除 objc_stub/stub)
mc "{\"jsonrpc\":\"2.0\",\"id\":25,\"method\":\"tools/call\",\"params\":{\"name\":\"find_function_refs\",\"arguments\":{\"target\":\"$NETS\",\"direction\":\"callees\"}}}" > /tmp/dh_fref3.json
eq "$(jq '.result.structuredContent.count' /tmp/dh_fref3.json)" "0" "test_network 内部 callees=0(objc_stub/import 不算内部)"
# 缺参 / 无法归属
eq "$(mc '{"jsonrpc":"2.0","id":26,"method":"tools/call","params":{"name":"find_function_refs","arguments":{}}}' | jq -r '.result.isError')" "true" "无 target → isError"
eq "$(mc '{"jsonrpc":"2.0","id":27,"method":"tools/call","params":{"name":"find_function_refs","arguments":{"target":"0x1"}}}' | jq -r '.result.isError')" "true" "无法归属地址 → isError"

echo ""; echo "== list_functions (tier-3B: 函数清单) =="
mc '{"jsonrpc":"2.0","id":28,"method":"tools/call","params":{"name":"list_functions","arguments":{"limit":100}}}' > /tmp/dh_lf.json
ge "$(jq '.result.structuredContent.total' /tmp/dh_lf.json)" 5 "list_functions total ≥5"
eq "$(jq -r '[.result.structuredContent.functions[]|select(.name=="main")]|length>0' /tmp/dh_lf.json)" "true" "含 main 函数"
eq "$(jq -r '[.result.structuredContent.functions[]|select(.name=="main")][0].has_symbol' /tmp/dh_lf.json)" "true" "main has_symbol=true"
eq "$(jq -r '[.result.structuredContent.functions[]|select(.name=="main")][0]|(.vmaddr|test("^0x")) and (.size>0)' /tmp/dh_lf.json)" "true" "main 带 vmaddr 与 size>0"
# query 过滤
eq "$(jq -r '[.result.structuredContent.functions[]|.name]|all(test("test_"))' <(mc '{"jsonrpc":"2.0","id":29,"method":"tools/call","params":{"name":"list_functions","arguments":{"query":"test_"}}}'))" "true" "query=test_ 全部含 test_"
# 分页: offset 生效
eq "$(mc '{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"list_functions","arguments":{"query":"test_","offset":2,"limit":2}}}' | jq '.result.structuredContent.shown')" "2" "分页 shown=2"

echo ""; echo "== find_string_refs indirect (经典 selref → SEL) =="
# 用 -fno-objc-msgsend-selector-stubs 强制经典 adrp+ldr selref 模式, 触发间接引用
CLSDK=$(xcrun --sdk macosx --show-sdk-path 2>/dev/null)
xcrun --find clang >/dev/null 2>&1 && "$(xcrun --find clang)" -arch arm64 -isysroot "$CLSDK" \
  -mmacosx-version-min=11.0 -ObjC -fobjc-arc -O0 -fno-objc-msgsend-selector-stubs \
  -framework Foundation -framework CoreFoundation -framework Security \
  tests/exercise_runner.m -o /tmp/dh_er_classic >/tmp/dh_classic_build.log 2>&1
if [ -x /tmp/dh_er_classic ]; then
  eq "$(otool -l /tmp/dh_er_classic 2>/dev/null | grep -c 'sectname __objc_stubs')" "0" "classic 变体无 __objc_stubs"
  rm -f "$HOME/Documents/.dh_token.conf"
  DYLD_INSERT_LIBRARIES=./decrypt_helper.mac.dylib /tmp/dh_er_classic >/tmp/dh_host3.log 2>&1 &
  HOST3=$!; sleep 3
  P3=$(grep -oE 'http://[0-9.]+:[0-9]+' /tmp/dh_host3.log | head -1 | grep -oE '[0-9]+$'); P3=${P3:-8088}
  T3=$(cat "$HOME/Documents/.dh_token.conf" 2>/dev/null)
  curl -s --max-time 15 -X POST "http://127.0.0.1:$P3/api/mcp?token=$T3" -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"find_string_refs","arguments":{"string":"dataWithBytes","max_results":5}}}' > /tmp/dh_sref2.json
  ge "$(jq '.result.structuredContent.count' /tmp/dh_sref2.json)" 1 "indirect: selector dataWithBytes ≥1 引用"
  eq "$(jq -r 'any(.result.structuredContent.results[]; .indirect==true)' /tmp/dh_sref2.json)" "true" "含 indirect=true(经 selref)"
  eq "$(jq -r '[.result.structuredContent.results[]|select(.indirect==true)][0].string|test("dataWithBytes")' /tmp/dh_sref2.json)" "true" "间接读出 selector 名"
  # 同一 classic 宿主验 find_selector_refs path A (selref + blr objc_msgSend)
  curl -s --max-time 15 -X POST "http://127.0.0.1:$P3/api/mcp?token=$T3" -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find_selector_refs","arguments":{"selector":"dataWithBytes:length:"}}}' > /tmp/dh_selr3.json
  ge "$(jq '.result.structuredContent.count' /tmp/dh_selr3.json)" 1 "path A: classic selref ≥1 调用点"
  eq "$(jq -r '.result.structuredContent.results[0].target_kind' /tmp/dh_selr3.json)" "objc_msgsend" "path A kind=objc_msgsend"
  eq "$(jq -r '.result.structuredContent.results[0].selector_source' /tmp/dh_selr3.json)" "__objc_selrefs" "selector_source=__objc_selrefs"
  eq "$(jq -r '.result.structuredContent.results[0].selector_load_site!=null' /tmp/dh_selr3.json)" "true" "带 selector_load_site"
  eq "$(jq -r '.result.structuredContent.results[0].selector_slot!=null' /tmp/dh_selr3.json)" "true" "带 selector_slot(__objc_selrefs)"
  kill $HOST3 2>/dev/null; wait $HOST3 2>/dev/null
else
  ng "classic 变体编译失败, 跳过 indirect 验证 (见 /tmp/dh_classic_build.log)"
fi

echo ""; echo "== 诊断 =="
eq "$(mc '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"get_diag","arguments":{"board":"general"}}}' | jq -r '.result.structuredContent.diag|test("hook")')" "true" "get_diag 含 hook 时间线"

echo ""
printf '结果: \033[32mPASS=%d\033[0m \033[31mFAIL=%d\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
