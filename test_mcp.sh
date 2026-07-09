#!/bin/bash
# MCP 服务端到端冒烟测试。
# 用法: ./test_mcp.sh [host:port]   默认 127.0.0.1:8088
# 需目标进程已注入 dylib 且 HTTP 服务在线。

set -u
BASE="${1:-127.0.0.1:8088}"
U="http://$BASE/api/mcp"
PP() { if command -v jq >/dev/null; then jq -c "$@"; else cat; fi; }

echo "MCP endpoint: $U"
echo ""

echo "[1] initialize"
curl -s -X POST "$U" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}' \
  | PP '.result | {protocolVersion, serverInfo}'

echo "[2] notifications/initialized (期望 HTTP 202 空体)"
curl -s -o /dev/null -w "    HTTP %{http_code}\n" -X POST "$U" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

echo "[3] tools/list"
curl -s -X POST "$U" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | PP '.result.tools | map(.name)'

echo "[4] tools/call disassemble"
curl -s -X POST "$U" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"disassemble","arguments":{"bytes":"fd7bbfa9 fd030091 c0035fd6","arch":"arm64"}}}' \
  | PP '{isError:.result.isError, insns:.result.structuredContent.instructions|map(.mnemonic)}'

echo "[5] tools/call get_macho_info"
curl -s -X POST "$U" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_macho_info","arguments":{}}}' \
  | PP '.result.structuredContent | {count, encrypted_count}'

echo "[6] tools/call list_imports (image_index=0)"
curl -s -X POST "$U" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"list_imports","arguments":{"image_index":0,"limit":5}}}' \
  | PP '.result.structuredContent | {image, total, sample:.symbols[0:5]}'

echo "[7] GET /api/mcp (期望 405)"
curl -s -o /dev/null -w "    HTTP %{http_code}\n" "$U"
