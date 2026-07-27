#!/bin/bash

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PASS=0
FAIL=0

ok(){ printf '  [PASS] %s\n' "$1"; PASS=$((PASS + 1)); }
ng(){ printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL + 1)); }

expect_absent() {
    local label="$1"
    local pattern="$2"
    shift 2
    local output
    output=$(rg -n "$pattern" "$@" 2>/dev/null || true)
    if [[ -z "$output" ]]; then
        ok "$label"
    else
        ng "$label"
        printf '%s\n' "$output"
    fi
}

expect_present() {
    local label="$1"
    local pattern="$2"
    shift 2
    if rg -q "$pattern" "$@"; then ok "$label"; else ng "$label"; fi
}

echo "== Hook 技术边界 =="
expect_absent "无越狱框架 Hook API 调用" \
    'MSHook(Function|MessageEx)[[:space:]]*\(|LHHook(Function|Functions)[[:space:]]*\(|DobbyHook[[:space:]]*\(' \
    src --glob '!core/capstone/**'
expect_absent "无 Logos %hook" '^[[:space:]]*%hook([[:space:]]|$)' src
expect_absent "共享核心不引入越狱框架头文件" \
    '^[[:space:]]*#[[:space:]]*(include|import).*(substrate|ellekit|libhooker)' src -i
expect_absent "无 DBI 框架引用" \
    '^[[:space:]]*#[[:space:]]*(include|import).*(QBDI|Frida|Stalker)' src -i
expect_absent "无可执行内存/JIT API" \
    'VM_PROT_EXECUTE|MAP_JIT|pthread_jit_write_protect_np' src --glob '!core/capstone/**'

echo "== 共享核心边界 =="
expect_absent "共享核心不引用 daemon 接口" \
    '^[[:space:]]*#[[:space:]]*(include|import).*dh_server|xpc_connection_create_mach_service' src
expect_present "存在 fishhook 实现" 'rebind_symbols' src/core/fishhook.c
expect_present "存在 ObjC swizzle 实现" 'method_setImplementation|method_exchangeImplementations' src

echo "== 服务与协议边界 =="
expect_present "HTTP 首选端口保持 8088" '^#define DH_HTTP_PORT_FIRST[[:space:]]+8088$' src/server/http_server.m
expect_present "UDP 信标端口保持 8089" '^#define DH_BEACON_PORT[[:space:]]+8089$' src/server/udp_beacon.h
expect_present "MCP 路径保持 /api/mcp" '"/api/mcp"' src/server/http_server.m

echo "== constructor 顺序 =="
main_file="src/core/main.m"
warm_line=$(rg -n '\(void\)DHTimestampNow[[:space:]]*\(' "$main_file" | tail -1 | cut -d: -f1)
hook_line=$(rg -n 'dh_install_all_hooks[[:space:]]*\(' "$main_file" | tail -1 | cut -d: -f1)
http_line=$(rg -n 'dh_http_start[[:space:]]*\(' "$main_file" | tail -1 | cut -d: -f1)
if [[ -n "$warm_line" && -n "$hook_line" && -n "$http_line" \
      && "$warm_line" -lt "$hook_line" && "$hook_line" -lt "$http_line" ]]; then
    ok "预热 -> 安装 Hook -> HTTP 启动顺序保持不变"
else
    ng "无法确认 constructor 启动顺序"
fi

echo ""
printf '架构检查结果: PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
