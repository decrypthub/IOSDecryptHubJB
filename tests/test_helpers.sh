#!/bin/bash

# 测试公共函数。调用者必须先设置 RESULT_DIR。

DH_TEST_STARTED_EPOCH="${DH_TEST_STARTED_EPOCH:-$(date +%s)}"

dh_wait_for_http() {
    local log_file="$1"
    local host_pid="$2"
    local timeout_seconds="${3:-15}"
    local attempts=$((timeout_seconds * 10))
    local port=""

    for ((i = 0; i < attempts; i++)); do
        if ! kill -0 "$host_pid" 2>/dev/null; then
            return 1
        fi
        port=$(grep -oE 'http://[0-9.]+:[0-9]+' "$log_file" 2>/dev/null \
            | head -1 | grep -oE '[0-9]+$' || true)
        if [[ -n "$port" ]] && curl -sf --max-time 1 "http://127.0.0.1:$port/api/stats" >/dev/null; then
            printf '%s\n' "$port"
            return 0
        fi
        sleep 0.1
    done
    return 1
}

dh_wait_for_marker() {
    local log_file="$1"
    local marker="$2"
    local timeout_seconds="${3:-15}"
    local attempts=$((timeout_seconds * 10))

    for ((i = 0; i < attempts; i++)); do
        if grep -Fq "$marker" "$log_file" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

dh_find_http_for_bundle() {
    local bundle_id="$1"
    local timeout_seconds="${2:-20}"
    local attempts=$((timeout_seconds * 5))
    local port response found

    for ((i = 0; i < attempts; i++)); do
        for port in $(seq 8088 8108); do
            response=$(curl -sf --max-time 1 "http://127.0.0.1:$port/api/stats" 2>/dev/null || true)
            [[ -n "$response" ]] || continue
            found=$(printf '%s' "$response" | jq -r '.process.bundleId // empty' 2>/dev/null || true)
            if [[ "$found" = "$bundle_id" ]]; then
                printf '%s\n' "$port"
                return 0
            fi
        done
        sleep 0.2
    done
    return 1
}

dh_write_results() {
    local suite="$1"
    local pass_count="$2"
    local fail_count="$3"
    local platform="$4"
    local status="passed"
    local ended_epoch duration_seconds
    ended_epoch=$(date +%s)
    duration_seconds=$((ended_epoch - DH_TEST_STARTED_EPOCH))
    [[ "$fail_count" -gt 0 ]] && status="failed"

    jq -n \
        --arg suite "$suite" \
        --arg platform "$platform" \
        --arg status "$status" \
        --arg runId "$(basename "$RESULT_DIR")" \
        --argjson passed "$pass_count" \
        --argjson failed "$fail_count" \
        --argjson durationSeconds "$duration_seconds" \
        '{schema_version:1, run_id:$runId, suite:$suite, platform:$platform,
          status:$status, passed:$passed, failed:$failed, duration_seconds:$durationSeconds}' \
        > "$RESULT_DIR/manifest.json"

    jq -n --argjson durationSeconds "$duration_seconds" \
        '{schema_version:1, suite_duration_seconds:$durationSeconds,
          note:"阶段 0 只记录测试套件墙钟耗时；Hook 热路径基准在后续性能阶段补充。"}' \
        > "$RESULT_DIR/performance.json"

    if [[ ! -f "$RESULT_DIR/coverage.json" ]]; then
        jq -n '{schema_version:1, status:"not_available", planned_stage:2}' \
            > "$RESULT_DIR/coverage.json"
    fi
    if [[ ! -f "$RESULT_DIR/diagnostics.json" ]]; then
        jq -n '{schema_version:1, status:"not_collected"}' \
            > "$RESULT_DIR/diagnostics.json"
    fi

    if [[ "$fail_count" -eq 0 ]]; then
        printf '<testsuite name="%s" tests="%d" failures="0"><testcase name="all assertions"/></testsuite>\n' \
            "$suite" "$pass_count" > "$RESULT_DIR/junit.xml"
    else
        printf '<testsuite name="%s" tests="%d" failures="%d"><testcase name="assertions"><failure message="%d assertions failed"/></testcase></testsuite>\n' \
            "$suite" "$((pass_count + fail_count))" "$fail_count" "$fail_count" \
            > "$RESULT_DIR/junit.xml"
    fi
}

# ---------- 真机（越狱）辅助 ----------
# 真机不走本机端口探测：MCP 直接打在设备 IP 的 8088 上（与 idh 的连接方式一致）。
dh_device_mcp() { # dh_device_mcp <host> <json>
    curl -sf --connect-timeout 2 --max-time 6 -X POST "http://$1:8088/api/mcp" \
        -H 'Content-Type: application/json' -d "$2"
}

dh_device_wait_mcp() { # dh_device_wait_mcp <host> <bundleid> [timeout_s]
    local host="$1" want="$2" timeout="${3:-30}" got
    local attempts=$(( timeout * 2 ))
    for ((i = 0; i < attempts; i++)); do
        got=$(dh_device_mcp "$host" \
            '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_stats","arguments":{}}}' \
            2>/dev/null | jq -r '.result.structuredContent.process.bundleId // empty' 2>/dev/null || true)
        [[ "$got" = "$want" ]] && return 0
        sleep 0.5
    done
    return 1
}

# 当前已捕获事件的算法名集合（清空后调用即可知道本次触发了什么）
dh_device_algorithms() { # dh_device_algorithms <host>
    dh_device_mcp "$1" \
        '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"query_events","arguments":{"limit":1000}}}' \
        2>/dev/null | jq -r '[.result.structuredContent.events[].algorithm] | unique | .[]' 2>/dev/null || true
}

dh_device_tool() { # dh_device_tool <host> <tool> <json-args>
    dh_device_mcp "$1" "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":$3}}"
}
