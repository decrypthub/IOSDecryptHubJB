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
