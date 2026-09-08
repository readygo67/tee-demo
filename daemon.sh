#!/usr/bin/env bash
# 启动常驻 TEE 守护进程（Enclave 长期驻留）
#
# 环境变量：
#   TEE_SANDBOX=1     → Host --sandbox（bwrap 最小挂载，§7 / PR-4）
#   TEE_DATA_DIR=...  → data / run 目录
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PROFILE="${PROFILE:-release}"
DATA_DIR="${TEE_DATA_DIR:-/tmp/tee-demo-data}"
PID_FILE="${TEE_PID:-/tmp/tee-demo.pid}"
SOCK="${TEE_SOCK:-/tmp/tee-demo.sock}"
ENCLAVE_SOCK="${TEE_ENCLAVE_SOCK:-/tmp/tee-demo-enclave.sock}"
HOST_BIN="target/x86_64-unknown-linux-gnu/release/tee-demo-host"

cmd="${1:-start}"

ensure_run_dir() {
    mkdir -p "$DATA_DIR"
    # 本地 demo：当前用户可读写；生产见 PRODUCTION-PLAN §7.3
    chmod 0750 "$DATA_DIR" 2>/dev/null || true
}

build_runtime() {
    ./build-runtime.sh "${PROFILE}"
    ./build-host.sh
    ./build-loader.sh
}

case "$cmd" in
    start)
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo "守护进程已在运行，pid=$(cat "$PID_FILE")"
            exit 0
        fi
        build_runtime
        ensure_run_dir
        echo "==> 启动 TEE 常驻守护进程..."
        EXTRA=()
        if [ "${TEE_SANDBOX:-0}" = "1" ]; then
            EXTRA+=(--sandbox --sandbox-wrapper "$SCRIPT_DIR/deploy/loader-sandbox.sh")
            echo "==> 沙箱模式: bwrap (deploy/loader-sandbox.sh)"
        fi
        TEE_PROJECT_ROOT="$SCRIPT_DIR" nohup "$HOST_BIN" serve \
            --socket "$SOCK" \
            --enclave-socket "$ENCLAVE_SOCK" \
            --pid "$PID_FILE" \
            --data-dir "$DATA_DIR" \
            "${EXTRA[@]}" \
            > /tmp/tee-demo.log 2>&1 &
        sleep 1
        if [ -f "$PID_FILE" ]; then
            echo "==> 已启动，pid=$(cat "$PID_FILE")"
            echo "==> socket: $SOCK"
            echo "==> enclave socket: $ENCLAVE_SOCK"
            echo "==> data dir: $DATA_DIR"
            echo "==> 日志: /tmp/tee-demo.log"
        else
            echo "启动失败，查看 /tmp/tee-demo.log"
            exit 1
        fi
        ;;
    stop)
        if [ -x "$HOST_BIN" ]; then
            "$HOST_BIN" stop --socket "$SOCK" --enclave-socket "$ENCLAVE_SOCK" --pid "$PID_FILE"
        else
            [ -f "$PID_FILE" ] && kill "$(cat "$PID_FILE")" 2>/dev/null || true
            rm -f "$PID_FILE" "$SOCK" "$ENCLAVE_SOCK"
        fi
        echo "==> 已停止"
        ;;
    status)
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo "运行中，pid=$(cat "$PID_FILE"), socket=$SOCK"
        else
            echo "未运行"
            exit 1
        fi
        ;;
    restart)
        "$0" stop || true
        "$0" start
        ;;
    *)
        echo "用法: $0 {start|stop|status|restart}"
        echo "  TEE_SANDBOX=1 $0 start   # bwrap 沙箱"
        exit 1
        ;;
esac
