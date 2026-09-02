#!/usr/bin/env bash
# 启动常驻 TEE 守护进程（Enclave 长期驻留）
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PROFILE="${PROFILE:-release}"
PID_FILE="/tmp/tee-demo.pid"
SOCK="/tmp/tee-demo.sock"
ENCLAVE_SOCK="/tmp/tee-demo-enclave.sock"
HOST_BIN="host/target/x86_64-unknown-linux-gnu/release/tee-demo-host"

cmd="${1:-start}"

build_all() {
    ./build.sh "${PROFILE}"
    ./build-host.sh
    ./build-loader.sh
}

case "$cmd" in
    start)
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo "守护进程已在运行，pid=$(cat "$PID_FILE")"
            exit 0
        fi
        build_all
        echo "==> 启动 TEE 常驻守护进程..."
        TEE_PROJECT_ROOT="$SCRIPT_DIR" nohup "$HOST_BIN" serve > /tmp/tee-demo.log 2>&1 &
        sleep 1
        if [ -f "$PID_FILE" ]; then
            echo "==> 已启动，pid=$(cat "$PID_FILE")"
            echo "==> socket: $SOCK"
            echo "==> enclave socket: $ENCLAVE_SOCK"
            echo "==> 日志: /tmp/tee-demo.log"
        else
            echo "启动失败，查看 /tmp/tee-demo.log"
            exit 1
        fi
        ;;
    stop)
        if [ -x "$HOST_BIN" ]; then
            "$HOST_BIN" stop
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
        exit 1
        ;;
esac
