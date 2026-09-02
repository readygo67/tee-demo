#!/usr/bin/env bash
# 向常驻 TEE 发送计算请求
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_BIN="$SCRIPT_DIR/host/target/x86_64-unknown-linux-gnu/release/tee-demo-host"

usage() {
    echo "用法: $0 <x> <y>"
    echo "示例: $0 2 3"
    echo ""
    echo "需先启动守护进程: ./daemon.sh start"
    exit 1
}

[ "$#" -eq 2 ] || usage

if [ ! -x "$HOST_BIN" ]; then
    echo "Host 未编译，正在构建..."
    cargo build --release --manifest-path "$SCRIPT_DIR/host/Cargo.toml" --target x86_64-unknown-linux-gnu
fi

"$HOST_BIN" calc "$1" "$2"
