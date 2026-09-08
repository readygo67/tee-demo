#!/usr/bin/env bash
# Client nonce challenge + DCAP verify + AEAD calc
#
# 用法:
#   ./client.sh <x> <y>              # challenge + DCAP + HPKE calc
#   ./client.sh challenge [HEX]      # 仅 challenge + 验证
#   ./client.sh pubkey | rotate
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_BIN="$SCRIPT_DIR/target/x86_64-unknown-linux-gnu/release/tee-demo-host"
SOCK="${TEE_SOCK:-/tmp/tee-demo.sock}"
EXPECTED_MRE="${TEE_EXPECTED_MRENCLAVE:-}"

usage() {
    echo "用法: $0 <x> <y>             # nonce challenge + DCAP + HPKE"
    echo "      $0 challenge [hex]     # Client nonce challenge"
    echo "      $0 pubkey | rotate"
    echo ""
    echo "环境变量: TEE_SOCK, TEE_EXPECTED_MRENCLAVE"
    echo "需先启动: ./daemon.sh start"
    exit 1
}

if [ ! -x "$HOST_BIN" ]; then
    echo "Host 未编译，正在构建..."
    cargo build --release -p tee-demo-host --target x86_64-unknown-linux-gnu
fi

mre_args=()
if [ -n "$EXPECTED_MRE" ]; then
    mre_args=(--expected-mrenclave "$EXPECTED_MRE")
fi

case "${1:-}" in
    pubkey)
        "$HOST_BIN" pubkey --socket "$SOCK"
        ;;
    rotate)
        "$HOST_BIN" rotate --socket "$SOCK"
        ;;
    challenge)
        if [ -n "${2:-}" ]; then
            "$HOST_BIN" challenge --socket "$SOCK" --nonce "$2" "${mre_args[@]}"
        else
            "$HOST_BIN" challenge --socket "$SOCK" "${mre_args[@]}"
        fi
        ;;
    ""|-h|--help)
        usage
        ;;
    *)
        X="$1"
        Y="${2:-}"
        [ -n "$Y" ] || usage
        "$HOST_BIN" calc "$X" "$Y" --socket "$SOCK" "${mre_args[@]}"
        ;;
esac
