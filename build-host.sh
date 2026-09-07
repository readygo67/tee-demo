#!/usr/bin/env bash
# 编译 Host 守护进程（原生 Linux，非 SGX 目标）
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

cargo build --release -p tee-demo-host --target x86_64-unknown-linux-gnu
