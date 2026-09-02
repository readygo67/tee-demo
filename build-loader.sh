#!/usr/bin/env bash
# 编译 tee-demo-loader（）
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

cargo build --release --manifest-path loader/Cargo.toml --target x86_64-unknown-linux-gnu

echo "==> loader 编译完成"
ls -lh loader/target/x86_64-unknown-linux-gnu/release/tee-demo-loader
