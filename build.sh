#!/usr/bin/env bash
# 步骤 1：将 TEE 代码编译为 Enclave binary，并转换为 SGXS 格式
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PROFILE="${1:-release}"
TARGET="x86_64-fortanix-unknown-sgx"
ELF="target/${TARGET}/${PROFILE}/tee-demo"
SGXS="target/${TARGET}/${PROFILE}/tee-demo.sgxs"

HEAP_SIZE="0x2000000"   # 32 MB
STACK_SIZE="0x40000"    # 256 KB

echo "==> 检查 SGX 设备..."
if [ ! -e /dev/sgx_enclave ]; then
    echo "错误: /dev/sgx_enclave 不存在，请确认 SGX 驱动已加载"
    exit 1
fi

echo "==> 检查 Rust SGX 目标..."
if ! rustup target list --installed | grep -q "^${TARGET}$"; then
    echo "安装 Rust SGX 目标: ${TARGET}"
    rustup target add "${TARGET}"
fi

echo "==> 编译 Enclave ELF (${PROFILE})..."
if [ "$PROFILE" = "release" ]; then
    cargo build --release
else
    cargo build
fi

echo "==> 转换 ELF → SGXS（SGX 加载格式）..."
ftxsgx-elf2sgxs "${ELF}" \
    --heap-size "${HEAP_SIZE}" \
    --stack-size "${STACK_SIZE}" \
    -o "${SGXS}"

echo "==> 编译完成"
echo "    ELF:  ${ELF}"
echo "    SGXS: ${SGXS}"
ls -lh "${ELF}" "${SGXS}"
