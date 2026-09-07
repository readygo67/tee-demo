#!/usr/bin/env bash
# 编译 Runtime（SGX Enclave）：ELF → SGXS；可选生产签名。
#
# 用法:
#   ./build-runtime.sh [release|debug]           # 开发构建（默认 release，不签名）
#   ./build-runtime.sh --production [选项]       # 生产构建：签名 → .sig + .mrenclave
#
# 生产选项:
#   --key PATH          签名私钥（默认 keys/enclave.pem）
#   --isvprodid N       ISVPRODID（默认 0）
#   --isvsvn N          ISVSVN（默认 1）
#
# 产物:
#   target/x86_64-fortanix-unknown-sgx/{release|debug}/tee-demo.sgxs
#   --production 额外:
#     keys/enclave.sig          # SIGSTRUCT（无 DEBUG 位）
#     keys/enclave.mrenclave    # MRENCLAVE hex
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TARGET="x86_64-fortanix-unknown-sgx"
HEAP_SIZE="0x2000000"   # 32 MB
STACK_SIZE="0x40000"    # 256 KB
THREADS=1

PROFILE="release"
PRODUCTION=0
KEY="keys/enclave.pem"
ISVPRODID=0
ISVSVN=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        release|debug)
            PROFILE="$1"
            shift
            ;;
        --production)
            PRODUCTION=1
            PROFILE="release"
            shift
            ;;
        --key)
            KEY="$2"
            shift 2
            ;;
        --isvprodid)
            ISVPRODID="$2"
            shift 2
            ;;
        --isvsvn)
            ISVSVN="$2"
            shift 2
            ;;
        -h|--help)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *)
            echo "未知参数: $1（见 --help）"
            exit 1
            ;;
    esac
done

ELF="target/${TARGET}/${PROFILE}/tee-demo"
SGXS="target/${TARGET}/${PROFILE}/tee-demo.sgxs"
SIG="keys/enclave.sig"
MRE="keys/enclave.mrenclave"

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

if [ "$PRODUCTION" = "1" ]; then
    if [ ! -f "$KEY" ]; then
        echo "错误: 签名密钥不存在: $KEY"
        echo "请先运行: openssl genrsa -3 -out $KEY 3072"
        exit 1
    fi
    exponent=$(openssl rsa -in "$KEY" -text -noout 2>/dev/null | grep '^publicExponent:' | awk '{print $2}')
    if [ "$exponent" != "3" ]; then
        echo "错误: 密钥公钥指数必须为 3，当前为 ${exponent:-未知}"
        echo "请重新生成: openssl genrsa -3 -out $KEY 3072"
        exit 1
    fi
    echo "==> 生产编译 Runtime (release)..."
else
    echo "==> 编译 Runtime (${PROFILE})..."
fi

if [ "$PROFILE" = "release" ]; then
    cargo build --release -p tee-demo
else
    cargo build -p tee-demo
fi

echo "==> ELF → SGXS（heap=${HEAP_SIZE} stack=${STACK_SIZE} threads=${THREADS}）..."
ftxsgx-elf2sgxs "${ELF}" \
    --heap-size "${HEAP_SIZE}" \
    --stack-size "${STACK_SIZE}" \
    --threads "${THREADS}" \
    -o "${SGXS}"

if [ "$PRODUCTION" != "1" ]; then
    echo "==> 开发构建完成（未签名；loader 可用 dummy_signature）"
    echo "    ELF:  ${ELF}"
    echo "    SGXS: ${SGXS}"
    ls -lh "${ELF}" "${SGXS}"
    exit 0
fi

# ── 生产签名 ────────────────────────────────────────────────
mkdir -p keys

# 当前机器 XFRM（XCR0），须与 ECREATE 一致
XFRM_VAL=$(cat > /tmp/__xgetbv0.c << 'CSRC'
#include <stdio.h>
#include <stdint.h>
static inline uint64_t xgetbv0(void) {
    uint32_t lo, hi;
    asm volatile (".byte 0x0f,0x01,0xd0" : "=a"(lo), "=d"(hi) : "c"(0));
    return ((uint64_t)hi << 32) | lo;
}
int main() { printf("0x%llx\n", (unsigned long long)xgetbv0()); return 0; }
CSRC
gcc /tmp/__xgetbv0.c -o /tmp/__xgetbv0 && /tmp/__xgetbv0)
echo "==> 当前机器 XFRM (XCR0) = ${XFRM_VAL}"

echo "==> SGXS → SIGSTRUCT（不含 DEBUG 位）..."
sgxs_output=$(sgxs-sign --key "${KEY}" "${SGXS}" "${SIG}" \
    -x "${XFRM_VAL}/0" -p "${ISVPRODID}" -v "${ISVSVN}" 2>&1)
echo "$sgxs_output"

mrenclave=$(echo "$sgxs_output" | sed -n 's/^ENCLAVEHASH: \([0-9a-f]*\).*/\1/p')
if [ -z "$mrenclave" ]; then
    mrenclave=$(dd if="${SIG}" bs=1 skip=960 count=32 2>/dev/null | xxd -p -c 32)
fi
if [ -z "$mrenclave" ]; then
    echo "错误: 无法提取 MRENCLAVE"
    exit 1
fi
echo "$mrenclave" > "${MRE}"

echo ""
echo "==> 生产构建完成"
echo "    SGXS:      ${SGXS}"
echo "    SIG:       ${SIG} ($(wc -c < "${SIG}") 字节)"
echo "    MRENCLAVE: ${mrenclave}"
echo "    写入:      ${MRE}"
echo ""
echo "发布时将 MRENCLAVE 写入 config 或 Client --expected-mrenclave"
ls -lh "${SGXS}" "${SIG}"
