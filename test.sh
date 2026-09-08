#!/usr/bin/env bash
# tee-demo 集成测试（合并原 test-pr0…pr4 + 旧 test.sh）
#
# 覆盖：
#   1. 构建（./build-runtime.sh --production）+ serve 真实 SIGSTRUCT（keys/enclave.sig，无 DEBUG）
#   2. challenge + DCAP + REPORTDATA；calc HPKE；多组 x³+5y
#   3. sealing / keyring / rotate retention / 重启恢复
#   4. 错误 MRENCLAVE 拒绝
#   5. （可选）bwrap 沙箱
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

HOST_BIN="$SCRIPT_DIR/target/x86_64-unknown-linux-gnu/release/tee-demo-host"
LOADER_BIN="$SCRIPT_DIR/target/x86_64-unknown-linux-gnu/release/tee-demo-loader"
SGXS="$SCRIPT_DIR/target/x86_64-fortanix-unknown-sgx/release/tee-demo.sgxs"
WRAPPER="$SCRIPT_DIR/deploy/loader-sandbox.sh"
PROD_SIG="$SCRIPT_DIR/keys/enclave.sig"
MRE_FILE="$SCRIPT_DIR/keys/enclave.mrenclave"
PROD_ARGS=()
MRE_ARGS=()

RUN_DIR="${TEE_TEST_DIR:-/tmp/tee-demo-test}"
SOCK="$RUN_DIR/client.sock"
ENCLAVE_SOCK="$RUN_DIR/enclave.sock"
PID_FILE="$RUN_DIR/tee.pid"
DATA_DIR="$RUN_DIR/data"
HOST_LOG="$RUN_DIR/host.log"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0
FAIL=0
HOST_PID=""

pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

cleanup() {
    if [ -n "${HOST_PID:-}" ]; then
        kill "$HOST_PID" 2>/dev/null || true
        wait "$HOST_PID" 2>/dev/null || true
        HOST_PID=""
    fi
    ./daemon.sh stop >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

stop_host() {
    if [ -n "${HOST_PID:-}" ]; then
        kill "$HOST_PID" 2>/dev/null || true
        wait "$HOST_PID" 2>/dev/null || true
        HOST_PID=""
    fi
    rm -f "$SOCK" "$ENCLAVE_SOCK" "$PID_FILE"
    sleep 0.5
}

start_host() {
    local sandbox="${1:-0}"
    stop_host
    mkdir -p "$DATA_DIR"
    local EXTRA=("${PROD_ARGS[@]}")
    if [ "$sandbox" = "1" ]; then
        EXTRA+=(--sandbox --sandbox-wrapper "$WRAPPER")
    fi
    (
        exec "$HOST_BIN" serve \
            --sgxs "$SGXS" \
            --loader "$LOADER_BIN" \
            --socket "$SOCK" \
            --enclave-socket "$ENCLAVE_SOCK" \
            --pid "$PID_FILE" \
            --data-dir "$DATA_DIR" \
            --interval-secs 9999 \
            --initial-delay-secs 9999 \
            "${EXTRA[@]}" \
            >"$HOST_LOG" 2>&1
    ) &
    HOST_PID=$!
    disown "$HOST_PID" 2>/dev/null || true
    local WAIT=90
    while [ $WAIT -gt 0 ] && [ ! -S "$SOCK" ]; do
        sleep 0.5
        WAIT=$((WAIT - 1))
    done
    if [ ! -S "$SOCK" ]; then
        fail "Host 未就绪（sandbox=$sandbox）"
        cat "$HOST_LOG" || true
        exit 1
    fi
}

build_all() {
    info "构建 workspace（Runtime --production）..."
    if [ ! -f keys/enclave.pem ]; then
        fail "缺少 keys/enclave.pem（先: openssl genrsa -3 -out keys/enclave.pem 3072）"
        exit 1
    fi
    ./build-runtime.sh --production
    ./build-host.sh
    ./build-loader.sh
    if [ ! -f "$SGXS" ] || [ ! -f "$PROD_SIG" ] || [ ! -f "$MRE_FILE" ]; then
        fail "缺少 .sgxs / enclave.sig / enclave.mrenclave"
        exit 1
    fi
    MRE=$(tr -d ' \n' < "$MRE_FILE")
    PROD_ARGS=(--production --sig "$PROD_SIG" --expected-mrenclave "$MRE")
    MRE_ARGS=(--expected-mrenclave "$MRE")
    info "生产加载: --production --sig enclave.sig（无 DEBUG） --expected-mrenclave ${MRE:0:16}…"
}

expect_result() {
    local x=$1 y=$2
    local expected=$((x * x * x + 5 * y))
    local out actual
    out=$("$HOST_BIN" calc "$x" "$y" --socket "$SOCK" "${MRE_ARGS[@]}" 2>&1 || true)
    actual=$(echo "$out" | grep '^RESULT=' | cut -d= -f2 || true)
    if [ "$actual" = "$expected" ]; then
        pass "calc($x,$y)=$actual"
    else
        info "$out"
        fail "calc($x,$y) expected=$expected actual=${actual:-<empty>}"
    fi
}

# ─── 1. Build ───────────────────────────────────────────────
echo "===== tee-demo 集成测试 ====="
rm -rf "$RUN_DIR"
mkdir -p "$DATA_DIR"
build_all

# ─── 2. Core: challenge / calc / compute cases ───────────────
echo ""
info "==> [core] challenge + DCAP + HPKE calc"
start_host 0
sleep 1

NONCE_HEX="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
CH=$("$HOST_BIN" challenge --socket "$SOCK" --nonce "$NONCE_HEX" "${MRE_ARGS[@]}" 2>&1 || true)
if echo "$CH" | grep -q "QUOTE_VERIFY_OK" && echo "$CH" | grep -q "REPORTDATA_BINDING_OK"; then
    pass "challenge + DCAP + REPORTDATA 绑定"
else
    info "$CH"
    fail "challenge 验证失败"
fi
MRE=$(echo "$CH" | sed -n 's/^MRENCLAVE=//p' | head -1)
# 与 keys/enclave.mrenclave 对齐（build 已写入）
if [ -f "$MRE_FILE" ]; then
    MRE=$(tr -d ' \n' < "$MRE_FILE")
    MRE_ARGS=(--expected-mrenclave "$MRE")
fi

OUT=$("$HOST_BIN" calc 2 3 --socket "$SOCK" "${MRE_ARGS[@]}" 2>&1 || true)
if echo "$OUT" | grep -q "RESULT=23"; then
    pass "calc(2,3)=23（含 challenge）"
else
    info "$OUT"
    fail "calc(2,3) 失败"
fi

expect_result 0 10
expect_result -1 4
expect_result 10 20

BAD=$("$HOST_BIN" challenge --socket "$SOCK" \
    --expected-mrenclave "0000000000000000000000000000000000000000000000000000000000000000" \
    2>&1 || true)
if echo "$BAD" | grep -qi "MRENCLAVE mismatch\|错误\|failed\|Error"; then
    pass "错误 expected_mrenclave 被拒绝"
else
    info "$BAD"
    fail "错误 MRENCLAVE 未被拒绝"
fi

if [ -n "$MRE" ]; then
    GOOD=$("$HOST_BIN" challenge --socket "$SOCK" --expected-mrenclave "$MRE" 2>&1 || true)
    if echo "$GOOD" | grep -q "QUOTE_VERIFY_OK"; then
        pass "正确 expected_mrenclave 通过"
    else
        info "$GOOD"
        fail "正确 MRENCLAVE 未通过"
    fi
fi

# Host opaque 转发（代码审查）
if grep -q 'request_compute_ct' "$SCRIPT_DIR/host/src/main.rs" && \
   ! grep -A40 'fn request_compute_ct' "$SCRIPT_DIR/host/src/main.rs" | grep -qE 'req\.x\s*=|req\.y\s*='; then
    pass "Host opaque 转发（无明文 x/y）"
else
    fail "Host request_compute_ct 检查失败"
fi

# ─── 3. Sealing / rotate / restart ───────────────────────────
echo ""
info "==> [keys] sealing + rotate retention + restart"

if [ -f "$DATA_DIR/sealed_keys.bin" ] && [ -f "$DATA_DIR/keyring.json" ]; then
    pass "sealed_keys.bin + keyring.json 已生成"
else
    fail "缺少 sealed_keys / keyring"
fi

MAGIC=$(dd if="$DATA_DIR/sealed_keys.bin" bs=4 count=1 2>/dev/null | tr -d '\0' || true)
if [ "$MAGIC" = "TDK1" ]; then
    pass "sealed_keys.bin 为 TDK1 opaque blob"
else
    fail "sealed magic 不是 TDK1 (got: $MAGIC)"
fi

V1=$("$HOST_BIN" pubkey --socket "$SOCK" 2>&1 | sed -n 's/^KEY_VERSION=//p' | head -1)
"$HOST_BIN" rotate --socket "$SOCK" >/tmp/tee-test-rot1.txt 2>&1 || true
V2=$(sed -n 's/^KEY_VERSION=//p' /tmp/tee-test-rot1.txt | head -1)

KR=$(python3 - <<PY
import json
d=json.load(open("$DATA_DIR/keyring.json"))
vers=",".join(str(k["version"]) for k in sorted(d["keys"], key=lambda x: x["version"]))
print(vers)
print(d.get("current_version"))
PY
)
VERS=$(echo "$KR" | sed -n '1p')
CUR=$(echo "$KR" | sed -n '2p')
if [ "$VERS" = "$V1,$V2" ] && [ "$CUR" = "$V2" ]; then
    pass "rotate 后 keyring 保留 N-1+N ($VERS)"
else
    fail "keyring 异常 versions=$VERS current=$CUR (期望 $V1,$V2 / $V2)"
fi

"$HOST_BIN" rotate --socket "$SOCK" >/tmp/tee-test-rot2.txt 2>&1 || true
V3=$(sed -n 's/^KEY_VERSION=//p' /tmp/tee-test-rot2.txt | head -1)
HAS_V1=$(python3 - <<PY
import json
d=json.load(open("$DATA_DIR/keyring.json"))
print(any(k["version"]==int("$V1") for k in d["keys"]))
print(",".join(str(k["version"]) for k in sorted(d["keys"], key=lambda x: x["version"])))
print(d.get("current_version"))
PY
)
if [ "$(echo "$HAS_V1" | sed -n '1p')" = "False" ] && \
   [ "$(echo "$HAS_V1" | sed -n '2p')" = "$V2,$V3" ]; then
    pass "再 rotate 后淘汰 N-2；保留 $V2,$V3"
else
    fail "淘汰失败: $HAS_V1"
fi

expect_result 2 3

info "重启 Host，验证 unseal..."
stop_host
start_host 0
sleep 1
expect_result 1 1

# ─── 4. One-shot attest ─────────────────────────────────────
echo ""
info "==> [attest] 一次性 attest 命令"
stop_host
ATT=$("$HOST_BIN" attest --nonce "e2e-attest-nonce" \
    --sgxs "$SGXS" --loader "$LOADER_BIN" \
    --enclave-socket "$RUN_DIR/attest-enclave.sock" \
    --data-dir "$RUN_DIR/attest-data" \
    "${PROD_ARGS[@]}" \
    2>&1 || true)
if echo "$ATT" | grep -q "QUOTE_VERIFY_OK" && echo "$ATT" | grep -q "REPORTDATA_BINDING_OK"; then
    pass "host attest + Quote/REPORTDATA OK"
else
    info "$ATT"
    fail "host attest 失败"
fi

# ─── 5. Sandbox（可选）──────────────────────────────────────
echo ""
if command -v bwrap >/dev/null 2>&1; then
    info "==> [sandbox] bwrap"
    chmod +x "$WRAPPER"
    rm -rf "$RUN_DIR/sandbox"
    DATA_DIR="$RUN_DIR/sandbox"
    SOCK="$DATA_DIR/client.sock"
    ENCLAVE_SOCK="$DATA_DIR/enclave.sock"
    PID_FILE="$DATA_DIR/tee.pid"
    HOST_LOG="$DATA_DIR/host.log"
    mkdir -p "$DATA_DIR"
    start_host 1
    if grep -qE '沙箱启动 Loader|sandbox: bwrap' "$HOST_LOG"; then
        pass "沙箱模式启动 Loader"
    else
        fail "未看到沙箱启动日志"
    fi
    expect_result 2 3

    CANDS=()
    for cand in $(pgrep -P "$HOST_PID" 2>/dev/null || true); do
        CANDS+=("$cand")
        for gchild in $(pgrep -P "$cand" 2>/dev/null || true); do
            CANDS+=("$gchild")
        done
    done
    FOUND_MNT=0
    FOUND_NET=0
    for pid in "${CANDS[@]:-}"; do
        [ -r "/proc/$pid/ns/mnt" ] || continue
        cmd=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)
        case "$cmd" in
            *bwrap*|*tee-demo-loader*) ;;
            *) continue ;;
        esac
        if [ "$(readlink /proc/$$/ns/mnt)" != "$(readlink /proc/$pid/ns/mnt)" ]; then
            FOUND_MNT=1
        fi
        if [ "$(readlink /proc/$$/ns/net)" != "$(readlink /proc/$pid/ns/net)" ]; then
            FOUND_NET=1
        fi
    done
    [ "$FOUND_MNT" = "1" ] && pass "loader/bwrap 独立 mount ns" || fail "未发现独立 mount ns"
    [ "$FOUND_NET" = "1" ] && pass "loader/bwrap 独立 net ns" || fail "未发现独立 net ns"
    stop_host
else
    info "==> [sandbox] 跳过（未安装 bwrap）"
fi

# ─── Summary ────────────────────────────────────────────────
echo ""
echo "===== 结果汇总 ====="
echo -e "通过: ${GREEN}${PASS}${NC}  失败: ${RED}${FAIL}${NC}"
[ "$FAIL" -eq 0 ] && echo -e "${GREEN}全部通过${NC}" && exit 0 || exit 1
