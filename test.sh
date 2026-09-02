#!/usr/bin/env bash
# 功能验证：确认常驻 TEE 输出符合 x^3 + 5*y
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

pass=0
fail=0

cleanup() {
    ./daemon.sh stop >/dev/null 2>&1 || true
}
trap cleanup EXIT

run_case() {
    local x=$1 y=$2
    local expected=$((x * x * x + 5 * y))
    local output
    output=$(./client.sh "$x" "$y")
    local actual
    actual=$(echo "$output" | grep '^RESULT=' | cut -d= -f2)

    if [ "$actual" = "$expected" ]; then
        echo "PASS  x=$x y=$y  expected=$expected  actual=$actual"
        pass=$((pass + 1))
    else
        echo "FAIL  x=$x y=$y  expected=$expected  actual=$actual"
        fail=$((fail + 1))
    fi
}

echo "==> 构建并启动常驻 TEE..."
./daemon.sh stop >/dev/null 2>&1 || true
./daemon.sh start

echo ""
echo "==> 运行测试用例..."
run_case 2 3
run_case 0 10
run_case -1 4
run_case 10 20

echo ""
echo "结果: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
