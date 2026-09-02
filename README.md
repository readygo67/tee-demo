# tee-demo

在 Intel SGX Enclave（可信执行环境）中计算 `x^3 + 5*y`。Enclave **长期驻留**于 TEE 中，通过守护进程接收多次计算请求。

## 架构

```
client.sh ──> Unix Socket ──> tee-demo-host (Host 守护进程，监听)
                                  │
                                  │ Unix Socket（Host 监听，loader 连接）
                                  ▼
                           tee-demo-loader（enclave-runner）
                                  │ usercall: worker-host → Host Socket
                                  ▼
                           SGX Enclave（connect worker-host）
                                  │
                                  ▼
                           compute(x, y) = x³ + 5y
```

## 前置条件

```bash
# Intel SGX 设备
ls /dev/sgx_enclave

# Rust SGX 目标
rustup target add x86_64-fortanix-unknown-sgx

# Fortanix SGX 运行工具
cargo install fortanix-sgx-tools
```

## 使用步骤

### 步骤 1：编译

```bash
chmod +x build.sh build-host.sh build-loader.sh daemon.sh client.sh test.sh
./build.sh release      # 编译 Enclave
./build-host.sh         # 编译 Host 守护进程
./build-loader.sh       # 编译 SGX loader
```

产物：

```
target/x86_64-fortanix-unknown-sgx/release/tee-demo.sgxs              # SGX Enclave
host/target/x86_64-unknown-linux-gnu/release/tee-demo-host           # Host 守护进程
loader/target/x86_64-unknown-linux-gnu/release/tee-demo-loader       # SGX loader
```

### 步骤 2：启动常驻 TEE

```bash
./daemon.sh start
```

Enclave 加载进 TEE 后持续运行，等待请求。

### 步骤 3：发送参数并获取结果

```bash
./client.sh 2 3
# TEE 计算结果: 2^3 + 5*3 = 23
# RESULT=23

./client.sh 10 20
# TEE 计算结果: 10^3 + 5*20 = 1100
# RESULT=1100
```

提取结果：

```bash
result=$(./client.sh 2 3 | grep '^RESULT=' | cut -d= -f2)
echo "result=$result"
```

### 步骤 4：停止

```bash
./daemon.sh status   # 查看运行状态
./daemon.sh stop     # 停止守护进程，卸载 Enclave
```

## 一键测试

```bash
./test.sh
```

或使用 Makefile：

```bash
make build   # 编译 Enclave + Host
make start   # 启动常驻 TEE
make run     # 发送示例请求 (2, 3)
make test    # 自动启动、测试、停止
make stop    # 停止守护进程
```

## 示例

| x | y | x³ + 5y |
|---|---|---------|
| 2 | 3 | 23      |
| 0 | 10| 50      |
| -1| 4 | 19      |
| 10| 20| 1100    |

## 项目结构

```
tee-demo/
├── .cargo/config.toml   # SGX 编译目标配置
├── src/main.rs          # TEE 内计算逻辑（常驻循环）
├── host/                # Host 守护进程（原生 Linux）
│   └── src/main.rs
├── loader/              # SGX loader（loader 连接 Host 监听的 socket）
│   └── src/main.rs
├── build.sh             # 编译 Enclave
├── build-host.sh        # 编译 Host 守护进程
├── build-loader.sh      # 编译 SGX loader
├── daemon.sh            # 启动/停止/状态
├── client.sh            # 发送计算请求
├── test.sh              # 功能验证
├── Makefile
└── README.md
```
