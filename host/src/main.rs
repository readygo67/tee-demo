use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DEFAULT_SOCK: &str = "/tmp/tee-demo.sock";
const DEFAULT_ENCLAVE_SOCK: &str = "/tmp/tee-demo-enclave.sock";
const DEFAULT_PID: &str = "/tmp/tee-demo.pid";
const LOADER_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

struct EnclaveConnection {
    stream: UnixStream,
    child: Child,
}

impl EnclaveConnection {
    fn start(sgxs: &Path, enclave_sock: &Path, loader_bin: &Path) -> std::io::Result<Self> {
        if enclave_sock.exists() {
            fs::remove_file(enclave_sock)?;
        }

        let listener = UnixListener::bind(enclave_sock)?;
        listener
            .set_nonblocking(true)
            .map_err(|err| std::io::Error::other(format!("设置非阻塞失败: {err}")))?;

        eprintln!(
            "==> 等待 Enclave 通过 worker-host 连接: {}",
            enclave_sock.display()
        );

        let mut child = Command::new(loader_bin)
            .arg("--host-socket")
            .arg(enclave_sock)
            .arg(sgxs)
            .spawn()?;

        let deadline = std::time::Instant::now() + LOADER_CONNECT_TIMEOUT;
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if child.try_wait()?.is_some() {
                        return Err(std::io::Error::other(format!(
                            "loader 提前退出: {}",
                            child.id()
                        )));
                    }
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "等待 loader 连接超时",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(err) => return Err(err),
            }
        };

        stream.set_nonblocking(false)?;
        eprintln!("==> Enclave 已通过 worker-host 连接");

        Ok(Self { stream, child })
    }

    fn compute(&mut self, x: i64, y: i64) -> std::io::Result<i64> {
        let mut reader = BufReader::new(self.stream.try_clone()?);
        writeln!(self.stream, "{x} {y}")?;
        self.stream.flush()?;

        let mut line = String::new();
        loop {
            line.clear();
            reader.read_line(&mut line)?;
            if line.starts_with("RESULT=") {
                return line
                    .trim()
                    .strip_prefix("RESULT=")
                    .unwrap_or("")
                    .parse()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e));
            }
            if line.starts_with("ERROR=") {
                return Err(std::io::Error::other(line.trim()));
            }
        }
    }

    fn shutdown(&mut self) -> std::io::Result<()> {
        let _ = writeln!(self.stream, "quit");
        let _ = self.stream.flush();
        let _ = self.child.wait();
        Ok(())
    }
}

fn project_root() -> PathBuf {
    env::var("TEE_PROJECT_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("parent")
                .to_path_buf()
        })
}

fn default_sgxs() -> PathBuf {
    project_root().join("target/x86_64-fortanix-unknown-sgx/release/tee-demo.sgxs")
}

fn default_loader() -> PathBuf {
    project_root().join("loader/target/x86_64-unknown-linux-gnu/release/tee-demo-loader")
}

fn usage() {
    eprintln!("用法:");
    eprintln!("  tee-demo-host serve [--sgxs PATH] [--loader PATH] [--socket PATH] [--enclave-socket PATH]");
    eprintln!("  tee-demo-host calc <x> <y> [--socket PATH]");
    eprintln!("  tee-demo-host stop [--socket PATH] [--enclave-socket PATH] [--pid PATH]");
}

fn write_pid(pid_path: &Path) -> std::io::Result<()> {
    fs::write(pid_path, std::process::id().to_string())
}

fn read_pid(pid_path: &Path) -> std::io::Result<u32> {
    fs::read_to_string(pid_path)?
        .trim()
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn is_running(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn handle_client(
    mut stream: UnixStream,
    enclave: Arc<Mutex<EnclaveConnection>>,
) -> std::io::Result<()> {
    let mut req = String::new();
    stream.read_to_string(&mut req)?;
    let parts: Vec<&str> = req.split_whitespace().collect();
    if parts.len() != 2 {
        writeln!(stream, "ERROR=bad_input")?;
        return Ok(());
    }

    let x: i64 = parts[0]
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let y: i64 = parts[1]
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let result = {
        let mut enclave = enclave.lock().unwrap();
        enclave.compute(x, y)?
    };

    writeln!(stream, "RESULT={result}")?;
    stream.shutdown(Shutdown::Both)?;
    Ok(())
}

fn cmd_serve(
    sgxs: PathBuf,
    loader_bin: PathBuf,
    socket_path: PathBuf,
    enclave_sock: PathBuf,
    pid_path: PathBuf,
) -> std::io::Result<()> {
    if socket_path.exists() {
        return Err(std::io::Error::other(format!(
            "socket 已存在: {}，请先 stop",
            socket_path.display()
        )));
    }
    if !loader_bin.exists() {
        return Err(std::io::Error::other(format!(
            "loader 未编译: {}，请先运行 ./build-loader.sh",
            loader_bin.display()
        )));
    }

    eprintln!("==> 加载 Enclave 到 TEE（Host 监听模式）: {}", sgxs.display());
    let enclave = EnclaveConnection::start(&sgxs, &enclave_sock, &loader_bin)?;
    let enclave = Arc::new(Mutex::new(enclave));

    write_pid(&pid_path)?;
    eprintln!("==> TEE 守护进程已启动，pid={}", std::process::id());
    eprintln!("==> 客户端 socket: {}", socket_path.display());
    eprintln!("==> Enclave socket: {}", enclave_sock.display());

    let listener = UnixListener::bind(&socket_path)?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let enclave = Arc::clone(&enclave);
                if let Err(err) = handle_client(stream, enclave) {
                    eprintln!("处理请求失败: {err}");
                }
            }
            Err(err) => eprintln!("accept 失败: {err}"),
        }
    }

    let mut enclave = enclave.lock().unwrap();
    enclave.shutdown()?;
    let _ = fs::remove_file(&socket_path);
    let _ = fs::remove_file(&enclave_sock);
    let _ = fs::remove_file(&pid_path);
    Ok(())
}

fn cmd_calc(x: i64, y: i64, socket_path: PathBuf) -> std::io::Result<()> {
    let mut stream = UnixStream::connect(&socket_path)?;
    write!(stream, "{x} {y}")?;
    stream.shutdown(Shutdown::Write)?;

    let mut resp = String::new();
    stream.read_to_string(&mut resp)?;
    for line in resp.lines() {
        if let Some(value) = line.strip_prefix("RESULT=") {
            println!("TEE 计算结果: {x}^3 + 5*{y} = {value}");
            println!("RESULT={value}");
            return Ok(());
        }
        if line.starts_with("ERROR=") {
            return Err(std::io::Error::other(line));
        }
    }
    Err(std::io::Error::other("未收到 RESULT"))
}

fn cmd_stop(socket_path: PathBuf, enclave_sock: PathBuf, pid_path: PathBuf) -> std::io::Result<()> {
    if pid_path.exists() {
        let pid = read_pid(&pid_path)?;
        if is_running(pid) {
            Command::new("kill").arg(pid.to_string()).status()?;
            eprintln!("==> 已发送 SIGTERM 到 pid={pid}");
        }
        let _ = fs::remove_file(&pid_path);
    }
    if socket_path.exists() {
        let _ = fs::remove_file(&socket_path);
    }
    if enclave_sock.exists() {
        let _ = fs::remove_file(&enclave_sock);
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
        std::process::exit(1);
    }

    let mut sgxs = default_sgxs();
    let mut loader_bin = default_loader();
    let mut socket_path = PathBuf::from(DEFAULT_SOCK);
    let mut enclave_sock = PathBuf::from(DEFAULT_ENCLAVE_SOCK);
    let mut pid_path = PathBuf::from(DEFAULT_PID);

    let cmd = args[1].as_str();
    match cmd {
        "serve" => {
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--sgxs" => {
                        i += 1;
                        sgxs = PathBuf::from(&args[i]);
                    }
                    "--loader" => {
                        i += 1;
                        loader_bin = PathBuf::from(&args[i]);
                    }
                    "--socket" => {
                        i += 1;
                        socket_path = PathBuf::from(&args[i]);
                    }
                    "--enclave-socket" => {
                        i += 1;
                        enclave_sock = PathBuf::from(&args[i]);
                    }
                    "--pid" => {
                        i += 1;
                        pid_path = PathBuf::from(&args[i]);
                    }
                    other => {
                        eprintln!("未知参数: {other}");
                        usage();
                        std::process::exit(1);
                    }
                }
                i += 1;
            }
            if let Err(err) = cmd_serve(sgxs, loader_bin, socket_path, enclave_sock, pid_path) {
                eprintln!("启动失败: {err}");
                std::process::exit(1);
            }
        }
        "calc" => {
            if args.len() != 4 {
                usage();
                std::process::exit(1);
            }
            let x: i64 = args[2].parse().expect("x 必须是整数");
            let y: i64 = args[3].parse().expect("y 必须是整数");
            let mut i = 4;
            while i < args.len() {
                if args[i] == "--socket" {
                    i += 1;
                    socket_path = PathBuf::from(&args[i]);
                }
                i += 1;
            }
            if let Err(err) = cmd_calc(x, y, socket_path) {
                eprintln!("计算失败: {err}");
                std::process::exit(1);
            }
        }
        "stop" => {
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--socket" => {
                        i += 1;
                        socket_path = PathBuf::from(&args[i]);
                    }
                    "--enclave-socket" => {
                        i += 1;
                        enclave_sock = PathBuf::from(&args[i]);
                    }
                    "--pid" => {
                        i += 1;
                        pid_path = PathBuf::from(&args[i]);
                    }
                    other => {
                        eprintln!("未知参数: {other}");
                        usage();
                        std::process::exit(1);
                    }
                }
                i += 1;
            }
            if let Err(err) = cmd_stop(socket_path, enclave_sock, pid_path) {
                eprintln!("停止失败: {err}");
                std::process::exit(1);
            }
        }
        _ => {
            usage();
            std::process::exit(1);
        }
    }
}
