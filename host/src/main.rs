//! Host daemon: Client nonce challenge + DCAP verify + AEAD calc.
//!
//! - `challenge` / `calc`: Client nonce → runtime.AttestationRequest
//! - dcap-qvl verify + REPORTDATA binding before accepting public_key
//! - `calc` always verifies Quote then HPKE-encrypts inputs

use std::fs;
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use tee_demo_protocol::{
    aead, b64_decode, b64_encode, read_frame, report_data_binding, write_frame, Frame,
    CHALLENGE_NONCE_LEN, OP_CLIENT_CHALLENGE, OP_CLIENT_COMPUTE, OP_CLIENT_PUBKEY,
    OP_CLIENT_ROTATE, OP_HOST_ATTESTATION_RESPONSE, OP_HOST_CHALLENGE_RESULT,
    OP_HOST_COMPUTE_RESPONSE, OP_HOST_COMPUTE_RESULT, OP_HOST_PUBKEY_RESULT,
    OP_HOST_ROTATE_RESPONSE, OP_HOST_ROTATE_RESULT, OP_RUNTIME_ATTESTATION_REQUEST,
    OP_RUNTIME_COMPUTE_REQUEST, OP_RUNTIME_ROTATE_REQUEST,
};

const DEFAULT_SOCK: &str = "/tmp/tee-demo.sock";
const DEFAULT_ENCLAVE_SOCK: &str = "/tmp/tee-demo-enclave.sock";
const DEFAULT_PID: &str = "/tmp/tee-demo.pid";
const LOADER_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

// PR-2 默认参数（§三）
const DEFAULT_INTERVAL_SECS: u64 = 3600;
const DEFAULT_INITIAL_DELAY_SECS: u64 = 0;

struct LoaderConfig {
    production: bool,
    sig: Option<PathBuf>,
    expected_mrenclave: Option<String>,
    data_dir: PathBuf,
    /// PR-4: spawn loader via bwrap wrapper
    sandbox: bool,
    sandbox_wrapper: PathBuf,
}

impl LoaderConfig {
    #[allow(dead_code)]
    fn dev() -> Self {
        Self {
            production: false,
            sig: None,
            expected_mrenclave: None,
            data_dir: PathBuf::from("/tmp/tee-demo-data"),
            sandbox: false,
            sandbox_wrapper: default_sandbox_wrapper(),
        }
    }
}

/// Host 侧缓存的最新 attestation bundle（不可信，仅运维用）
#[derive(Clone, Default)]
struct AttestationBundle {
    attested_at: u64,
    key_version: u64,
    public_key: Option<String>,
    quote: Option<String>,
    binding_nonce: Option<String>,
    report_data: Option<String>,
}

impl AttestationBundle {
    fn from_frame(frame: &Frame) -> Self {
        Self {
            attested_at: frame.attested_at.unwrap_or(0),
            key_version: frame.key_version.unwrap_or(0),
            public_key: frame.public_key.clone(),
            quote: frame.quote.clone(),
            binding_nonce: frame.binding_nonce.clone(),
            report_data: frame.report_data.clone(),
        }
    }
}

struct RuntimeConnection {
    stream: UnixStream,
    child: Child,
    next_id: u64,
    /// 最新 attestation bundle（ComputeRequest 触发补做时同步更新）
    latest_bundle: AttestationBundle,
}

impl RuntimeConnection {
    fn start(sgxs: &Path, runtime_sock: &Path, loader_bin: &Path, loader_cfg: &LoaderConfig) -> Result<Self> {
        if runtime_sock.exists() {
            fs::remove_file(runtime_sock)?;
        }

        let listener = UnixListener::bind(runtime_sock).context("bind runtime socket")?;
        listener
            .set_nonblocking(true)
            .map_err(|e| anyhow!("set_nonblocking: {e}"))?;

        eprintln!("==> 等待 Loader 连接 host leg: {}", runtime_sock.display());

        let mut child = if loader_cfg.sandbox {
            let wrapper = &loader_cfg.sandbox_wrapper;
            if !wrapper.exists() {
                return Err(anyhow!(
                    "sandbox wrapper missing: {} (disable with --sandbox=false)",
                    wrapper.display()
                ));
            }
            let run_dir = runtime_sock
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| loader_cfg.data_dir.clone());
            let mut cmd = Command::new(wrapper);
            cmd.env("LOADER", loader_bin);
            cmd.env("HOST_SOCK", runtime_sock);
            cmd.env("SGXS", sgxs);
            cmd.env("DATA_DIR", &loader_cfg.data_dir);
            cmd.env("RUN_DIR", &run_dir);
            cmd.env("TEE_ROOT", project_root());
            cmd.env(
                "PRODUCTION",
                if loader_cfg.production { "1" } else { "0" },
            );
            if let Some(sig) = &loader_cfg.sig {
                cmd.env("SIG", sig);
            }
            if let Some(mre) = &loader_cfg.expected_mrenclave {
                cmd.env("EXPECTED_MRENCLAVE", mre);
            }
            eprintln!(
                "==> 沙箱启动 Loader: {} (wrapper={})",
                loader_bin.display(),
                wrapper.display()
            );
            cmd.spawn()
                .with_context(|| format!("spawn sandbox wrapper: {}", wrapper.display()))?
        } else {
            let mut cmd = Command::new(loader_bin);
            cmd.arg("--host-socket").arg(runtime_sock);
            cmd.arg("--data-dir").arg(&loader_cfg.data_dir);
            if loader_cfg.production {
                cmd.arg("--production");
                if let Some(sig) = &loader_cfg.sig {
                    cmd.arg("--sig").arg(sig);
                }
                if let Some(mre) = &loader_cfg.expected_mrenclave {
                    cmd.arg("--expected-mrenclave").arg(mre);
                }
            }
            cmd.arg(sgxs);
            eprintln!("==> 直接启动 Loader: {}", loader_bin.display());
            cmd.spawn()
                .with_context(|| format!("spawn loader: {}", loader_bin.display()))?
        };

        let deadline = Instant::now() + LOADER_CONNECT_TIMEOUT;
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if child.try_wait()?.is_some() {
                        return Err(anyhow!("loader exited early"));
                    }
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        return Err(anyhow!("timeout waiting for loader host leg"));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(err) => return Err(err.into()),
            }
        };

        stream.set_nonblocking(false)?;
        eprintln!("==> Runtime host leg connected");

        // Wait until Runtime finishes KeyStore bootstrap (host.Ready).
        let ready = read_frame(&mut stream).map_err(|e| anyhow!("wait host.Ready: {e}"))?;
        if ready.op != tee_demo_protocol::OP_HOST_READY {
            return Err(anyhow!("expected host.Ready, got {}", ready.op));
        }
        let latest_bundle = AttestationBundle::from_frame(&ready);
        eprintln!(
            "==> Runtime ready (key_version={:?})",
            latest_bundle.key_version
        );

        Ok(Self {
            stream,
            child,
            next_id: 0,
            latest_bundle,
        })
    }

    fn next_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// 发 AttestationRequest，等待 AttestationResponse，更新缓存并返回帧。
    fn request_attestation(&mut self, nonce: Option<&[u8]>) -> Result<Frame> {
        let id = self.next_id();
        let mut req = Frame::new(OP_RUNTIME_ATTESTATION_REQUEST);
        req.id = Some(id);
        if let Some(n) = nonce {
            req.nonce = Some(b64_encode(n));
        }
        write_frame(&mut self.stream, &req).map_err(|e| anyhow!(e))?;

        // 等待响应；理论上只有一个 in-flight，直接读下一帧
        let resp = read_frame(&mut self.stream).map_err(|e| anyhow!(e))?;
        if resp.op != OP_HOST_ATTESTATION_RESPONSE {
            return Err(anyhow!("unexpected op: {}", resp.op));
        }
        if resp.id != Some(id) {
            return Err(anyhow!("attestation response id mismatch (got {:?}, want {id})", resp.id));
        }
        if resp.ok != Some(true) {
            return Err(anyhow!("attestation failed: {}", resp.error.unwrap_or_default()));
        }
        self.latest_bundle = AttestationBundle::from_frame(&resp);
        Ok(resp)
    }

    /// 发 ComputeRequest。
    /// Runtime 在 stale 时会先发一个无 id 的 `host.AttestationResponse`（补做），
    /// 再发 `host.ComputeResponse`。Host 必须识别并处理。
    fn request_compute(&mut self, x: i64, y: i64) -> Result<i64> {
        let id = self.next_id();
        let mut req = Frame::new(OP_RUNTIME_COMPUTE_REQUEST);
        req.id = Some(id);
        req.x = Some(x);
        req.y = Some(y);
        write_frame(&mut self.stream, &req).map_err(|e| anyhow!(e))?;

        loop {
            let resp = read_frame(&mut self.stream).map_err(|e| anyhow!(e))?;
            match resp.op.as_str() {
                OP_HOST_ATTESTATION_RESPONSE => {
                    // Runtime 补做的 attestation（id 为 None 或不匹配）
                    eprintln!(
                        "==> 收到 Runtime 补做 AttestationResponse (attested_at={:?}, key_version={:?})",
                        resp.attested_at, resp.key_version
                    );
                    self.latest_bundle = AttestationBundle::from_frame(&resp);
                    // 继续等 ComputeResponse
                }
                OP_HOST_COMPUTE_RESPONSE => {
                    if resp.id != Some(id) {
                        return Err(anyhow!("compute response id mismatch"));
                    }
                    if resp.ok != Some(true) {
                        return Err(anyhow!("compute failed: {}", resp.error.unwrap_or_default()));
                    }
                    return resp.result.ok_or_else(|| anyhow!("missing result"));
                }
                other => {
                    return Err(anyhow!("unexpected op during compute: {other}"));
                }
            }
        }
    }

    /// PR-3a: opaque 转发——Host 直接把 client 的 ct/key_version 转给 Runtime，不解密。
    /// 返回 (result, code, error)；Host 路径上看不到明文 x/y。
    fn request_compute_ct(
        &mut self,
        client_id: u64,
        ct: &str,
        aad_json: &str,
        key_version: u64,
    ) -> Result<Frame> {
        let id = self.next_id();
        let mut req = Frame::new(OP_RUNTIME_COMPUTE_REQUEST);
        req.id = Some(id);
        // PR-3a: opaque 字段；Host 不可见明文
        req.ct = Some(ct.to_owned());
        req.aad_json = Some(aad_json.to_owned());
        req.key_version = Some(key_version);
        write_frame(&mut self.stream, &req).map_err(|e| anyhow!(e))?;

        loop {
            let resp = read_frame(&mut self.stream).map_err(|e| anyhow!(e))?;
            match resp.op.as_str() {
                OP_HOST_ATTESTATION_RESPONSE => {
                    eprintln!(
                        "==> [CT] 收到 Runtime 补做 AttestationResponse (attested_at={:?})",
                        resp.attested_at
                    );
                    self.latest_bundle = AttestationBundle::from_frame(&resp);
                }
                OP_HOST_COMPUTE_RESPONSE => {
                    if resp.id != Some(id) {
                        return Err(anyhow!("compute_ct response id mismatch"));
                    }
                    // 构造 client 响应帧（id 回填 client_id）
                    let mut out = resp.clone();
                    out.id = Some(client_id);
                    return Ok(out);
                }
                other => return Err(anyhow!("unexpected op during compute_ct: {other}")),
            }
        }
    }

    fn request_rotate(&mut self) -> Result<Frame> {
        let id = self.next_id();
        let mut req = Frame::new(OP_RUNTIME_ROTATE_REQUEST);
        req.id = Some(id);
        write_frame(&mut self.stream, &req).map_err(|e| anyhow!(e))?;
        loop {
            let resp = read_frame(&mut self.stream).map_err(|e| anyhow!(e))?;
            match resp.op.as_str() {
                OP_HOST_ATTESTATION_RESPONSE => {
                    // PR-3c: rotate 后先到的绑定 Quote
                    eprintln!(
                        "==> [rotate] AttestationResponse key_version={:?} (REPORTDATA-bound)",
                        resp.key_version
                    );
                    self.latest_bundle = AttestationBundle::from_frame(&resp);
                }
                OP_HOST_ROTATE_RESPONSE => {
                    if resp.id != Some(id) {
                        return Err(anyhow!("rotate response id mismatch"));
                    }
                    if resp.ok != Some(true) {
                        return Err(anyhow!("rotate failed: {}", resp.error.unwrap_or_default()));
                    }
                    // Prefer quote-bearing fields on RotateResponse if present
                    if resp.quote.is_some() {
                        self.latest_bundle = AttestationBundle::from_frame(&resp);
                    } else {
                        self.latest_bundle.key_version = resp.key_version.unwrap_or(0);
                        self.latest_bundle.public_key = resp.public_key.clone();
                    }
                    return Ok(resp);
                }
                other => return Err(anyhow!("unexpected op during rotate: {other}")),
            }
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        Ok(())
    }
}

fn project_root() -> PathBuf {
    std::env::var("TEE_PROJECT_ROOT")
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
    project_root().join("target/x86_64-unknown-linux-gnu/release/tee-demo-loader")
}

fn default_sandbox_wrapper() -> PathBuf {
    project_root().join("deploy/loader-sandbox.sh")
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

/// PR-3a: client.sock 改为 JSON 帧协议。
///
/// Client 发送 JSON 帧（Length-prefixed）；Host 根据 `op` 分发：
/// - `"compute"`: 读取 `ct`/`key_version`/`aad_json`，opaque 转发给 Runtime
/// - `"pubkey"`: 返回缓存的 latest_bundle 里的 public_key
///
/// Host 路径上**不解密 ct**；result 明文返回 Client。
fn handle_client(stream: UnixStream, runtime: Arc<Mutex<RuntimeConnection>>) -> Result<()> {
    use std::io::BufReader;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;

    // 读一帧
    let req = tee_demo_protocol::read_frame(&mut reader).map_err(|e| anyhow!(e))?;
    let client_id = req.id.unwrap_or(0);

    match req.op.as_str() {
        OP_CLIENT_COMPUTE => {
            let ct = req.ct.as_deref().ok_or_else(|| anyhow!("missing ct"))?;
            let key_version = req.key_version.unwrap_or(1);

            // AAD = {v, id, op, key_version} — Client 构造并与 ct 一起发来
            // Host 原样转发；Runtime 用 AAD 做 AEAD 验证
            let aad_json = req.aad_json.clone().unwrap_or_else(|| {
                // 若 Client 未发 aad_json，Host 按规范重建（不可信，仅 spike 兼容）
                format!(
                    r#"{{"v":{v},"id":{id},"op":"{op}","key_version":{kv}}}"#,
                    v = req.v,
                    id = client_id,
                    op = OP_CLIENT_COMPUTE,
                    kv = key_version,
                )
            });

            let resp_frame = {
                let mut rt = runtime.lock().unwrap();
                rt.request_compute_ct(client_id, ct, &aad_json, key_version)?
            };

            // 向 Client 回复 compute_result 帧
            let mut out = Frame::new(OP_HOST_COMPUTE_RESULT);
            out.id = Some(client_id);
            if resp_frame.ok == Some(true) {
                out.ok = Some(true);
                out.result = resp_frame.result;
                out.status = Some("ok".into());
            } else {
                out.ok = Some(false);
                out.status = Some("error".into());
                out.code = resp_frame.code;
                out.error = resp_frame.error;
            }
            write_frame(&mut writer, &out).map_err(|e| anyhow!(e))?;
        }
        OP_CLIENT_CHALLENGE => {
            // PR-3d: Client 提供 nonce，Host 转发 runtime.AttestationRequest
            let nonce = match req.nonce.as_deref() {
                Some(n) => b64_decode(n).map_err(|e| anyhow!(e))?,
                None => {
                    let mut out = Frame::new(OP_HOST_CHALLENGE_RESULT);
                    out.id = Some(client_id);
                    out.ok = Some(false);
                    out.error = Some("missing nonce".into());
                    write_frame(&mut writer, &out).map_err(|e| anyhow!(e))?;
                    return Ok(());
                }
            };
            let resp_frame = {
                let mut rt = runtime.lock().unwrap();
                rt.request_attestation(Some(&nonce))?
            };
            let mut out = Frame::new(OP_HOST_CHALLENGE_RESULT);
            out.id = Some(client_id);
            out.ok = Some(true);
            out.key_version = resp_frame.key_version;
            out.public_key = resp_frame.public_key;
            out.quote = resp_frame.quote;
            out.binding_nonce = resp_frame.binding_nonce;
            out.report_data = resp_frame.report_data;
            out.attested_at = resp_frame.attested_at;
            write_frame(&mut writer, &out).map_err(|e| anyhow!(e))?;
        }
        OP_CLIENT_PUBKEY => {
            let bundle = {
                let mut rt = runtime.lock().unwrap();
                // Prefer Quote-bound pubkey; if never attested, trigger one
                if rt.latest_bundle.quote.is_none() {
                    let _ = rt.request_attestation(Some(b"pubkey-attest-nonce"))?;
                }
                rt.latest_bundle.clone()
            };
            let mut out = Frame::new(OP_HOST_PUBKEY_RESULT);
            out.id = Some(client_id);
            out.ok = Some(true);
            out.key_version = Some(bundle.key_version);
            out.public_key = bundle.public_key;
            out.attested_at = Some(bundle.attested_at);
            out.quote = bundle.quote;
            out.binding_nonce = bundle.binding_nonce;
            out.report_data = bundle.report_data;
            write_frame(&mut writer, &out).map_err(|e| anyhow!(e))?;
        }
        OP_CLIENT_ROTATE => {
            let resp_frame = {
                let mut rt = runtime.lock().unwrap();
                rt.request_rotate()?
            };
            let mut out = Frame::new(OP_HOST_ROTATE_RESULT);
            out.id = Some(client_id);
            out.ok = Some(true);
            out.key_version = resp_frame.key_version;
            out.public_key = resp_frame.public_key;
            out.quote = resp_frame.quote;
            out.binding_nonce = resp_frame.binding_nonce;
            out.report_data = resp_frame.report_data;
            out.attested_at = resp_frame.attested_at;
            write_frame(&mut writer, &out).map_err(|e| anyhow!(e))?;
        }
        other => {
            let mut out = Frame::new("error");
            out.id = Some(client_id);
            out.ok = Some(false);
            out.error = Some(format!("unsupported client op: {other}"));
            write_frame(&mut writer, &out).map_err(|e| anyhow!(e))?;
        }
    }
    Ok(())
}

/// PR-2/3d: DCAP verify + REPORTDATA 绑定校验（§5.5）
async fn verify_attestation_frame(
    resp: &Frame,
    client_nonce: Option<&[u8]>,
    expected_mrenclave: Option<&str>,
) -> Result<()> {
    let quote_b64 = resp.quote.as_deref().ok_or_else(|| anyhow!("missing quote"))?;
    let pk_b64 = resp
        .public_key
        .as_deref()
        .ok_or_else(|| anyhow!("missing public_key"))?;
    let kv = resp.key_version.unwrap_or(0);
    let binding = resp
        .binding_nonce
        .as_deref()
        .ok_or_else(|| anyhow!("missing binding_nonce"))?;

    let nonce_owned;
    let nonce: &[u8] = if let Some(n) = client_nonce {
        n
    } else {
        nonce_owned = b64_decode(binding).map_err(|e| anyhow!(e))?;
        &nonce_owned
    };

    let verified = tee_demo_protocol::verify::verify_attestation(
        quote_b64,
        pk_b64,
        kv,
        nonce,
        binding,
        expected_mrenclave,
    )
    .await
    .map_err(|e| anyhow!("{e}"))?;

    let mrenclave = tee_demo_protocol::verify::mrenclave_hex(&verified)
        .ok_or_else(|| anyhow!("no SGX enclave report"))?;
    let report_data_b64 = tee_demo_protocol::verify::report_data_b64(&verified)
        .ok_or_else(|| anyhow!("no report_data"))?;

    println!("MRENCLAVE={mrenclave}");
    println!("REPORTDATA={report_data_b64}");
    println!("KEY_VERSION={kv}");
    println!("PUBLIC_KEY={pk_b64}");
    println!("REPORTDATA_BINDING_OK");
    println!("QUOTE_VERIFY_OK");
    Ok(())
}

fn random_challenge_nonce() -> [u8; CHALLENGE_NONCE_LEN] {
    let mut nonce = [0u8; CHALLENGE_NONCE_LEN];
    // getrandom via OsRng path used by hpke; fall back to time-based if needed
    if getrandom_fill(&mut nonce).is_err() {
        let t = now_secs().to_le_bytes();
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = t[i % t.len()].wrapping_add(i as u8);
        }
    }
    nonce
}

fn getrandom_fill(buf: &mut [u8]) -> Result<(), ()> {
    use std::fs::File;
    use std::io::Read;
    let mut f = File::open("/dev/urandom").map_err(|_| ())?;
    f.read_exact(buf).map_err(|_| ())
}

/// PR-2: attest worker — 在 serve 模式下每 interval_secs 触发一次 AttestationRequest。
/// 注：所有 Host 侧 sleep 都在 Host 进程里（合法），Runtime 内禁止 sleep。
fn spawn_attest_worker(
    runtime: Arc<Mutex<RuntimeConnection>>,
    interval_secs: u64,
    initial_delay_secs: u64,
) {
    std::thread::spawn(move || {
        if initial_delay_secs > 0 {
            eprintln!("==> attest worker: 初始等待 {initial_delay_secs}s 后开始");
            std::thread::sleep(Duration::from_secs(initial_delay_secs));
        }

        loop {
            eprintln!("==> attest worker: 发送 runtime.AttestationRequest...");
            let result = {
                let mut rt = runtime.lock().unwrap();
                // 用随机 nonce（spike 中用时间戳代替）
                let nonce = format!("attest-worker-{}", now_secs()).into_bytes();
                rt.request_attestation(Some(&nonce))
            };

            match result {
                Ok(resp) => {
                    eprintln!(
                        "==> attest worker: 成功 attested_at={:?} key_version={:?}",
                        resp.attested_at, resp.key_version
                    );
                }
                Err(err) => {
                    eprintln!("==> attest worker: 失败: {err:#}");
                }
            }

            std::thread::sleep(Duration::from_secs(interval_secs));
        }
    });
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn cmd_serve(
    sgxs: PathBuf,
    loader_bin: PathBuf,
    socket_path: PathBuf,
    runtime_sock: PathBuf,
    pid_path: PathBuf,
    loader_cfg: LoaderConfig,
    interval_secs: u64,
    initial_delay_secs: u64,
) -> Result<()> {
    if socket_path.exists() {
        return Err(anyhow!(
            "client socket exists: {}, run stop first",
            socket_path.display()
        ));
    }
    if !loader_bin.exists() {
        return Err(anyhow!("loader not built: {}", loader_bin.display()));
    }
    if !sgxs.exists() {
        return Err(anyhow!("sgxs not found: {}", sgxs.display()));
    }

    eprintln!("==> 加载 Runtime: {}", sgxs.display());
    let runtime = RuntimeConnection::start(&sgxs, &runtime_sock, &loader_bin, &loader_cfg)?;
    let runtime = Arc::new(Mutex::new(runtime));

    write_pid(&pid_path)?;
    eprintln!("==> Host 已启动 pid={}", std::process::id());
    eprintln!("==> client socket: {}", socket_path.display());
    eprintln!("==> runtime socket: {}", runtime_sock.display());
    eprintln!("==> attest worker interval: {interval_secs}s (initial_delay: {initial_delay_secs}s)");

    // PR-2: 启动 attest worker 线程（Host 驱动周期 attestation）
    spawn_attest_worker(Arc::clone(&runtime), interval_secs, initial_delay_secs);

    let listener = UnixListener::bind(&socket_path)?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let runtime = Arc::clone(&runtime);
                if let Err(err) = handle_client(stream, runtime) {
                    eprintln!("client error: {err:#}");
                }
            }
            Err(err) => eprintln!("accept error: {err}"),
        }
    }

    let mut runtime = runtime.lock().unwrap();
    runtime.shutdown()?;
    let _ = fs::remove_file(&socket_path);
    let _ = fs::remove_file(&runtime_sock);
    let _ = fs::remove_file(&pid_path);
    Ok(())
}

/// Send one client JSON frame and read the response.
fn client_roundtrip(socket_path: &Path, req: &Frame) -> Result<Frame> {
    use std::io::BufReader;
    let mut stream = UnixStream::connect(socket_path)?;
    write_frame(&mut stream, req).map_err(|e| anyhow!(e))?;
    stream.shutdown(Shutdown::Write)?;
    let mut reader = BufReader::new(stream);
    read_frame(&mut reader).map_err(|e| anyhow!(e))
}

/// PR-3d: Client nonce challenge via serve socket → DCAP + REPORTDATA 验证。
fn cmd_challenge(
    socket_path: PathBuf,
    nonce_hex: Option<String>,
    expected_mrenclave: Option<String>,
) -> Result<()> {
    let nonce = match nonce_hex {
        Some(h) => {
            let bytes = hex_decode(&h)?;
            if bytes.is_empty() || bytes.len() > 255 {
                return Err(anyhow!("nonce length must be 1..=255"));
            }
            bytes
        }
        None => random_challenge_nonce().to_vec(),
    };

    let mut req = Frame::new(OP_CLIENT_CHALLENGE);
    req.id = Some(1);
    req.nonce = Some(b64_encode(&nonce));
    let resp = client_roundtrip(&socket_path, &req)?;
    if resp.ok != Some(true) {
        return Err(anyhow!("challenge failed: {}", resp.error.unwrap_or_default()));
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(verify_attestation_frame(
        &resp,
        Some(&nonce),
        expected_mrenclave.as_deref(),
    ))?;
    println!("NONCE={}", b64_encode(&nonce));
    if let Some(q) = resp.quote.as_deref() {
        println!("QUOTE={q}");
    }
    Ok(())
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(anyhow!("hex length must be even"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!("bad hex: {e}")))
        .collect()
}

/// Challenge through serve, verify Quote, return (key_version, public_key_bytes).
fn challenge_and_verify(
    socket_path: &Path,
    expected_mrenclave: Option<&str>,
) -> Result<(u64, Vec<u8>)> {
    let nonce = random_challenge_nonce();
    let mut req = Frame::new(OP_CLIENT_CHALLENGE);
    req.id = Some(now_secs());
    req.nonce = Some(b64_encode(&nonce));
    let resp = client_roundtrip(socket_path, &req)?;
    if resp.ok != Some(true) {
        return Err(anyhow!("challenge failed: {}", resp.error.unwrap_or_default()));
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(verify_attestation_frame(
        &resp,
        Some(&nonce),
        expected_mrenclave,
    ))?;

    let kv = resp.key_version.unwrap_or(0);
    let pk = b64_decode(resp.public_key.as_deref().ok_or_else(|| anyhow!("no public_key"))?)
        .map_err(|e| anyhow!(e))?;
    Ok((kv, pk))
}

/// Client nonce challenge + DCAP verify，再用验证过的公钥 HPKE 加密后计算。
fn cmd_calc(
    x: i64,
    y: i64,
    socket_path: PathBuf,
    expected_mrenclave: Option<String>,
) -> Result<()> {
    let (kv, pubkey) = challenge_and_verify(&socket_path, expected_mrenclave.as_deref())?;

    let id = now_secs();
    let aad = aead::aad_json(1, id, OP_CLIENT_COMPUTE, kv);
    let plaintext = format!(r#"{{"x":{x},"y":{y}}}"#);
    let ct = aead::encrypt(&pubkey, plaintext.as_bytes(), aad.as_bytes()).map_err(|e| anyhow!(e))?;

    let mut req = Frame::new(OP_CLIENT_COMPUTE);
    req.id = Some(id);
    req.key_version = Some(kv);
    req.ct = Some(b64_encode(&ct));
    req.aad_json = Some(aad);

    let resp = client_roundtrip(&socket_path, &req)?;
    if resp.ok == Some(true) {
        let result = resp.result.ok_or_else(|| anyhow!("missing result"))?;
        println!("TEE 计算结果: {x}^3 + 5*{y} = {result}");
        println!("RESULT={result}");
        println!("KEY_VERSION={kv}");
        Ok(())
    } else {
        Err(anyhow!(
            "compute failed: {} (code: {})",
            resp.error.unwrap_or_default(),
            resp.code.unwrap_or_default()
        ))
    }
}

fn cmd_pubkey(socket_path: PathBuf) -> Result<()> {
    let mut req = Frame::new(OP_CLIENT_PUBKEY);
    req.id = Some(1);
    let resp = client_roundtrip(&socket_path, &req)?;
    println!("KEY_VERSION={}", resp.key_version.unwrap_or(0));
    println!("PUBLIC_KEY={}", resp.public_key.as_deref().unwrap_or(""));
    if let Some(q) = resp.quote.as_deref() {
        println!("QUOTE={q}");
    }
    if let Some(rd) = resp.report_data.as_deref() {
        println!("REPORTDATA={rd}");
    }
    Ok(())
}

fn cmd_rotate(socket_path: PathBuf) -> Result<()> {
    let mut req = Frame::new(OP_CLIENT_ROTATE);
    req.id = Some(1);
    let resp = client_roundtrip(&socket_path, &req)?;
    if resp.ok != Some(true) {
        return Err(anyhow!("rotate failed: {}", resp.error.unwrap_or_default()));
    }
    println!("KEY_VERSION={}", resp.key_version.unwrap_or(0));
    println!("PUBLIC_KEY={}", resp.public_key.as_deref().unwrap_or(""));
    if let Some(q) = resp.quote.as_deref() {
        println!("QUOTE={q}");
    }
    if let Some(n) = resp.binding_nonce.as_deref() {
        println!("BINDING_NONCE={n}");
    }
    if let Some(rd) = resp.report_data.as_deref() {
        println!("REPORTDATA={rd}");
        // 本地校验 REPORTDATA 绑定（不依赖 DCAP；防 Host 替换公钥）
        if let (Some(pk_b64), Some(kv), Some(nonce_b64)) = (
            resp.public_key.as_deref(),
            resp.key_version,
            resp.binding_nonce.as_deref(),
        ) {
            let pk = b64_decode(pk_b64).map_err(|e| anyhow!(e))?;
            let nonce = b64_decode(nonce_b64).map_err(|e| anyhow!(e))?;
            let expected = report_data_binding(kv, &pk, &nonce);
            let actual = b64_decode(rd).map_err(|e| anyhow!(e))?;
            if expected.as_slice() == actual.as_slice() {
                println!("REPORTDATA_BINDING_OK");
            } else {
                return Err(anyhow!("REPORTDATA binding mismatch after rotate"));
            }
        }
    }
    Ok(())
}

fn cmd_attest(
    sgxs: PathBuf,
    loader_bin: PathBuf,
    runtime_sock: PathBuf,
    nonce: Option<String>,
    loader_cfg: LoaderConfig,
) -> Result<()> {
    if runtime_sock.exists() {
        return Err(anyhow!(
            "runtime socket busy: {}, stop serve first",
            runtime_sock.display()
        ));
    }

    let nonce_bytes = match nonce {
        Some(n) => n.into_bytes(),
        None => b"pr2-attest-nonce".to_vec(),
    };
    let expected = loader_cfg.expected_mrenclave.clone();

    let mut runtime = RuntimeConnection::start(&sgxs, &runtime_sock, &loader_bin, &loader_cfg)?;
    let resp = runtime.request_attestation(Some(&nonce_bytes))?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(verify_attestation_frame(
        &resp,
        Some(&nonce_bytes),
        expected.as_deref(),
    ))?;

    runtime.shutdown()?;
    let _ = fs::remove_file(&runtime_sock);
    Ok(())
}

fn cmd_stop(socket_path: PathBuf, runtime_sock: PathBuf, pid_path: PathBuf) -> Result<()> {
    if pid_path.exists() {
        let pid = read_pid(&pid_path)?;
        if is_running(pid) {
            Command::new("kill").arg(pid.to_string()).status()?;
            eprintln!("==> sent SIGTERM to pid={pid}");
        }
        let _ = fs::remove_file(&pid_path);
    }
    if socket_path.exists() {
        let _ = fs::remove_file(&socket_path);
    }
    if runtime_sock.exists() {
        let _ = fs::remove_file(&runtime_sock);
    }
    Ok(())
}

#[derive(Parser)]
#[command(name = "tee-demo-host")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 常驻服务：加载 Runtime，接受 client 计算请求；PR-2 attest worker
    Serve {
        #[arg(long, default_value_os_t = default_sgxs())]
        sgxs: PathBuf,
        #[arg(long, default_value_os_t = default_loader())]
        loader: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCK)]
        socket: String,
        #[arg(long, default_value = DEFAULT_ENCLAVE_SOCK)]
        enclave_socket: String,
        #[arg(long, default_value = DEFAULT_PID)]
        pid: String,
        /// 生产模式：传 --production 给 Loader
        #[arg(long)]
        production: bool,
        #[arg(long)]
        sig: Option<PathBuf>,
        #[arg(long)]
        expected_mrenclave: Option<String>,
        /// attest worker 间隔（秒）
        #[arg(long, default_value_t = DEFAULT_INTERVAL_SECS)]
        interval_secs: u64,
        /// 初始延迟（秒）；0 = 立即发第一次
        #[arg(long, default_value_t = DEFAULT_INITIAL_DELAY_SECS)]
        initial_delay_secs: u64,
        /// Loader 落盘目录（sealed_keys.bin / keyring.json）
        #[arg(long, default_value = "/tmp/tee-demo-data")]
        data_dir: PathBuf,
        /// PR-4：经 bwrap 最小挂载启动 Loader
        #[arg(long, default_value_t = false)]
        sandbox: bool,
        /// bwrap 包装脚本路径
        #[arg(long, default_value_os_t = default_sandbox_wrapper())]
        sandbox_wrapper: PathBuf,
    },
    /// 客户端计算（经 client socket，HPKE 加密）
    Calc {
        #[arg(allow_hyphen_values = true)]
        x: i64,
        #[arg(allow_hyphen_values = true)]
        y: i64,
        #[arg(long, default_value = DEFAULT_SOCK)]
        socket: String,
        /// 期望 MRENCLAVE（hex）；与 Quote 比对
        #[arg(long)]
        expected_mrenclave: Option<String>,
    },
    /// 查询当前公钥（必要时先触发 attestation）
    Pubkey {
        #[arg(long, default_value = DEFAULT_SOCK)]
        socket: String,
    },
    /// PR-3d：经 serve socket 发 Client nonce challenge 并 DCAP 验证
    Challenge {
        #[arg(long, default_value = DEFAULT_SOCK)]
        socket: String,
        /// hex nonce；缺省则随机 32 字节
        #[arg(long)]
        nonce: Option<String>,
        #[arg(long)]
        expected_mrenclave: Option<String>,
    },
    /// 请求 Runtime 轮换密钥（保留最近 2 把）
    Rotate {
        #[arg(long, default_value = DEFAULT_SOCK)]
        socket: String,
    },
    /// 发 AttestationRequest 并用 dcap-qvl 验证 Quote
    Attest {
        #[arg(long, default_value_os_t = default_sgxs())]
        sgxs: PathBuf,
        #[arg(long, default_value_os_t = default_loader())]
        loader: PathBuf,
        #[arg(long, default_value = DEFAULT_ENCLAVE_SOCK)]
        enclave_socket: String,
        #[arg(long)]
        nonce: Option<String>,
        #[arg(long)]
        production: bool,
        #[arg(long)]
        sig: Option<PathBuf>,
        #[arg(long)]
        expected_mrenclave: Option<String>,
        #[arg(long, default_value_t = false)]
        sandbox: bool,
        #[arg(long, default_value_os_t = default_sandbox_wrapper())]
        sandbox_wrapper: PathBuf,
        #[arg(long, default_value = "/tmp/tee-demo-data")]
        data_dir: PathBuf,
    },
    /// 停止 serve
    Stop {
        #[arg(long, default_value = DEFAULT_SOCK)]
        socket: String,
        #[arg(long, default_value = DEFAULT_ENCLAVE_SOCK)]
        enclave_socket: String,
        #[arg(long, default_value = DEFAULT_PID)]
        pid: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Serve {
            sgxs,
            loader,
            socket,
            enclave_socket,
            pid,
            production,
            sig,
            expected_mrenclave,
            interval_secs,
            initial_delay_secs,
            data_dir,
            sandbox,
            sandbox_wrapper,
        } => cmd_serve(
            sgxs,
            loader,
            PathBuf::from(socket),
            PathBuf::from(enclave_socket),
            PathBuf::from(pid),
            LoaderConfig {
                production,
                sig,
                expected_mrenclave,
                data_dir,
                sandbox,
                sandbox_wrapper,
            },
            interval_secs,
            initial_delay_secs,
        ),
        Commands::Calc {
            x,
            y,
            socket,
            expected_mrenclave,
        } => cmd_calc(
            x,
            y,
            PathBuf::from(socket),
            expected_mrenclave,
        ),
        Commands::Pubkey { socket } => cmd_pubkey(PathBuf::from(socket)),
        Commands::Challenge {
            socket,
            nonce,
            expected_mrenclave,
        } => cmd_challenge(PathBuf::from(socket), nonce, expected_mrenclave),
        Commands::Rotate { socket } => cmd_rotate(PathBuf::from(socket)),
        Commands::Attest {
            sgxs,
            loader,
            enclave_socket,
            nonce,
            production,
            sig,
            expected_mrenclave,
            sandbox,
            sandbox_wrapper,
            data_dir,
        } => cmd_attest(
            sgxs,
            loader,
            PathBuf::from(enclave_socket),
            nonce,
            LoaderConfig {
                production,
                sig,
                expected_mrenclave,
                data_dir,
                sandbox,
                sandbox_wrapper,
            },
        ),
        Commands::Stop { socket, enclave_socket, pid } => cmd_stop(
            PathBuf::from(socket),
            PathBuf::from(enclave_socket),
            PathBuf::from(pid),
        ),
    };

    if let Err(err) = result {
        eprintln!("错误: {err:#}");
        std::process::exit(1);
    }
}
