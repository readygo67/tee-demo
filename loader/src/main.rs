//! Loader: multiplex Enclave `worker-host` stream.
//!
//! - `loader.*` handled locally via AESM
//! - other frames forwarded to Host Unix socket (host leg)

use std::future::Future;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use enclave_runner::{
    usercalls::{AsyncStream, UsercallExtension},
    EnclaveBuilder,
};
use futures::future::FutureExt;
use sgxs_loaders::isgx::Device as IsgxDevice;
use tee_demo_protocol::{
    b64_decode, b64_encode, decode_frame_body, encode_frame, Frame, OP_LOADER_GET_QUOTE,
    OP_LOADER_GET_QUOTE_RESULT, OP_LOADER_INIT_QUOTE, OP_LOADER_INIT_QUOTE_RESULT,
    OP_LOADER_READ_BLOB, OP_LOADER_READ_BLOB_RESULT, OP_LOADER_WRITE_BLOB,
    OP_LOADER_WRITE_BLOB_RESULT,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
struct HostService {
    host_socket: String,
    data_dir: std::path::PathBuf,
}

impl HostService {
    fn new(host_socket: &str, data_dir: std::path::PathBuf) -> Self {
        Self {
            host_socket: host_socket.to_owned(),
            data_dir,
        }
    }
}

#[allow(clippy::type_complexity)]
impl UsercallExtension for HostService {
    fn connect_stream<'future>(
        &'future self,
        addr: &'future str,
        _local_addr: Option<&'future mut String>,
        _peer_addr: Option<&'future mut String>,
    ) -> Pin<Box<dyn Future<Output = IoResult<Option<Box<dyn AsyncStream>>>> + 'future>> {
        async move {
            match addr {
                "worker-host" => {
                    let (enclave_side, mux_side) = UnixStream::pair()?;
                    let host_leg = UnixStream::connect(&self.host_socket).await?;
                    let data_dir = self.data_dir.clone();
                    tokio::spawn(async move {
                        if let Err(err) = run_multiplexer(mux_side, host_leg, data_dir).await {
                            eprintln!("multiplexer exited: {err:#}");
                        }
                    });
                    let async_stream: Box<dyn AsyncStream> = Box::new(enclave_side);
                    Ok(Some(async_stream))
                }
                _ => Err(IoError::new(
                    IoErrorKind::Other,
                    format!("unknown destination: {addr}"),
                )),
            }
        }
        .boxed_local()
    }
}

async fn read_frame_async(stream: &mut UnixStream) -> Result<Frame> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(anyhow!("frame too large: {len}"));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    decode_frame_body(&body).map_err(|e| anyhow!(e))
}

async fn write_frame_async(stream: &mut UnixStream, frame: &Frame) -> Result<()> {
    let bytes = encode_frame(frame).map_err(|e| anyhow!(e))?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

fn safe_blob_name(name: &str) -> Option<&str> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
        return None;
    }
    if name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        Some(name)
    } else {
        None
    }
}

fn handle_blob_op(frame: &Frame, data_dir: &Path) -> Frame {
    let seq = frame.seq;
    let result_op = if frame.op == OP_LOADER_READ_BLOB {
        OP_LOADER_READ_BLOB_RESULT
    } else {
        OP_LOADER_WRITE_BLOB_RESULT
    };
    let Some(name) = frame.path.as_deref().and_then(safe_blob_name) else {
        let mut out = Frame::new(result_op);
        out.seq = seq;
        out.ok = Some(false);
        out.error = Some("invalid blob path".into());
        return out;
    };
    let path = data_dir.join(name);
    match frame.op.as_str() {
        OP_LOADER_READ_BLOB => match std::fs::read(&path) {
            Ok(bytes) => {
                let mut out = Frame::new(OP_LOADER_READ_BLOB_RESULT);
                out.seq = seq;
                out.ok = Some(true);
                out.blob = Some(b64_encode(&bytes));
                out
            }
            Err(_) => {
                let mut out = Frame::new(OP_LOADER_READ_BLOB_RESULT);
                out.seq = seq;
                out.ok = Some(false);
                out.error = Some("not found".into());
                out
            }
        },
        OP_LOADER_WRITE_BLOB => {
            let decoded = match frame.blob.as_deref().map(b64_decode) {
                Some(Ok(b)) => b,
                Some(Err(e)) => {
                    let mut out = Frame::new(OP_LOADER_WRITE_BLOB_RESULT);
                    out.seq = seq;
                    out.ok = Some(false);
                    out.error = Some(e);
                    return out;
                }
                None => {
                    let mut out = Frame::new(OP_LOADER_WRITE_BLOB_RESULT);
                    out.seq = seq;
                    out.ok = Some(false);
                    out.error = Some("missing blob".into());
                    return out;
                }
            };
            if let Err(err) = std::fs::create_dir_all(data_dir) {
                let mut out = Frame::new(OP_LOADER_WRITE_BLOB_RESULT);
                out.seq = seq;
                out.ok = Some(false);
                out.error = Some(err.to_string());
                return out;
            }
            match std::fs::write(&path, decoded) {
                Ok(()) => {
                    let mut out = Frame::new(OP_LOADER_WRITE_BLOB_RESULT);
                    out.seq = seq;
                    out.ok = Some(true);
                    out
                }
                Err(err) => {
                    let mut out = Frame::new(OP_LOADER_WRITE_BLOB_RESULT);
                    out.seq = seq;
                    out.ok = Some(false);
                    out.error = Some(err.to_string());
                    out
                }
            }
        }
        _ => unreachable!(),
    }
}

fn handle_loader_op(frame: &Frame, data_dir: &Path) -> Frame {
    let seq = frame.seq;
    match frame.op.as_str() {
        OP_LOADER_READ_BLOB | OP_LOADER_WRITE_BLOB => handle_blob_op(frame, data_dir),
        OP_LOADER_INIT_QUOTE => match aesm_init_quote() {
            Ok((att_key_id, target_info)) => {
                let mut out = Frame::new(OP_LOADER_INIT_QUOTE_RESULT);
                out.seq = seq;
                out.ok = Some(true);
                out.att_key_id = Some(b64_encode(&att_key_id));
                out.target_info = Some(b64_encode(&target_info));
                out
            }
            Err(err) => {
                let mut out = Frame::new(OP_LOADER_INIT_QUOTE_RESULT);
                out.seq = seq;
                out.ok = Some(false);
                out.error = Some(err.to_string());
                out
            }
        },
        OP_LOADER_GET_QUOTE => {
            let report = match frame.report.as_deref().map(b64_decode) {
                Some(Ok(r)) => r,
                Some(Err(e)) => {
                    let mut out = Frame::new(OP_LOADER_GET_QUOTE_RESULT);
                    out.seq = seq;
                    out.ok = Some(false);
                    out.error = Some(e);
                    return out;
                }
                None => {
                    let mut out = Frame::new(OP_LOADER_GET_QUOTE_RESULT);
                    out.seq = seq;
                    out.ok = Some(false);
                    out.error = Some("missing report".into());
                    return out;
                }
            };
            let att_key_id = match frame.att_key_id.as_deref().map(b64_decode) {
                Some(Ok(r)) => r,
                Some(Err(e)) => {
                    let mut out = Frame::new(OP_LOADER_GET_QUOTE_RESULT);
                    out.seq = seq;
                    out.ok = Some(false);
                    out.error = Some(e);
                    return out;
                }
                None => {
                    let mut out = Frame::new(OP_LOADER_GET_QUOTE_RESULT);
                    out.seq = seq;
                    out.ok = Some(false);
                    out.error = Some("missing att_key_id".into());
                    return out;
                }
            };
            match aesm_get_quote(att_key_id, report) {
                Ok(quote) => {
                    let mut out = Frame::new(OP_LOADER_GET_QUOTE_RESULT);
                    out.seq = seq;
                    out.ok = Some(true);
                    out.quote = Some(b64_encode(&quote));
                    out
                }
                Err(err) => {
                    let mut out = Frame::new(OP_LOADER_GET_QUOTE_RESULT);
                    out.seq = seq;
                    out.ok = Some(false);
                    out.error = Some(err.to_string());
                    out
                }
            }
        }
        other => {
            let mut out = Frame::new(format!("{other}_result"));
            out.seq = seq;
            out.ok = Some(false);
            out.error = Some(format!("unsupported loader op: {other}"));
            out
        }
    }
}

fn aesm_init_quote() -> Result<(Vec<u8>, Vec<u8>)> {
    let aesm = aesm_client::AesmClient::new();
    let ids = aesm
        .get_supported_att_key_ids()
        .context("get_supported_att_key_ids")?;
    let att_key_id = ids
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no att_key_id from aesmd"))?;
    let qi = aesm
        .init_quote_ex(att_key_id.clone())
        .context("init_quote_ex")?;
    Ok((att_key_id, qi.target_info().to_vec()))
}

fn aesm_get_quote(att_key_id: Vec<u8>, report: Vec<u8>) -> Result<Vec<u8>> {
    let aesm = aesm_client::AesmClient::new();
    // AESM ECDSA path: 16-byte QE nonce (distinct from REPORTDATA binding nonce).
    let qe_nonce = vec![0u8; 16];
    let qr = aesm
        .get_quote_ex(att_key_id, report, None, qe_nonce)
        .context("get_quote_ex")?;
    Ok(qr.quote().to_vec())
}

async fn run_multiplexer(
    mut enclave_leg: UnixStream,
    mut host_leg: UnixStream,
    data_dir: std::path::PathBuf,
) -> Result<()> {
    // Serialize writes to enclave_leg when forwarding host→enclave and loader replies.
    let enclave_write = Arc::new(Mutex::new(()));

    loop {
        tokio::select! {
            res = read_frame_async(&mut enclave_leg) => {
                let frame = match res {
                    Ok(f) => f,
                    Err(err) => {
                        eprintln!("enclave leg closed: {err:#}");
                        break;
                    }
                };
                if frame.is_loader_op() && !frame.op.ends_with("_result") {
                    let reply = handle_loader_op(&frame, &data_dir);
                    let _g = enclave_write.lock().await;
                    write_frame_async(&mut enclave_leg, &reply).await?;
                } else {
                    // Forward Runtime → Host (AttestationResponse / ComputeResponse / ...)
                    write_frame_async(&mut host_leg, &frame).await?;
                }
            }
            res = read_frame_async(&mut host_leg) => {
                let frame = match res {
                    Ok(f) => f,
                    Err(err) => {
                        eprintln!("host leg closed: {err:#}");
                        break;
                    }
                };
                let _g = enclave_write.lock().await;
                write_frame_async(&mut enclave_leg, &frame).await?;
            }
        }
    }
    Ok(())
}

/// 从 SIGSTRUCT 文件读取 MRENCLAVE（偏移 960，32 字节），与期望值比对。
/// sig_path: 要读取的 .sig 文件；expected_hex: 期望的 64 字符 hex 串。
fn verify_mrenclave(sig_path: &Path, expected_hex: &str) -> Result<()> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(sig_path)
        .with_context(|| format!("打开 SIGSTRUCT 失败: {}", sig_path.display()))?;
    let mut buf = vec![0u8; 992]; // SIGSTRUCT 最小读取长度
    file.read_exact(&mut buf)
        .context("读取 SIGSTRUCT 失败（文件太短？）")?;

    let mrenclave_bytes = &buf[960..992]; // ENCLAVEHASH 偏移 960，长 32 字节
    let actual_hex: String = mrenclave_bytes.iter().map(|b| format!("{b:02x}")).collect();

    if actual_hex != expected_hex.to_lowercase() {
        return Err(anyhow!(
            "MRENCLAVE 不匹配！\n  期望: {expected_hex}\n  实际: {actual_hex}\n\
             可能 sgxs 已被替换，拒绝加载。"
        ));
    }
    eprintln!("==> MRENCLAVE 校验通过: {actual_hex}");
    Ok(())
}

fn run(
    sgxs: &Path,
    host_socket: &str,
    sig: Option<&Path>,
    expected_mrenclave: Option<&str>,
    data_dir: &Path,
) -> Result<()> {
    // 生产模式：校验 MRENCLAVE（从 .sig 读取，与期望值比对）
    if let (Some(sig_path), Some(expected)) = (sig, expected_mrenclave) {
        verify_mrenclave(sig_path, expected)?;
    }

    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("create data dir {}", data_dir.display()))?;
    eprintln!("==> blob data dir: {}", data_dir.display());

    let mut device = IsgxDevice::new()?
        .einittoken_provider(aesm_client::AesmClient::new())
        .build();

    let mut enclave_builder = EnclaveBuilder::new(sgxs);
    match sig {
        Some(sig_path) => {
            enclave_builder
                .signature(sig_path)
                .with_context(|| format!("加载 SIGSTRUCT 失败: {}", sig_path.display()))?;
            // build-runtime.sh --production 签名时已写入当前机器的 XFRM 值到 SIGSTRUCT，
            // 无需在此覆盖 attributes，enclave-runner 会直接用 SIGSTRUCT.ATTRIBUTES。
            eprintln!("==> 生产模式：使用签名 {}", sig_path.display());
        }
        None => {
            enclave_builder.dummy_signature();
            eprintln!("==> 开发模式：使用 dummy_signature（生产请加 --production）");
        }
    }

    enclave_builder.usercall_extension(HostService::new(host_socket, data_dir.to_path_buf()));
    let enclave = enclave_builder
        .build(&mut device)
        .map_err(|err| anyhow!("{err}"))?;

    enclave.run().map_err(|err| anyhow!("{err}"))
}

#[derive(Parser)]
#[command(name = "tee-demo-loader")]
struct Args {
    /// Host 监听的 Unix socket（host leg）
    #[arg(long)]
    host_socket: String,

    /// SGXS Runtime 文件
    sgxs: String,

    /// 生产模式：使用真实 SIGSTRUCT（由 sgxs-sign 生成）
    #[arg(long)]
    production: bool,

    /// SIGSTRUCT 文件路径（仅 --production 时生效；默认 <sgxs>.sig）
    #[arg(long)]
    sig: Option<String>,

    /// 期望的 MRENCLAVE hex（仅 --production 时强制校验）
    #[arg(long)]
    expected_mrenclave: Option<String>,

    /// 存放 sealed_keys.bin / keyring.json 的目录（opaque blob，loader 不解密）
    #[arg(long, default_value = "/tmp/tee-demo-data")]
    data_dir: String,
}

fn main() {
    let args = Args::parse();
    let sgxs = Path::new(&args.sgxs);
    if !sgxs.exists() {
        eprintln!("错误: 找不到 Runtime 文件: {}", sgxs.display());
        std::process::exit(1);
    }

    // 生产模式参数解析
    let (sig_path_buf, expected_mrenclave): (Option<std::path::PathBuf>, Option<String>) =
        if args.production {
            let sig = args
                .sig
                .as_deref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| sgxs.with_extension("sig"));
            if !sig.exists() {
                eprintln!(
                    "错误: --production 模式下 SIGSTRUCT 不存在: {}",
                    sig.display()
                );
                std::process::exit(1);
            }
            let mre = args.expected_mrenclave.clone();
            (Some(sig), mre)
        } else {
            if args.sig.is_some() || args.expected_mrenclave.is_some() {
                eprintln!("警告: --sig / --expected-mrenclave 仅在 --production 下生效");
            }
            (None, None)
        };

    // enclave-runner uses a single-threaded local executor; keep tokio available for mux tasks.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let _guard = rt.enter();

    if let Err(err) = run(
        sgxs,
        &args.host_socket,
        sig_path_buf.as_deref(),
        expected_mrenclave.as_deref(),
        Path::new(&args.data_dir),
    ) {
        eprintln!("loader 运行失败: {err:#}");
        std::process::exit(1);
    }
}
