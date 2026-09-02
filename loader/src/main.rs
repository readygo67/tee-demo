//! 基于 enclave-runner 的 loader：Enclave 内 `connect("worker-host")` 会连到 Host 监听的 Unix Socket。
use std::future::Future;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};
use std::path::Path;
use std::pin::Pin;

use anyhow::{anyhow, Result};
use clap::Parser;
use enclave_runner::{
    usercalls::{AsyncStream, UsercallExtension},
    EnclaveBuilder,
};
use futures::future::FutureExt;
use sgxs_loaders::isgx::Device as IsgxDevice;
use tokio::net::UnixStream;

#[derive(Debug)]
struct HostService {
    host_socket: String,
}

impl HostService {
    fn new(host_socket: &str) -> Self {
        Self {
            host_socket: host_socket.to_owned(),
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
                    let stream = UnixStream::connect(self.host_socket.clone()).await?;
                    let async_stream: Box<dyn AsyncStream> = Box::new(stream);
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

fn run(sgxs: &Path, host_socket: &str) -> Result<()> {
    let mut device = IsgxDevice::new()?
        .einittoken_provider(aesm_client::AesmClient::new())
        .build();

    let mut enclave_builder = EnclaveBuilder::new(sgxs);
    enclave_builder.dummy_signature();
    enclave_builder.usercall_extension(HostService::new(host_socket));
    let enclave = enclave_builder
        .build(&mut device)
        .map_err(|err| anyhow!("{err}"))?;

    enclave.run().map_err(|err| anyhow!("{err}"))
}

#[derive(Parser)]
#[command(name = "tee-demo-loader")]
struct Args {
    /// Host 监听的 Unix Socket 路径
    #[arg(long)]
    host_socket: String,

    /// SGXS Enclave 文件路径
    sgxs: String,
}

fn main() {
    let args = Args::parse();
    let sgxs = Path::new(&args.sgxs);
    if !sgxs.exists() {
        eprintln!("错误: 找不到 Enclave 文件: {}", sgxs.display());
        std::process::exit(1);
    }

    if let Err(err) = run(sgxs, &args.host_socket) {
        eprintln!("loader 运行失败: {err}");
        std::process::exit(1);
    }
}
