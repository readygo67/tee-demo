//! Length-prefixed JSON protocol shared by Host, Loader, and Runtime.
//!
//! Wire format: `[u32 little-endian length][utf-8 JSON bytes]`

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROTOCOL_VERSION: u16 = 1;

// Loader ↔ Runtime
pub const OP_LOADER_INIT_QUOTE: &str = "loader.init_quote";
pub const OP_LOADER_INIT_QUOTE_RESULT: &str = "loader.init_quote_result";
pub const OP_LOADER_GET_QUOTE: &str = "loader.get_quote";
pub const OP_LOADER_GET_QUOTE_RESULT: &str = "loader.get_quote_result";
pub const OP_LOADER_READ_BLOB: &str = "loader.read_blob";
pub const OP_LOADER_READ_BLOB_RESULT: &str = "loader.read_blob_result";
pub const OP_LOADER_WRITE_BLOB: &str = "loader.write_blob";
pub const OP_LOADER_WRITE_BLOB_RESULT: &str = "loader.write_blob_result";

// Host ↔ Runtime (经 Loader host leg 转发)
pub const OP_RUNTIME_ATTESTATION_REQUEST: &str = "runtime.AttestationRequest";
pub const OP_HOST_ATTESTATION_RESPONSE: &str = "host.AttestationResponse";
/// PR-3a: ComputeRequest 携带 AEAD 密文 ct（Host 不可见明文 x/y）
pub const OP_RUNTIME_COMPUTE_REQUEST: &str = "runtime.ComputeRequest";
pub const OP_HOST_COMPUTE_RESPONSE: &str = "host.ComputeResponse";

// Client ↔ Host (client.sock，PR-3a 新增 JSON 协议)
pub const OP_CLIENT_COMPUTE: &str = "compute";
pub const OP_HOST_COMPUTE_RESULT: &str = "compute_result";
pub const OP_CLIENT_PUBKEY: &str = "pubkey";
pub const OP_HOST_PUBKEY_RESULT: &str = "pubkey_result";
pub const OP_CLIENT_ROTATE: &str = "rotate";
pub const OP_HOST_ROTATE_RESULT: &str = "rotate_result";
/// PR-3d: Client nonce challenge → Host 转发 runtime.AttestationRequest
pub const OP_CLIENT_CHALLENGE: &str = "challenge";
pub const OP_HOST_CHALLENGE_RESULT: &str = "challenge_result";
pub const OP_RUNTIME_ROTATE_REQUEST: &str = "runtime.RotateRequest";
pub const OP_HOST_ROTATE_RESPONSE: &str = "host.RotateResponse";
pub const OP_HOST_READY: &str = "host.Ready";

/// Client challenge nonce 推荐长度（§5.5）
pub const CHALLENGE_NONCE_LEN: usize = 32;

pub const SEALED_KEYS_NAME: &str = "sealed_keys.bin";
pub const KEYRING_NAME: &str = "keyring.json";
/// Host/Loader 侧不可信缓存（§5.4）；权威信任仅来自已验证 Quote + REPORTDATA
pub const ATTESTATION_NAME: &str = "attestation.json";
pub const ALG_HPKE_P256: &str = "hpke-p256";
/// attestation.json 默认 TTL（秒），仅运维缓存，不能代替 Client nonce freshness
pub const ATTESTATION_CACHE_TTL_SECS: u64 = 3600;

/// PR-3a: error codes returned in host.ComputeResponse
pub const ERR_KEY_EXPIRED: &str = "key_expired";
pub const ERR_KEY_UNKNOWN: &str = "key_unknown";
pub const ERR_DECRYPT_FAILED: &str = "decrypt_failed";
pub const ERR_BAD_INPUT: &str = "bad_input";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    pub v: u16,
    pub op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_info: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub att_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    // --- PR-3a: AEAD compute fields ---
    /// PR-3a: AEAD 密文（base64）；Host 不可见明文 x/y
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ct: Option<String>,
    /// PR-3a: AAD JSON 字符串（{v,id,op,key_version}，明文，供 Runtime 验证完整性）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad_json: Option<String>,
    /// PR-3a: 错误码（key_expired / decrypt_failed / bad_input）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,

    // --- legacy / dev / plaintext fields (PR-0/1/2 spike only) ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// loader.read_blob / write_blob 文件名（仅 basename）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// loader blob 内容（base64）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
}

impl Frame {
    pub fn new(op: impl Into<String>) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            op: op.into(),
            id: None,
            seq: None,
            ok: None,
            error: None,
            nonce: None,
            binding_nonce: None,
            target_info: None,
            att_key_id: None,
            report: None,
            quote: None,
            report_data: None,
            attested_at: None,
            key_version: None,
            public_key: None,
            ct: None,
            aad_json: None,
            code: None,
            x: None,
            y: None,
            status: None,
            result: None,
            message: None,
            path: None,
            blob: None,
        }
    }

    pub fn is_loader_op(&self) -> bool {
        self.op.starts_with("loader.")
    }
}

/// REPORTDATA 绑定（§5.5，v3.2）：
///
/// digest = SHA256(
///     protocol_version : u16 LE
///   || key_version      : u64 LE
///   || pubkey_len       : u16 LE
///   || public_key_bytes : [u8]
///   || nonce_len        : u8
///   || nonce            : [u8]    // 若无 nonce 则 nonce_len=0
/// )
/// REPORTDATA = digest[0..32] || [0u8; 32]
pub fn report_data_binding(
    key_version: u64,
    public_key: &[u8],
    nonce: &[u8],
) -> [u8; 64] {
    let mut hasher = Sha256::new();
    hasher.update(PROTOCOL_VERSION.to_le_bytes());
    hasher.update(key_version.to_le_bytes());
    hasher.update((public_key.len() as u16).to_le_bytes());
    hasher.update(public_key);
    hasher.update([nonce.len() as u8]);
    hasher.update(nonce);
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&digest);
    out
}

/// 旧版（PR-0 spike）简单绑定：仅 H(version || nonce)
/// 保留以便测试对比；生产使用 `report_data_binding`。
#[deprecated(note = "use report_data_binding instead")]
pub fn report_data_from_nonce(nonce: &[u8]) -> [u8; 64] {
    report_data_binding(0, b"", nonce)
}

/// §5.4 attestation.json（不可信缓存）。Client 不得仅凭此文件信任公钥。
pub fn attestation_cache_json(
    quote_b64: &str,
    key_version: u64,
    public_key_b64: &str,
    binding_nonce_b64: Option<&str>,
    report_data_b64: Option<&str>,
    generated_at: u64,
    sequence: u64,
) -> String {
    let expires_at = generated_at.saturating_add(ATTESTATION_CACHE_TTL_SECS);
    let nonce_field = match binding_nonce_b64 {
        Some(n) => alloc::format!(r#""binding_nonce":"{n}","#),
        None => String::new(),
    };
    let rd_field = match report_data_b64 {
        Some(r) => alloc::format!(r#""report_data":"{r}","#),
        None => String::new(),
    };
    alloc::format!(
        r#"{{"v":{v},"quote_type":"ecdsa","quote":"{quote}","key_version":{kv},"public_key":"{pk}",{nonce}{rd}"generated_at":{gen},"expires_at":{exp},"sequence":{seq}}}"#,
        v = PROTOCOL_VERSION,
        quote = quote_b64,
        kv = key_version,
        pk = public_key_b64,
        nonce = nonce_field,
        rd = rd_field,
        gen = generated_at,
        exp = expires_at,
        seq = sequence,
    )
}

pub fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    B64.decode(s).map_err(|e| e.to_string())
}

pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(frame).map_err(|e| e.to_string())?;
    if json.len() > u32::MAX as usize {
        return Err("frame too large".into());
    }
    let mut out = Vec::with_capacity(4 + json.len());
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

pub fn decode_frame_body(json: &[u8]) -> Result<Frame, String> {
    serde_json::from_slice(json).map_err(|e| e.to_string())
}

#[cfg(feature = "std")]
mod std_io {
    use super::*;
    use std::io::{Read, Write};

    pub fn read_frame<R: Read>(reader: &mut R) -> Result<Frame, String> {
        let mut len_buf = [0u8; 4];
        reader
            .read_exact(&mut len_buf)
            .map_err(|e| format!("read len: {e}"))?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > 16 * 1024 * 1024 {
            return Err(format!("frame len too large: {len}"));
        }
        let mut body = vec![0u8; len];
        reader
            .read_exact(&mut body)
            .map_err(|e| format!("read body: {e}"))?;
        decode_frame_body(&body)
    }

    pub fn write_frame<W: Write>(writer: &mut W, frame: &Frame) -> Result<(), String> {
        let bytes = encode_frame(frame)?;
        writer
            .write_all(&bytes)
            .map_err(|e| format!("write frame: {e}"))?;
        writer.flush().map_err(|e| format!("flush: {e}"))?;
        Ok(())
    }
}

#[cfg(feature = "std")]
pub use std_io::{read_frame, write_frame};

pub mod aead;

#[cfg(feature = "verify")]
pub mod verify {
    use super::*;
    use dcap_qvl::collateral::{CollateralClient, INTEL_PCS_URL};
    use dcap_qvl::verify::{QuoteVerifier, VerifiedReport};

    pub async fn verify_quote_allow_debug(quote: &[u8]) -> Result<VerifiedReport, String> {
        let client =
            CollateralClient::with_default_http(INTEL_PCS_URL).map_err(|e| e.to_string())?;
        let collateral = client.fetch(quote).await.map_err(|e| e.to_string())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        QuoteVerifier::new_prod()
            .allow_debug(true)
            .verify(quote, &collateral, now)
            .map_err(|e| e.to_string())
    }

    pub fn mrenclave_hex(report: &VerifiedReport) -> Option<String> {
        use dcap_qvl::quote::Report;
        match &report.report {
            Report::SgxEnclave(r) => Some(hex::encode(&r.mr_enclave)),
            _ => None,
        }
    }

    pub fn report_data_b64(report: &VerifiedReport) -> Option<String> {
        use dcap_qvl::quote::Report;
        match &report.report {
            Report::SgxEnclave(r) => Some(b64_encode(&r.report_data)),
            _ => None,
        }
    }

    /// Attestation 验证清单（§5.5）：
    /// 1. DCAP Quote verify
    /// 2. 可选 expected_mrenclave
    /// 3. REPORTDATA == f(client_nonce, public_key, key_version)
    /// 4. binding_nonce 必须等于本次 challenge nonce（防 replay / Host 偷换）
    pub async fn verify_attestation(
        quote_b64: &str,
        public_key_b64: &str,
        key_version: u64,
        client_nonce: &[u8],
        binding_nonce_b64: &str,
        expected_mrenclave: Option<&str>,
    ) -> Result<VerifiedReport, String> {
        let quote = b64_decode(quote_b64)?;
        let verified = verify_quote_allow_debug(&quote).await?;

        let mrenclave = mrenclave_hex(&verified).ok_or_else(|| "no SGX enclave report".to_string())?;
        if let Some(expected) = expected_mrenclave {
            let exp = expected.to_lowercase();
            if mrenclave != exp {
                return Err(alloc::format!(
                    "MRENCLAVE mismatch: expected {exp}, got {mrenclave}"
                ));
            }
        }

        let binding = b64_decode(binding_nonce_b64)?;
        if binding != client_nonce {
            return Err("binding_nonce does not match Client challenge nonce".into());
        }

        let pubkey = b64_decode(public_key_b64)?;
        let expected_rd = report_data_binding(key_version, &pubkey, client_nonce);
        let rd_b64 = report_data_b64(&verified).ok_or_else(|| "no report_data".to_string())?;
        let verified_rd = b64_decode(&rd_b64)?;
        if verified_rd != expected_rd {
            return Err(alloc::format!(
                "REPORTDATA binding failed (Host may have swapped public_key)\n\
                 expected: {}\n\
                 actual:   {}",
                b64_encode(&expected_rd),
                b64_encode(&verified_rd),
            ));
        }

        Ok(verified)
    }
}

#[cfg(feature = "verify")]
mod hex {
    pub fn encode(bytes: &[u8]) -> alloc::string::String {
        bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
    }
}
