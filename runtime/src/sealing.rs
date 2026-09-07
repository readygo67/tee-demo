//! SGX sealing for KeyStore (confidentiality only — not anti-rollback).
//!
//! Seal key is derived with `EGETKEY` (SEAL + MRENCLAVE). The blob is
//! AES-128-GCM over a compact KeyStore encoding.

use crate::key_store::KeyStore;

const MAGIC: &[u8; 4] = b"TDK1";

/// Encrypted blob written via `loader.write_blob`.
///
/// Layout:
///   magic[4] || keyid[32] || isvsvn[2] || cpusvn[16] || nonce[12] || ct+tag
#[cfg(target_env = "sgx")]
pub fn seal(store: &KeyStore) -> Result<Vec<u8>, String> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes128Gcm, Nonce,
    };
    use sgx_isa::{Keypolicy, Keyrequest, Report};

    const KEYNAME_SEAL: u16 = 4;

    let report = Report::for_self();
    let mut keyid = [0u8; 32];
    getrandom::getrandom(&mut keyid).map_err(|e| e.to_string())?;
    let key = seal_key(&report, &keyid)?;
    let cipher = Aes128Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = store.encode();
    let ct = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("seal encrypt: {e}"))?;

    let mut out = Vec::with_capacity(4 + 32 + 2 + 16 + 12 + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&keyid);
    out.extend_from_slice(&report.isvsvn.to_le_bytes());
    out.extend_from_slice(&report.cpusvn);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

#[cfg(not(target_env = "sgx"))]
pub fn seal(_store: &KeyStore) -> Result<Vec<u8>, String> {
    Err("sealing requires SGX".into())
}

#[cfg(target_env = "sgx")]
pub fn unseal(blob: &[u8]) -> Result<KeyStore, String> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes128Gcm, Nonce,
    };
    use sgx_isa::{Keypolicy, Keyrequest, Report};

    const HDR: usize = 4 + 32 + 2 + 16 + 12;
    const KEYNAME_SEAL: u16 = 4;
    if blob.len() < HDR + 16 || &blob[..4] != MAGIC {
        return Err("invalid sealed blob".into());
    }
    let keyid: [u8; 32] = blob[4..36].try_into().unwrap();
    let isvsvn = u16::from_le_bytes([blob[36], blob[37]]);
    let cpusvn: [u8; 16] = blob[38..54].try_into().unwrap();
    let nonce_bytes = &blob[54..66];
    let ct = &blob[66..];

    let mut report = Report::for_self();
    report.isvsvn = isvsvn;
    report.cpusvn = cpusvn;
    let key = seal_key(&report, &keyid)?;
    let cipher = Aes128Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let pt = cipher
        .decrypt(nonce, ct)
        .map_err(|_| "unseal failed (wrong MRENCLAVE / corrupt blob)".to_string())?;
    KeyStore::decode(&pt)
}

#[cfg(not(target_env = "sgx"))]
pub fn unseal(_blob: &[u8]) -> Result<KeyStore, String> {
    Err("sealing requires SGX".into())
}

#[cfg(target_env = "sgx")]
fn seal_key(report: &sgx_isa::Report, keyid: &[u8; 32]) -> Result<[u8; 16], String> {
    use sgx_isa::{Keypolicy, Keyrequest};
    const KEYNAME_SEAL: u16 = 4;
    let req = Keyrequest {
        keyname: KEYNAME_SEAL,
        keypolicy: Keypolicy::MRENCLAVE,
        isvsvn: report.isvsvn,
        _reserved1: 0,
        cpusvn: report.cpusvn,
        attributemask: [u64::MAX, u64::MAX],
        keyid: *keyid,
        miscmask: u32::MAX,
        _reserved2: [0u8; 436],
    };
    req.egetkey().map_err(|e| format!("egetkey: {e:?}"))
}
