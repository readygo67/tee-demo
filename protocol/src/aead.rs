//! HPKE-P256 + AES-GCM-128 (RFC 9180), shared by Host/Client and Runtime.
//!
//! Wire `ct` (before base64):
//!   enc_len : u16 LE
//!   enc     : encapsulated key (P-256, typically 65 bytes)
//!   ciphertext || tag

use alloc::string::String;
use alloc::vec::Vec;

use hpke::{
    aead::AesGcm128,
    kdf::HkdfSha256,
    kem::DhP256HkdfSha256,
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, single_shot_open,
    single_shot_seal,
};
use rand_core::OsRng;

pub const HPKE_INFO: &[u8] = b"tee-demo/hpke-p256/v1";

type Aead = AesGcm128;
type Kdf = HkdfSha256;
type Kem = DhP256HkdfSha256;

/// Canonical AAD JSON: `{"v":1,"id":42,"op":"compute","key_version":5}`
pub fn aad_json(v: u16, id: u64, op: &str, key_version: u64) -> String {
    alloc::format!(r#"{{"v":{v},"id":{id},"op":"{op}","key_version":{key_version}}}"#)
}

/// Returns (public_key_bytes, private_key_bytes).
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    let (sk, pk) = Kem::gen_keypair(&mut OsRng);
    Ok((pk.to_bytes().to_vec(), sk.to_bytes().to_vec()))
}

pub fn encrypt(public_key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(public_key)
        .map_err(|e| alloc::format!("invalid hpke public key: {e}"))?;
    let (enc, ct) = single_shot_seal::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &pk,
        HPKE_INFO,
        plaintext,
        aad,
        &mut OsRng,
    )
    .map_err(|e| alloc::format!("hpke seal: {e}"))?;
    let enc_bytes = enc.to_bytes();
    let mut out = Vec::with_capacity(2 + enc_bytes.len() + ct.len());
    out.extend_from_slice(&(enc_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&enc_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(private_key: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if ct.len() < 2 {
        return Err("ct too short".into());
    }
    let enc_len = u16::from_le_bytes([ct[0], ct[1]]) as usize;
    if ct.len() < 2 + enc_len {
        return Err("ct truncated".into());
    }
    let enc_bytes = &ct[2..2 + enc_len];
    let ciphertext = &ct[2 + enc_len..];
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(private_key)
        .map_err(|e| alloc::format!("invalid hpke private key: {e}"))?;
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(enc_bytes)
        .map_err(|e| alloc::format!("invalid hpke encapsulated key: {e}"))?;
    single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk,
        &enc,
        HPKE_INFO,
        ciphertext,
        aad,
    )
    .map_err(|e| alloc::format!("hpke open: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let (pk, sk) = generate_keypair().unwrap();
        let aad = aad_json(1, 42, "compute", 5);
        let pt = br#"{"x":2,"y":3}"#;
        let ct = encrypt(&pk, pt, aad.as_bytes()).unwrap();
        let out = decrypt(&sk, &ct, aad.as_bytes()).unwrap();
        assert_eq!(out, pt);
        assert!(decrypt(&sk, &ct, b"tampered").is_err());
    }
}
