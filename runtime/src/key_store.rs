//! In-enclave KeyStore: at most 2 HPKE private keys + current version.

use tee_demo_protocol::aead;
use tee_demo_protocol::{ERR_DECRYPT_FAILED, ERR_KEY_EXPIRED, ERR_KEY_UNKNOWN};

pub const RETENTION: usize = 2;

#[derive(Clone)]
pub struct StoredKey {
    pub version: u64,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Clone)]
pub struct KeyStore {
    pub current_version: u64,
    pub keys: Vec<StoredKey>,
}

impl KeyStore {
    pub fn new() -> Result<Self, String> {
        let mut store = Self {
            current_version: 0,
            keys: Vec::new(),
        };
        store.rotate()?;
        Ok(store)
    }

    pub fn rotate(&mut self) -> Result<&StoredKey, String> {
        let (pk, sk) = aead::generate_keypair()?;
        let version = self.current_version + 1;
        self.current_version = version;
        self.keys.push(StoredKey {
            version,
            public_key: pk,
            private_key: sk,
        });
        while self.keys.len() > RETENTION {
            self.keys.remove(0);
        }
        Ok(self.keys.last().unwrap())
    }

    pub fn current(&self) -> Option<&StoredKey> {
        self.keys.iter().find(|k| k.version == self.current_version)
    }

    pub fn lookup(&self, version: u64) -> Result<&StoredKey, DecryptErr> {
        if let Some(k) = self.keys.iter().find(|k| k.version == version) {
            return Ok(k);
        }
        if self.current_version.saturating_sub(version) >= 2 {
            Err(DecryptErr::Expired)
        } else {
            Err(DecryptErr::Unknown)
        }
    }

    pub fn decrypt(&self, version: u64, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, DecryptErr> {
        let key = self.lookup(version)?;
        aead::decrypt(&key.private_key, ct, aad).map_err(|_| DecryptErr::Failed)
    }

    pub fn keyring_json(&self) -> String {
        let keys: Vec<String> = self
            .keys
            .iter()
            .map(|k| {
                format!(
                    r#"{{"version":{},"public_key":"{}","algorithm":"hpke-p256"}}"#,
                    k.version,
                    tee_demo_protocol::b64_encode(&k.public_key)
                )
            })
            .collect();
        format!(
            r#"{{"v":1,"current_version":{},"keys":[{}]}}"#,
            self.current_version,
            keys.join(",")
        )
    }

    /// Compact binary encoding for sealing.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.current_version.to_le_bytes());
        out.push(self.keys.len() as u8);
        for k in &self.keys {
            out.extend_from_slice(&k.version.to_le_bytes());
            out.extend_from_slice(&(k.public_key.len() as u16).to_le_bytes());
            out.extend_from_slice(&k.public_key);
            out.extend_from_slice(&(k.private_key.len() as u16).to_le_bytes());
            out.extend_from_slice(&k.private_key);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 9 {
            return Err("keystore too short".into());
        }
        let current_version = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let n = bytes[8] as usize;
        let mut off = 9;
        let mut keys = Vec::new();
        for _ in 0..n {
            if off + 8 + 2 > bytes.len() {
                return Err("truncated keystore".into());
            }
            let version = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            off += 8;
            let pk_len = u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap()) as usize;
            off += 2;
            if off + pk_len + 2 > bytes.len() {
                return Err("truncated pubkey".into());
            }
            let public_key = bytes[off..off + pk_len].to_vec();
            off += pk_len;
            let sk_len = u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap()) as usize;
            off += 2;
            if off + sk_len > bytes.len() {
                return Err("truncated seckey".into());
            }
            let private_key = bytes[off..off + sk_len].to_vec();
            off += sk_len;
            keys.push(StoredKey {
                version,
                public_key,
                private_key,
            });
        }
        Ok(Self {
            current_version,
            keys,
        })
    }
}

pub enum DecryptErr {
    Expired,
    Unknown,
    Failed,
}

impl DecryptErr {
    pub fn code(&self) -> &'static str {
        match self {
            DecryptErr::Expired => ERR_KEY_EXPIRED,
            DecryptErr::Unknown => ERR_KEY_UNKNOWN,
            DecryptErr::Failed => ERR_DECRYPT_FAILED,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            DecryptErr::Expired => "key version expired (retention=2)",
            DecryptErr::Unknown => "key version unknown",
            DecryptErr::Failed => "hpke decrypt failed",
        }
    }
}
