//! SGX Runtime: attestation + HPKE compute + sealing (PR-3c).
//!
//! PR-3c:
//! - rotation **后**立即生成绑定新公钥的 Quote（REPORTDATA）
//! - 写 attestation.json / keyring.json（不可信缓存）

extern crate alloc;

mod key_store;
mod sealing;

use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sgx_isa::{Report, Targetinfo};
use tee_demo_protocol::{
    attestation_cache_json, b64_decode, b64_encode, read_frame, report_data_binding, write_frame,
    Frame, ATTESTATION_NAME, KEYRING_NAME, OP_HOST_ATTESTATION_RESPONSE, OP_HOST_COMPUTE_RESPONSE,
    OP_HOST_ROTATE_RESPONSE, OP_LOADER_GET_QUOTE, OP_LOADER_GET_QUOTE_RESULT,
    OP_LOADER_INIT_QUOTE, OP_LOADER_INIT_QUOTE_RESULT, OP_LOADER_READ_BLOB,
    OP_LOADER_READ_BLOB_RESULT, OP_LOADER_WRITE_BLOB, OP_LOADER_WRITE_BLOB_RESULT,
    OP_RUNTIME_ATTESTATION_REQUEST, OP_RUNTIME_COMPUTE_REQUEST, OP_RUNTIME_ROTATE_REQUEST,
    SEALED_KEYS_NAME,
};

use crate::key_store::KeyStore;

const STALE_THRESHOLD_SECS: u64 = 5400;

fn compute(x: i64, y: i64) -> i64 {
    x.pow(3) + 5 * y
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn next_seq(seq: &mut u64) -> u64 {
    *seq += 1;
    *seq
}

fn loader_init_quote(stream: &mut TcpStream, seq: &mut u64) -> Result<(Vec<u8>, Vec<u8>), String> {
    let req_seq = next_seq(seq);
    let mut req = Frame::new(OP_LOADER_INIT_QUOTE);
    req.seq = Some(req_seq);
    write_frame(stream, &req)?;

    loop {
        let resp = read_frame(stream)?;
        if resp.op == OP_LOADER_INIT_QUOTE_RESULT && resp.seq == Some(req_seq) {
            if resp.ok != Some(true) {
                return Err(resp.error.unwrap_or_else(|| "loader.init_quote failed".into()));
            }
            let att_key_id = resp.att_key_id.as_deref().ok_or("missing att_key_id")?.to_owned();
            let target_info = resp.target_info.as_deref().ok_or("missing target_info")?.to_owned();
            return Ok((b64_decode(&att_key_id)?, b64_decode(&target_info)?));
        }
    }
}

fn loader_get_quote(
    stream: &mut TcpStream,
    seq: &mut u64,
    att_key_id: &[u8],
    report: &[u8],
) -> Result<Vec<u8>, String> {
    let req_seq = next_seq(seq);
    let mut req = Frame::new(OP_LOADER_GET_QUOTE);
    req.seq = Some(req_seq);
    req.att_key_id = Some(b64_encode(att_key_id));
    req.report = Some(b64_encode(report));
    write_frame(stream, &req)?;

    loop {
        let resp = read_frame(stream)?;
        if resp.op == OP_LOADER_GET_QUOTE_RESULT && resp.seq == Some(req_seq) {
            if resp.ok != Some(true) {
                return Err(resp.error.unwrap_or_else(|| "loader.get_quote failed".into()));
            }
            let quote = resp.quote.as_deref().ok_or("missing quote")?;
            return b64_decode(quote);
        }
    }
}

fn loader_read_blob(stream: &mut TcpStream, seq: &mut u64, path: &str) -> Result<Option<Vec<u8>>, String> {
    let req_seq = next_seq(seq);
    let mut req = Frame::new(OP_LOADER_READ_BLOB);
    req.seq = Some(req_seq);
    req.path = Some(path.into());
    write_frame(stream, &req)?;
    loop {
        let resp = read_frame(stream)?;
        if resp.op == OP_LOADER_READ_BLOB_RESULT && resp.seq == Some(req_seq) {
            if resp.ok != Some(true) {
                return Ok(None);
            }
            return match resp.blob.as_deref() {
                Some(b) => Ok(Some(b64_decode(b)?)),
                None => Ok(None),
            };
        }
    }
}

fn loader_write_blob(stream: &mut TcpStream, seq: &mut u64, path: &str, data: &[u8]) -> Result<(), String> {
    let req_seq = next_seq(seq);
    let mut req = Frame::new(OP_LOADER_WRITE_BLOB);
    req.seq = Some(req_seq);
    req.path = Some(path.into());
    req.blob = Some(b64_encode(data));
    write_frame(stream, &req)?;
    loop {
        let resp = read_frame(stream)?;
        if resp.op == OP_LOADER_WRITE_BLOB_RESULT && resp.seq == Some(req_seq) {
            if resp.ok != Some(true) {
                return Err(resp.error.unwrap_or_else(|| "loader.write_blob failed".into()));
            }
            return Ok(());
        }
    }
}

fn persist_store(stream: &mut TcpStream, seq: &mut u64, store: &KeyStore) -> Result<(), String> {
    let sealed = sealing::seal(store)?;
    loader_write_blob(stream, seq, SEALED_KEYS_NAME, &sealed)?;
    loader_write_blob(stream, seq, KEYRING_NAME, store.keyring_json().as_bytes())?;
    Ok(())
}

/// PR-3c: 将最新 AttestationResponse 落盘为不可信 attestation.json。
fn write_attestation_cache(
    stream: &mut TcpStream,
    seq: &mut u64,
    resp: &Frame,
    sequence: u64,
) -> Result<(), String> {
    let quote = resp.quote.as_deref().ok_or("missing quote for attestation cache")?;
    let pk = resp
        .public_key
        .as_deref()
        .ok_or("missing public_key for attestation cache")?;
    let kv = resp.key_version.unwrap_or(0);
    let generated_at = resp.attested_at.unwrap_or_else(now_secs);
    let json = attestation_cache_json(
        quote,
        kv,
        pk,
        resp.binding_nonce.as_deref(),
        resp.report_data.as_deref(),
        generated_at,
        sequence,
    );
    loader_write_blob(stream, seq, ATTESTATION_NAME, json.as_bytes())
}

/// 出证 + 刷新不可信缓存（attestation.json / keyring.json）。
fn do_attestation_and_cache(
    stream: &mut TcpStream,
    seq: &mut u64,
    nonce: &[u8],
    store: &KeyStore,
    sequence: &mut u64,
) -> Result<Frame, String> {
    let out = do_attestation(stream, seq, nonce, store)?;
    *sequence = sequence.saturating_add(1);
    write_attestation_cache(stream, seq, &out, *sequence)?;
    // 同步刷新 keyring（公钥列表；私钥仍只在 sealed blob）
    loader_write_blob(stream, seq, KEYRING_NAME, store.keyring_json().as_bytes())?;
    Ok(out)
}

fn send_ready(stream: &mut TcpStream, store: &KeyStore) -> Result<(), String> {
    let mut ready = Frame::new(tee_demo_protocol::OP_HOST_READY);
    ready.ok = Some(true);
    ready.key_version = Some(store.current_version);
    if let Some(cur) = store.current() {
        ready.public_key = Some(b64_encode(&cur.public_key));
    }
    write_frame(stream, &ready)
}

fn bootstrap_store(stream: &mut TcpStream, seq: &mut u64) -> Result<KeyStore, String> {
    let store = match loader_read_blob(stream, seq, SEALED_KEYS_NAME)? {
        Some(blob) => match sealing::unseal(&blob) {
            Ok(store) => {
                eprintln!(
                    "Runtime: unsealed KeyStore current_version={}",
                    store.current_version
                );
                loader_write_blob(stream, seq, KEYRING_NAME, store.keyring_json().as_bytes())?;
                store
            }
            Err(err) => {
                eprintln!("Runtime: unseal failed ({err}), starting new KeyStore");
                let store = KeyStore::new()?;
                persist_store(stream, seq, &store)?;
                store
            }
        },
        None => {
            eprintln!("Runtime: no sealed_keys.bin, initializing KeyStore v=1");
            let store = KeyStore::new()?;
            persist_store(stream, seq, &store)?;
            store
        }
    };
    send_ready(stream, &store)?;
    Ok(store)
}

fn do_attestation(
    stream: &mut TcpStream,
    seq: &mut u64,
    nonce: &[u8],
    store: &KeyStore,
) -> Result<Frame, String> {
    let current = store.current().ok_or("empty KeyStore")?;
    let (att_key_id, target_info_bytes) = loader_init_quote(stream, seq)?;
    let target_info = Targetinfo::try_copy_from(&target_info_bytes)
        .ok_or_else(|| "invalid target_info".to_string())?;

    let report_data = report_data_binding(current.version, &current.public_key, nonce);
    let report = Report::for_target(&target_info, &report_data);
    let report_bytes: &[u8] = report.as_ref();
    let quote = loader_get_quote(stream, seq, &att_key_id, report_bytes)?;


    let attested_at = now_secs();
    let mut out = Frame::new(OP_HOST_ATTESTATION_RESPONSE);
    out.ok = Some(true);
    out.attested_at = Some(attested_at);
    out.key_version = Some(current.version);
    out.public_key = Some(b64_encode(&current.public_key));
    out.quote = Some(b64_encode(&quote));
    out.binding_nonce = Some(b64_encode(nonce));
    out.report_data = Some(b64_encode(&report_data));
    Ok(out)
}

fn maybe_stale_attest(
    stream: &mut TcpStream,
    seq: &mut u64,
    last_attested_at: &mut u64,
    store: &KeyStore,
    sequence: &mut u64,
) -> Result<(), String> {
    let elapsed = now_secs().saturating_sub(*last_attested_at);
    if *last_attested_at == 0 || elapsed > STALE_THRESHOLD_SECS {
        let nonce = b"stale-auto-attest-nonce".to_vec();
        let mut attest_resp = do_attestation_and_cache(stream, seq, &nonce, store, sequence)?;
        attest_resp.id = None;
        write_frame(stream, &attest_resp)?;
        *last_attested_at = attest_resp.attested_at.unwrap_or_else(now_secs);
    }
    Ok(())
}

fn handle_attestation_request(
    stream: &mut TcpStream,
    seq: &mut u64,
    frame: &Frame,
    last_attested_at: &mut u64,
    store: &KeyStore,
    sequence: &mut u64,
) -> Result<(), String> {
    let nonce = match frame.nonce.as_deref() {
        Some(n) => b64_decode(n)?,
        None => b"pr3c-default-nonce".to_vec(),
    };
    let mut resp = do_attestation_and_cache(stream, seq, &nonce, store, sequence)?;
    resp.id = frame.id;
    *last_attested_at = resp.attested_at.unwrap_or_else(now_secs);
    write_frame(stream, &resp)
}

fn parse_xy_json(s: &str) -> Result<(i64, i64), String> {
    fn extract_field(s: &str, key: &str) -> Option<i64> {
        let needle = alloc::format!("\"{key}\":");
        let start = s.find(needle.as_str())? + needle.len();
        let rest = s[start..].trim_start();
        let end = rest
            .find(|c: char| !c.is_ascii_digit() && c != '-')
            .unwrap_or(rest.len());
        rest[..end].parse().ok()
    }
    let x = extract_field(s, "x").ok_or_else(|| alloc::format!("missing x in plaintext: {s}"))?;
    let y = extract_field(s, "y").ok_or_else(|| alloc::format!("missing y in plaintext: {s}"))?;
    Ok((x, y))
}

fn handle_compute_request(
    stream: &mut TcpStream,
    seq: &mut u64,
    frame: &Frame,
    last_attested_at: &mut u64,
    store: &KeyStore,
    sequence: &mut u64,
) -> Result<(), String> {
    maybe_stale_attest(stream, seq, last_attested_at, store, sequence)?;

    let ct_b64 = match frame.ct.as_deref() {
        Some(c) => c,
        None => {
            let mut resp = Frame::new(OP_HOST_COMPUTE_RESPONSE);
            resp.id = frame.id;
            resp.ok = Some(false);
            resp.code = Some(tee_demo_protocol::ERR_BAD_INPUT.into());
            resp.error = Some("missing ct".into());
            write_frame(stream, &resp)?;
            return Ok(());
        }
    };
    let key_version = frame.key_version.unwrap_or(0);
    let aad = frame
        .aad_json
        .clone()
        .unwrap_or_else(|| tee_demo_protocol::aead::aad_json(frame.v, frame.id.unwrap_or(0), "compute", key_version));

    let xy: Result<(i64, i64), (&str, String)> = (|| {
        let ct = b64_decode(ct_b64).map_err(|e| (tee_demo_protocol::ERR_BAD_INPUT, e))?;
        let pt = store
            .decrypt(key_version, &ct, aad.as_bytes())
            .map_err(|err| (err.code(), err.message().into()))?;
        let s = core::str::from_utf8(&pt)
            .map_err(|e| (tee_demo_protocol::ERR_BAD_INPUT, e.to_string()))?;
        parse_xy_json(s).map_err(|e| (tee_demo_protocol::ERR_BAD_INPUT, e))
    })();

    let mut resp = Frame::new(OP_HOST_COMPUTE_RESPONSE);
    resp.id = frame.id;
    match xy {
        Ok((x, y)) => {
            resp.ok = Some(true);
            resp.result = Some(compute(x, y));
        }
        Err((code, msg)) => {
            resp.ok = Some(false);
            resp.code = Some(code.into());
            resp.error = Some(msg);
        }
    }
    write_frame(stream, &resp)
}

/// PR-3c: rotation **后**立即生成绑定新公钥的 Quote，并写 attestation/keyring 缓存。
fn handle_rotate_request(
    stream: &mut TcpStream,
    seq: &mut u64,
    frame: &Frame,
    last_attested_at: &mut u64,
    store: &mut KeyStore,
    sequence: &mut u64,
) -> Result<(), String> {
    let key = store.rotate()?;
    let version = key.version;
    let public_key = key.public_key.clone();
    persist_store(stream, seq, store)?;

    // 绑定新公钥：nonce 可用 Client 提供的，否则用 rotation counter
    let nonce = match frame.nonce.as_deref() {
        Some(n) => b64_decode(n)?,
        None => version.to_le_bytes().to_vec(),
    };
    let mut attest = do_attestation_and_cache(stream, seq, &nonce, store, sequence)?;
    *last_attested_at = attest.attested_at.unwrap_or_else(now_secs);

    // 先发 AttestationResponse（Host 更新 quote 绑定的 bundle）
    attest.id = None;
    write_frame(stream, &attest)?;

    // 再发 RotateResponse（含 quote 字段，便于 Client 一次拿到）
    let mut resp = Frame::new(OP_HOST_ROTATE_RESPONSE);
    resp.id = frame.id;
    resp.ok = Some(true);
    resp.key_version = Some(version);
    resp.public_key = Some(b64_encode(&public_key));
    resp.quote = attest.quote.clone();
    resp.binding_nonce = attest.binding_nonce.clone();
    resp.report_data = attest.report_data.clone();
    resp.attested_at = attest.attested_at;
    write_frame(stream, &resp)
}

fn run_loop(stream: &mut TcpStream) -> Result<(), String> {
    let mut loader_seq = 0u64;
    let mut last_attested_at: u64 = 0;
    let mut attest_sequence: u64 = 0;
    let mut store = bootstrap_store(stream, &mut loader_seq)?;

    loop {
        let frame = read_frame(stream)?;
        match frame.op.as_str() {
            OP_RUNTIME_ATTESTATION_REQUEST => handle_attestation_request(
                stream,
                &mut loader_seq,
                &frame,
                &mut last_attested_at,
                &store,
                &mut attest_sequence,
            )?,
            OP_RUNTIME_COMPUTE_REQUEST => handle_compute_request(
                stream,
                &mut loader_seq,
                &frame,
                &mut last_attested_at,
                &store,
                &mut attest_sequence,
            )?,
            OP_RUNTIME_ROTATE_REQUEST => handle_rotate_request(
                stream,
                &mut loader_seq,
                &frame,
                &mut last_attested_at,
                &mut store,
                &mut attest_sequence,
            )?,
            other => {
                let mut err = Frame::new(format!("{other}_error"));
                err.id = frame.id;
                err.ok = Some(false);
                err.error = Some(format!("unsupported op: {other}"));
                write_frame(stream, &err)?;
            }
        }
    }
}

#[cfg(target_env = "sgx")]
fn main() {
    eprintln!("Runtime ready (PR-3c)");
    let mut stream = TcpStream::connect("worker-host").expect("connect worker-host failed");
    if let Err(err) = run_loop(&mut stream) {
        eprintln!("Runtime loop error: {err}");
    }
}

#[cfg(not(target_env = "sgx"))]
fn main() {
    eprintln!("tee-demo Runtime must be built for SGX target");
}
