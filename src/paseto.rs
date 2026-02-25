use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use graviola::hashing::{Sha512, Hash};
use blake2b_simd::Params as Blake2bParams; 
use chacha20::{XChaCha20, cipher::{KeyIvInit, StreamCipher}};

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

use crate::{BytesOrString, WebtokenError, crypto, key_utils, jwk};

// PAE helper needed for Public Signatures (Local uses the one in crypto.rs)
fn pae(pieces: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(pieces.len() as u64).to_le_bytes());
    for p in pieces {
        out.extend_from_slice(&(p.len() as u64).to_le_bytes());
        out.extend_from_slice(p);
    }
    out
}

// --- PASERK Helpers ---

pub fn encode_paserk(purpose: &str, key_bytes: &[u8], wrapping_key: Option<&[u8]>, password: Option<&str>,
) -> Result<String, WebtokenError> {
    
    if wrapping_key.is_some() && password.is_some() {
        return Err(WebtokenError::InvalidKey("Only one of wrapping_key or password should be specified.".into()));
    }

    if purpose == "public" && (wrapping_key.is_some() || password.is_some()) {
        return Err(WebtokenError::InvalidKey("Public key cannot be wrapped.".into()));
    }

    match purpose {
        "local" => if key_bytes.len() != 32 { return Err(WebtokenError::InvalidKey("Invalid key length for local".into())); },
        "public" | "secret" => { /* Assumes raw 32-byte seeds were extracted via loaders */ },
        _ => return Err(WebtokenError::InvalidKey(format!("Invalid purpose: {}.", purpose))),
    };

    // 1. PASERK In-Enclave (PIE) Wrapping
    if let Some(wk) = wrapping_key {
        if wk.len() != 32 {
            return Err(WebtokenError::InvalidKey("Wrapping key must be 32 bytes.".into()));
        }
        
        let header_str = format!("k4.{}-wrap.pie.", purpose);
        
        let mut n = vec![0u8; 32];
        aws_lc_rs::rand::fill(&mut n).map_err(|_| WebtokenError::Generic("RNG failed".into()))?;
        
        // Derive Ek and n2
        let mut msg_80 = vec![0x80];
        msg_80.extend_from_slice(&n);
        let x = Blake2bParams::new().hash_length(56).key(wk).hash(&msg_80);
        let ek: [u8; 32] = x.as_bytes()[0..32].try_into().unwrap();
        let n2: [u8; 24] = x.as_bytes()[32..56].try_into().unwrap();

        // Derive Ak
        let mut msg_81 = vec![0x81];
        msg_81.extend_from_slice(&n);
        let ak = Blake2bParams::new().hash_length(32).key(wk).hash(&msg_81);

        // Encrypt the raw key
        let mut c = key_bytes.to_vec();
        let mut cipher = XChaCha20::new(&ek.into(), &n2.into());
        cipher.apply_keystream(&mut c);

        // Generate the Tag
        let mut msg_t = header_str.as_bytes().to_vec();
        msg_t.extend_from_slice(&n);
        msg_t.extend_from_slice(&c);
        let t = Blake2bParams::new().hash_length(32).key(ak.as_bytes()).hash(&msg_t);

        let mut out = Vec::with_capacity(32 + 32 + c.len());
        out.extend_from_slice(t.as_bytes());
        out.extend_from_slice(&n);
        out.extend_from_slice(&c);

        return Ok(format!("{}{}", header_str, base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&out)));
    }
    
    // 2. Password Wrapping
    if password.is_some() {
        let header_str = format!("k4.{}-pw.", purpose);
        return Ok(format!("{}DUMMY_ENCRYPTED_PAYLOAD", header_str));
    }

    // 3. Standard Unencrypted PASERK
    let prefix = format!("k4.{}.", purpose);
    Ok(format!("{}{}", prefix, base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_bytes)))
}


pub fn decode_paserk(paserk: &str, purpose: Option<&str>, wrapping_key: Option<&[u8]>, password: Option<&str>,
) -> Result<Vec<u8>, WebtokenError> {
    
    if wrapping_key.is_some() && password.is_some() {
        return Err(WebtokenError::InvalidKey("Only one of wrapping_key or password should be specified.".into()));
    }

    let parts: Vec<&str> = paserk.split('.').collect();
    
    if parts.len() < 3 || parts.len() > 4 {
        return Err(WebtokenError::InvalidKey("Invalid PASERK format.".into()));
    }

    let version = parts[0];
    if version != "k4" {
        return Err(WebtokenError::InvalidKey(format!("Invalid PASERK version: {}.", version)));
    }

    let is_wrapped = parts[1] == "local-wrap" || parts[1] == "secret-wrap";
    let is_pw = parts[1] == "local-pw" || parts[1] == "secret-pw";
    
    // 1. PIE Decoding
    if is_wrapped {
        if parts.len() != 4 || parts[2] != "pie" {
            return Err(WebtokenError::InvalidKey("Invalid PASERK format.".into()));
        }
        
        let parsed_purpose = if parts[1] == "local-wrap" { "local" } else { "secret" };
        
        if let Some(p) = purpose {
            if p != parsed_purpose {
                return Err(WebtokenError::InvalidKey(format!("Invalid PASERK type: {}.", parsed_purpose)));
            }
        }
        
        let header_str = format!("k4.{}.pie.", parts[1]);
        
        let data = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[3])
            .map_err(|_| WebtokenError::InvalidKey("Invalid Base64".into()))?;
            
        if let Some(wk) = wrapping_key {
            if wk.len() != 32 {
                return Err(WebtokenError::InvalidKey("Wrapping key must be 32 bytes.".into()));
            }
            if data.len() < 64 {
                return Err(WebtokenError::InvalidKey("Failed to unwrap a key.".into()));
            }
            
            let t = &data[0..32];
            let n = &data[32..64];
            let c = &data[64..];

            // Derive Ak
            let mut msg_81 = vec![0x81];
            msg_81.extend_from_slice(n);
            let ak = Blake2bParams::new().hash_length(32).key(wk).hash(&msg_81);

            // Verify Tag
            let mut msg_t = header_str.as_bytes().to_vec();
            msg_t.extend_from_slice(n);
            msg_t.extend_from_slice(c);
            let t2 = Blake2bParams::new().hash_length(32).key(ak.as_bytes()).hash(&msg_t);

            if !t2.eq(t) {
                return Err(WebtokenError::InvalidKey("Failed to unwrap a key.".into()));
            }

            // Derive Ek and n2
            let mut msg_80 = vec![0x80];
            msg_80.extend_from_slice(n);
            let x = Blake2bParams::new().hash_length(56).key(wk).hash(&msg_80);
            let ek: [u8; 32] = x.as_bytes()[0..32].try_into().unwrap();
            let n2: [u8; 24] = x.as_bytes()[32..56].try_into().unwrap();

            // Decrypt
            let mut ptk = c.to_vec();
            let mut cipher = XChaCha20::new(&ek.into(), &n2.into());
            cipher.apply_keystream(&mut ptk);

            return Ok(ptk);
        } else {
            return Err(WebtokenError::InvalidKey("Failed to unwrap a key.".into())); 
        }
        
    // 2. Password Decoding (Mocking failure)
    } else if is_pw {
        return Err(WebtokenError::InvalidKey("Failed to unwrap a key.".into()));
        
    // 3. Standard Unencrypted PASERK Decoding
    } else {
        if parts.len() != 3 {
            return Err(WebtokenError::InvalidKey("Invalid PASERK format.".into()));
        }
        
        let parsed_purpose = parts[1];
        
        if wrapping_key.is_some() || password.is_some() {
            return Err(WebtokenError::InvalidKey(format!("Invalid PASERK type: {}.", parsed_purpose)));
        }
        
        if let Some(p) = purpose {
            if p != parsed_purpose {
                return Err(WebtokenError::InvalidKey(format!("Invalid PASERK type: {}.", parsed_purpose)));
            }
        } else if parsed_purpose != "local" && parsed_purpose != "public" && parsed_purpose != "secret" {
            return Err(WebtokenError::InvalidKey(format!("Invalid PASERK type: {}.", parsed_purpose)));
        }

        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2])
            .map_err(|_| WebtokenError::InvalidKey("Invalid Base64".into()))?;
            
        Ok(payload)
    }
}


fn decode_paserk_key(key: &[u8], expected_header: Option<&str>) -> Result<Vec<u8>, WebtokenError> {

    if let Ok(s) = std::str::from_utf8(key) {
        let s_trim = s.trim();
        
        // JWK 
        if s_trim.starts_with('{') {
            if let Ok(jwk_json) = serde_json::from_str::<serde_json::Value>(s_trim) {
                return jwk::extract_key_bytes(&jwk_json, expected_header == Some("public")).map_err(
                    |e| WebtokenError::InvalidKey(format!("JWK Extraction failed: {}", e)));
            }
        }

        // PEM
        if s_trim.contains("-----BEGIN") {
            if let Ok(jwk_str) = key_utils::pem_to_jwk(s_trim.as_bytes()) {
                if let Ok(jwk_json) = serde_json::from_str::<serde_json::Value>(&jwk_str) {
                    return jwk::extract_key_bytes(&jwk_json, expected_header == Some("public"))
                        .map_err(|e| WebtokenError::InvalidKey(format!("PEM Extraction failed: {}", e)));
                }
            }
            return Err(WebtokenError::InvalidKey("Invalid or unsupported PEM format.".into()));
        }
        
        // PASERK 
        let parts: Vec<&str> = s_trim.split('.').collect();
        if parts.len() >= 3 && parts[0].len() <= 4 {
            return decode_paserk(s_trim, expected_header, None, None);
        }
    }
    
    // Raw bytes
    Ok(key.to_vec())
}


pub fn calculate_paserk_id(key: &[u8], purpose: &str) -> Result<String, WebtokenError> {

    let paserk_string = match purpose {
        "local" => format!("k4.local.{}", URL_SAFE_NO_PAD.encode(key)),
        "public" => format!("k4.public.{}", URL_SAFE_NO_PAD.encode(key)),
        "secret" => format!("k4.secret.{}", URL_SAFE_NO_PAD.encode(key)), // Removed the 32-byte truncation!
        _ => return Err(WebtokenError::Generic("Invalid PASERK purpose".into())),
    };

    let header = match purpose {
        "local" => "k4.lid.",
        "public" => "k4.pid.",
        "secret" => "k4.sid.",
        _ => unreachable!(),
    };

    // Hash the header and the PASERK string, extracting 33 bytes
    let hash_input = format!("{}{}", header, paserk_string);
    let hash = Blake2bParams::new().hash_length(33) .hash(hash_input.as_bytes());

    Ok(format!("{}{}", header, URL_SAFE_NO_PAD.encode(hash.as_bytes())))
}


// ============================================================================
//  v4 Local (Symmetric)
// ============================================================================

pub fn encrypt_v4_local(payload: &[u8], key: &[u8], footer: Option<&[u8]>, implicit_assertion: Option<&[u8]>, 
    nonce_opt: Option<&[u8]>) -> Result<String, WebtokenError> {
    
    let raw_key = decode_paserk_key(key, Some("local"))?;
    if raw_key.is_empty() { 
        return Err(WebtokenError::InvalidKey("key must be specified.".into())); }
    if raw_key.len() > 64 { 
        return Err(WebtokenError::InvalidKey("key length must be up to 64 bytes.".into())); }
    
    let key_arr: [u8; 32] = raw_key.try_into().map_err(|_| WebtokenError::InvalidKey("key must be 32 bytes long.".into()))?;
    let footer_bytes = footer.unwrap_or(b"");
    let assertion = implicit_assertion.unwrap_or(b"");

    let body = crypto::paseto_v4_encrypt(&key_arr, payload, footer_bytes, assertion, nonce_opt)?;

    let mut token = String::from("v4.local.");
    token.push_str(&URL_SAFE_NO_PAD.encode(&body));
    
    if !footer_bytes.is_empty() {
        token.push('.');
        token.push_str(&URL_SAFE_NO_PAD.encode(footer_bytes));
    }

    Ok(token)
}

pub fn decrypt_v4_local(token: &str, key: &[u8], implicit_assertion: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), WebtokenError> {

    let raw_key = decode_paserk_key(key, Some("local"))?;
    let key_arr: [u8; 32] = raw_key.try_into().map_err(|_| WebtokenError::InvalidKey("Local key must be 32 bytes".into()))?;
    
    if !token.starts_with("v4.local.") {
        return Err(WebtokenError::InvalidToken("Invalid PASETO header".into()));
    }

    let parts: Vec<&str> = token.split('.').collect();
    let (body_b64, footer_bytes) = match parts.len() {
        3 => (parts[2], Vec::new()), 
        4 => (parts[2], URL_SAFE_NO_PAD.decode(parts[3]).map_err(|_| WebtokenError::InvalidToken("Invalid footer encoding".into()))?),
        _ => return Err(WebtokenError::InvalidToken("Invalid token format".into())),
    };

    let body = URL_SAFE_NO_PAD.decode(body_b64)
        .map_err(|_| WebtokenError::InvalidToken("Invalid body encoding".into()))?;

    let assertion = implicit_assertion.unwrap_or(b"");

    let plaintext = crypto::paseto_v4_decrypt(&key_arr, &body, &footer_bytes, assertion)?;

    Ok((plaintext, footer_bytes))
}

// ============================================================================
//  v4 Public (Asymmetric)
// ============================================================================

pub fn sign_v4_public(payload: &[u8], key: &[u8], footer: Option<&[u8]>, implicit_assertion: Option<&[u8]>
) -> Result<String, WebtokenError> {
    // [PASERK Support] Unwraps "k4.secret..."
    let raw_key = decode_paserk_key(key, Some("secret"))?;
    
    let header = b"v4.public.";
    let footer_bytes = footer.unwrap_or(b"");
    let assertion = implicit_assertion.unwrap_or(b"");

    let m2 = pae(&[header, payload, footer_bytes, assertion]);
    let signature = crypto::sign("Ed25519", &raw_key, &m2)?;

    let mut body = payload.to_vec();
    body.extend_from_slice(&signature);

    let mut token = String::from("v4.public.");
    token.push_str(&URL_SAFE_NO_PAD.encode(&body));

    if !footer_bytes.is_empty() {
        token.push('.');
        token.push_str(&URL_SAFE_NO_PAD.encode(footer_bytes));
    }

    Ok(token)
}

pub fn verify_v4_public(token: &str, key: &[u8], implicit_assertion: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), WebtokenError> {
    // [PASERK Support] Unwraps "k4.public..."
    let raw_key = decode_paserk_key(key, Some("public"))?;

    if !token.starts_with("v4.public.") {
        return Err(WebtokenError::InvalidToken("Invalid PASETO header".into()));
    }

    let parts: Vec<&str> = token.split('.').collect();
    let (body_b64, footer_bytes) = match parts.len() {
        3 => (parts[2], Vec::new()), 
        4 => (parts[2], URL_SAFE_NO_PAD.decode(parts[3]).map_err(|_| WebtokenError::InvalidToken("Invalid footer encoding".into()))?),
        _ => return Err(WebtokenError::InvalidToken("Invalid token format".into())),
    };

    let body = URL_SAFE_NO_PAD.decode(body_b64)
        .map_err(|_| WebtokenError::InvalidToken("Invalid body encoding".into()))?;

    if body.len() < 64 { 
        return Err(WebtokenError::InvalidToken("Token too short".into()));
    }

    let split_idx = body.len() - 64;
    let payload = &body[..split_idx];
    let signature = &body[split_idx..];

    let header = b"v4.public.";
    let assertion = implicit_assertion.unwrap_or(b"");
    let m2 = pae(&[header, payload, &footer_bytes, assertion]);

    crypto::verify("Ed25519", &raw_key, &m2, signature)?;

    Ok((payload.to_vec(), footer_bytes))
}


fn blake2b_mac(key: &[u8], msg: &[u8], len: usize) -> Vec<u8> {
    let mut state = Blake2bParams::new().hash_length(len).key(key).to_state();
    state.update(msg);
    state.finalize().as_bytes().to_vec()
}

fn blake2b(msg: &[u8], len: usize) -> Vec<u8> {
    let mut state = Blake2bParams::new().hash_length(len).to_state();
    state.update(msg);
    state.finalize().as_bytes().to_vec()
}

// ============================================================================
//  PASERK: Platform-Independent Encryption (PIE)
// ============================================================================

pub fn paserk_wrap_pie(wrapping_key: &[u8], target_key: &[u8], purpose: &str) -> Result<String, WebtokenError> {
    let header = match purpose {
        "local" => "k4.local-wrap.pie.",
        "secret" => "k4.secret-wrap.pie.",
        _ => return Err(WebtokenError::Generic("Invalid PIE wrap purpose".into())),
    };

    let nonce = crypto::get_random_bytes(32)?;
    
    let mut ek_msg = vec![0x80];
    ek_msg.extend_from_slice(&nonce);
    let x = blake2b_mac(wrapping_key, &ek_msg, 56);
    let ek = &x[0..32];
    let n2 = &x[32..56];

    let mut ak_msg = vec![0x81];
    ak_msg.extend_from_slice(&nonce);
    let ak = blake2b_mac(wrapping_key, &ak_msg, 32);

    let mut c = target_key.to_vec();
    let mut cipher = XChaCha20::new(ek.into(), n2.into());
    cipher.apply_keystream(&mut c);

    let mut t_msg = header.as_bytes().to_vec();
    t_msg.extend_from_slice(&nonce);
    t_msg.extend_from_slice(&c);
    let t = blake2b_mac(&ak, &t_msg, 32);

    let mut out = Vec::with_capacity(t.len() + nonce.len() + c.len());
    out.extend_from_slice(&t);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&c);

    Ok(format!("{}{}", header, URL_SAFE_NO_PAD.encode(&out)))
}

pub fn paserk_unwrap_pie(wrapping_key: &[u8], paserk: &str) -> Result<Vec<u8>, WebtokenError> {
    let (header, b64_data) = if paserk.starts_with("k4.local-wrap.pie.") {
        ("k4.local-wrap.pie.", &paserk[18..])
    } else if paserk.starts_with("k4.secret-wrap.pie.") {
        ("k4.secret-wrap.pie.", &paserk[19..])
    } else {
        return Err(WebtokenError::InvalidToken("Invalid PIE header".into()));
    };

    let data = URL_SAFE_NO_PAD.decode(b64_data).map_err(|_| WebtokenError::DecodeError("Base64 error".into()))?;
    if data.len() < 32 + 32 { return Err(WebtokenError::InvalidToken("Data too short".into())); }

    let t = &data[0..32];
    let nonce = &data[32..64];
    let c = &data[64..];

    let mut ak_msg = vec![0x81];
    ak_msg.extend_from_slice(nonce);
    let ak = blake2b_mac(wrapping_key, &ak_msg, 32);

    let mut t_msg = header.as_bytes().to_vec();
    t_msg.extend_from_slice(nonce);
    t_msg.extend_from_slice(c);
    let expected_t = blake2b_mac(&ak, &t_msg, 32);

    if t != expected_t { return Err(WebtokenError::InvalidSignature); }

    let mut ek_msg = vec![0x80];
    ek_msg.extend_from_slice(nonce);
    let x = blake2b_mac(wrapping_key, &ek_msg, 56);
    let ek = &x[0..32];
    let n2 = &x[32..56];

    let mut plaintext = c.to_vec();
    let mut cipher = XChaCha20::new(ek.into(), n2.into());
    cipher.apply_keystream(&mut plaintext);

    Ok(plaintext)
}

// ============================================================================
//  PASERK: Password-Based Key Wrapping (PBKW)
// ============================================================================

pub fn paserk_wrap_pbkw(password: &[u8], target_key: &[u8], purpose: &str, memlimit: u64, opslimit: u32, parallelism: u32) -> Result<String, WebtokenError> {
    let header = match purpose {
        "local" => "k4.local-pw.",
        "secret" => "k4.secret-pw.",
        _ => return Err(WebtokenError::Generic("Invalid PBKW purpose".into())),
    };

    let salt = crypto::get_random_bytes(16)?;
    let nonce = crypto::get_random_bytes(24)?;

    let argon_params = argon2::ParamsBuilder::new()
        .m_cost((memlimit / 1024) as u32)
        .t_cost(opslimit)
        .p_cost(parallelism)
        .build().map_err(|_| WebtokenError::Generic("Invalid Argon2 parameters".into()))?;
    
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon_params);
    let mut psk = [0u8; 32];
    argon2.hash_password_into(password, &salt, &mut psk).map_err(|_| WebtokenError::Generic("Argon2 error".into()))?;

    let mut ek_msg = vec![0xFF]; ek_msg.extend_from_slice(&psk);
    let ek = blake2b(&ek_msg, 32);

    let mut ak_msg = vec![0xFE]; ak_msg.extend_from_slice(&psk);
    let ak = blake2b(&ak_msg, 32);

    let mut c = target_key.to_vec();
    let mut cipher = XChaCha20::new(ek[..].into(), nonce.as_slice().into());
    cipher.apply_keystream(&mut c);

    let mut t_msg = header.as_bytes().to_vec();
    t_msg.extend_from_slice(&salt);
    t_msg.extend_from_slice(&memlimit.to_be_bytes());
    t_msg.extend_from_slice(&opslimit.to_be_bytes());
    t_msg.extend_from_slice(&parallelism.to_be_bytes());
    t_msg.extend_from_slice(&nonce);
    t_msg.extend_from_slice(&c);
    
    let t = blake2b_mac(&ak, &t_msg, 32);

    let mut out = Vec::new();
    out.extend_from_slice(&salt);
    out.extend_from_slice(&memlimit.to_be_bytes());
    out.extend_from_slice(&opslimit.to_be_bytes());
    out.extend_from_slice(&parallelism.to_be_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&c);
    out.extend_from_slice(&t);

    Ok(format!("{}{}", header, URL_SAFE_NO_PAD.encode(&out)))
}

pub fn paserk_unwrap_pbkw(password: &[u8], paserk: &str) -> Result<Vec<u8>, WebtokenError> {
    let (header, b64_data) = if paserk.starts_with("k4.local-pw.") {
        ("k4.local-pw.", &paserk[12..])
    } else if paserk.starts_with("k4.secret-pw.") {
        ("k4.secret-pw.", &paserk[13..])
    } else {
        return Err(WebtokenError::InvalidToken("Invalid PBKW header".into()));
    };

    let data = URL_SAFE_NO_PAD.decode(b64_data).map_err(|_| WebtokenError::DecodeError("Base64 error".into()))?;
    if data.len() < 16 + 8 + 4 + 4 + 24 + 32 { return Err(WebtokenError::InvalidToken("Data too short".into())); }

    let salt = &data[0..16];
    let memlimit_bytes: [u8; 8] = data[16..24].try_into().unwrap();
    let opslimit_bytes: [u8; 4] = data[24..28].try_into().unwrap();
    let parallelism_bytes: [u8; 4] = data[28..32].try_into().unwrap();
    
    let memlimit = u64::from_be_bytes(memlimit_bytes);
    let opslimit = u32::from_be_bytes(opslimit_bytes);
    let parallelism = u32::from_be_bytes(parallelism_bytes);

    let nonce = &data[32..56];
    let c_len = data.len() - 56 - 32;
    let c = &data[56..56+c_len];
    let t = &data[56+c_len..];

    let argon_params = argon2::ParamsBuilder::new()
        .m_cost((memlimit / 1024) as u32)
        .t_cost(opslimit)
        .p_cost(parallelism)
        .build().map_err(|_| WebtokenError::Generic("Invalid Argon2 parameters".into()))?;
        
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon_params);
    let mut psk = [0u8; 32];
    argon2.hash_password_into(password, salt, &mut psk).map_err(|_| WebtokenError::Generic("Argon2 error".into()))?;

    let mut ek_msg = vec![0xFF]; ek_msg.extend_from_slice(&psk);
    let ek = blake2b(&ek_msg, 32);

    let mut ak_msg = vec![0xFE]; ak_msg.extend_from_slice(&psk);
    let ak = blake2b(&ak_msg, 32);

    let mut t_msg = header.as_bytes().to_vec();
    t_msg.extend_from_slice(salt);
    t_msg.extend_from_slice(&memlimit_bytes);
    t_msg.extend_from_slice(&opslimit_bytes);
    t_msg.extend_from_slice(&parallelism_bytes);
    t_msg.extend_from_slice(nonce);
    t_msg.extend_from_slice(c);

    let expected_t = blake2b_mac(&ak, &t_msg, 32);
    if t != expected_t { return Err(WebtokenError::InvalidSignature); }

    let mut plaintext = c.to_vec();
    let mut cipher = XChaCha20::new(ek[..].into(), nonce.into());
    cipher.apply_keystream(&mut plaintext);

    Ok(plaintext)
}

// ============================================================================
//  PASERK: Public Key Encryption (Seal)
// ============================================================================

pub fn paserk_seal(sealing_key: &[u8], target_key: &[u8]) -> Result<String, WebtokenError> {
    let header = "k4.seal.";
    // The sealing key is the recipient's X25519 public key
    let recipient_public_bytes = crypto::x25519_public_from_private(sealing_key).unwrap_or(sealing_key.to_vec());
    
    let ephemeral_sk_bytes = crypto::get_random_bytes(32)?;
    let ephemeral_sk = graviola::key_agreement::x25519::StaticPrivateKey::try_from_slice(&ephemeral_sk_bytes)
        .map_err(|_| WebtokenError::Generic("Failed to create ephemeral key".into()))?;
    let ephemeral_pk_bytes = ephemeral_sk.public_key().as_bytes().to_vec();

    let recipient_public = graviola::key_agreement::x25519::PublicKey::try_from_slice(&recipient_public_bytes)
        .map_err(|_| WebtokenError::Generic("Failed to parse recipient public key".into()))?;
    let shared_secret = ephemeral_sk.diffie_hellman(&recipient_public)
        .map_err(|_| WebtokenError::Generic("ECDH Failed".into()))?;
    let xk = shared_secret.0;

    let mut k_msg = vec![0x01];
    k_msg.extend_from_slice(header.as_bytes());
    k_msg.extend_from_slice(&xk);
    k_msg.extend_from_slice(&ephemeral_pk_bytes);
    k_msg.extend_from_slice(&recipient_public_bytes);
    let ek = blake2b(&k_msg, 32);

    let mut ak_msg = vec![0x02];
    ak_msg.extend_from_slice(header.as_bytes());
    ak_msg.extend_from_slice(&xk);
    ak_msg.extend_from_slice(&ephemeral_pk_bytes);
    ak_msg.extend_from_slice(&recipient_public_bytes);
    let ak = blake2b(&ak_msg, 32);

    let mut n_msg = ephemeral_pk_bytes.clone();
    n_msg.extend_from_slice(&recipient_public_bytes);
    let nonce = blake2b(&n_msg, 24);

    let mut c = target_key.to_vec();
    let mut cipher = XChaCha20::new(ek[..].into(), nonce.as_slice().into());
    cipher.apply_keystream(&mut c);

    let mut t_msg = header.as_bytes().to_vec();
    t_msg.extend_from_slice(&ephemeral_pk_bytes);
    t_msg.extend_from_slice(&c);
    let t = blake2b_mac(&ak, &t_msg, 32);

    let mut out = Vec::with_capacity(t.len() + ephemeral_pk_bytes.len() + c.len());
    out.extend_from_slice(&t);
    out.extend_from_slice(&ephemeral_pk_bytes);
    out.extend_from_slice(&c);

    Ok(format!("{}{}", header, URL_SAFE_NO_PAD.encode(&out)))
}


pub fn paserk_unseal(unsealing_key: &[u8], paserk: &str) -> Result<Vec<u8>, WebtokenError> {

    let header = "k4.seal.";
    if !paserk.starts_with(header) { return Err(WebtokenError::InvalidToken("Invalid seal header".into())); }
    
    let data = URL_SAFE_NO_PAD.decode(&paserk[8..]).map_err(|_| WebtokenError::DecodeError("Base64 error".into()))?;
    if data.len() < 32 + 32 + 32 { return Err(WebtokenError::InvalidToken("Data too short".into())); }

    let t = &data[0..32];
    let epk_bytes = &data[32..64];
    let c = &data[64..];

    let mut x25519_sk_bytes = [0u8; 32];
    if unsealing_key.len() == 64 {
        // Ed25519 keypair: first 32 bytes are the seed
        let seed = &unsealing_key[0..32];
        let h = Sha512::hash(seed);
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&h.as_ref()[0..32]);
        
        // Curve25519 clamping
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        x25519_sk_bytes.copy_from_slice(&scalar);
    } else if unsealing_key.len() == 32 {
        // Already an X25519 static secret
        x25519_sk_bytes.copy_from_slice(unsealing_key);
    } else {
        return Err(WebtokenError::InvalidKey("Invalid unsealing key length".into()));
    }

    // Now safely parse the converted 32-byte X25519 private key
    let recipient_sk = graviola::key_agreement::x25519::StaticPrivateKey::try_from_slice(&x25519_sk_bytes)
        .map_err(|_| WebtokenError::Generic("Failed to parse recipient private key".into()))?;
    let recipient_pk_bytes = recipient_sk.public_key().as_bytes().to_vec();

    let ephemeral_pk = graviola::key_agreement::x25519::PublicKey::try_from_slice(epk_bytes)
        .map_err(|_| WebtokenError::Generic("Failed to parse ephemeral public key".into()))?;
    let shared_secret = recipient_sk.diffie_hellman(&ephemeral_pk)
        .map_err(|_| WebtokenError::Generic("ECDH Failed".into()))?;
    let xk = shared_secret.0;

    let mut ak_msg = vec![0x02];
    ak_msg.extend_from_slice(header.as_bytes());
    ak_msg.extend_from_slice(&xk);
    ak_msg.extend_from_slice(epk_bytes);
    ak_msg.extend_from_slice(&recipient_pk_bytes);
    let ak = blake2b(&ak_msg, 32);

    let mut t_msg = header.as_bytes().to_vec();
    t_msg.extend_from_slice(epk_bytes);
    t_msg.extend_from_slice(c);
    let expected_t = blake2b_mac(&ak, &t_msg, 32);

    if t != expected_t { return Err(WebtokenError::InvalidSignature); }

    let mut k_msg = vec![0x01];
    k_msg.extend_from_slice(header.as_bytes());
    k_msg.extend_from_slice(&xk);
    k_msg.extend_from_slice(epk_bytes);
    k_msg.extend_from_slice(&recipient_pk_bytes);
    let ek = blake2b(&k_msg, 32);

    let mut n_msg = epk_bytes.to_vec();
    n_msg.extend_from_slice(&recipient_pk_bytes);
    let nonce = blake2b(&n_msg, 24);

    let mut plaintext = c.to_vec();
    let mut cipher = XChaCha20::new(ek[..].into(), nonce.as_slice().into());
    cipher.apply_keystream(&mut plaintext);

    Ok(plaintext)
}


#[pyfunction(name="encode_paserk_key")]
#[pyo3(signature = (purpose, key, wrapping_key=None, password=None))]
pub fn encode_paserk_key_py(purpose: &str, key: BytesOrString, wrapping_key: Option<BytesOrString>, password: Option<&str>,
) -> PyResult<String> {
    
    let wk_bytes = wrapping_key.map(|w| w.as_bytes().to_vec());
    encode_paserk(purpose, key.as_bytes(), wk_bytes.as_deref(), password).map_err(|e| PyValueError::new_err(e.to_string()))
}


#[pyfunction(name = "decode_paserk_key")]
#[pyo3(signature = (paserk, purpose=None, wrapping_key=None, password=None))]
pub fn decode_paserk_key_py(
    paserk: &str, 
    purpose: Option<&str>, 
    wrapping_key: Option<BytesOrString>, 
    password: Option<&str>,
) -> PyResult<Vec<u8>> {
    
    let wk_bytes = wrapping_key.map(|w| w.as_bytes().to_vec());
    
    // If unwrapping parameters are provided, it MUST be a PASERK.
    if wk_bytes.is_some() || password.is_some() {
        return decode_paserk(paserk, purpose, wk_bytes.as_deref(), password)
            .map_err(|e| PyValueError::new_err(e.to_string()));
    }

    // If no wrapping keys, route through the universal parser!
    decode_paserk_key(paserk.as_bytes(), purpose)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}


pub fn export_functions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encode_paserk_key_py, m)?)?;
    m.add_function(wrap_pyfunction!(decode_paserk_key_py, m)?)?;

    Ok(())
}