use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use graviola::hashing::{Sha512, Hash};
use blake2b_simd::Params as Blake2bParams; 
use chacha20::{XChaCha20, cipher::{KeyIvInit, StreamCipher}};
use argon2::{Argon2, Algorithm, Version, Params};
use subtle::ConstantTimeEq;

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

use crate::{BytesOrString, WebtokenError, crypto, crypto_parsing, key_utils, jwk};

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

pub fn encode_paserk(
    purpose: &str, key_bytes: &[u8], wrapping_key: Option<&[u8]>, password: Option<&str>, sealing_key: Option<&[u8]>,
) -> Result<String, WebtokenError> {
    
    if wrapping_key.is_some() && password.is_some() {
        return Err(WebtokenError::InvalidKey("Only one of wrapping_key or password should be specified.".into()));
    }

    if purpose == "public" && (wrapping_key.is_some() || password.is_some()) {
        return Err(WebtokenError::InvalidKey("Public key cannot be wrapped.".into()));
    }

    let mut key_bytes = key_bytes.to_vec();

    match purpose {
        "local" => {
            if key_bytes.len() != 32 { 
                return Err(WebtokenError::InvalidKey("Invalid key length for local".into())); 
            }
        },
        "public" => {
            if key_bytes.len() != 32 {
                return Err(WebtokenError::InvalidKey("Invalid key length for public".into()));
            }
        },
        "secret" => {
            if key_bytes.len() == 32 {
                // Spec requires 64 bytes for k4.secret. Deriving the public key and appending it
                let pub_key = crate::crypto::ed25519_public_from_seed(&key_bytes)?;
                key_bytes.extend_from_slice(&pub_key);
            } else if key_bytes.len() != 64 {
                return Err(WebtokenError::InvalidKey("Invalid key length for secret".into()));
            }
        },
        _ => return Err(WebtokenError::InvalidKey(format!("Invalid purpose: {}.", purpose))),
    };

    // Password Wrapping (PBKW)
    if let Some(pwd) = password {        
        let header_str = format!("k4.{}-pw.", purpose);
        let h = header_str.as_bytes();
        
        // Initialize the aws-lc-rs random number generator
        let rng = SystemRandom::new();
        
        let mut s = [0u8; 16];
        rng.fill(&mut s).map_err(|_| WebtokenError::InvalidKey("RNG failed".into()))?;
        
        // Standard secure defaults for encoding
        let m_cost_kib: u32 = 65536; // 64 MB
        let t_cost: u32 = 2;
        let p_cost: u32 = 1;
        
        let params = Params::new(m_cost_kib, t_cost, p_cost, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        
        let mut k = [0u8; 32];
        argon2.hash_password_into(pwd.as_bytes(), &s, &mut k)
            .map_err(|_| WebtokenError::InvalidKey("Argon2 hash failed".into()))?;
            
        let mut ek_msg = vec![0xff];
        ek_msg.extend_from_slice(&k);
        let ek = Blake2bParams::new().hash_length(32).hash(&ek_msg);
        
        let mut ak_msg = vec![0xfe];
        ak_msg.extend_from_slice(&k);
        let ak = Blake2bParams::new().hash_length(32).hash(&ak_msg);
        
        let mut n = [0u8; 24];
        // Use aws-lc-rs for the ChaCha20 nonce as well
        rng.fill(&mut n).map_err(|_| WebtokenError::InvalidKey("RNG failed".into()))?;
        
        let mut edk = key_bytes.clone();
        let mut cipher = XChaCha20::new_from_slices(ek.as_bytes(), &n).unwrap();
        cipher.apply_keystream(&mut edk);
        
        let mem = ((m_cost_kib as u64) * 1024).to_be_bytes();
        let time = t_cost.to_be_bytes();
        let para = p_cost.to_be_bytes();
        
        let mut pre_auth = h.to_vec();
        pre_auth.extend_from_slice(&s);
        pre_auth.extend_from_slice(&mem);
        pre_auth.extend_from_slice(&time);
        pre_auth.extend_from_slice(&para);
        pre_auth.extend_from_slice(&n);
        pre_auth.extend_from_slice(&edk);
        
        let t = Blake2bParams::new().hash_length(32).key(ak.as_bytes()).hash(&pre_auth);
        
        let mut out = s.to_vec();
        out.extend_from_slice(&mem);
        out.extend_from_slice(&time);
        out.extend_from_slice(&para);
        out.extend_from_slice(&n);
        out.extend_from_slice(&edk);
        out.extend_from_slice(t.as_bytes());
        
        return Ok(format!("{}{}", header_str, base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out)));
    }

    // Sealing (PKE via X25519)
    if let Some(xpk_input) = sealing_key {
        if purpose != "local" {
            return Err(WebtokenError::InvalidKey("Key sealing can only be used for local key.".into()));
        }

        // Extract raw 32 bytes from potential PEM/DER wrapper
        let xpk_vec = crypto_parsing::extract_x25519_bytes(xpk_input)?;
        let xpk = xpk_vec.as_slice();
        
        let header_str = format!("k4.seal.");
        let h = header_str.as_bytes();
        
        // Generate Ephemeral X25519 Keypair
        let esk = crypto::get_random_bytes(32)?;
        let epk = crypto::x25519_public_from_private(&esk)?;
        let xk = crypto::x25519_derive(&esk, xpk)?;
        
        // Derive Encryption Key (ek)
        let mut ek_msg = vec![0x01];
        ek_msg.extend_from_slice(h);
        ek_msg.extend_from_slice(&xk);
        ek_msg.extend_from_slice(&epk);
        ek_msg.extend_from_slice(xpk);
        let ek = Blake2bParams::new().hash_length(32).hash(&ek_msg);
        
        // Derive Auth Key (ak)
        let mut ak_msg = vec![0x02];
        ak_msg.extend_from_slice(h);
        ak_msg.extend_from_slice(&xk);
        ak_msg.extend_from_slice(&epk);
        ak_msg.extend_from_slice(xpk);
        let ak = Blake2bParams::new().hash_length(32).hash(&ak_msg);
        
        // Derive Nonce (n)
        let mut n_msg = epk.clone();
        n_msg.extend_from_slice(xpk);
        let n = Blake2bParams::new().hash_length(24).hash(&n_msg);
        
        // Encrypt the local key
        let mut edk = key_bytes.clone();
        let mut cipher = XChaCha20::new_from_slices(ek.as_bytes(), n.as_bytes()).unwrap();
        cipher.apply_keystream(&mut edk);
        
        // MAC Tag
        let mut pre_auth = h.to_vec();
        pre_auth.extend_from_slice(&epk);
        pre_auth.extend_from_slice(&edk);
        let t = Blake2bParams::new().hash_length(32).key(ak.as_bytes()).hash(&pre_auth);
        
        // Assemble output
        let mut out = t.as_bytes().to_vec();
        out.extend_from_slice(&epk);
        out.extend_from_slice(&edk);
        
        return Ok(format!("{}{}", header_str, base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out)));
    }

    // PIE wrapping
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
        let mut cipher = XChaCha20::new_from_slices(&ek, &n2).unwrap();
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
    
    if password.is_some() {
        let header_str = format!("k4.{}-pw.", purpose);
        return Ok(format!("{}DUMMY_ENCRYPTED_PAYLOAD", header_str));
    }

    let prefix = format!("k4.{}.", purpose);
    Ok(format!("{}{}", prefix, base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_bytes)))
}


pub fn decode_paserk(
    paserk: &str, purpose: Option<&str>, wrapping_key: Option<&[u8]>, password: Option<&str>, unsealing_key: Option<&[u8]>
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
    let is_seal = parts[1] == "seal";

    // PIE Decoding
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
            let mut cipher = XChaCha20::new_from_slices(&ek, &n2).unwrap();
            cipher.apply_keystream(&mut ptk);

            return Ok(ptk);
        } else {
            return Err(WebtokenError::InvalidKey("Failed to unwrap a key.".into())); 
        }
        
    // Password Decoding (Temporarily adding prints to inspect the 26-byte prefix)
    } else if is_pw {
        if parts.len() != 3 {
            return Err(WebtokenError::InvalidKey("Invalid PASERK format.".into()));
        }
        
        let parsed_purpose = if parts[1] == "local-pw" { "local" } else { "secret" };
        
        if let Some(p) = purpose {
            if p != parsed_purpose {
                return Err(WebtokenError::InvalidKey(format!("Invalid PASERK type: {}.", parsed_purpose)));
            }
        }
        
        let password_str = password.ok_or_else(|| {
            WebtokenError::InvalidKey(format!("{} needs password.", parts[1]))
        })?;

        let header_str = format!("k4.{}.", parts[1]);
        let d = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2])
            .map_err(|_| WebtokenError::InvalidKey("Invalid Base64".into()))?;

        // 16(salt) + 8(mem) + 4(time) + 4(para) + 24(nonce) + 32(edk_min) + 32(tag) = 120 bytes minimum
        if d.len() < 120 {
            return Err(WebtokenError::InvalidKey("Failed to unwrap a key.".into()));
        }

        let s = &d[0..16];
        let mem = &d[16..24];
        let time = &d[24..28];
        let para = &d[28..32];
        let n = &d[32..56];
        let edk = &d[56..d.len() - 32];
        let t = &d[d.len() - 32..];

        // Argon2 strictly uses KiB, but the PASERK spec encodes bytes, so we divide by 1024
        let memory_cost = u64::from_be_bytes(mem.try_into().unwrap());
        let m_cost_kib = (memory_cost / 1024) as u32;
        let t_cost = u32::from_be_bytes(time.try_into().unwrap());
        let p_cost = u32::from_be_bytes(para.try_into().unwrap());

        let params = Params::new(m_cost_kib, t_cost, p_cost, Some(32))
            .map_err(|_| WebtokenError::InvalidKey("Invalid Argon2 parameters".into()))?;
        
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut k = [0u8; 32];
        argon2.hash_password_into(password_str.as_bytes(), s, &mut k)
            .map_err(|_| WebtokenError::InvalidKey("Argon2 hash failed".into()))?;

        // Derive ak (Authentication Key)
        let mut ak_msg = vec![0xfe];
        ak_msg.extend_from_slice(&k);
        let ak = Blake2bParams::new().hash_length(32).hash(&ak_msg);

        // Verify MAC Tag
        let mut pre_auth = header_str.as_bytes().to_vec();
        pre_auth.extend_from_slice(s);
        pre_auth.extend_from_slice(mem);
        pre_auth.extend_from_slice(time);
        pre_auth.extend_from_slice(para);
        pre_auth.extend_from_slice(n);
        pre_auth.extend_from_slice(edk);

        let t2 = Blake2bParams::new().hash_length(32).key(ak.as_bytes()).hash(&pre_auth);
        
        if t.ct_eq(t2.as_bytes()).unwrap_u8() != 1 {
            return Err(WebtokenError::InvalidKey("Failed to unwrap a key.".into()));
        }

        // Derive ek (Encryption Key)
        let mut ek_msg = vec![0xff];
        ek_msg.extend_from_slice(&k);
        let ek = Blake2bParams::new().hash_length(32).hash(&ek_msg);

        // Decrypt the payload using ChaCha20
        let mut ptk = edk.to_vec();
        let mut cipher = XChaCha20::new_from_slices(ek.as_bytes(), n.into()).unwrap();
        cipher.apply_keystream(&mut ptk);

        return Ok(ptk);
        
    // Seal Decoding (PKE via X25519)
    } else if is_seal {
        let xsk_input = unsealing_key.ok_or_else(|| WebtokenError::InvalidKey("seal needs unsealing_key.".into()))?;
        
        // Extract raw 32 bytes from potential PEM/DER wrapper
        let xsk_vec = crypto_parsing::extract_x25519_bytes(xsk_input)?;
        let xsk = xsk_vec.as_slice();
        
        let header_str = format!("k4.seal.");
        let h = header_str.as_bytes();
        let data = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2])
            .map_err(|_| WebtokenError::InvalidKey("Invalid Base64".into()))?;
            
        if data.len() < 96 {
            return Err(WebtokenError::InvalidKey("Failed to unseal a key.".into()));
        }
        
        let t = &data[0..32];
        let epk = &data[32..64];
        let edk = &data[64..];
        
        let xpk = crate::crypto::x25519_public_from_private(xsk)?;
        let xk = crate::crypto::x25519_derive(xsk, epk)?;
        
        // Verify MAC tag first!
        let mut ak_msg = vec![0x02];
        ak_msg.extend_from_slice(h);
        ak_msg.extend_from_slice(&xk);
        ak_msg.extend_from_slice(epk);
        ak_msg.extend_from_slice(&xpk);
        let ak = Blake2bParams::new().hash_length(32).hash(&ak_msg);
        
        let mut pre_auth = h.to_vec();
        pre_auth.extend_from_slice(epk);
        pre_auth.extend_from_slice(edk);
        let t2 = Blake2bParams::new().hash_length(32).key(ak.as_bytes()).hash(&pre_auth);
        
        use subtle::ConstantTimeEq;
        if t.ct_eq(t2.as_bytes()).unwrap_u8() != 1 {
            return Err(WebtokenError::InvalidKey("Failed to unseal a key.".into()));
        }
        
        // Derive ek and n
        let mut ek_msg = vec![0x01];
        ek_msg.extend_from_slice(h);
        ek_msg.extend_from_slice(&xk);
        ek_msg.extend_from_slice(epk);
        ek_msg.extend_from_slice(&xpk);
        let ek = Blake2bParams::new().hash_length(32).hash(&ek_msg);
        
        let mut n_msg = epk.to_vec();
        n_msg.extend_from_slice(&xpk);
        let n = Blake2bParams::new().hash_length(24).hash(&n_msg);
        
        // Decrypt the local key
        let mut ptk = edk.to_vec();
        let mut cipher = XChaCha20::new_from_slices(ek.as_bytes(), n.as_bytes().into()).unwrap();
        cipher.apply_keystream(&mut ptk);
        
        return Ok(ptk);
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
            return decode_paserk(s_trim, expected_header, None, None, None);
        }
    }
    
    // Raw bytes
    Ok(key.to_vec())
}


pub fn calculate_paserk_id(key: &[u8], purpose: &str) -> Result<String, WebtokenError> {

    let paserk_string = encode_paserk(purpose, key, None, None, None)?;

    let header = match purpose {
        "local" => "k4.lid.",
        "public" => "k4.pid.",
        "secret" => "k4.sid.",
        _ => return Err(WebtokenError::Generic("Invalid PASERK purpose".into())),
    };

    let hash_input = format!("{}{}", header, paserk_string);
    let hash = Blake2bParams::new().hash_length(33).hash(hash_input.as_bytes());

    Ok(format!("{}{}", header, URL_SAFE_NO_PAD.encode(hash.as_bytes())))
}


// ============================================================================
//  v4 Local (Symmetric)
// ============================================================================

#[pyfunction]
#[pyo3(signature = (payload, key, footer=None, implicit_assertion=None, nonce_opt=None))]
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
    let mut cipher = XChaCha20::new_from_slices(ek.into(), n2.into()).unwrap();
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
    let mut cipher = XChaCha20::new_from_slices(ek.into(), n2.into()).unwrap();
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
    let mut cipher = XChaCha20::new_from_slices(&ek, &nonce).unwrap();
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
    let mut cipher = XChaCha20::new_from_slices(&ek, nonce.into()).unwrap();
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
    let mut cipher = XChaCha20::new_from_slices(&ek, &nonce).unwrap();
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
    let mut cipher = XChaCha20::new_from_slices(&ek, &nonce).unwrap();
    cipher.apply_keystream(&mut plaintext);

    Ok(plaintext)
}


#[pyfunction(name="encode_paserk_key")]
#[pyo3(signature = (purpose, key, wrapping_key=None, password=None, sealing_key=None))]
pub fn encode_paserk_key_py(
    purpose: &str, key: BytesOrString, wrapping_key: Option<BytesOrString>, password: Option<&str>, sealing_key: Option<&[u8]>
) -> PyResult<String> {
    
    let wk_bytes = wrapping_key.map(|w| w.as_bytes().to_vec());
    encode_paserk(purpose, key.as_bytes(), wk_bytes.as_deref(), password, sealing_key).map_err(|e| PyValueError::new_err(e.to_string()))
}


#[pyfunction(name = "decode_paserk_key")]
#[pyo3(signature = (paserk, purpose=None, wrapping_key=None, password=None, unsealing_key=None))]
pub fn decode_paserk_key_py(
    paserk: BytesOrString, purpose: Option<&str>, wrapping_key: Option<BytesOrString>, password: Option<&str>, unsealing_key: Option<&[u8]>
) -> PyResult<Vec<u8>> {
    
    let wk_bytes = wrapping_key.map(|w| w.as_bytes().to_vec());
    
    // If unwrapping parameters are provided, it must be a PASERK.
    if wk_bytes.is_some() || password.is_some() || unsealing_key.is_some() {
        return decode_paserk(
            std::str::from_utf8(paserk.as_bytes()).unwrap(), purpose, wk_bytes.as_deref(), password, unsealing_key
        ).map_err(|e| PyValueError::new_err(e.to_string()));
    }

    // If no wrapping keys, route through the universal parser!
    decode_paserk_key(paserk.as_bytes(), purpose)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}


pub fn export_functions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encode_paserk_key_py, m)?)?;
    m.add_function(wrap_pyfunction!(decode_paserk_key_py, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_v4_local, m)?)?;

    Ok(())
}