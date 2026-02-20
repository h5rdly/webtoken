use serde_json::{Value, json};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crate::{WebtokenError, crypto, py_utils::decode_base64_permissive};
use std::borrow::Cow;
use std::io::{Read, Write};
use flate2::{read::DeflateDecoder, write::DeflateEncoder, Compression};

// ============================================================================
//  Key Management (ALG)
// ============================================================================

fn manage_cek_encrypt(alg: &str, enc: &str, key: &[u8], headers: &mut Value) -> Result<(Vec<u8>, Vec<u8>), WebtokenError> {
    let cek_len = get_cek_length(enc)?;
    
    match alg {
        "dir" => {
            if key.len() != cek_len {
                return Err(WebtokenError::InvalidToken(format!("Direct encryption requires key length {}, got {}", cek_len, key.len())));
            }
            Ok((key.to_vec(), vec![]))
        },
        "RSA1_5" => {
            let cek = crypto::get_random_bytes(cek_len)?;
            let encrypted_cek = crypto::rsa_encrypt_pkcs1(key, &cek)?;
            Ok((cek, encrypted_cek))
        },
        "RSA-OAEP" | "RSA-OAEP-256" | "RSA-OAEP-384" | "RSA-OAEP-512" => {
            let cek = crypto::get_random_bytes(cek_len)?;
            let encrypted_cek = crypto::rsa_encrypt_oaep(key, &cek, alg)?;
            Ok((cek, encrypted_cek))
        },
        "A128KW" | "A192KW" | "A256KW" => {
            let cek = crypto::get_random_bytes(cek_len)?;
            let encrypted_cek = crypto::aes_key_wrap(key, &cek)?;
            Ok((cek, encrypted_cek))
        },
        "ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A192KW" | "ECDH-ES+A256KW" => {
            // 1. Ephemeral Key
            let ephemeral_priv = crypto::get_random_bytes(32)?;
            let ephemeral_pub = crypto::x25519_public_from_private(&ephemeral_priv)?;
            
            // 2. Add EPK to header
            let epk_obj = json!({
                "kty": "OKP", "crv": "X25519", 
                "x": URL_SAFE_NO_PAD.encode(&ephemeral_pub)
            });
            if let Some(obj) = headers.as_object_mut() {
                obj.insert("epk".to_string(), epk_obj);
            }

            // 3. Derive Z
            let z = crypto::x25519_derive(&ephemeral_priv, key)?;
            
            // 4. Derive/Wrap
            if alg == "ECDH-ES" {
                let cek = crypto::concat_kdf_sha256(&z, (cek_len * 8) as u32, enc.as_bytes(), &[], &[]);
                Ok((cek, vec![]))
            } else {
                let wrap_alg = alg.split('+').nth(1).unwrap();
                let kek_len = get_key_wrap_length(wrap_alg)?;
                let kek = crypto::concat_kdf_sha256(&z, (kek_len * 8) as u32, wrap_alg.as_bytes(), &[], &[]);
                
                let cek = crypto::get_random_bytes(cek_len)?;
                let encrypted_cek = crypto::aes_key_wrap(&kek, &cek)?;
                Ok((cek, encrypted_cek))
            }
        },
        // PBES2-HS256+A128KW, etc.
        alg if alg.starts_with("PBES2-") => {
            let (p2s, p2c, kek_len) = prepare_pbes2_params_encrypt(alg, headers)?;
            let kek = derive_pbes2_kek(alg, key, &p2s, p2c, kek_len)?;
            
            let cek = crypto::get_random_bytes(cek_len)?;
            let encrypted_cek = crypto::aes_key_wrap(&kek, &cek)?;
            Ok((cek, encrypted_cek))
        },
        _ => Err(WebtokenError::UnsupportedAlgorithm(format!("Unknown alg: {}", alg).into()))
    }
}

fn manage_cek_decrypt(alg: &str, enc: &str, key: &[u8], encrypted_key: &[u8], headers: &Value) -> Result<Vec<u8>, WebtokenError> {
    let cek_len = get_cek_length(enc)?;

    match alg {
        "dir" => {
            if !encrypted_key.is_empty() { return Err(WebtokenError::InvalidToken("dir alg must have empty EK".into())); }
            Ok(key.to_vec())
        },
        "RSA1_5" => {
            crypto::rsa_decrypt_pkcs1(key, encrypted_key)
        },
        "RSA-OAEP" | "RSA-OAEP-256" | "RSA-OAEP-384" | "RSA-OAEP-512" => {
            crypto::rsa_decrypt_oaep(key, encrypted_key, alg)
        },
        "A128KW" | "A192KW" | "A256KW" => {
             crypto::aes_key_unwrap(key, encrypted_key)
        },
        alg if alg.starts_with("PBES2-") => {
            let (p2s, p2c, kek_len) = prepare_pbes2_params_decrypt(alg, headers)?;
            let kek = derive_pbes2_kek(alg, key, &p2s, p2c, kek_len)?;
            
            crypto::aes_key_unwrap(&kek, encrypted_key)
        },
        "ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A192KW" | "ECDH-ES+A256KW" => {
            let epk = headers.get("epk").ok_or_else(|| WebtokenError::InvalidToken("Missing epk".into()))?;
            let x_b64 = epk.get("x").and_then(|x| x.as_str()).ok_or_else(|| WebtokenError::InvalidToken("Invalid epk.x".into()))?;
            let sender_pub = decode_base64_permissive(x_b64.as_bytes()).map_err(|_| WebtokenError::InvalidToken("Invalid epk".into()))?;

            let z = crypto::x25519_derive(key, &sender_pub)?;

            if alg == "ECDH-ES" {
                Ok(crypto::concat_kdf_sha256(&z, (cek_len * 8) as u32, enc.as_bytes(), &[], &[]))
            } else {
                let wrap_alg = alg.split('+').nth(1).unwrap();
                let kek_len = get_key_wrap_length(wrap_alg)?;
                let kek = crypto::concat_kdf_sha256(&z, (kek_len * 8) as u32, wrap_alg.as_bytes(), &[], &[]);
                crypto::aes_key_unwrap(&kek, encrypted_key)
            }
        },
        _ => Err(WebtokenError::UnsupportedAlgorithm(format!("Unknown alg: {}", alg).into()))
    }
}

// ============================================================================
//  Content Encryption (ENC)
// ============================================================================

fn encrypt_content(enc: &str, cek: &[u8], payload: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), WebtokenError> {
    match enc {
        "A128GCM" | "A192GCM" | "A256GCM" => {
            let (ciphertext, tag, nonce) = crypto::aes_gcm_encrypt(cek, None, payload, aad)?;
            Ok((ciphertext, tag, nonce))
        },
        "XC20P" => {
            crypto::encrypt_xchacha20(cek, payload, aad, None)
        },
        "A128CBC-HS256" | "A192CBC-HS384" | "A256CBC-HS512" => {
            // Composite Logic: [ MAC_KEY | ENC_KEY ]
            let key_len = cek.len() / 2;
            let mac_key = &cek[0..key_len];
            let enc_key = &cek[key_len..];
            
            // CBC Encrypt
            let nonce = crypto::get_random_bytes(16)?; // CBC uses 16-byte IV
            let ciphertext = crypto::aes_cbc_encrypt(enc_key, &nonce, payload)?;

            // Calc AL (AAD Length in bits, 64-bit Big Endian)
            let al = ((aad.len() as u64) * 8).to_be_bytes();

            // HMAC Input: AAD || IV || Ciphertext || AL
            let mut mac_input = Vec::new();
            mac_input.extend_from_slice(aad);
            mac_input.extend_from_slice(&nonce);
            mac_input.extend_from_slice(&ciphertext);
            mac_input.extend_from_slice(&al);

            let hmac_alg = match enc {
                "A128CBC-HS256" => "HS256",
                "A192CBC-HS384" => "HS384",
                "A256CBC-HS512" => "HS512",
                _ => return Err(WebtokenError::Generic("Bad composite".into())),
            };

            let full_tag = crypto::hmac_sign(mac_key, &mac_input, hmac_alg)?;
            // JWE uses truncated HMAC (first half)
            let tag = full_tag[0..full_tag.len()/2].to_vec();

            Ok((ciphertext, tag, nonce))
        },
        _ => Err(WebtokenError::UnsupportedAlgorithm(format!("Unknown enc: {}", enc).into()))
    }
}

fn decrypt_content(enc: &str, cek: &[u8], ciphertext: &[u8], aad: &[u8], nonce: &[u8], tag: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    match enc {
        "A128GCM" | "A192GCM" | "A256GCM" => {
            crypto::aes_gcm_decrypt(cek, nonce, ciphertext, tag, aad)
        },
        "XC20P" => {
            crypto::decrypt_xchacha20(cek, ciphertext, aad, nonce, tag)
        },
        "A128CBC-HS256" | "A192CBC-HS384" | "A256CBC-HS512" => {
            // Composite Logic
            let key_len = cek.len() / 2;
            let mac_key = &cek[0..key_len];
            let enc_key = &cek[key_len..];

            // Verify Tag
            let al = ((aad.len() as u64) * 8).to_be_bytes();
            let mut mac_input = Vec::new();
            mac_input.extend_from_slice(aad);
            mac_input.extend_from_slice(nonce);
            mac_input.extend_from_slice(ciphertext);
            mac_input.extend_from_slice(&al);

            let hmac_alg = match enc {
                "A128CBC-HS256" => "HS256",
                "A192CBC-HS384" => "HS384",
                "A256CBC-HS512" => "HS512",
                _ => return Err(WebtokenError::Generic("Bad composite".into())),
            };

            let full_tag = crypto::hmac_sign(mac_key, &mac_input, hmac_alg)?;
            let expected_tag = &full_tag[0..full_tag.len()/2];

            // Constant time comparison (using simple slice compare here, in prod use constant_time_eq)
            if tag != expected_tag {
                return Err(WebtokenError::InvalidSignature);
            }

            // Decrypt
            crypto::aes_cbc_decrypt(enc_key, nonce, ciphertext)
        },
        _ => Err(WebtokenError::UnsupportedAlgorithm(format!("Unknown enc: {enc}").into()))
    }
}

// ============================================================================
//  High Level API
// ============================================================================

pub fn encrypt_compact(
    protected: &Value,
    payload: &[u8],
    key: &[u8]
) -> Result<String, WebtokenError> {
    // 1. Prepare Header
    let alg = protected["alg"].as_str().ok_or(WebtokenError::InvalidToken("Missing alg".into()))?.to_string();
    let enc = protected["enc"].as_str().ok_or(WebtokenError::InvalidToken("Missing enc".into()))?.to_string();
    let mut header = protected.clone();

    // 2. Manage Key
    let (cek, encrypted_key) = manage_cek_encrypt(&alg, &enc, key, &mut header)?;

    // 3. Encode Header (AAD)
    let header_json = serde_json::to_vec(&header).map_err(|e| WebtokenError::Generic(e.to_string()))?;
    let encoded_header = URL_SAFE_NO_PAD.encode(&header_json);
    let aad = encoded_header.as_bytes();

    // 4. Compress Payload (Optional)
    let mut final_payload = Cow::Borrowed(payload);
    if let Some("DEF") = header.get("zip").and_then(|v| v.as_str()) {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).map_err(|e| WebtokenError::Generic(e.to_string()))?;
        final_payload = Cow::Owned(encoder.finish().map_err(|e| WebtokenError::Generic(e.to_string()))?);
    }

    // 5. Encrypt Content
    let (ciphertext, tag, nonce) = encrypt_content(&enc, &cek, &final_payload, aad)?;

    // 6. Assemble
    Ok(format!("{}.{}.{}.{}.{}", 
        encoded_header, 
        URL_SAFE_NO_PAD.encode(&encrypted_key),
        URL_SAFE_NO_PAD.encode(&nonce), 
        URL_SAFE_NO_PAD.encode(&ciphertext), 
        URL_SAFE_NO_PAD.encode(&tag)
    ))
}

pub fn decrypt_compact(token: &str, key: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 5 { return Err(WebtokenError::InvalidToken("Invalid JWE compact format".into())); }

    let (b64_header, b64_ek, b64_iv, b64_ct, b64_tag) = (parts[0], parts[1], parts[2], parts[3], parts[4]);

    // Decode
    let header_bytes = decode_base64_permissive(b64_header.as_bytes()).map_err(|_| WebtokenError::InvalidToken("Bad header".into()))?;
    let header: Value = serde_json::from_slice(&header_bytes).map_err(|_| WebtokenError::InvalidToken("Bad header JSON".into()))?;
    let encrypted_key = decode_base64_permissive(b64_ek.as_bytes()).map_err(|_| WebtokenError::InvalidToken("Bad key".into()))?;
    let nonce = decode_base64_permissive(b64_iv.as_bytes()).map_err(|_| WebtokenError::InvalidToken("Bad IV".into()))?;
    let ciphertext = decode_base64_permissive(b64_ct.as_bytes()).map_err(|_| WebtokenError::InvalidToken("Bad ciphertext".into()))?;
    let tag = decode_base64_permissive(b64_tag.as_bytes()).map_err(|_| WebtokenError::InvalidToken("Bad tag".into()))?;
    let aad = b64_header.as_bytes();

    let alg = header["alg"].as_str().ok_or(WebtokenError::InvalidToken("Missing alg".into()))?;
    let enc = header["enc"].as_str().ok_or(WebtokenError::InvalidToken("Missing enc".into()))?;

    // Unwrap Key
    let cek = manage_cek_decrypt(alg, enc, key, &encrypted_key, &header)?;

    // Decrypt Content
    let plaintext = decrypt_content(enc, &cek, &ciphertext, aad, &nonce, &tag)?;

    // Decompress (Optional)
    if let Some("DEF") = header.get("zip").and_then(|v| v.as_str()) {
        let mut decoder = DeflateDecoder::new(&plaintext[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).map_err(|_| WebtokenError::Generic("Decompression failed".into()))?;
        Ok(decompressed)
    } else {
        Ok(plaintext)
    }
}

// Helpers
fn get_cek_length(enc: &str) -> Result<usize, WebtokenError> {
    match enc {
        "A128GCM" => Ok(16),
        "A192GCM" => Ok(24),
        "A256GCM" | "XC20P" => Ok(32),
        "A128CBC-HS256" => Ok(32), // 16 MAC + 16 ENC
        "A192CBC-HS384" => Ok(48), // 24 MAC + 24 ENC
        "A256CBC-HS512" => Ok(64), // 32 MAC + 32 ENC
        _ => Err(WebtokenError::UnsupportedEncryption(format!("Unknown enc: {enc}").into()))
    }
}

fn get_key_wrap_length(alg: &str) -> Result<usize, WebtokenError> {
    match alg {
        "A128KW" => Ok(16),
        "A192KW" => Ok(24),
        "A256KW" => Ok(32),
        _ => Err(WebtokenError::UnsupportedAlgorithm(format!("Unknown wrap alg: {alg}", ).into()))
    }
}


fn prepare_pbes2_params_encrypt(alg: &str, headers: &mut Value) -> Result<(Vec<u8>, u32, usize), WebtokenError> {
    let (kek_len, default_p2c) = match alg {
        "PBES2-HS256+A128KW" => (16, 8192), // 8192 is a common default for JWT iterations
        "PBES2-HS384+A192KW" => (24, 8192),
        "PBES2-HS512+A256KW" => (32, 8192),
        _ => return Err(WebtokenError::UnsupportedAlgorithm(format!("Unsupported PBES2 alg: {}", alg))),
    };

    // Generate 16 bytes of random salt for p2s
    let p2s = crypto::get_random_bytes(16)?;
    let p2c = default_p2c;

    if let Some(obj) = headers.as_object_mut() {
        obj.insert("p2s".to_string(), Value::String(URL_SAFE_NO_PAD.encode(&p2s)));
        obj.insert("p2c".to_string(), Value::Number(p2c.into()));
    }

    Ok((p2s, p2c, kek_len))
}

fn prepare_pbes2_params_decrypt(alg: &str, headers: &Value) -> Result<(Vec<u8>, u32, usize), WebtokenError> {
    let kek_len = match alg {
        "PBES2-HS256+A128KW" => 16,
        "PBES2-HS384+A192KW" => 24,
        "PBES2-HS512+A256KW" => 32,
        _ => return Err(WebtokenError::UnsupportedAlgorithm(format!("Unsupported PBES2 alg: {}", alg))),
    };

    let p2s_b64 = headers.get("p2s").and_then(|v| v.as_str())
        .ok_or_else(|| WebtokenError::InvalidToken("Missing p2s parameter".into()))?;
    let p2s = decode_base64_permissive(p2s_b64.as_bytes())
        .map_err(|_| WebtokenError::InvalidToken("Invalid p2s encoding".into()))?;

    let p2c = headers.get("p2c").and_then(|v| v.as_u64())
        .ok_or_else(|| WebtokenError::InvalidToken("Missing p2c parameter".into()))? as u32;

    Ok((p2s, p2c, kek_len))
}

fn derive_pbes2_kek(alg: &str, password: &[u8], p2s: &[u8], p2c: u32, kek_len: usize) -> Result<Vec<u8>, WebtokenError> {
    // JWE Spec formats the PBKDF2 salt as: UTF8(alg) || 0x00 || p2s
    let mut salt = Vec::with_capacity(alg.len() + 1 + p2s.len());
    salt.extend_from_slice(alg.as_bytes());
    salt.push(0x00);
    salt.extend_from_slice(p2s);

    let mut kek = vec![0u8; kek_len];
    match alg {
        "PBES2-HS256+A128KW" => crypto::pbkdf2_manual_sha256(password, &salt, p2c, &mut kek),
        "PBES2-HS384+A192KW" => crypto::pbkdf2_manual_sha384(password, &salt, p2c, &mut kek),
        "PBES2-HS512+A256KW" => crypto::pbkdf2_manual_sha512(password, &salt, p2c, &mut kek),
        _ => return Err(WebtokenError::UnsupportedAlgorithm(format!("Unsupported PBES2 alg: {}", alg))),
    }
    
    Ok(kek)
}

