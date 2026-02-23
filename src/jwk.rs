use serde_json::{Value};
use base64::{engine::general_purpose::{URL_SAFE_NO_PAD}, Engine as _};

use crate::key_utils::{extract_or_recover_rsa_components, get_biguint};
use crate::crypto_parsing::{OID_P256, OID_P384, OID_P521, OID_SECP256K1, OID_EC_PUBLIC_KEY, OID_RSA_ENCRYPTION, 
 encode_der_int, encode_der_len,};



pub fn parse_json(data: &str) -> Result<Value, String> {
    serde_json::from_str(data).map_err(|e| format!("Invalid JWK JSON: {}", e))
}


pub fn normalize_key_set(keys: Vec<Value>) -> Vec<(Value, Option<String>)> {
    keys.into_iter().filter_map(|k| {
        if let Some("enc") = k.get("use").and_then(|u| u.as_str()) { return None; }
        normalize(k, None).ok()
    }).collect()
}


fn validate_ec_coordinates(jwk: &Value) -> Result<(), String> {

    if let Some("EC") = jwk.get("kty").and_then(|v| v.as_str()) {
        let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
        let expected_len = match crv {
            "P-256" | "secp256k1" => 32,
            "P-384" => 48,
            "P-521" => 66,
            _ => return Ok(()),
        };

        for param in ["x", "y", "d"] {
            if let Some(val) = jwk.get(param).and_then(|v| v.as_str()) {
                let bytes = URL_SAFE_NO_PAD.decode(val).map_err(|_| format!("Invalid base64 for {}", param))?;
                if bytes.len() != expected_len {
                    return Err(format!("Invalid coordinate length for curve {}. Expected {}, got {}", crv, expected_len, bytes.len()));
                }
            }
        }
    }
    Ok(())
}


pub fn normalize(jwk: Value, algorithm_hint: Option<String>) -> Result<(Value, Option<String>), String> {

    if !jwk.is_object() { return Err("JWK must be an object".to_string()); }
    if jwk.get("kty").is_none() { return Err("Key type (kty) not found".to_string()); }
    validate_ec_coordinates(&jwk)?;
    let alg = if let Some(a) = algorithm_hint { Some(a) } 
    else if let Some(key_alg) = jwk.get("alg").and_then(|v| v.as_str()) { Some(key_alg.to_string()) } 
    else { deduce_algorithm(&jwk)? };
    Ok((jwk, alg))
}


pub fn deduce_algorithm(jwk: &Value) -> Result<Option<String>, String> {

    let kty = jwk.get("kty").and_then(|v| v.as_str()).ok_or("kty missing")?;
    match kty {
        "EC" => {
            let crv = jwk.get("crv").and_then(|v| v.as_str()).ok_or("crv missing for EC key")?;
            match crv {
                "P-256" => Ok(Some("ES256".to_string())),
                "P-384" => Ok(Some("ES384".to_string())),
                "P-521" => Ok(Some("ES512".to_string())),
                "secp256k1" => Ok(Some("ES256K".to_string())),
                "P-192" => Ok(None), // to be caught for a proper error message
                _ => Err(format!("Unsupported crv: {}", crv))
            }
        },
        "RSA" => Ok(None),
        "oct" => Ok(Some("HS256".to_string())),
        "OKP" => {
             let crv = jwk.get("crv").and_then(|v| v.as_str()).ok_or("crv missing for OKP")?;
             match crv {
                 "Ed25519" | "Ed448" => Ok(Some("EdDSA".to_string())),
                 _ => Err(format!("Unsupported crv for OKP: {}", crv))
             }
        },
        other => Err(format!("Unknown key type: {}", other))
    }
}



pub fn extract_key_bytes(jwk: &Value, public_only: bool) -> Result<Vec<u8>, String> {
    let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or_default();

    match kty {

        "oct" => {
            let k = jwk.get("k").and_then(|v| v.as_str()).ok_or("Missing 'k' parameter")?;
            URL_SAFE_NO_PAD.decode(k).map_err(|e| format!("Invalid base64 k: {}", e))
        },

        "OKP" => {
            if !public_only {
                if let Some(d) = jwk.get("d").and_then(|v| v.as_str()) {
                     return URL_SAFE_NO_PAD.decode(d).map_err(|e| format!("Invalid base64 d: {}", e));
                }
            }
            if let Some(x) = jwk.get("x").and_then(|v| v.as_str()) {
                 URL_SAFE_NO_PAD.decode(x).map_err(|e| format!("Invalid base64 x: {}", e))
            } else { 
                Err("Missing parameters for OKP".to_string()) 
            }
        },

        "RSA" => {
             let n = get_biguint(jwk, "n").map_err(|e| e.to_string())?;
             let e = get_biguint(jwk, "e").map_err(|e| e.to_string())?;

             if !public_only && jwk.get("d").is_some() {
                 // Private Key -> PKCS#1 (RsaPrivateKey)
                 // Sequence(version, n, e, d, p, q, dp, dq, qi)
                 let comps = extract_or_recover_rsa_components(jwk).map_err(|e| e.to_string())?;
                 
                 let mut seq = Vec::new();
                 encode_der_int(&mut seq, &[0]); // version = 0
                 encode_der_int(&mut seq, &comps.n.to_bytes_be());
                 encode_der_int(&mut seq, &comps.e.to_bytes_be());
                 encode_der_int(&mut seq, &comps.d.to_bytes_be());
                 encode_der_int(&mut seq, &comps.p.to_bytes_be());
                 encode_der_int(&mut seq, &comps.q.to_bytes_be());
                 encode_der_int(&mut seq, &comps.dp.to_bytes_be());
                 encode_der_int(&mut seq, &comps.dq.to_bytes_be());
                 encode_der_int(&mut seq, &comps.qi.to_bytes_be());

                 let mut der = Vec::new();
                 der.push(0x30); // SEQUENCE
                 encode_der_len(&mut der, seq.len());
                 der.extend_from_slice(&seq);
                 return Ok(der);
             } else {
                 // Public Key -> SPKI (SubjectPublicKeyInfo)
                 // This is required for aws-lc-rs verification
                 // Sequence(AlgoID, BitString(PKCS1_RSAPublicKey))
                 
                 // 1. Build PKCS#1 RSAPublicKey: Sequence(n, e)
                 let mut pkcs1_seq = Vec::new();
                 encode_der_int(&mut pkcs1_seq, &n.to_bytes_be());
                 encode_der_int(&mut pkcs1_seq, &e.to_bytes_be());
                 
                 let mut pkcs1 = Vec::new();
                 pkcs1.push(0x30);
                 encode_der_len(&mut pkcs1, pkcs1_seq.len());
                 pkcs1.extend_from_slice(&pkcs1_seq);

                 // 2. Algo Identifier (rsaEncryption): Sequence(OID, Null)
                 let mut algo_seq = Vec::new();
                 algo_seq.push(0x06); // OID
                 encode_der_len(&mut algo_seq, OID_RSA_ENCRYPTION.len());
                 algo_seq.extend_from_slice(OID_RSA_ENCRYPTION);
                 algo_seq.push(0x05); // NULL
                 algo_seq.push(0x00);

                 let mut algo_wrap = Vec::new();
                 algo_wrap.push(0x30);
                 encode_der_len(&mut algo_wrap, algo_seq.len());
                 algo_wrap.extend_from_slice(&algo_seq);

                 // 3. BitString wrapper
                 let mut bit_string = Vec::new();
                 bit_string.push(0x03); // BIT STRING
                 encode_der_len(&mut bit_string, pkcs1.len() + 1);
                 bit_string.push(0x00); // Unused bits
                 bit_string.extend_from_slice(&pkcs1);

                 // 4. Final Sequence
                 let mut spki = Vec::new();
                 spki.push(0x30);
                 encode_der_len(&mut spki, algo_wrap.len() + bit_string.len());
                 spki.extend_from_slice(&algo_wrap);
                 spki.extend_from_slice(&bit_string);
                 
                 return Ok(spki);
             }
        },

        "EC" => {
             if !public_only {
                 if let Some(d) = jwk.get("d").and_then(|v| v.as_str()) {
                     let d_bytes = URL_SAFE_NO_PAD.decode(d).map_err(|e| format!("Invalid d: {}", e))?;
                     let crv = jwk.get("crv").and_then(|v| v.as_str()).ok_or("Missing crv")?;
                     let curve_oid = match crv {
                         "P-256" => OID_P256,
                         "P-384" => OID_P384,
                         "P-521" => OID_P521,
                         "secp256k1" => OID_SECP256K1,
                         _ => return Err(format!("Unsupported curve: {}", crv)),
                     };
                     let mut sec1 = Vec::new();
                     sec1.extend_from_slice(&[0x02, 0x01, 0x01]); 
                     sec1.push(0x04); 
                     encode_der_len(&mut sec1, d_bytes.len());
                     sec1.extend_from_slice(&d_bytes);

                     sec1.push(0xA0); 
                     encode_der_len(&mut sec1, curve_oid.len());
                     sec1.extend_from_slice(curve_oid);
                     
                     if let (Some(x_b64), Some(y_b64)) = (jwk.get("x").and_then(|v| v.as_str()), jwk.get("y").and_then(|v| v.as_str())) {
                         if let (Ok(x_bytes), Ok(y_bytes)) = (URL_SAFE_NO_PAD.decode(x_b64), URL_SAFE_NO_PAD.decode(y_b64)) {
                             let mut pub_key = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
                             pub_key.push(0x04); // Uncompressed point format
                             pub_key.extend_from_slice(&x_bytes);
                             pub_key.extend_from_slice(&y_bytes);
                             
                             let mut bit_string = Vec::new();
                             bit_string.push(0x03);
                             encode_der_len(&mut bit_string, pub_key.len() + 1);
                             bit_string.push(0x00); // 0 unused bits
                             bit_string.extend_from_slice(&pub_key);

                             sec1.push(0xA1); // [1] Context-specific Constructed tag
                             encode_der_len(&mut sec1, bit_string.len());
                             sec1.extend_from_slice(&bit_string);
                         }
                     }
                     
                     let mut sec1_seq = Vec::new();
                     sec1_seq.push(0x30); 
                     encode_der_len(&mut sec1_seq, sec1.len());
                     sec1_seq.extend_from_slice(&sec1);

                     let mut alg_id = Vec::new();
                     alg_id.extend_from_slice(OID_EC_PUBLIC_KEY);
                     alg_id.extend_from_slice(curve_oid);
                     
                     let mut alg_seq = Vec::new();
                     alg_seq.push(0x30);
                     encode_der_len(&mut alg_seq, alg_id.len());
                     alg_seq.extend_from_slice(&alg_id);

                     let mut pkcs8_inner = Vec::new();
                     pkcs8_inner.extend_from_slice(&[0x02, 0x01, 0x00]); 
                     pkcs8_inner.extend_from_slice(&alg_seq);
                     pkcs8_inner.push(0x04); 
                     encode_der_len(&mut pkcs8_inner, sec1_seq.len());
                     pkcs8_inner.extend_from_slice(&sec1_seq);

                     let mut pkcs8 = Vec::new();
                     pkcs8.push(0x30);
                     encode_der_len(&mut pkcs8, pkcs8_inner.len());
                     pkcs8.extend_from_slice(&pkcs8_inner);
                     return Ok(pkcs8);
                 }
             }
             if let (Some(x_b64), Some(y_b64)) = (jwk.get("x").and_then(|v| v.as_str()), jwk.get("y").and_then(|v| v.as_str())) {
                 let x_bytes = URL_SAFE_NO_PAD.decode(x_b64).map_err(|e| format!("Invalid x: {}", e))?;
                 let y_bytes = URL_SAFE_NO_PAD.decode(y_b64).map_err(|e| format!("Invalid y: {}", e))?;
                 let mut out = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
                 out.push(0x04); 
                 out.extend_from_slice(&x_bytes);
                 out.extend_from_slice(&y_bytes);
                 return Ok(out);
             }
             Err("Missing parameters for EC".to_string())
        },

        _ => Err(format!("Unsupported key type for raw extraction: {}", kty))
    }
}
