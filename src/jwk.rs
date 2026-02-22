use serde_json::{Value, json};
use base64::{engine::general_purpose::{URL_SAFE_NO_PAD, STANDARD}, Engine as _};
use num_bigint::BigUint;

use crate::{WebtokenError};
use crate::crypto::{recover_primes, compute_crt, ed25519_public_from_seed};
use crate::crypto_parsing::{OID_P256, OID_P384, OID_P521, OID_SECP256K1, OID_EC_PUBLIC_KEY, OID_RSA_ENCRYPTION, 
    DerReader, encode_der_int, encode_der_len, oid_to_curve_info};



pub struct RsaPrivateComponents {
    pub n: BigUint, pub e: BigUint, pub d: BigUint,
    pub p: BigUint, pub q: BigUint, pub dp: BigUint, pub dq: BigUint, pub qi: BigUint,
}


fn b64(data: &[u8]) -> String { URL_SAFE_NO_PAD.encode(data) }


fn get_biguint(jwk: &Value, field: &str) -> Result<BigUint, WebtokenError> {
    let s = jwk.get(field).and_then(|v| v.as_str())
        .ok_or_else(|| WebtokenError::Generic(format!("Missing '{}'", field)))?;
    let bytes = URL_SAFE_NO_PAD.decode(s).map_err(|e| WebtokenError::Generic(e.to_string()))?;
    
    Ok(BigUint::from_bytes_be(&bytes))
}



pub fn extract_or_recover_rsa_components(jwk: &Value) -> Result<RsaPrivateComponents, WebtokenError> {

    let n = get_biguint(jwk, "n")?;
    let e = get_biguint(jwk, "e")?;
    let d = get_biguint(jwk, "d")?;

    if jwk.get("p").is_some() {
        return Ok(RsaPrivateComponents {
            n, e, d,
            p: get_biguint(jwk, "p")?, q: get_biguint(jwk, "q")?,
            dp: get_biguint(jwk, "dp")?, dq: get_biguint(jwk, "dq")?, qi: get_biguint(jwk, "qi")?,
        });
    }

    let (mut p, mut q) = recover_primes(&n, &e, &d).map_err(|err| WebtokenError::Generic(err))?;
    if p < q { 
        std::mem::swap(&mut p, &mut q); }

    let (dp, dq, qi) = compute_crt(&n, &p, &q, &d).map_err(|err| WebtokenError::Generic(err))?;

    Ok(RsaPrivateComponents { n, e, d, p, q, dp, dq, qi })
}


pub fn parse_json(data: &str) -> Result<Value, String> {
    serde_json::from_str(data).map_err(|e| format!("Invalid JWK JSON: {}", e))
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


pub fn normalize_key_set(keys: Vec<Value>) -> Vec<(Value, Option<String>)> {
    keys.into_iter().filter_map(|k| {
        if let Some("enc") = k.get("use").and_then(|u| u.as_str()) { return None; }
        normalize(k, None).ok()
    }).collect()
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


pub fn get_rsa_bits_from_value(inner: &Value) -> Option<usize> {

    if let Some(kty) = inner.get("kty").and_then(|s| s.as_str()) {
        if kty == "RSA" {
            if let Some(n_b64) = inner.get("n").and_then(|v| v.as_str()) {
                if let Ok(n_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(n_b64) {
                    return Some(num_bigint::BigUint::from_bytes_be(&n_bytes).bits() as usize);
                }
            }
        }
    }
    None
}


fn parse_rsa_private(der: &[u8]) -> Result<Value, String> {

    let mut reader = DerReader::new(der).read_sequence().or(Err("Not a sequence"))?;
    let _ver = reader.read_integer_bytes().map_err(|e| format!("Failed to read Version: {}", e))?;

    if !reader.input.is_empty() && reader.input[0] == 0x30 {
        // PKCS#8
        let mut algo = reader.read_sequence().map_err(|e| format!("Failed to read AlgoId: {}", e))?;
        let oid = algo.read_oid().map_err(|e| format!("Failed to read OID: {}", e))?;
        if oid != [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01] { 
            return Err("Not an RSA key in PKCS8".into()); 
        }
        let inner_bytes = reader.read_octet_string().map_err(|e| format!("Failed to read PrivateKey octets: {}", e))?;
        return parse_rsa_private(inner_bytes);
    } 

    let n = reader.read_integer_bytes().map_err(|e| format!("Failed to read n: {}", e))?;
    let e = reader.read_integer_bytes().map_err(|e| format!("Failed to read e: {}", e))?;
    let d = reader.read_integer_bytes().map_err(|e| format!("Failed to read d: {}", e))?;
    let p = reader.read_integer_bytes().map_err(|e| format!("Failed to read p: {}", e))?;
    let q = reader.read_integer_bytes().map_err(|e| format!("Failed to read q: {}", e))?;
    let dp = reader.read_integer_bytes().map_err(|e| format!("Failed to read dp: {}", e))?;
    let dq = reader.read_integer_bytes().map_err(|e| format!("Failed to read dq: {}", e))?;
    let qi = reader.read_integer_bytes().map_err(|e| format!("Failed to read qi: {}", e))?;
    
    Ok(json!({ "kty": "RSA", "n": b64(n), "e": b64(e), "d": b64(d), "p": b64(p), "q": b64(q), "dp": b64(dp), "dq": b64(dq), "qi": b64(qi) }))
}


fn parse_rsa_public(der: &[u8]) -> Result<Value, String> {

    let mut reader = DerReader::new(der).read_sequence()?;
    if !reader.input.is_empty() && reader.input[0] == 0x30 {
        let _algo = reader.read_sequence()?;
        let pub_key_bits = reader.read_bit_string()?;
        reader = DerReader::new(pub_key_bits).read_sequence()?;
    }
    let n = reader.read_integer_bytes()?; let e = reader.read_integer_bytes()?;
    Ok(json!({ "kty": "RSA", "n": b64(n), "e": b64(e) }))
}


fn parse_okp_public(der: &[u8]) -> Result<Value, String> {

    let mut reader = DerReader::new(der).read_sequence()?;
    let mut algo = reader.read_sequence()?;
    let oid = algo.read_oid()?;
    let crv = match oid { [0x2b, 0x65, 0x70] => "Ed25519", [0x2b, 0x65, 0x71] => "Ed448", _ => return Err("Not an EdDSA key".into()), };
    let bits = reader.read_bit_string()?;
    Ok(json!({ "kty": "OKP", "crv": crv, "x": b64(bits) }))
}


fn parse_okp_private(der: &[u8]) -> Result<Value, String> {

    let mut reader = DerReader::new(der).read_sequence()?;
    let _ver = reader.read_integer_bytes()?;
    let mut algo = reader.read_sequence()?;
    let oid = algo.read_oid()?;
    
    let crv = match oid { 
        [0x2b, 0x65, 0x70] => "Ed25519", 
        [0x2b, 0x65, 0x71] => "Ed448", 
        _ => return Err("Not OKP".into()), 
    };
    
    let outer = reader.read_octet_string()?;
    let mut inner = DerReader::new(outer);
    let d = inner.read_octet_string()?; // This is the private seed
    
    let mut j = json!({ "kty": "OKP", "crv": crv, "d": b64(d) });

    // Derive public key 'x' from private seed 'd' for Ed25519, so that the JWK is complete
    if crv == "Ed25519" {
        if let Ok(x) = ed25519_public_from_seed(d) {
             j["x"] = json!(b64(&x));
         }
    }

    Ok(j)
}


fn parse_ec_public(der: &[u8]) -> Result<Value, String> {

    let mut reader = DerReader::new(der).read_sequence()?;
    let mut algo = reader.read_sequence()?;
    let _id = algo.read_oid()?;
    let oid = algo.read_oid()?;
    
    let (crv, len) = oid_to_curve_info(oid).ok_or("Unknown Curve OID")?;
    
    let bits = reader.read_bit_string()?;
    if bits.len() < 1 + 2 * len || bits[0] != 0x04 { return Err("Invalid EC point".into()); }
    
    Ok(json!({ "kty": "EC", "crv": crv, "x": b64(&bits[1..1+len]), "y": b64(&bits[1+len..1+2*len]) }))
}


fn parse_ec_private(der: &[u8]) -> Result<Value, String> {

    let mut input = der;
    let mut temp_reader = DerReader::new(der);
    let mut crv_name_opt: Option<&str> = None; 

    // Iif wrapped in PKCS#8, extract the Curve OID from the headers
    if let Ok(mut seq) = temp_reader.read_sequence() {
        if let Ok(ver) = seq.read_integer_bytes() {
             if ver == [0] && !seq.input.is_empty() && seq.input[0] == 0x30 {
                 if let Ok(mut algo) = seq.read_sequence() {
                     if let Ok(oid) = algo.read_oid() {
                         // id-ecPublicKey: 1.2.840.10045.2.1
                         if oid == [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01] {
                             if let Ok(curve_oid) = algo.read_oid() {
                                 // Delegate to helper
                                 crv_name_opt = oid_to_curve_info(curve_oid).map(|(name, _)| name);
                             }
                             if let Ok(inner) = seq.read_octet_string() { input = inner; }
                         }
                     }
                 }
             }
        }
    }

    // Parse Inner SEC1 Structure
    let mut reader = DerReader::new(input).read_sequence()?; 
    let _ver = reader.read_integer_bytes()?;
    let d = reader.read_octet_string()?;
    
    // Fallback: If not in PKCS#8, the OID might be in the SEC1 parameters (Tag 0)
    if let Ok(Some(mut params)) = reader.read_optional_explicit(0) {
        if let Ok(oid) = params.read_oid() {
            if let Some((inner_crv, _)) = oid_to_curve_info(oid) {
                crv_name_opt = Some(inner_crv);
            }
        }
    }
    
    let crv_name = crv_name_opt.ok_or("Could not determine Curve OID from PKCS#8 or SEC1")?;

    let mut x_val = Value::Null; let mut y_val = Value::Null;
    if let Ok(Some(mut pubk)) = reader.read_optional_explicit(1) {
        if let Ok(bits) = pubk.read_bit_string() {
            if !bits.is_empty() && bits[0] == 0x04 {
                let len = (bits.len() - 1) / 2;
                x_val = json!(b64(&bits[1..1+len]));
                y_val = json!(b64(&bits[1+len..]));
            }
        }
    }
    
    let mut j = json!({ "kty": "EC", "crv": crv_name, "d": b64(d) });
    if !x_val.is_null() { j["x"] = x_val; j["y"] = y_val; }
    Ok(j)
}


pub fn pem_to_jwk(pem_bytes: &[u8]) -> Result<String, String> {

    let s = std::str::from_utf8(pem_bytes).map_err(|_| "Invalid UTF-8")?;
    let s_trim = s.trim();

    if s_trim.starts_with("ssh-") || s_trim.starts_with("ecdsa-") {
        let pem_vec = crate::crypto_parsing::ssh_to_pem(s_trim.as_bytes())?;
        // Recurse: Parse the generated PEM (which will now hit the -----BEGIN block below)
        return pem_to_jwk(&pem_vec);
    }

    let start_idx = s.find("-----BEGIN").ok_or("Missing Header")?;
    let end_idx = s.find("-----END").ok_or("Missing Footer")?;
    
    let body_start = if let Some(eol) = s[start_idx..].find('\n') {
        start_idx + eol + 1
    } else {
        start_idx
    };
    
    if body_start >= end_idx { return Err("Empty PEM body".into()); }
    
    let body = &s[body_start..end_idx];
    
    let base64_data: String = body.lines()
        .filter(|l| !l.contains(':')) 
        .flat_map(|l| l.trim().chars())
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            _ => c
        })
        .collect();

    let der = STANDARD.decode(&base64_data).map_err(|e| format!("Invalid PEM Base64: {}", e))?;
    
    if s.contains("BEGIN PUBLIC KEY") || s.contains("BEGIN RSA PUBLIC KEY") {
        if let Ok(j) = parse_rsa_public(&der) { return Ok(j.to_string()); }
        if let Ok(j) = parse_ec_public(&der) { return Ok(j.to_string()); }
        if let Ok(j) = parse_okp_public(&der) { return Ok(j.to_string()); }
    }
    
    if s.contains("BEGIN RSA PRIVATE KEY") || s.contains("BEGIN PRIVATE KEY") || s.contains("BEGIN EC PRIVATE KEY") {
        if let Ok(j) = parse_rsa_private(&der) { return Ok(j.to_string()); }
        if let Ok(j) = parse_ec_private(&der) { return Ok(j.to_string()); }
        if let Ok(j) = parse_okp_private(&der) { return Ok(j.to_string()); }
    }

    Err("Unknown Key Format".into())
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

