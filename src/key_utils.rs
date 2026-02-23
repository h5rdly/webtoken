use serde_json::{Value, json};
use base64;
use base64::{engine::general_purpose::{URL_SAFE_NO_PAD, STANDARD}, Engine as _};
use num_bigint::BigUint;

use crate::{WebtokenError};
use crate::crypto::{recover_primes, compute_crt, ed25519_public_from_seed};
use crate::crypto_parsing::{DerReader, oid_to_curve_info, };


pub struct RsaPrivateComponents {
    pub n: BigUint, pub e: BigUint, pub d: BigUint,
    pub p: BigUint, pub q: BigUint, pub dp: BigUint, pub dq: BigUint, pub qi: BigUint,
}


fn b64(data: &[u8]) -> String { URL_SAFE_NO_PAD.encode(data) }


pub fn get_biguint(jwk: &Value, field: &str) -> Result<BigUint, WebtokenError> {
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


