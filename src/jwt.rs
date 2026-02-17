use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashSet;

use serde::{Serialize, Deserialize};
use serde_json::{Map, Value, from_slice};

use crate::{WebtokenError, py_utils::decode_base64_permissive, crypto, algorithms};


#[derive(Deserialize)]
struct LenientHeader {
    alg: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum TokenPayload {
    Claims(Value),
    Raw(#[serde(with = "serde_bytes")] Vec<u8>),
}

#[derive(Debug, Serialize)]
pub struct CompleteToken {
    pub header: Value,
    pub payload: TokenPayload,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Validation {
    pub leeway: u64,
    pub required_spec_claims: HashSet<String>,
    pub algorithms: Vec<String>,
}

impl Default for Validation {
    fn default() -> Self {
        Self {
            leeway: 0,
            required_spec_claims: HashSet::new(),
            algorithms: vec!["HS256".to_string()],
        }
    }
}


// hold parsed components before validation
struct ParsedJws {
    header: Map<String, Value>,
    payload_bytes: Vec<u8>,
    signature_bytes: Vec<u8>,
    signing_input: String,
}

// -- Helpers 

fn current_time() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as f64
}

pub fn get_numeric_date(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

fn check_numeric_claims(claims: &Value) -> Result<(), WebtokenError> {
    for (claim, err_msg) in [
        ("exp", "exp must be a number"),
        ("iat", "iat must be a number"),
        ("nbf", "nbf must be a number"),
    ] {
        if let Some(val) = claims.get(claim) {
            if !val.is_number() && val.as_str().and_then(|s| s.parse::<f64>().ok()).is_none() {
                // Return specific errors for specific claims if needed for compatibility
                let exc = if claim == "iat" { "InvalidIssuedAtError" } else { "DecodeError" };
                return Err(WebtokenError::Custom { exc: exc.into(), msg: err_msg.into() });
            }
        }
    }
    Ok(())
}

pub fn sort_map(map: &mut Map<String, Value>) {
    let mut entries: Vec<(String, Value)> = std::mem::take(map).into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v) in entries {
        map.insert(k, v);
    }
}


// re-assemble tokens with detached content
pub fn handle_detached_content(token: &str, content: Option<&[u8]>) -> Result<String, WebtokenError> {
    if let Some(c) = content {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 { 
            return Err(WebtokenError::DecodeError("Not enough segments".into())); 
        }
        Ok(format!("{}.{}.{}", parts[0], URL_SAFE_NO_PAD.encode(c), parts[2]))
    } else { 
        Ok(token.to_string()) 
    }
}


pub fn prepare_headers(algorithm: &str, mut header_map: Map<String, Value>, sort_headers: bool
) -> Result<Map<String, Value>, WebtokenError> {

    header_map.entry("alg").or_insert_with(|| Value::String(algorithm.to_string()));

    if header_map.get("kid").is_some_and(|kid| !kid.is_string()) {
        return Err(WebtokenError::InvalidToken("Key ID header parameter must be a string".into()));
    }

    // RFC 7797 b64 removal
    if header_map.get("b64") == Some(&Value::Bool(true)) {
        header_map.remove("b64");
    }

    // Ensure 'typ' is set or clean
    header_map.entry("typ").and_modify(|v| { if v.is_null() || v.as_str() == Some("") { *v = Value::Null; }
        }).or_insert(Value::String("JWT".to_string()));

    if header_map.get("typ") == Some(&Value::Null) {
        header_map.remove("typ");
    }

    if sort_headers {
        sort_map(&mut header_map);
    }

    Ok(header_map)
}


fn validate_audience(token_aud: Option<&Value>, expected_auds: &HashSet<String>, strict: bool
) -> Result<(), WebtokenError> {
    if strict {
        // Strict mode: token must have exactly one audience matching the expected one
        if expected_auds.len() != 1 {
            return Err(WebtokenError::Custom { exc: "InvalidAudienceError".into(), msg: "Invalid audience (strict)".into() });
        }
        match token_aud {
            Some(Value::String(s)) => {
                if expected_auds.contains(s) { Ok(()) }
                else { Err(WebtokenError::Custom { exc: "InvalidAudienceError".into(), msg: "Audience doesn't match (strict)".into() }) }
            },
            Some(Value::Array(_)) => Err(WebtokenError::Custom { exc: "InvalidAudienceError".into(), msg: "Invalid claim format in token (strict)".into() }),
            Some(Value::Null) | None => Err(WebtokenError::MissingRequiredClaim("aud".into())),
            _ => Err(WebtokenError::Custom { exc: "InvalidAudienceError".into(), msg: "Invalid claim format in token (strict)".into() }),
        }
    } else {
        // Standard mode: At least one token audience must match one expected audience
        if token_aud.is_none() || token_aud == Some(&Value::Null) {
            // If expected_auds are provided, we require the token to have an audience.
            return Err(WebtokenError::MissingRequiredClaim("aud".into()));
        }

        let token_auds: Vec<String> = match token_aud {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(arr)) => {
                let mut strs = Vec::new();
                for v in arr {
                    if let Some(s) = v.as_str() {
                        strs.push(s.to_string());
                    } else {
                        // [FIX 1] Restore type check failure for invalid list members
                        return Err(WebtokenError::Custom { exc: "InvalidAudienceError".into(), msg: "Invalid claim format in token".into() });
                    }
                }
                strs
            },
            _ => return Err(WebtokenError::Custom { exc: "InvalidAudienceError".into(), msg: "Invalid claim format in token".into() }),
        };

        if token_auds.iter().any(|ta| expected_auds.contains(ta)) {
            Ok(())
        } else {
            Err(WebtokenError::InvalidAudience)
        }
    }
}


pub fn validate_claims(
    claims: &Value, 
    val: &Validation, 
    // Group boolean flags - (iat, exp, nbf, aud, iss, sub, strict_aud)
    flags: (bool, bool, bool, bool, bool, bool, bool),
    // Group expected values
    expected: (&Option<HashSet<String>>, &Option<HashSet<String>>, &Option<String>)
) -> Result<(), WebtokenError> {

    let (check_iat, check_exp, check_nbf, check_aud, check_iss, check_sub, strict_aud) = flags;
    let (exp_aud, exp_iss, exp_sub) = expected;
    let now = current_time();

    check_numeric_claims(claims)?;

    // Expiration
    if check_exp {
        if let Some(exp) = claims.get("exp").and_then(get_numeric_date) {
            if exp < (now - val.leeway as f64) {
                return Err(WebtokenError::ExpiredSignature);
            }
        } else if val.required_spec_claims.contains("exp") {
            return Err(WebtokenError::MissingRequiredClaim("exp".into()));
        }
    }

    // Not Before
    if check_nbf {
        if let Some(nbf) = claims.get("nbf").and_then(get_numeric_date) {
            if nbf > (now + val.leeway as f64) {
                return Err(WebtokenError::ImmatureSignature);
            }
        }
    }

    // Issuer
    if check_iss {
        if let Some(issuers) = exp_iss {
            match claims.get("iss") {
                Some(Value::String(s)) if issuers.contains(s) => {},
                Some(_) => return Err(WebtokenError::InvalidIssuer),
                None => return Err(WebtokenError::MissingRequiredClaim("iss".into())),
            }
        } else if claims.get("iss").is_none() && val.required_spec_claims.contains("iss") {
            return Err(WebtokenError::MissingRequiredClaim("iss".into()));
        } else if claims.get("iss").is_some_and(|v| !v.is_string()) {
            return Err(WebtokenError::InvalidIssuer);
        }
    }

    // Audience
    if check_aud {
        if let Some(auds) = exp_aud {
            validate_audience(claims.get("aud"), auds, strict_aud)?;
        } else if let Some(aud) = claims.get("aud") {
            // Check if present but not required? 
             let is_truthy = match aud { 
                 Value::Null => false, 
                 Value::String(s) => !s.is_empty(), 
                 Value::Array(a) => !a.is_empty(), 
                 Value::Bool(b) => *b, 
                 _ => true 
            };
             if is_truthy { return Err(WebtokenError::InvalidAudience); }
        } else if val.required_spec_claims.contains("aud") {
            return Err(WebtokenError::MissingRequiredClaim("aud".into()));
        }
    }

    // Subject
    if check_sub {
        if let Some(sub) = exp_sub {
            match claims.get("sub") {
                Some(Value::String(s)) if s == sub => {},
                Some(Value::String(_)) => return Err(WebtokenError::Custom { exc: "InvalidSubjectError".into(), msg: "Invalid subject".into() }),
                _ => return Err(WebtokenError::Custom { exc: "InvalidSubjectError".into(), msg: "Invalid subject: must be a string".into() }),
            }
        } else if let Some(v) = claims.get("sub") {
            if !v.is_string() { return Err(WebtokenError::Custom { exc: "InvalidSubjectError".into(), msg: "Invalid subject: must be a string".into() }); }
        }
    }

    // JTI
    if let Some(jti) = claims.get("jti") {
        if !jti.is_string() { return Err(WebtokenError::Custom { exc: "InvalidJTIError".into(), msg: "Invalid jti: must be a string".into() }); }
    }

    // Issued At
    if check_iat {
        if let Some(iat) = claims.get("iat").and_then(get_numeric_date) {
            if iat > (now + val.leeway as f64) {
                return Err(WebtokenError::ImmatureSignature);
            }
        }
    }

    // General Required Claims
    for req in &val.required_spec_claims {
        if claims.get(req).is_none() {
            return Err(WebtokenError::MissingRequiredClaim(req.clone()));
        }
    }

    Ok(())
}


fn parse_jws(token: &str, detached_content: Option<&[u8]>) -> Result<ParsedJws, WebtokenError> {

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 { return Err(WebtokenError::DecodeError("Not enough segments".into()));}

    let header_bytes = decode_base64_permissive(parts[0].as_bytes())
        .map_err(|_| WebtokenError::Custom { exc: "DecodeError".into(), msg: "Invalid header padding".into() })?;

    let header_val: Value = from_slice(&header_bytes)
        .map_err(|e| WebtokenError::Custom { exc: "DecodeError".into(), msg: format!("Invalid header string: {}", e) })?;

    // Must be object
    let mut header_map = match header_val {
        Value::Object(m) => m,
        _ => return Err(WebtokenError::Custom { exc: "DecodeError".into(), msg: "Invalid header string: must be a json object".into() }),
    };

    // RFC 7797 b64 logic
    if let Some(val) = header_map.get("b64") {
         if let Some(b) = val.as_bool() {
             if !b {
                  if detached_content.is_none() {
                       return Err(WebtokenError::Custom { 
                           exc: "DecodeError".into(), 
                           msg: "It is required that you pass in a value for the \"detached_payload\" argument to decode a message having the b64 header set to false.".into() 
                       });
                  }
                  header_map.remove("b64");
             }
         } else {
             return Err(WebtokenError::Custom { exc: "DecodeError".into(), msg: "Invalid b64 header: must be boolean".into() });
         }
    }

    let payload_bytes = decode_base64_permissive(parts[1].as_bytes())
        .map_err(|_| WebtokenError::Custom { exc: "DecodeError".into(), msg: "Invalid payload padding".into() })?;
    
    let signature_bytes = decode_base64_permissive(parts[2].as_bytes())
        .map_err(|_| WebtokenError::Custom { exc: "DecodeError".into(), msg: "Invalid crypto padding".into() })?;
    
    let signing_input = format!("{}.{}", parts[0], parts[1]);

    Ok(ParsedJws {header: header_map, payload_bytes, signature_bytes, signing_input})
}


fn verify_signature(alg: &str, signing_input: &str, signature: &[u8], key: Option<&[u8]>, validation: &Validation,
) -> Result<(), WebtokenError> {
    
    if !algorithms::is_supported_algorithm(alg) {
        return Err(WebtokenError::InvalidAlgorithm);
    }
    
    if !validation.algorithms.iter().any(|a| a == alg) {
        return Err(WebtokenError::InvalidAlgorithm);
    }

    let key_bytes = key.ok_or_else(|| WebtokenError::Generic("Key required for verification".to_string()))?;
    crypto::verify(alg, key_bytes, signing_input.as_bytes(), signature)
}


pub fn decode(
    token: String, 
    key_bytes: Option<Vec<u8>>, 
    validation: Validation, 
    verify: bool, 
    flags: (bool, bool, bool, bool, bool, bool, bool),
    expected: (Option<HashSet<String>>, Option<HashSet<String>>, Option<String>),
    detached_content: Option<&[u8]>, 
    convert_to_json: bool,
) -> Result<CompleteToken, WebtokenError> {

    let parsed = parse_jws(&token, detached_content)?;
    
    let header_val = Value::Object(parsed.header.clone());
    
    if header_val.get("alg").is_none() {
        return Err(WebtokenError::Custom { 
            exc: "InvalidAlgorithmError".into(), 
            msg: "Missing 'alg' in header".into() 
        });
    }

    let header: LenientHeader = serde_json::from_value(header_val.clone())
        .map_err(|e| WebtokenError::Custom { exc: "DecodeError".into(), msg: format!("Invalid header string: {}", e) })?;
    
    let alg_norm = header.alg;

    if verify {
       verify_signature(&alg_norm, &parsed.signing_input, &parsed.signature_bytes, key_bytes.as_deref(), 
       &validation)?;
    }

    let payload = if !convert_to_json {
        TokenPayload::Raw(parsed.payload_bytes)
    } else {
        let claims: Value = from_slice(&parsed.payload_bytes).map_err(|_| WebtokenError::Custom { 
            exc: "DecodeError".into(), msg: "Invalid payload string: must be a json object".into() 
        })?;

        if !claims.is_object() {
            return Err(WebtokenError::Custom { 
                exc: "DecodeError".into(), msg: "Invalid payload string: must be a json object".into() 
            });
        }
        
        let (aud, iss, sub) = &expected;
        validate_claims(&claims, &validation, flags, (aud, iss, sub))?;

        TokenPayload::Claims(claims)
    };

    Ok(CompleteToken{header: header_val, payload, signature: parsed.signature_bytes})
}