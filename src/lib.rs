use std::{
    str::from_utf8, 
    collections::{HashSet, HashMap},
    sync::{OnceLock, RwLock},
};

use serde_json::{from_slice, from_str, to_vec, Value, Map};
use serde::{Deserialize};
use base64::{Engine as _, engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}};
use time::{OffsetDateTime, PrimitiveDateTime};

use pyo3::prelude::*;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::types::{PyBytes, PyDict, PyModule, PyString};
use pyo3::{wrap_pyfunction}; 

use pythonize::{depythonize, pythonize};

mod algorithms; 
mod crypto; 
mod crypto_parsing;
mod jwt;
mod jwk;
mod jws;
mod jwe;
mod key_utils;
mod py_utils;
mod paseto;
pub mod pyjwt_jwk_api;


use jwt::Validation;
use pyjwt_jwk_api::{
    PyJWK, PyJWKSet, perform_signature_jwk, perform_verification_jwk, validate_key_properties, check_rsa_key_length};


#[macro_export]
macro_rules! err_loc {
    ($($arg:tt)*) => {
        format!("[{}:{}] {}", file!(), line!(), format!($($arg)*))
    };
}

#[macro_export]
macro_rules! f {
    ($($arg:tt)*) => {
        format!($($arg)*)
    }
}

macro_rules! exc {
    ($name:ident, $base:path) => {
        pyo3::create_exception!(webtoken, $name, $base);
    }
}

exc!(PyJWTError, pyo3::exceptions::PyException);
exc!(InvalidTokenError, PyJWTError);
exc!(DecodeError, InvalidTokenError);
exc!(InvalidSignatureError, DecodeError);
exc!(ExpiredSignatureError, InvalidTokenError);
exc!(InvalidAudienceError, InvalidTokenError);
exc!(InvalidIssuerError, InvalidTokenError);
exc!(ImmatureSignatureError, InvalidTokenError);
exc!(MissingRequiredClaimError, InvalidTokenError);
exc!(InvalidIssuedAtError, InvalidTokenError);
exc!(InvalidJTIError, InvalidTokenError);
exc!(InvalidSubjectError, InvalidTokenError);
exc!(InvalidAlgorithmError, InvalidTokenError);
exc!(InvalidKeyError, PyJWTError);

#[derive(Deserialize)]
struct PartialHeader {
    alg: String,
}


#[derive(FromPyObject)]
pub enum BytesOrString {
    #[pyo3(transparent)]
    Str(String),
    #[pyo3(transparent)]
    Bytes(Vec<u8>),
}


impl BytesOrString {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            BytesOrString::Str(s) => s.as_bytes(),
            BytesOrString::Bytes(b) => b.as_slice(),
        }
    }
}


impl AsRef<[u8]> for BytesOrString {
    fn as_ref(&self) -> &[u8] {
        match self {
            BytesOrString::Str(s) => s.as_bytes(),
            BytesOrString::Bytes(b) => b.as_slice(),
        }
    }
}


impl From<BytesOrString> for Vec<u8> {
    fn from(value: BytesOrString) -> Self {
        match value {
            BytesOrString::Str(s) => s.into_bytes(),
            BytesOrString::Bytes(b) => b,
        }
    }
}


// impl std::ops::Deref for BytesOrString {
//     type Target = [u8];

//     fn deref(&self) -> &Self::Target {
//         match self {
//             BytesOrString::Str(s) => s.as_bytes(),
//             BytesOrString::Bytes(b) => b.as_slice(),
//         }
//     }
// }



#[derive(Debug)]
pub enum WebtokenError {
    Generic(String),
    
    InvalidSignature,
    ExpiredSignature,
    ImmatureSignature,
    InvalidIssuer(String),
    InvalidAudience(String),
    InvalidAlgorithm(String), 
    InvalidToken(String),
    MissingRequiredClaim(String),
    DecodeError(String),
    InvalidKey(String),
    InvalidSubject(String),
    InvalidJTI(String),
    InvalidIssuedAt(String),
    UnsupportedAlgorithm(String),
    UnsupportedEncryption(String),
}


impl std::fmt::Display for WebtokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebtokenError::Generic(s) => write!(f, "{}", s),

            WebtokenError::InvalidSignature => write!(f, "Signature verification failed"),
            WebtokenError::ExpiredSignature => write!(f, "Signature has expired"),
            WebtokenError::ImmatureSignature => write!(f, "The token is not yet valid"),
            WebtokenError::InvalidIssuer(msg) => write!(f, "InvalidIssuer: {msg}"),
            WebtokenError::InvalidAudience(msg) => write!(f, "InvalidAudience: {msg}"),
            WebtokenError::InvalidAlgorithm(msg) => write!(f, "Algorithm not supported: {msg}"),
            WebtokenError::InvalidToken(msg) => write!(f, "InvalidTokenError: {msg}"),
            WebtokenError::MissingRequiredClaim(c) => write!(f, "Missing required claim: {c}"),
            WebtokenError::DecodeError(msg) => write!(f, "DecodeError: {msg}"),
            WebtokenError::InvalidKey(msg) => write!(f, "InvalidKeyError: {msg}"),
            WebtokenError::InvalidSubject(msg) => write!(f, "InvalidSubjectError: {msg}"),
            WebtokenError::InvalidJTI(msg) => write!(f, "InvalidJTIError: {msg}"),
            WebtokenError::InvalidIssuedAt(msg) => write!(f, "InvalidIssuedAtError: {msg}"),
            WebtokenError::UnsupportedAlgorithm(msg) => write!(f, "UnsupportedAlgorithmError: {msg}"),
            WebtokenError::UnsupportedEncryption(msg) => write!(f, "UnsupportedEncryptionError: {msg}"),
        }
    }
}


impl From<WebtokenError> for PyErr {
    fn from(err: WebtokenError) -> PyErr {
        match err {
            WebtokenError::Generic(s) => PyValueError::new_err(s),
            
            WebtokenError::InvalidSignature => InvalidSignatureError::new_err("Signature verification failed"),
            WebtokenError::ExpiredSignature => ExpiredSignatureError::new_err("Signature has expired"),
            WebtokenError::ImmatureSignature => ImmatureSignatureError::new_err("The token is not yet valid (iat/nbf)"),
            WebtokenError::InvalidIssuer(msg) => InvalidIssuerError::new_err(msg),
            WebtokenError::InvalidAudience(msg) => InvalidAudienceError::new_err(msg),
            WebtokenError::InvalidAlgorithm(msg) => InvalidAlgorithmError::new_err(msg),
            WebtokenError::InvalidToken(msg) => InvalidTokenError::new_err(msg),
            WebtokenError::MissingRequiredClaim(c) => MissingRequiredClaimError::new_err(c),
            WebtokenError::DecodeError(msg) => DecodeError::new_err(msg), 
            WebtokenError::InvalidKey(msg) => InvalidKeyError::new_err(msg),
            WebtokenError::InvalidSubject(msg) => InvalidSubjectError::new_err(msg),
            WebtokenError::InvalidJTI(msg) => InvalidJTIError::new_err(msg),
            WebtokenError::InvalidIssuedAt(msg) => InvalidIssuedAtError::new_err(msg),
            WebtokenError::UnsupportedAlgorithm(msg) => InvalidAlgorithmError::new_err(msg),
            WebtokenError::UnsupportedEncryption(msg) => PyValueError::new_err(msg),
        }
    }
}


fn raise_missing_claim_error<T>(py: Python, claim: &str) -> PyResult<T> {
    let m = PyModule::import(py, "webtoken")?;
    let exc_class = m.getattr("MissingRequiredClaimError")?;
    let exc_instance = exc_class.call1((claim,))?;
    Err(PyErr::from_value(exc_instance))
}


// -- For external algos

static ALGORITHM_REGISTRY: OnceLock<RwLock<HashMap<String, Py<PyAny>>>> = OnceLock::new();

fn get_registry() -> &'static RwLock<HashMap<String, Py<PyAny>>> {
    ALGORITHM_REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}


// -- Helpers 

pub fn get_algorithm(py: Python, name: &str) -> Option<Py<PyAny>> {
    let map_lock = get_registry();
    let map = map_lock.read().unwrap();
    map.get(&name.to_uppercase()).map(|obj| obj.clone_ref(py))
}


fn is_hmac(alg: &str) -> bool {
    let s = alg.to_uppercase();
    matches!(s.as_str(), "HS256" | "HS384" | "HS512" | "BLAKE2b512" | "BLAKE2b256")
}


fn bytes_look_like_public_key(key: &[u8]) -> bool {
    if let Ok(s) = from_utf8(key) {
        let s = s.trim();
        s.starts_with("-----BEGIN") 
        || s.starts_with("ssh-") 
        || s.starts_with("ecdsa-")
    } else { 
        false 
    }
}


pub fn looks_like_public_key(key: &Bound<'_, PyAny>) -> bool {
    if let Ok(b) = key.extract::<Vec<u8>>() {
        return bytes_look_like_public_key(&b);
    }
    if let Ok(s) = key.extract::<String>() {
        return bytes_look_like_public_key(s.as_bytes());
    }
    false
}


fn peek_algorithm(token: &str) -> PyResult<String> {
    let part = token.split('.').next()
        .ok_or_else(|| PyValueError::new_err("Invalid Token Format"))?;
    
    let bytes = base64url_decode_inner(part)
        .map_err(|_| PyValueError::new_err("Invalid Header Encoding"))?;
        
    let header: PartialHeader = from_slice(&bytes)
        .map_err(|_| PyValueError::new_err("Invalid Header JSON"))?;
        
    Ok(header.alg)
}


fn extract_token_str(token: &Bound<'_, PyAny>) -> PyResult<String> {
    if let Ok(s) = token.extract::<String>() { Ok(s) }
    else if let Ok(b) = token.extract::<&[u8]>() { from_utf8(b).map(|s| s.to_string())
        .map_err(|_| DecodeError::new_err("Invalid token type")) }
    else { Err(DecodeError::new_err("Invalid token type. Token must be a <class 'bytes'>")) }
}


fn get_key_bytes(key: &Bound<'_, PyAny>, alg_name: &str, is_signing: bool, check_length: bool
) -> PyResult<Vec<u8>> {

    // Handle PyJWK Object
    if let Ok(jwk) = key.extract::<PyJWK>() { 
        if let Some(ref jwk_alg) = jwk.algorithm_name {
            if jwk_alg.to_uppercase() != alg_name.to_uppercase() {
                let msg = format!(
                    "The specified key is for algorithm {} but the token is signed with {}.",
                    jwk_alg, alg_name
                );
                if jwk_alg.starts_with("ES") && alg_name.starts_with("ES") {
                    return Err(InvalidKeyError::new_err(msg));
                }
                return Err(InvalidAlgorithmError::new_err(msg));
            }
        }
        return jwk.to_key_bytes(!is_signing); 
    }

    // Handle 'none' algorithm
    if alg_name.eq_ignore_ascii_case("none") { 
        return Ok(Vec::new()); 
    }

    // extract Raw Bytes
    let key_slice = if let Ok(s) = key.cast::<PyString>() {
        s.to_str()?.as_bytes()
    } else if let Ok(b) = key.cast::<PyBytes>() {
        b.as_bytes()
    } else {
        return Err(PyTypeError::new_err("Key must be string or bytes"));
    };

    // Handle PEM/SSH keys
    if let Ok(s) = from_utf8(key_slice) {
        let s_trim = s.trim();
        if s_trim.starts_with("ssh-") || s_trim.starts_with("ecdsa-") {
            if let Ok(pem) = crypto_parsing::ssh_to_pem(key_slice) {
                return Ok(pem);
            }
        }
    }
    
    if algorithms::is_supported_algorithm(alg_name) {
        if is_hmac(alg_name) {
            if bytes_look_like_public_key(key_slice) { 
                return Err(InvalidKeyError::new_err("The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret.")); 
            }

            if check_length {
                let min_len = match alg_name.to_uppercase().as_str() {
                    "HS256" => 32,
                    "HS384" => 48,
                    "HS512" => 64,
                    "BLAKE2b512" => 64,
                    "BLAKE2b256" => 32,
                    _ => 0,
                };
                if key_slice.len() < min_len {
                    return Err(InvalidKeyError::new_err(format!(
                        "The specified key is {} bytes long, which is below the minimum recommended length of {} bytes.",
                        key_slice.len(), min_len
                    )));
                }
            }
        }
    } else {
        return Err(InvalidAlgorithmError::new_err(format!("Algorithm not supported")));
    }

    Ok(key_slice.to_vec())
}


fn extract_aud_iss(audience: Option<&Bound<'_, PyAny>>, issuer: Option<&Bound<'_, PyAny>>
) -> PyResult<(Option<HashSet<String>>, Option<HashSet<String>>)> {
    
    let expected_aud = if let Some(aud) = audience {
        let mut s = HashSet::new();
        if let Ok(aud_str) = aud.extract::<String>() {
            s.insert(aud_str); 
        } else if let Ok(aud_list) = aud.extract::<Vec<String>>() {
            for a in aud_list { s.insert(a); } 
        } else {
            if aud.is_instance_of::<PyBytes>() {
                return Err(InvalidAudienceError::new_err("audience must be a string, iterable or None"));
            }
            return Err(PyTypeError::new_err("audience must be a string, iterable or None"));
        }
        Some(s)
    } else { None };

    let expected_iss = if let Some(iss) = issuer {
        let mut s = HashSet::new();
        if let Ok(iss_str) = iss.extract::<String>() { 
            s.insert(iss_str); 
        } else if let Ok(iss_list) = iss.extract::<Vec<String>>() {
            for i in iss_list { s.insert(i); } 
        } else {
            if iss.is_instance_of::<PyBytes>() {
                return Err(InvalidIssuerError::new_err("issuer must be a string, iterable or None"));
            }
            return Err(PyTypeError::new_err("issuer must be a string, iterable or None"));
        }
        Some(s)
    } else { None };

    Ok((expected_aud, expected_iss))
}



fn prepare_validation(
    algorithms: Option<Vec<String>>, options: Option<&Bound<'_, PyDict>>, verify_arg: Option<bool>, leeway_arg: f64,
    ) -> PyResult<(Validation, bool, bool, bool, bool, bool, bool, bool)> { 
    
    let verify_signature = if let Some(opts) = options && let Some(val) = opts.get_item(
        "verify_signature")? {
            val.extract::<bool>()? } else if let Some(false) = verify_arg {false} else { true };
    
    // Claim flags
    let get_flag = |key: &str, default: bool| -> PyResult<bool> {
        if let Some(opts) = options {
            if let Some(val) = opts.get_item(key)? {
                return val.extract::<bool>();
            }
        }
        Ok(default)
    };

    let check_exp = get_flag("verify_exp", verify_signature)?;
    let check_nbf = get_flag("verify_nbf", verify_signature)?;
    let check_iat = get_flag("verify_iat", verify_signature)?;
    let check_aud = get_flag("verify_aud", verify_signature)?;
    let check_iss = get_flag("verify_iss", verify_signature)?;
    let check_sub = get_flag("verify_sub", verify_signature)?;
    let strict_aud = get_flag("strict_aud", false)?;

    // Validation struct
    let alg_strs = algorithms.unwrap_or_else(|| vec!["HS256".to_string()]);
    
    let mut validation = Validation::default();
    validation.algorithms = alg_strs;

    if leeway_arg > 0.0 {
        validation.leeway = leeway_arg as u64;
    } else if let Some(opts) = options {
        if let Some(val) = opts.get_item("leeway")? {
            validation.leeway = val.extract::<u64>()?;
        }
    } 

    if let Some(opts) = options {
        if let Some(val) = opts.get_item("require")? {
            validation.required_spec_claims.extend(val.extract::<Vec<String>>()?);
        }
    }
    let effective_check_aud = if strict_aud { true } else { check_aud };

    Ok((validation, check_iat, check_exp, check_nbf, effective_check_aud, check_iss, check_sub, strict_aud))
}


// -- Python API

#[pyfunction]
#[pyo3(signature = (message, key, algorithm))]
fn raw_sign(message: &[u8], key: &Bound<'_, PyAny>, algorithm: &str) -> PyResult<Vec<u8>> {
    let key_bytes = get_key_bytes(key, algorithm, true, false)?;
    
    if let Ok(jwk) = key.extract::<PyJWK>() { 
        return perform_signature_jwk(message, &jwk, algorithm).map_err(Into::into); 
    }

    crypto::sign(algorithm, &key_bytes, message)
        .map_err(|e| PyValueError::new_err(format!("{}", e)))
}


#[pyfunction]
#[pyo3(signature = (message, signature, key, algorithm))]
fn raw_verify(message: &[u8], signature: &[u8], key: &Bound<'_, PyAny>, algorithm: &str) -> PyResult<bool> {
    let key_bytes = get_key_bytes(key, algorithm, false, false)?;
    
    if let Ok(jwk) = key.extract::<PyJWK>() { 
        return perform_verification_jwk(message, signature, &jwk, algorithm).map_err(Into::into); 
    }

    match crypto::verify(algorithm, &key_bytes, message, signature) {
        Ok(_) => Ok(true),
        Err(WebtokenError::InvalidSignature) => Ok(false),
        Err(e) => Err(PyValueError::new_err(format!("{}", e))),
    }
}


#[pyfunction]
#[pyo3(signature = (payload, key, algorithm="HS256", headers=None, sort_headers=true, check_length=false))] 
fn sign(
    payload: &Bound<'_, PyAny>, 
    key: &Bound<'_, PyAny>, 
    algorithm: &str, 
    headers: Option<&Bound<'_, PyDict>>,
    sort_headers: bool,
    check_length: bool, 
) -> PyResult<String> {
    
    let initial_header_map = match headers {
        Some(h) => depythonize(h).map_err(|e| PyTypeError::new_err(format!("Invalid header: {}", e)))?,
        None => Map::new() 
    };
    let header_map = jwt::prepare_headers(algorithm, initial_header_map, sort_headers)?;
    let payload_slice = payload.extract::<&[u8]>().map_err(|_| PyTypeError::new_err("Payload must be string or bytes"))?;

    let (header_b64, payload_b64, signing_input) = jws::prepare_jws_parts(&header_map, &payload_slice).map_err(Into::<PyErr>::into)?;
    let detached = header_map.get("b64") == Some(&Value::Bool(false));
    let key_bytes = get_key_bytes(key, algorithm, true, check_length)?;

    jws::sign_output(&signing_input, &header_b64, &payload_b64, &key_bytes, algorithm, detached)
        .map_err(Into::into)
}


#[pyfunction]
#[pyo3(signature = (token, key, algorithm))]
fn verify(py: Python, token: &Bound<'_, PyAny>, key: &Bound<'_, PyAny>, algorithm: &str) -> PyResult<(Py<PyAny>, Py<PyBytes>)> {
    let token_str = extract_token_str(token)?;
    let alg_norm = algorithm.to_uppercase();
    let key_bytes = get_key_bytes(key, &alg_norm, false, false)?;
    
    let (header, payload) = jws::verify_bytes(&token_str, &key_bytes, &alg_norm).map_err(Into::<PyErr>::into)?;
    let py_header = pythonize::pythonize(py, &header).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok((py_header.unbind(), PyBytes::new(py, &payload).unbind()))
}


#[pyfunction]
#[pyo3(signature = (key_data, algorithm=None))]
fn load_jwk(key_data: &Bound<'_, PyAny>, algorithm: Option<String>) -> PyResult<PyJWK> {
    crate::pyjwt_jwk_api::from_jwk(key_data, algorithm.as_deref().unwrap_or_default())
}


#[pyfunction]
fn load_jwk_set(data: &Bound<'_, PyAny>) -> PyResult<PyJWKSet> {
    crate::pyjwt_jwk_api::from_jwk_set(data)
}


#[pyfunction]
pub fn register_algorithm(name: &str, provider: Py<PyAny>) {
    let map_lock = get_registry();
    let mut map = map_lock.write().unwrap(); 
    map.insert(name.to_uppercase(), provider);
}


#[pyfunction]
pub fn unregister_algorithm(name: &str) {
    let map_lock = get_registry();
    let mut map = map_lock.write().unwrap();
    map.remove(&name.to_uppercase());
}


#[pyfunction(name = "decode_complete")]
#[pyo3(signature = (token, key=None, algorithms=None, options=None, audience=None, issuer=None, subject=None, verify=true, content=None, return_dict=true, leeway=0.0))]
fn decode_complete<'py>(
    py: Python<'py>, 
    token: &Bound<'py, PyAny>, 
    key: Option<&Bound<'py, PyAny>>, 
    algorithms: Option<Vec<String>>, 
    options: Option<&Bound<'py, PyDict>>, 
    audience: Option<&Bound<'py, PyAny>>, 
    issuer: Option<&Bound<'py, PyAny>>, 
    subject: Option<String>, 
    verify: Option<bool>, 
    content: Option<&[u8]>, 
    return_dict: bool, 
    leeway: f64
) -> PyResult<Bound<'py, PyAny>> {

    let token_str = extract_token_str(token)?;
    let token_final = jwt::handle_detached_content(&token_str, content).map_err(Into::<PyErr>::into)?;
    let alg_str = peek_algorithm(&token_final).unwrap_or_else(|_| "HS256".to_string());
    
    let mut effective_verify = verify.unwrap_or(true);
    let mut check_length = false; 
    if let Some(opts) = options {
        if let Ok(Some(v)) = opts.get_item("verify_signature") && let Ok(ver_sig) = v.extract::<bool>() { 
            effective_verify = ver_sig;
        }
        if let Ok(Some(v)) = opts.get_item("enforce_minimum_key_length") && let Ok(min_key) = v.extract::<bool>() { 
                check_length = min_key; 
        }
    }

    // Validate 'algorithms' Argument
    if effective_verify && algorithms.is_none() {
        let is_jwk = if let Some(k) = key { k.extract::<PyJWK>().is_ok() } else { false };
        if !is_jwk { 
            return Err(DecodeError::new_err("It is required that you pass in a value for the \"algorithms\" argument when calling decode().")); 
        }
    }

    // 'none' Algorithm Check
    if alg_str.eq_ignore_ascii_case("none") {
        if effective_verify {
            return Err(DecodeError::new_err("Signature verification failed"));
        }
    }

    // HMAC Key Check
    if alg_str.starts_with("HS") {
        if let Some(k) = key && looks_like_public_key(k) {
                 return Err(InvalidKeyError::new_err("The specified key is an asymmetric key or x509 certificate and \
                     should not be used as an HMAC secret."));   
        }
    }

    // Prepare Validation & Flags
    let (validation, check_iat, check_exp, check_nbf, check_aud, check_iss, check_sub, strict_aud)
        = prepare_validation(algorithms.clone(), options, verify, leeway)?;
    
    let (expected_aud, expected_iss) = extract_aud_iss(audience, issuer)?;

    // Load Key Bytes
    let decoding_key_bytes = if effective_verify && !alg_str.eq_ignore_ascii_case("none") {
        match key { 
            Some(k) => Some(get_key_bytes(k, &alg_str, false, check_length)?), 
            None => return Err(PyValueError::new_err("Key required")) 
        }
    } else { 
        None 
    };

    let result = py.detach(move || {
        crate::jwt::decode(
            token_final, 
            decoding_key_bytes, 
            validation, 
            effective_verify, 
            // Flags
            (check_iat, check_exp, check_nbf, check_aud, check_iss, check_sub, strict_aud), 
            // Expected Values
            (expected_aud, expected_iss, subject),
            content, 
            return_dict
        )
    });

    match result {
        Ok(val) => {
            let py_obj = pythonize(py, &val).map_err(|e| PyValueError::new_err(e.to_string()))?;
            Ok(py_obj) 
        },
        Err(e) => {
             if let WebtokenError::MissingRequiredClaim(claim) = e {
                 return raise_missing_claim_error(py, &claim);
             }
             Err(e.into())
        }
    }
}


#[pyfunction]
#[pyo3(signature = (payload, key, algorithm="HS256", headers=None, sort_headers=true, check_length=false))] 
fn encode(
    payload: &Bound<'_, PyDict>, 
    key: &Bound<'_, PyAny>, 
    algorithm: &str, 
    headers: Option<&Bound<'_, PyDict>>,
    sort_headers: bool,
    check_length: bool, 
) -> PyResult<String> {
    
    let time_claims = ["exp", "iat", "nbf"];
    let mut claims_map = Map::new();

    // Claims prep
    for (k_py, v_py) in payload {
        let key_str = k_py.extract::<&str>()?; 
        if key_str == "iss" && !v_py.is_instance_of::<PyString>() { 
            return Err(PyTypeError::new_err("Issuer (iss) must be a string.")); 
        }

        let timestamp = time_claims.contains(&key_str).then(|| {
            v_py.extract::<OffsetDateTime>().map(|dt| dt.unix_timestamp()).or_else(
                |_| v_py.extract::<PrimitiveDateTime>().map(|dt| dt.assume_utc().unix_timestamp())
            ).ok()
        }).flatten();

        let value_json = match timestamp {
            Some(ts) => Value::Number(ts.into()),
            None => depythonize(&v_py).map_err(|e| PyValueError::new_err(
                format!("Serialization failed: {e}")))?,
        };

        claims_map.insert(key_str.to_string(), value_json);
    }

    let initial_header_map = match headers {
        Some(h) => depythonize(h).map_err(|e| PyTypeError::new_err(format!("Invalid header: {}", e)))?,
        None => Map::new() 
    };

    let header_map = jwt::prepare_headers(algorithm, initial_header_map, sort_headers)?;
    let payload_bytes = to_vec(&claims_map).map_err(|e| PyValueError::new_err(e.to_string()))?;

    let (header_b64, payload_b64, signing_input) = jws::prepare_jws_parts(&header_map, &payload_bytes)
        .map_err(Into::<PyErr>::into)?;

    if let Ok(jwk) = key.extract::<PyJWK>() {
        let sig_bytes = perform_signature_jwk(signing_input.as_bytes(), &jwk, algorithm).map_err(Into::<PyErr>::into)?;
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);
        return Ok(format!("{}.{}", signing_input, sig_b64));
    }

    let key_bytes = get_key_bytes(key, algorithm, true, check_length)?;
    let detached = header_map.get("b64") == Some(&Value::Bool(false));

    jws::sign_output(&signing_input, &header_b64, &payload_b64, &key_bytes, algorithm, detached).map_err(Into::into)
}


#[pyfunction(name = "decode")]
#[pyo3(signature = (token, key=None, algorithms=None, options=None, audience=None, issuer=None, subject=None, verify=true, content=None, return_dict=true, leeway=0.0))]
fn decode<'py>(
    py: Python<'py>, 
    token: &Bound<'py, PyAny>, 
    key: Option<&Bound<'py, PyAny>>, 
    algorithms: Option<Vec<String>>, 
    options: Option<&Bound<'py, PyDict>>,
    audience: Option<&Bound<'py, PyAny>>, 
    issuer: Option<&Bound<'py, PyAny>>, 
    subject: Option<String>, 
    verify: Option<bool>, 
    content: Option<&[u8]>,
    return_dict: bool,
    leeway: f64,
) -> PyResult<Bound<'py, PyAny>> {
    
    let complete = decode_complete(
        py, token, key, algorithms, options, audience, issuer, subject, verify, content, return_dict, leeway)?;
    
    if let Ok(dict) = complete.cast::<PyDict>() {
        if let Some(payload) = dict.get_item("payload")? {
            return Ok(payload);
        }
    }
    Err(PyValueError::new_err("Failed to extract payload"))
}


fn get_jwe_key_bytes(key: &Bound<'_, PyAny>, is_public_only: bool) -> PyResult<Vec<u8>> {
    if let Ok(jwk) = key.extract::<PyJWK>() {
        return jwk.to_key_bytes(is_public_only).map_err(PyErr::from);
    }
    if let Ok(b) = key.extract::<Vec<u8>>() { return Ok(b); }
    if let Ok(s) = key.extract::<String>() { return Ok(s.into_bytes()); }
    Err(PyTypeError::new_err("JWE key must be bytes, str (PEM), or a PyJWK object"))
}


#[pyfunction]
#[pyo3(signature = (protected_header, payload, key))]
fn encrypt_compact<'py>(
    protected_header: &Bound<'py, PyDict>, 
    payload: BytesOrString, 
    key: &Bound<'py, PyAny>
) -> PyResult<String> {
    
    let header_val: serde_json::Value = pythonize::depythonize(protected_header)
        .map_err(|e| PyValueError::new_err(format!("Invalid header: {}", e)))?;
        
    let key_bytes = get_jwe_key_bytes(key, true)?;

    crate::jwe::encrypt_compact(&header_val, payload.as_bytes(), &key_bytes)
        .map_err(PyErr::from)
}


#[pyfunction]
#[pyo3(signature = (token, key))]
fn decrypt_compact<'py>(
    py: Python<'py>, 
    token: &str, 
    key: &Bound<'py, PyAny>
) -> PyResult<Bound<'py, PyBytes>> {
    
    let key_bytes = get_jwe_key_bytes(key, false)?;
    let payload = crate::jwe::decrypt_compact(token, &key_bytes).map_err(PyErr::from)?;
        
    Ok(PyBytes::new(py, &payload))
}


fn base64url_decode_inner(input: &str) -> Result<Vec<u8>, String> {
    let clean: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if let Ok(v) = URL_SAFE_NO_PAD.decode(&clean) { return Ok(v); }
    if let Ok(v) = STANDARD.decode(&clean) { return Ok(v); }
    Err("Invalid padding or alphabet".to_string())
}


#[pyfunction]
#[pyo3(signature = (token))]
fn get_unverified_header<'py>(py: Python<'py>, token: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {

    let token_str = extract_token_str(token)?;
    let part = token_str.split('.').next().ok_or_else(|| DecodeError::new_err("Invalid Token Format"))?;
    let bytes = base64url_decode_inner(part).map_err(|_| DecodeError::new_err("Invalid header padding"))?;
    let val: Value = from_slice(&bytes).map_err(|e| DecodeError::new_err(format!("Invalid header string: {}", e)))?;

    // PyJWT wants 'kid' to be a string if present, even for unverified headers
    if let Some(kid) = val.get("kid") {
        if !kid.is_string() {
            return Err(InvalidTokenError::new_err("Key ID header parameter must be a string"));
        }
    }
    pythonize(py, &val).map_err(|e| PyValueError::new_err(e.to_string()))
}


#[pyfunction]
fn unsafe_peek<'py>(py: Python<'py>, token: &str) -> PyResult<Bound<'py, PyAny>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 { 
        return Err(PyValueError::new_err("Invalid Token Format")); 
    }
    let payload_bytes = base64url_decode_inner(parts[1]).map_err(|_| PyValueError::new_err("Invalid Payload Base64"))?;
    let claims: Value = from_slice(&payload_bytes).map_err(|_| PyValueError::new_err("Invalid Payload JSON"))?;
    Ok(pythonize(py, &claims).unwrap())
}


#[pyfunction]
fn pem_to_jwk(pem: &[u8]) -> PyResult<String> {
    key_utils::pem_to_jwk(pem).map_err(|e| PyValueError::new_err(e))
}


#[pyfunction]
#[pyo3(signature = (claims, options=None, audience=None, issuer=None, subject=None, verify=true, leeway=0.0))]
fn validate_claims(
    claims: &Bound<'_, PyAny>,
    options: Option<&Bound<'_, PyDict>>,
    audience: Option<&Bound<'_, PyAny>>,
    issuer: Option<&Bound<'_, PyAny>>,
    subject: Option<String>,
    verify: Option<bool>,
    leeway: f64
) -> PyResult<()> {
    // 1. Convert Python Dict to Serde Value
    let claims_val: Value = depythonize(claims).map_err(|e| PyValueError::new_err(e.to_string()))?;
    
    // 2. Prepare Validation & Flags
    let (mut validation, check_iat, check_exp, check_nbf, check_aud, check_iss, check_sub, strict_aud) 
        = prepare_validation(None, options, verify, leeway)?;
    
    if validation.leeway == 0 && leeway > 0.0 {
        validation.leeway = leeway as u64; 
    }

    let (expected_aud, expected_iss) = extract_aud_iss(audience, issuer)?;

    // 3. Call the logic in jwt.rs (using the new tuple signature)
    let result = crate::jwt::validate_claims(
        &claims_val, 
        &validation, 
        // Group 1: Flags
        (check_iat, check_exp, check_nbf, check_aud, check_iss, check_sub, strict_aud),
        // Group 2: Expected Values
        (&expected_aud, &expected_iss, &subject)
    );

    // 4. Handle Result & Fix Type Inference Error (E0282)
    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            // Fix type inference by explicitly using PyErr::from
            Err(PyErr::from(e)) 
        }
    }
}


#[pyfunction]
fn load_key_from_pem(key_data: BytesOrString) -> PyResult<PyJWK> {

    let json_str = key_utils::pem_to_jwk(&<Vec<u8>>::from(key_data)).map_err(|e| PyValueError::new_err(e))?;
    let val: serde_json::Value = from_str(&json_str).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let alg = val.get("alg").and_then(|s| s.as_str()).map(|s| s.to_string());

    Ok(PyJWK { inner: val, algorithm_name: alg })
}



#[pyfunction]
#[pyo3(signature = (key, payload, purpose="local", footer=None, implicit_assertion=None, nonce=None))]
fn paseto_encode(key: BytesOrString, payload: &Bound<'_, PyAny>, purpose: &str, footer: Option<&[u8]>,
    implicit_assertion: Option<&[u8]>, nonce: Option<&[u8]>) -> PyResult<String> {

    let mut key_bytes = key.as_bytes().to_vec();

    if purpose == "secret" && key_bytes.len() == 64 {
        key_bytes = key_bytes[..32].to_vec();
    }
    
    // Map secret purpose to public for the underlying engine
    let actual_purpose = if purpose == "secret" { "public" } else { purpose };

    let payload_bytes: Vec<u8> = if let Ok(py_bytes) = payload.cast::<pyo3::types::PyBytes>() {
        py_bytes.as_bytes().to_vec()
    } else {
        let val: serde_json::Value = pythonize::depythonize(payload)
            .map_err(|e| PyValueError::new_err(format!("Serialization failed: {}", e)))?;
        serde_json::to_vec(&val).map_err(|_| PyValueError::new_err("JSON encoding failed"))?
    };

    match actual_purpose {
        "local" => {
            paseto::encrypt_v4_local(&payload_bytes, &key_bytes, footer, implicit_assertion, nonce)
                .map_err(|e| PyValueError::new_err(format!("{}", e)))
        },
        "public" => {
            paseto::sign_v4_public(&payload_bytes, &key_bytes, footer, implicit_assertion)
                .map_err(|e| PyValueError::new_err(format!("{}", e)))
        },
        _ => Err(PyValueError::new_err("Purpose must be 'local' or 'public'"))
    }
}


#[pyfunction]
#[pyo3(signature = (key, token, purpose=None, implicit_assertion=None))]
fn paseto_decode<'py>(
    py: Python<'py>, 
    key: &Bound<'py, PyAny>, 
    token: BytesOrString,
    purpose: Option<BytesOrString>,
    implicit_assertion: Option<&[u8]>
) -> PyResult<(Bound<'py, PyAny>, Bound<'py, PyBytes>)> {

    // 1. Mimic Python's "falsy" evaluation (if empty, treat as None)
    let purpose_is_empty = match &purpose {
        Some(BytesOrString::Str(s)) => s.is_empty(),
        Some(BytesOrString::Bytes(b)) => b.is_empty(),
        None => true,
    };

    let mut actual_purpose = match &purpose {
        Some(BytesOrString::Str(s)) if !s.is_empty() => s.clone(),
        Some(BytesOrString::Bytes(b)) if !b.is_empty() => from_utf8(b).unwrap_or("local").to_string(),
        _ => "local".to_string(), // Default fallback
    };

    // 2. Extract key and track its original type
    let mut key_bytes: Vec<u8>;
    let enforce_length: bool;

    if let Ok(kb) = key.getattr("key_bytes") {
        key_bytes = kb.extract::<Vec<u8>>()?;
        enforce_length = true; // Custom Key objects always contain raw bytes
        
        // Fallback to the object's purpose if None/Empty was passed
        if purpose_is_empty {
            if let Ok(p) = key.getattr("purpose") {
                if let Ok(p_str) = p.extract::<String>() {
                    actual_purpose = p_str;
                }
            }
        }
    } else if let Ok(b) = key.extract::<Vec<u8>>() {
        key_bytes = b;
        enforce_length = true; // Explicitly passed as raw bytes
    } else if let Ok(s) = key.extract::<String>() {
        key_bytes = s.into_bytes();
        enforce_length = false; // Strings (like PASERK) bypass the length check
    } else {
        return Err(PyTypeError::new_err("key must be bytes, str, or Key object"));
    }

    // 3. Token extraction
    let token_str = match token {
        BytesOrString::Str(s) => s,
        BytesOrString::Bytes(b) => from_utf8(&b).map_err(|_| PyValueError::new_err("Invalid UTF-8 in token"))?.to_string(),
    };

    // 4. Length Validation (matching the old Python isinstance check)
    if enforce_length && key_bytes.len() != 32 && key_bytes.len() != 64 {
        return Err(PyValueError::new_err("key is not found for verifying the token"));
    }

    // 5. Handle public-key derivation natively in Rust
    if actual_purpose == "secret" {
        if key_bytes.len() == 64 {
            key_bytes = key_bytes[32..].to_vec(); 
        } else if key_bytes.len() == 32 {
            key_bytes = crypto::ed25519_public_from_seed(&key_bytes)
                .map_err(|_| PyValueError::new_err("Invalid Ed25519 seed"))?;
        }
    }
    
    let engine_purpose = if actual_purpose == "secret" { "public" } else { actual_purpose.as_str() };

    // 6. Decrypt or Verify
    let (payload_bytes, footer) = match engine_purpose {
        "local" => {
             paseto::decrypt_v4_local(&token_str, &key_bytes, implicit_assertion)
                .map_err(|e| {
                    if let WebtokenError::InvalidSignature = e {
                        PyValueError::new_err("DecryptError") 
                    } else {
                        PyValueError::new_err(format!("{}", e))
                    }
                })?
        },
        "public" => {
             paseto::verify_v4_public(&token_str, &key_bytes, implicit_assertion)
                .map_err(|e| PyValueError::new_err(format!("{}", e)))?
        },
        _ => return Err(PyValueError::new_err("Purpose must be 'local' or 'public'"))
    };

    let footer_py = pyo3::types::PyBytes::new(py, &footer);

    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) {
        if let Ok(py_obj) = pythonize::pythonize(py, &val) {
            return Ok((py_obj, footer_py));
        }
    }

    let payload_py = pyo3::types::PyBytes::new(py, &payload_bytes).into_any();
    Ok((payload_py, footer_py))
}


#[pyfunction]
#[pyo3(signature = (payload, key, footer=None, implicit_assertion=None))]
fn paseto_sign(payload: &[u8], key: &[u8], footer: Option<&[u8]>, implicit_assertion: Option<&[u8]>) -> PyResult<String> {
    paseto::sign_v4_public(payload, key, footer, implicit_assertion).map_err(PyErr::from)
}


#[pyfunction]
fn paseto_verify<'py>(py: Python<'py>, token: &str, key: &[u8], implicit_assertion: Option<&[u8]>) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (payload, footer) = paseto::verify_v4_public(token, key, implicit_assertion).map_err(PyErr::from)?;
    Ok((PyBytes::new(py, &payload), PyBytes::new(py, &footer)))
}


#[pyfunction]
fn paserk_id(key: BytesOrString, purpose: &str) -> PyResult<String> {
    paseto::calculate_paserk_id(key.as_bytes(), purpose).map_err(PyErr::from)
}


#[pyfunction]
#[pyo3(signature = (key, purpose))]
fn paserk_peer_id(key: BytesOrString, purpose: &str) -> PyResult<String> {
    match purpose {
        "local" | "public" => { Ok("".to_string())},
        "secret" => {
            let pub_key = crypto::ed25519_public_from_seed(key.as_bytes()).map_err(|_| PyValueError::new_err(
                "Invalid Ed25519 secret key"))?;
            paseto::calculate_paserk_id(&pub_key, "public").map_err(PyErr::from)
        },
        _ => Err(PyValueError::new_err("Purpose must be 'local', 'public', or 'secret'")),
    }
}


#[pyfunction]
#[pyo3(signature = (key, purpose, wrapping_key=None, password=None, sealing_key=None, options=None))]
fn paserk_wrap(key: BytesOrString, purpose: &str, wrapping_key: Option<BytesOrString>, password: Option<BytesOrString>,
    sealing_key: Option<BytesOrString>, options: Option<&Bound<'_, PyDict>>) -> PyResult<String> {
    
    // Password-Based Key Wrapping (PBKW)
    if let Some(pw) = password {
        let pw_bytes: Vec<u8> = pw.into();
        let mut memlimit = 67108864; // Default 64 MiB
        let mut opslimit = 2;        // Default 2 iterations
        let parallelism = 1;         // Argon2 standard

        if let Some(opts) = options {
            if let Ok(Some(v)) = opts.get_item("memlimit") { memlimit = v.extract::<u64>()?; }
            if let Ok(Some(v)) = opts.get_item("opslimit") { opslimit = v.extract::<u32>()?; }
        }

        return paseto::paserk_wrap_pbkw(&pw_bytes, key.as_bytes(), purpose, memlimit, opslimit, parallelism)
            .map_err(|e| PyValueError::new_err(format!("{}", e)));
    }
    
    // Platform-Independent Encryption (PIE)
    if let Some(wk) = wrapping_key {
        let wk_bytes: Vec<u8> = wk.into();
        return paseto::paserk_wrap_pie(&wk_bytes, key.as_bytes(), purpose)
            .map_err(|e| PyValueError::new_err(format!("{}", e)));
    }

    // Public Key Sealing (Seal)
    if let Some(sk) = sealing_key {
        let sk_bytes: Vec<u8> = sk.into();
        let stripped_sk = crypto_parsing::extract_x25519_bytes(&sk_bytes).unwrap_or(sk_bytes.clone());
        return paseto::paserk_seal(&stripped_sk, key.as_bytes())
            .map_err(|e| PyValueError::new_err(format!("{}", e)));
    }

    // Basic Serialization
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let b64_key = URL_SAFE_NO_PAD.encode(key.as_bytes());
    match purpose {
        "local" => Ok(format!("k4.local.{}", b64_key)),
        "public" => Ok(format!("k4.public.{}", b64_key)),
        "secret" => Ok(format!("k4.secret.{}", b64_key)),
        _ => Err(PyValueError::new_err("Invalid PASERK purpose")),
    }
}


#[pyfunction]
#[pyo3(signature = (paserk, wrapping_key=None, password=None, unsealing_key=None))]
fn paserk_unwrap<'py>(py: Python<'py>, paserk: &str, wrapping_key: Option<BytesOrString>, password: Option<BytesOrString>,
    unsealing_key: Option<BytesOrString>,) -> PyResult<Bound<'py, PyBytes>> {

    // Password-Based Key Unwrapping (PBKW)
    if let Some(pw) = password {
        let pw_bytes: Vec<u8> = pw.into();
        let unwrapped = paseto::paserk_unwrap_pbkw(&pw_bytes, paserk)
            .map_err(|e| PyValueError::new_err(format!("{}", e)))?;
        return Ok(PyBytes::new(py, &unwrapped));
    }

    // Platform-Independent Decryption (PIE)
    if let Some(wk) = wrapping_key {
        let wk_bytes: Vec<u8> = wk.into();
        let unwrapped = paseto::paserk_unwrap_pie(&wk_bytes, paserk)
            .map_err(|e| PyValueError::new_err(format!("{}", e)))?;
        return Ok(PyBytes::new(py, &unwrapped));
    }

    // Public Key Unsealing (Seal)
    if let Some(uk) = unsealing_key {
        let uk_bytes: Vec<u8> = uk.into();
        let stripped_uk = crate::crypto_parsing::extract_x25519_bytes(&uk_bytes).unwrap_or(uk_bytes.clone());
        let unwrapped = paseto::paserk_unseal(&stripped_uk, paserk)
            .map_err(|e| PyValueError::new_err(format!("{}", e)))?;
        return Ok(PyBytes::new(py, &unwrapped));
    }

    // Basic Deserialization
    let parts: Vec<&str> = paserk.split('.').collect();
    if parts.len() < 3 || parts[0] != "k4" {
        return Err(PyValueError::new_err("Invalid PASERK basic format"));
    }
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let data = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| PyValueError::new_err("Invalid PASERK encoding"))?;
    
    Ok(PyBytes::new(py, &data))
}

// -- Module registration

// Register a submodule and add it to sys.modules 
fn add_submodule_with_sys(py: Python, parent: &Bound<'_, PyModule>, name: &str, 
    setup_fn: impl FnOnce(Python, &Bound<'_, PyModule>) -> PyResult<()>
) -> PyResult<()> {
        
    let submod = PyModule::new(py, name)?;
    setup_fn(py, &submod)?;
    parent.add_submodule(&submod)?;

    // Add to sys.modules - allows from webtoken.jwk import 
    let parent_name = parent.name()?;
    let full_name = format!("{}.{}", parent_name, name);
    py.import("sys")?.getattr("modules")?.set_item(full_name, &submod)?;

    Ok(())
}

#[pymodule]
fn _webtoken(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("PyJWTError", py.get_type::<PyJWTError>())?;
    m.add("InvalidTokenError", py.get_type::<InvalidTokenError>())?;
    m.add("DecodeError", py.get_type::<DecodeError>())?;
    m.add("InvalidSignatureError", py.get_type::<InvalidSignatureError>())?;
    m.add("ExpiredSignatureError", py.get_type::<ExpiredSignatureError>())?;
    m.add("InvalidAudienceError", py.get_type::<InvalidAudienceError>())?;
    m.add("InvalidIssuerError", py.get_type::<InvalidIssuerError>())?;
    m.add("ImmatureSignatureError", py.get_type::<ImmatureSignatureError>())?;
    m.add("MissingRequiredClaimError", py.get_type::<MissingRequiredClaimError>())?;
    m.add("InvalidIssuedAtError", py.get_type::<InvalidIssuedAtError>())?;
    m.add("InvalidJTIError", py.get_type::<InvalidJTIError>())?;
    m.add("InvalidSubjectError", py.get_type::<InvalidSubjectError>())?;
    m.add("InvalidKeyError", py.get_type::<InvalidKeyError>())?;
    m.add("InvalidAlgorithmError", py.get_type::<InvalidAlgorithmError>())?;

    m.add_function(wrap_pyfunction!(raw_sign, m)?)?;
    m.add_function(wrap_pyfunction!(raw_verify, m)?)?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(validate_key_properties, m)?)?;
    m.add_function(wrap_pyfunction!(encode, m)?)?; 
    m.add_function(wrap_pyfunction!(decode, m)?)?;
    m.add_function(wrap_pyfunction!(decode_complete, m)?)?;
    m.add_function(wrap_pyfunction!(get_unverified_header, m)?)?;
    m.add_function(wrap_pyfunction!(load_key_from_pem, m)?)?;
    m.add_function(wrap_pyfunction!(unsafe_peek, m)?)?;
    m.add_function(wrap_pyfunction!(register_algorithm, m)?)?;
    m.add_function(wrap_pyfunction!(unregister_algorithm, m)?)?;
    m.add_function(wrap_pyfunction!(validate_claims, m)?)?;

    m.add_function(wrap_pyfunction!(encrypt_compact, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_compact, m)?)?;
    m.add_function(wrap_pyfunction!(paseto_encode, m)?)?;  
    m.add_function(wrap_pyfunction!(paseto_decode, m)?)?;
    m.add_function(wrap_pyfunction!(paseto_sign, m)?)?;
    m.add_function(wrap_pyfunction!(paseto_verify, m)?)?;
    m.add_function(wrap_pyfunction!(paserk_id, m)?)?;
    m.add_function(wrap_pyfunction!(paserk_peer_id, m)?)?;
    m.add_function(wrap_pyfunction!(paserk_wrap, m)?)?;
    m.add_function(wrap_pyfunction!(paserk_unwrap, m)?)?;

    m.add_function(wrap_pyfunction!(load_jwk, m)?)?;
    m.add_function(wrap_pyfunction!(load_jwk_set, m)?)?; 
    m.add_function(wrap_pyfunction!(pem_to_jwk, m)?)?;
    m.add_function(wrap_pyfunction!(check_rsa_key_length, m)?)?;

    py_utils::export_py_utils(m)?;
    crypto::export_functions(m)?; 
    crypto_parsing::export_functions(m)?;
    paseto::export_functions(m)?;

    add_submodule_with_sys(py, m, "api_jwk", |_py, mod_| {
        mod_.add_class::<PyJWK>()?;
        mod_.add_class::<PyJWKSet>()?;
        pyjwt_jwk_api::register_jwk_module(py, mod_)
    })?;

    add_submodule_with_sys(py, m, "api_jws", |_py, mod_| {
        mod_.add_function(wrap_pyfunction!(get_unverified_header, mod_)?)?;
        Ok(())
    })?;

    add_submodule_with_sys(py, m, "algorithms", |_py, _mod_| {
        Ok(())
    })?;

    add_submodule_with_sys(py, m, "exceptions", |_py, m_exc| {
        m_exc.add("PyJWTError", py.get_type::<PyJWTError>())?;
        m_exc.add("InvalidTokenError", py.get_type::<InvalidTokenError>())?;
        m_exc.add("DecodeError", py.get_type::<DecodeError>())?;
        m_exc.add("InvalidSignatureError", py.get_type::<InvalidSignatureError>())?;
        m_exc.add("ExpiredSignatureError", py.get_type::<ExpiredSignatureError>())?;
        m_exc.add("InvalidAudienceError", py.get_type::<InvalidAudienceError>())?;
        m_exc.add("InvalidIssuerError", py.get_type::<InvalidIssuerError>())?;
        m_exc.add("ImmatureSignatureError", py.get_type::<ImmatureSignatureError>())?;
        m_exc.add("MissingRequiredClaimError", py.get_type::<MissingRequiredClaimError>())?;
        m_exc.add("InvalidIssuedAtError", py.get_type::<InvalidIssuedAtError>())?;
        m_exc.add("InvalidJTIError", py.get_type::<InvalidJTIError>())?;
        m_exc.add("InvalidSubjectError", py.get_type::<InvalidSubjectError>())?;
        m_exc.add("InvalidAlgorithmError", py.get_type::<InvalidAlgorithmError>())?;
        m_exc.add("InvalidKeyError", py.get_type::<InvalidKeyError>())?;
        Ok(())
    })?;

    Ok(())
}