
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value; 
use num_bigint::BigUint;

use pyo3::prelude::*;
use pyo3::create_exception; 
use pyo3::types::{PyDict, PyList, PyBytes, PyInt};
use pyo3::exceptions::{PyValueError, PyKeyError, PyTypeError};

use pythonize::depythonize;

use crate::{jwk, WebtokenError, PyJWTError, InvalidKeyError}; 
use crate::algorithms::Algorithm;
use crate::jwk::{extract_or_recover_rsa_components};

create_exception!(toke, PyJWKSetError, PyJWTError); 
create_exception!(toke, PyJWKError, PyJWTError);


#[pyclass(name = "PyJWK")]
#[derive(Clone)]
pub struct PyJWK {
    pub inner: Value, 
    pub algorithm_name: Option<String>,
}


// Helpers needed by lib.rs
impl PyJWK {

    pub(crate) fn to_key_bytes(&self, public_only: bool) -> PyResult<Vec<u8>> {
        jwk::extract_key_bytes(&self.inner, public_only).map_err(PyValueError::new_err)
    }
}


#[pymethods]
impl PyJWK {

    #[new]
    #[pyo3(signature = (jwk_data, algorithm=None))]
    fn new(jwk_data: &Bound<'_, PyDict>, algorithm: Option<String>) -> PyResult<Self> {
        let raw: Value = depythonize(jwk_data)
            .map_err(|e| PyValueError::new_err(format!("Invalid JWK data: {}", e)))?;
        
        let (inner, alg) = jwk::normalize(raw, algorithm)
            .map_err(|e| crate::InvalidKeyError::new_err(e))?;

        Ok(PyJWK { inner, algorithm_name: alg })
    }


    #[staticmethod]
    #[pyo3(signature = (data, algorithm=None))]
    pub fn from_json(data: &str, algorithm: Option<String>) -> PyResult<Self> {
        let raw = jwk::parse_json(data).map_err(PyValueError::new_err)?;
        
        let (inner, alg) = jwk::normalize(raw, algorithm)
            .map_err(|e| crate::InvalidKeyError::new_err(e))?;

        Ok(PyJWK { inner, algorithm_name: alg })
    }
    

    #[staticmethod]
    #[pyo3(signature = (obj, algorithm=None))]
    pub fn from_dict(obj: &Bound<'_, PyDict>, algorithm: Option<String>) -> PyResult<Self> {
        Self::new(obj, algorithm)
    }


    #[getter]
    fn key_id(&self) -> Option<String> {
        self.inner.get("kid").and_then(|v| v.as_str()).map(|s| s.to_string())
    }

    #[getter]
    fn public_key_use(&self) -> Option<String> {
        self.inner.get("use").and_then(|v| v.as_str()).map(|s| s.to_string())
    }

    #[getter]
    fn algorithm_name(&self) -> Option<String> {
        // [FIX] Compatibility: Default to RS256 for RSA keys if unspecified,
        // matching PyJWT behavior, while keeping the internal field None for flexibility.
        self.algorithm_name.clone().or_else(|| {
            if let Ok("RSA") = self.key_type().as_deref() {
                Some("RS256".to_string())
            } else {
                None
            }
        })
    }

    #[getter]
    fn key_type(&self) -> PyResult<String> {
        self.inner.get("kty")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| PyValueError::new_err("kty missing"))
    }
    
    
    #[getter]
    fn bit_length(&self) -> PyResult<usize> {
        let kty = self.key_type()?;
        
        match kty.as_str() {
            "RSA" => {
                let n_b64 = self.inner.get("n").and_then(|v| v.as_str())
                    .ok_or_else(|| crate::InvalidKeyError::new_err("RSA key missing 'n'"))?;
                let n_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(n_b64)
                    .map_err(|_| crate::InvalidKeyError::new_err("Invalid 'n' encoding"))?;
                Ok(num_bigint::BigUint::from_bytes_be(&n_bytes).bits() as usize)
            },
            "EC" => {
                let crv = self.inner.get("crv").and_then(|v| v.as_str()).unwrap_or("");
                match crv {
                    "P-256" | "secp256k1" => Ok(256),
                    "P-384" => Ok(384),
                    "P-521" => Ok(521),
                    _ => Ok(0)
                }
            },
            "oct" => {
                let k_b64 = self.inner.get("k").and_then(|v| v.as_str())
                    .ok_or_else(|| crate::InvalidKeyError::new_err("HMAC key missing 'k'"))?;
                let len = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(k_b64)
                    .map_err(|_| crate::InvalidKeyError::new_err("Invalid 'k' encoding"))?
                    .len();
                Ok(len * 8)
            },
            _ => Ok(0)
        }
    }

    
    fn validate_rsa_consistency(&self) -> PyResult<()> {

        let kty = self.key_type()?;
        if kty != "RSA" { return Ok(()); }
        
        if self.inner.get("n").is_none() || self.inner.get("e").is_none() {
             return Err(crate::InvalidKeyError::new_err("Missing RSA public key components"));
        }

        if self.inner.get("oth").is_some() {
             return Err(crate::InvalidKeyError::new_err("RSA keys with 'oth' (other primes) are not supported"));
        }

        let crt = ["p", "q", "dp", "dq", "qi"];
        let count = crt.iter().filter(|&&k| self.inner.get(k).is_some()).count();
        
        if count > 0 && count < 5 {
             let missing: Vec<_> = crt.iter().filter(|&&k| self.inner.get(k).is_none()).collect();
             return Err(crate::InvalidKeyError::new_err(format!("Missing RSA private key component: {:?}", missing)));
        }
        Ok(())
    }


    fn as_dict<'py>(&self, py: Python<'py>) -> PyResult<Py<PyAny>> {
        let dict = pythonize::pythonize(py, &self.inner)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(dict.unbind())
    }


    pub fn public_key(&self) -> PyResult<PyJWK> {
        let mut new_val = self.inner.clone();
        
        if let Value::Object(ref mut map) = new_val {
            map.remove("d");
            map.remove("p"); map.remove("q");
            map.remove("dp"); map.remove("dq"); map.remove("qi");
            map.remove("oth");
            map.remove("k"); 
        }

        Ok(PyJWK { 
            inner: new_val, 
            algorithm_name: self.algorithm_name.clone() 
        })
    }


    pub fn public_numbers(&self, py: Python) -> PyResult<Py<PyAny>> {
        let kty = self.key_type()?;

        if kty == "RSA" {
            let types = pyo3::types::PyModule::import(py, "types")?;              
            let sn = types.call_method0("SimpleNamespace")?;
             
             if let Some(n_b64) = self.inner.get("n").and_then(|v| v.as_str()) {
                 let n_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(n_b64)
                    .map_err(|_| PyValueError::new_err("Invalid n base64"))?;
                 let int_cls = py.get_type::<pyo3::types::PyInt>();
                 let py_n = int_cls.call_method1("from_bytes", (n_bytes.as_slice(), "big"))?;
                 sn.setattr("n", py_n)?;
             }
             if let Some(e_b64) = self.inner.get("e").and_then(|v| v.as_str()) {
                 let e_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(e_b64)
                      .map_err(|_| PyValueError::new_err("Invalid e base64"))?;
                 let int_cls = py.get_type::<pyo3::types::PyInt>();
                 let py_e = int_cls.call_method1("from_bytes", (e_bytes.as_slice(), "big"))?;
                 sn.setattr("e", py_e)?;
             }
             return Ok(sn.into());
        }

        if kty == "EC" {
            let b64_to_int = |field: &str| -> PyResult<Py<PyAny>> {
                let val_b64 = self.inner.get(field).and_then(|v| v.as_str())
                    .ok_or_else(|| PyValueError::new_err(format!("Missing '{}'", field)))?;
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(val_b64)
                    .map_err(|e| PyValueError::new_err(format!("Invalid base64 for {}: {}", field, e)))?;
                let int_cls = py.get_type::<pyo3::types::PyInt>();
                Ok(int_cls.call_method1("from_bytes", (bytes.as_slice(), "big"))?.into())
            };

            let x_py = b64_to_int("x")?;
            let y_py = b64_to_int("y")?;

            let obj = Py::new(py, PyEllipticCurvePublicNumbers { x: x_py, y: y_py })?;
            return Ok(obj.into_any());
        }

        Ok(py.None())
    }


    fn private_numbers(&self, py: Python) -> PyResult<Py<PyAny>> {
        let kty = self.key_type()?;

        if kty == "RSA" {
            let comps = extract_or_recover_rsa_components(&self.inner)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;

            let int_cls = py.get_type::<PyInt>();
            let bn_to_py = |bn: BigUint| -> PyResult<Py<PyAny>> {
                let bytes = bn.to_bytes_be();
                let bytes_obj = PyBytes::new(py, &bytes);
                Ok(int_cls.call_method1("from_bytes", (bytes_obj, "big"))?.into())
            };

            let n_py = bn_to_py(comps.n)?;
            let e_py = bn_to_py(comps.e)?;
            let pub_nums = Py::new(py, PyRSAPublicNumbers { n: n_py, e: e_py })?;

            let obj = Py::new(py, PyRSAPrivateNumbers {
                p: bn_to_py(comps.p)?,
                q: bn_to_py(comps.q)?,
                d: bn_to_py(comps.d)?,
                dmp1: bn_to_py(comps.dp)?,
                dmq1: bn_to_py(comps.dq)?,
                iqmp: bn_to_py(comps.qi)?,
                public_numbers: pub_nums.extract(py)?,
            })?;
            return Ok(obj.into_any());
        }

        if kty == "EC" {
            let d_b64 = self.inner.get("d").and_then(|v| v.as_str())
                .ok_or_else(|| PyValueError::new_err("EC private key missing 'd' parameter"))?;
            
            let d_bytes = URL_SAFE_NO_PAD.decode(d_b64)
                .map_err(|e| PyValueError::new_err(format!("Invalid d base64: {}", e)))?;
            
            let int_cls = py.get_type::<PyInt>();
            let d_py = int_cls.call_method1("from_bytes", (d_bytes.as_slice(), "big"))?;

            let pub_nums_any = self.public_numbers(py)?;
            if pub_nums_any.is_none(py) {
                return Err(PyValueError::new_err("EC public numbers (x, y) missing or invalid"));
            }
            
            let public_numbers: PyEllipticCurvePublicNumbers = pub_nums_any.extract(py)?;

            let obj = Py::new(py, PyEllipticCurvePrivateNumbers {
                private_value: d_py.into(),
                public_numbers,
            })?;
            
            return Ok(obj.into_any());
        }

        Ok(py.None().into())
    }


    fn __getitem__(&self, key: &str) -> PyResult<String> {
        match self.inner.get(key) {
            Some(Value::String(s)) => Ok(s.clone()),
            Some(v) => Ok(v.to_string()),
            None => Err(PyKeyError::new_err(key.to_string())),
        }
    }

    fn __repr__(&self) -> String {
        format!("<PyJWK kid={:?}>", self.key_id())
    }
}


// --- Helpers and Validation ---

fn map_curve_name_for_error(name: &str) -> &str {
    match name {
        "P-256" => "secp256r1",
        "P-384" => "secp384r1",
        "P-521" => "secp521r1",
        "P-192" => "secp192r1",
        _ => name
    }
}


#[pyfunction]
pub fn check_rsa_key_length(key: &Bound<'_, PyAny>) -> PyResult<Option<String>> {
    let mut bit_len = None;

    if let Ok(jwk) = key.extract::<PyJWK>() {
        // Call the helper in jwk.rs
        bit_len = jwk::get_rsa_bits_from_value(&jwk.inner);
    }
    else if let Ok(attr) = key.getattr("key_size") {
        if let Ok(val) = attr.extract::<usize>() {
            bit_len = Some(val);
        }
    }
    else {
        let key_bytes = if let Ok(s) = key.extract::<String>() { Some(s.into_bytes()) }
                        else if let Ok(b) = key.extract::<Vec<u8>>() { Some(b) }
                        else { None };

        if let Some(kb) = key_bytes {
             if let Ok(json_str) = jwk::pem_to_jwk(&kb) {
                 if let Ok(val) = serde_json::from_str::<Value>(&json_str) {
                      // Call the helper in jwk.rs
                      bit_len = jwk::get_rsa_bits_from_value(&val);
                 }
             }
        }
    }

    if let Some(bits) = bit_len {
        if bits < 2048 {
            return Ok(Some(format!("The specified key is {} bits, which is below the minimum recommended length of 2048 bits.", bits)));
        }
    }
    
    Ok(None)
}


#[pyfunction]
#[pyo3(signature = (key, expected_kty, expected_crv=None))]
pub fn validate_key_properties(key: &PyJWK, expected_kty: &str, expected_crv: Option<&str>) -> PyResult<()> {
   
    let kty = key.inner.get("kty").and_then(|v| v.as_str()).unwrap_or("");
    if kty != expected_kty {
        return Err(InvalidKeyError::new_err(format!("Invalid key type: {}. Expected {}.", kty, expected_kty)));
    }
    
    if let Some(req_crv) = expected_crv {
        let crv = key.inner.get("crv").and_then(|v| v.as_str())
            .ok_or_else(|| InvalidKeyError::new_err(format!("{} key missing 'crv'", expected_kty)))?;
        
        if crv != req_crv {
            let mapped_actual = map_curve_name_for_error(crv);
            let mapped_expected = map_curve_name_for_error(req_crv);
            return Err(InvalidKeyError::new_err(format!(
                "Key curve {} does not match algorithm curve {}.", mapped_actual, mapped_expected
            )));
        }
    }

    if kty == "EC" {
        if key.inner.get("crv").is_none() {
             return Err(InvalidKeyError::new_err("Key must be EC and have 'crv'"));
        }
        if key.inner.get("x").is_none() || key.inner.get("y").is_none() {
             return Err(InvalidKeyError::new_err("Invalid Key: Missing EC public key components"));
        }
    }

    if kty == "OKP" && expected_crv == Some("Ed25519") {
        let x_b64 = key.inner.get("x").and_then(|v| v.as_str())
            .ok_or_else(|| InvalidKeyError::new_err("Missing x component"))?;
        
        let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(x_b64)
            .map_err(|_| InvalidKeyError::new_err("Invalid x encoding"))?;
            
        if x_bytes.len() != 32 {
            return Err(InvalidKeyError::new_err("Invalid x length"));
        }

        // Validate 'd' (Private Component) - Optional
        if let Some(d_val) = key.inner.get("d") {
            let d_b64 = d_val.as_str()
                .ok_or_else(|| InvalidKeyError::new_err("Invalid d encoding"))?;
                
            let d_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(d_b64)
                .map_err(|_| InvalidKeyError::new_err("Invalid d encoding"))?;
                
            if d_bytes.len() != 32 {
                return Err(InvalidKeyError::new_err("Invalid d length"));
            }
        }
    }

    Ok(())
}


// --- PyJWKSet ---

#[pyclass(name = "PyJWKSet")]
pub struct PyJWKSet {
    pub keys: Vec<PyJWK>,
}

#[pymethods]
impl PyJWKSet {
    #[new]
    #[pyo3(signature = (keys))]
    fn new(keys: &Bound<'_, PyAny>) -> PyResult<Self> {
        let raw_list: Vec<Value> = depythonize(keys)
            .map_err(|_| PyJWKSetError::new_err("Invalid JWK Set value"))?;
        Self::from_values(raw_list)
    }

    #[getter]
    fn keys(&self) -> Vec<PyJWK> {
        self.keys.clone()
    }

    #[staticmethod]
    fn from_json(data: &str) -> PyResult<Self> {
        let val = jwk::parse_json(data).map_err(PyValueError::new_err)?;
        let keys_array = val.get("keys")
            .and_then(|v| v.as_array())
            .ok_or_else(|| PyValueError::new_err("JWK Set must have a 'keys' array"))?
            .clone();
        Self::from_values(keys_array)
    }

    #[staticmethod]
    fn from_dict(obj: &Bound<'_, PyDict>) -> PyResult<Self> {
        let keys = obj.get_item("keys")
            .map_err(|_| PyValueError::new_err("JWK Set must have a 'keys' key"))?
            .ok_or_else(|| PyValueError::new_err("JWK Set 'keys' is None"))?;
        Self::new(&keys)
    }

    fn __getitem__(&self, kid: String) -> PyResult<PyJWK> {
        for key in &self.keys {
            if let Some(k) = key.key_id() {
                if k == kid { return Ok(key.clone()); }
            }
        }
        Err(PyKeyError::new_err(format!("keyset has no key for kid: {}", kid)))
    }

    fn __len__(&self) -> usize {
        self.keys.len()
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PyResult<Py<PyJWKSetIterator>> {
        let iter = PyJWKSetIterator { iter: slf.keys.clone().into_iter() };
        Py::new(slf.py(), iter)
    }
    
    fn __repr__(&self) -> String {
        format!("<PyJWKSet keys_len={}>", self.keys.len())
    }
}

impl PyJWKSet {
    fn from_values(values: Vec<Value>) -> PyResult<Self> {
        let valid_keys = jwk::normalize_key_set(values);
        if valid_keys.is_empty() {
             return Err(PyJWKSetError::new_err("The JWK Set did not contain any usable keys"));
        }
        let py_keys = valid_keys.into_iter()
            .map(|(inner, alg)| PyJWK { inner, algorithm_name: alg })
            .collect();
        Ok(PyJWKSet { keys: py_keys })
    }
}

#[pyclass]
struct PyJWKSetIterator {
    iter: std::vec::IntoIter<PyJWK>,
}

#[pymethods]
impl PyJWKSetIterator {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> { slf }
    fn __next__(mut slf: PyRefMut<'_, Self>) -> Option<PyJWK> { slf.iter.next() }
}

#[pyclass]
#[derive(Clone)]
pub struct PyRSAPublicNumbers { #[pyo3(get)] n: Py<PyAny>, #[pyo3(get)] e: Py<PyAny> }
#[pymethods]
impl PyRSAPublicNumbers {
    fn __eq__(&self, other: &PyRSAPublicNumbers, py: Python) -> bool {
        self.n.bind(py).eq(other.n.bind(py)).unwrap_or(false) && 
        self.e.bind(py).eq(other.e.bind(py)).unwrap_or(false)
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyRSAPrivateNumbers { 
    #[pyo3(get)] p: Py<PyAny>, #[pyo3(get)] q: Py<PyAny>, #[pyo3(get)] d: Py<PyAny>, 
    #[pyo3(get)] dmp1: Py<PyAny>, #[pyo3(get)] dmq1: Py<PyAny>, #[pyo3(get)] iqmp: Py<PyAny>, 
    #[pyo3(get)] public_numbers: PyRSAPublicNumbers,
}
#[pymethods]
impl PyRSAPrivateNumbers {
    fn __eq__(&self, other: &PyRSAPrivateNumbers, py: Python) -> bool {
        self.d.bind(py).eq(other.d.bind(py)).unwrap_or(false) &&
        self.public_numbers.__eq__(&other.public_numbers, py)
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyEllipticCurvePublicNumbers { #[pyo3(get)] x: Py<PyAny>, #[pyo3(get)] y: Py<PyAny> }
#[pymethods]
impl PyEllipticCurvePublicNumbers {
    fn __eq__(&self, other: &PyEllipticCurvePublicNumbers, py: Python) -> bool {
        self.x.bind(py).eq(other.x.bind(py)).unwrap_or(false) &&
        self.y.bind(py).eq(other.y.bind(py)).unwrap_or(false)
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyEllipticCurvePrivateNumbers {
    #[pyo3(get)] private_value: Py<PyAny>, #[pyo3(get)] public_numbers: PyEllipticCurvePublicNumbers,
}
#[pymethods]
impl PyEllipticCurvePrivateNumbers {
    fn __eq__(&self, other: &PyEllipticCurvePrivateNumbers, py: Python) -> bool {
        self.private_value.bind(py).eq(other.private_value.bind(py)).unwrap_or(false) &&
        self.public_numbers.__eq__(&other.public_numbers, py)
    }
}


// --- Exposed Functions ---

pub fn from_jwk(jwk: &Bound<'_, PyAny>, algorithm_hint: &str) -> PyResult<PyJWK> {

    let hint = if algorithm_hint.is_empty() { 
        None 
    } else { 
        Some(algorithm_hint.to_string()) 
    };

    if let Ok(s) = jwk.extract::<String>() {
         PyJWK::from_json(&s, hint)
    } else if let Ok(d) = jwk.extract::<Bound<'_, PyDict>>() {
         PyJWK::from_dict(&d, hint)
    } else {
         Err(PyTypeError::new_err("Expected string or dict"))
    }
}

pub fn from_jwk_set(data: &Bound<'_, PyAny>) -> PyResult<PyJWKSet> {

    if let Ok(s) = data.extract::<String>() {
        PyJWKSet::from_json(&s)
    } else if let Ok(d) = data.extract::<Bound<'_, PyDict>>() {
        PyJWKSet::from_dict(&d)
    } else if let Ok(_l) = data.extract::<Bound<'_, PyList>>() {
        PyJWKSet::new(data)
    } else {
        Err(PyTypeError::new_err("Expected string, dict, or list of keys"))
    }
}


pub fn perform_signature_jwk(message: &[u8], key: &PyJWK, algorithm: &str) -> Result<Vec<u8>, WebtokenError> {
    
    let mut alg_override = algorithm;
    if algorithm == "ES256" {
        if let Some(crv) = key.inner.get("crv").and_then(|v| v.as_str()) {
            if crv == "secp256k1" {
                alg_override = "ES256K";
            }
        }
    }

    if let Ok(alg) = alg_override.parse::<Algorithm>() {
        let key_bytes = key.to_key_bytes(false).map_err(|e| WebtokenError::Generic(e.to_string()))?;
        return alg.sign(message, &key_bytes);
    }
    
    Err(WebtokenError::Generic(format!("Algorithm '{}' not supported (or key type mismatch)", algorithm)))
}


pub fn perform_verification_jwk(payload: &[u8], signature: &[u8], jwk: &PyJWK, alg_name: &str) -> Result<bool, WebtokenError> {
    
    let mut alg_override = alg_name;
    if alg_name == "ES256" {
        if let Some(crv) = jwk.inner.get("crv").and_then(|v| v.as_str()) {
            if crv == "secp256k1" {
                alg_override = "ES256K";
            }
        }
    }

    if let Ok(alg) = alg_override.parse::<Algorithm>() {
        // [FIX] Pass public_only=true for verification (extract x/y even if d exists)
        let bytes = jwk.to_key_bytes(true).map_err(|e| WebtokenError::Generic(e.to_string()))?;
        return alg.verify(payload, signature, &bytes);
    }
    
    Err(WebtokenError::Generic(format!("Algorithm '{}' not supported (or key type mismatch)", alg_name)))
}


pub fn register_jwk_module(py: Python, parent_module: &Bound<'_, PyModule>) -> PyResult<()> {   

    parent_module.add("PyJWKSetError", py.get_type::<PyJWKSetError>())?; 
    parent_module.add("PyJWKError", py.get_type::<PyJWKError>())?;  
    parent_module.add_class::<PyJWKSetIterator>()?;
    parent_module.add_class::<PyJWK>()?;
    parent_module.add_class::<PyJWKSet>()?;
    
    parent_module.add_class::<PyRSAPublicNumbers>()?;
    parent_module.add_class::<PyRSAPrivateNumbers>()?;
    parent_module.add_class::<PyEllipticCurvePublicNumbers>()?;
    parent_module.add_class::<PyEllipticCurvePrivateNumbers>()?;

    Ok(())
}