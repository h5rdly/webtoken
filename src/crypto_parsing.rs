use base64::{engine::general_purpose::STANDARD, Engine as _};
use num_bigint::BigUint;

use pyo3::prelude::{Bound, PyModule, wrap_pyfunction, PyModuleMethods, Python, PyDictMethods};
use pyo3::{pyfunction, PyResult, exceptions::PyValueError, types::PyDict};

use crate::WebtokenError;

pub const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
pub const OID_P192: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01];
pub const OID_P256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
pub const OID_P384: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
pub const OID_P521: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23];
pub const OID_SECP256K1: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A];
pub const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

pub const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03]; // 2.5.4.3
pub const OID_COUNTRY: &[u8] = &[0x55, 0x04, 0x06];
pub const OID_ORG: &[u8] = &[0x55, 0x04, 0x0a];
pub const OID_ORG_UNIT: &[u8] = &[0x55, 0x04, 0x0b];
pub const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f]; // 2.5.29.15
pub const OID_AUTHORITY_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x23]; // 2.5.29.35


// ============================================================================
//  DER / PEM Extractors & Strippers
// ============================================================================

pub fn decode_key_bytes(data: &[u8]) -> Vec<u8> {
    let s = std::str::from_utf8(data).unwrap_or("");
    let trimmed = s.trim();
    if trimmed.starts_with("-----BEGIN") {
        let lines: Vec<&str> = trimmed.lines()
            .filter(|l| !l.contains("-----BEGIN") && !l.contains("-----END"))
            .collect();
        let body = lines.join("");
        if let Ok(der) = STANDARD.decode(&body) {
            return der;
        }
    }
    data.to_vec()
}

pub fn to_pem(tag: &str, data: &[u8]) -> Vec<u8> {
    let mut pem = String::new();
    pem.push_str(&format!("-----BEGIN {}-----\n", tag));
    for chunk in STANDARD.encode(data).as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", tag));
    pem.into_bytes()
}

pub fn extract_x25519_bytes(data: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    let bytes = decode_key_bytes(data);
    match bytes.len() {
        32 => Ok(bytes),
        44 if bytes.starts_with(&[0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00]) => {
            Ok(bytes[12..].to_vec())
        },
        48 if bytes.starts_with(&[0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x04, 0x22, 0x04, 0x20]) => {
            Ok(bytes[16..].to_vec())
        },
        _ => Err(WebtokenError::Generic(format!("Invalid X25519 key length or format: {}", bytes.len()))),
    }
}

pub fn extract_ed25519_bytes(data: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    let bytes = decode_key_bytes(data);
    match bytes.len() {
        32 => Ok(bytes),
        // SPKI (Public Key): OID 1.3.101.112 (2B 65 70)
        44 if bytes.starts_with(&[0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00]) => {
            Ok(bytes[12..].to_vec())
        },
        // PKCS#8 (Private Key): OID 1.3.101.112 (2B 65 70)
        48 if bytes.starts_with(&[0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]) => {
            Ok(bytes[16..].to_vec())
        },
        _ => Err(WebtokenError::Generic(format!("Invalid Ed25519 key length or format: {}", bytes.len()))),
    }
}

// ============================================================================
//  Manual DER Encoding Builders
// ============================================================================

pub fn encode_der_len(out: &mut Vec<u8>, len: usize) {
    if len < 128 { out.push(len as u8); } 
    else if len < 256 { out.push(0x81); out.push(len as u8); } 
    else { out.push(0x82); out.extend_from_slice(&(len as u16).to_be_bytes()); }
}

pub fn encode_der_int(out: &mut Vec<u8>, bytes: &[u8]) { 
    out.push(0x02); 
    let mut start = 0; 
    while start < bytes.len() - 1 && bytes[start] == 0 && (bytes[start+1] & 0x80) == 0 { start += 1; } 
    let slice = &bytes[start..];
    
    // If the highest bit is set, we must prepend a 0x00 byte to keep it positive
    if !slice.is_empty() && (slice[0] & 0x80) != 0 {
        encode_der_len(out, slice.len() + 1);
        out.push(0x00);
    } else {
        encode_der_len(out, slice.len());
    }
    out.extend_from_slice(slice); 
}

pub fn encode_der_sequence(content: &[u8]) -> Vec<u8> { 
    let mut out = vec![0x30];
    encode_der_len(&mut out, content.len());
    out.extend_from_slice(content); 
    out 
}

pub fn wrap_pkcs1_as_pkcs8(pkcs1: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x02, 0x01, 0x00]); // Version
    let algo = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
    out.extend_from_slice(&algo);
    out.push(0x04); // Octet String
    encode_der_len(&mut out, pkcs1.len());
    out.extend_from_slice(pkcs1);
    encode_der_sequence(&out)
}

pub fn ssh_to_pem(data: &[u8]) -> Result<Vec<u8>, String> { 
    let s = std::str::from_utf8(data).map_err(|_| "Invalid UTF-8")?; 
    let parts: Vec<&str> = s.split_whitespace().collect(); 
    if parts.len() < 2 { return Err("Invalid SSH key".into()); } 
    let decoded = STANDARD.decode(parts[1]).map_err(|_| "Invalid Base64")?; 
    let mut cursor = &decoded[..]; 
    let read_string = |buf: &mut &[u8]| -> Result<Vec<u8>, String> { 
        if buf.len() < 4 { return Err("Truncated".into()); } 
        let len = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize; 
        *buf = &buf[4..]; 
        if buf.len() < len { return Err("Truncated".into()); } 
        let val = buf[0..len].to_vec(); 
        *buf = &buf[len..]; 
        Ok(val)
    }; 
    let header = read_string(&mut cursor)?; 
    if parts[0] == "ssh-rsa" && header == b"ssh-rsa" { 
        let e = read_string(&mut cursor)?; 
        let n = read_string(&mut cursor)?; 
        let mut seq = Vec::new(); 
        encode_der_int(&mut seq, &n); 
        encode_der_int(&mut seq, &e); 
        return Ok(to_pem("RSA PUBLIC KEY", &encode_der_sequence(&seq)));
    } 
    else if parts[0] == "ssh-ed25519" && header == b"ssh-ed25519" { 
        let key = read_string(&mut cursor)?; 
        if key.len() != 32 { return Err("Invalid Ed25519 len".into()); } 
        let alg_id = vec![0x06, 0x03, 0x2b, 0x65, 0x70]; 
        let mut bit_string = vec![0x03, 0x21, 0x00]; 
        bit_string.extend_from_slice(&key); 
        let mut der = encode_der_sequence(&alg_id); 
        der.extend_from_slice(&bit_string); 
        return Ok(to_pem("PUBLIC KEY", &encode_der_sequence(&der)));
    }
    else if parts[0].starts_with("ecdsa-sha2-") {
        let curve_id_bytes = read_string(&mut cursor)?;
        let q = read_string(&mut cursor)?;
        let curve_oid = match curve_id_bytes.as_slice() {
            b"nistp256" => vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07], 
            b"nistp384" => vec![0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22], 
            b"nistp521" => vec![0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23], 
            _ => return Err(format!("Unsupported ECDSA curve: {:?}", String::from_utf8_lossy(&curve_id_bytes))),
        };
        let mut algo_vec = Vec::new();
        algo_vec.extend_from_slice(OID_EC_PUBLIC_KEY);
        algo_vec.extend_from_slice(&curve_oid);
        let algo_seq = encode_der_sequence(&algo_vec);
        let mut bit_string = vec![0x03];
        encode_der_len(&mut bit_string, q.len() + 1);
        bit_string.push(0x00);
        bit_string.extend_from_slice(&q);
        let mut spki = Vec::new();
        spki.extend_from_slice(&algo_seq);
        spki.extend_from_slice(&bit_string);
        return Ok(to_pem("PUBLIC KEY", &encode_der_sequence(&spki)));
    }
    Err(format!("Unsupported SSH key type: {}", parts[0])) 
}

// ============================================================================
//  Manual ASN.1 DER Tree Traverser
// ============================================================================

pub struct DerReader<'a> { pub input: &'a [u8] }

impl<'a> DerReader<'a> {
    pub fn new(input: &'a [u8]) -> Self { Self { input } }

    pub fn read_tag(&mut self) -> Result<(u8, &'a [u8]), String> {
        if self.input.is_empty() { return Err("Unexpected EOF".into()); }
        let tag = self.input[0];
        self.input = &self.input[1..];
        if self.input.is_empty() { return Err("Unexpected EOF reading len".into()); }
        let mut len = self.input[0] as usize;
        self.input = &self.input[1..];
        if len & 0x80 != 0 {
            let len_bytes = len & 0x7F;
            if self.input.len() < len_bytes { return Err("EOF reading long len".into()); }
            len = 0;
            for b in &self.input[..len_bytes] { len = (len << 8) | (*b as usize); }
            self.input = &self.input[len_bytes..];
        }
        if self.input.len() < len { return Err("Content too short".into()); }
        let content = &self.input[..len];
        self.input = &self.input[len..];
        Ok((tag, content))
    }

    pub fn read_sequence(&mut self) -> Result<DerReader<'a>, String> {
        let (tag, content) = self.read_tag()?;
        if tag != 0x30 { return Err(format!("Expected SEQUENCE (0x30), got 0x{:02x}", tag)); }
        Ok(DerReader::new(content))
    }

    pub fn read_integer_bytes(&mut self) -> Result<&'a [u8], String> {
        let (tag, content) = self.read_tag()?;
        if tag != 0x02 { return Err(format!("Expected INTEGER (0x02), got 0x{:02x}", tag)); }
        let mut s = content;
        while s.len() > 1 && s[0] == 0 { s = &s[1..]; }
        Ok(s)
    }

    pub fn read_octet_string(&mut self) -> Result<&'a [u8], String> {
        let (tag, content) = self.read_tag()?;
        if tag != 0x04 { return Err("Expected OCTET STRING".into()); }
        Ok(content)
    }

    pub fn read_bit_string(&mut self) -> Result<&'a [u8], String> {
        let (tag, content) = self.read_tag()?;
        if tag != 0x03 { return Err("Expected BIT STRING".into()); }
        if content.is_empty() { return Err("Empty BIT STRING".into()); }
        Ok(&content[1..])
    }

    pub fn read_oid(&mut self) -> Result<&'a [u8], String> {
        let (tag, content) = self.read_tag()?;
        if tag != 0x06 { return Err("Expected OID".into()); }
        Ok(content)
    }

    pub fn read_optional_explicit(&mut self, tag_id: u8) -> Result<Option<DerReader<'a>>, String> {
        if !self.input.is_empty() && self.input[0] == (0xA0 | tag_id) {
            let (_, content) = self.read_tag()?;
            Ok(Some(DerReader::new(content)))
        } else { Ok(None) }
    }

    /// Returns the exact raw bytes of the current Tag-Length-Value object without parsing inside it
    pub fn read_tlv(&mut self) -> Result<&'a [u8], String> {
        let original_input = self.input;
        let _ = self.read_tag()?; // Advance past it
        let consumed = original_input.len() - self.input.len();
        Ok(&original_input[..consumed])
    }

    /// Reads an IMPLICIT tag (e.g., Context Specific [0] -> 0x80)
    pub fn read_optional_implicit(&mut self, tag_id: u8) -> Result<Option<&'a [u8]>, String> {
        if !self.input.is_empty() && self.input[0] == (0x80 | tag_id) {
            let (_, content) = self.read_tag()?;
            Ok(Some(content))
        } else { Ok(None) }
    }
}

// ============================================================================
//  X.509 Certificate Parsing
// ============================================================================

fn decode_directory_string(tag: u8, content: &[u8]) -> Result<String, String> {

    if tag == 0x1E { // BMPString (UTF-16 BE)
        if content.len() % 2 != 0 { return Err("Invalid BMPString length".into()); }
        let utf16_data: Vec<u16> = content.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        String::from_utf16(&utf16_data).map_err(|_| "Invalid UTF-16 in string".into())
    } else {
        // UTF8String (0x0C), PrintableString (0x13), TeletexString (0x14)
        String::from_utf8(content.to_vec()).map_err(|_| "Invalid UTF-8 in string".into())
    }
}


pub fn get_x509_subject_cn(der: &[u8]) -> Result<String, String> {

    let mut cert = DerReader::new(der).read_sequence()?;
    let mut tbs = cert.read_sequence()?; // TBSCertificate

    // Skip Version if present (Context Specific Tag [0] == 0xA0)
    let _ = tbs.read_optional_explicit(0)?;
    // Skip Serial Number (INTEGER)
    let _ = tbs.read_integer_bytes()?;
    // Skip Signature Algorithm (SEQUENCE)
    let _ = tbs.read_sequence()?;
    // Skip Issuer (SEQUENCE)
    let _ = tbs.read_sequence()?;
    // Skip Validity (SEQUENCE)
    let _ = tbs.read_sequence()?;

    // Read Subject (SEQUENCE)
    let mut subject = tbs.read_sequence()?;

    // The Subject is a SEQUENCE of SETs of sequences (AttributeTypeAndValue)
    while !subject.input.is_empty() {
        let (tag, set_content) = subject.read_tag()?;
        
        // SET tag is 0x31
        if tag != 0x31 { continue; } 
        
        let mut set_reader = DerReader::new(set_content);

        while !set_reader.input.is_empty() {
            let mut attr_seq = set_reader.read_sequence()?;
            
            if let Ok(oid) = attr_seq.read_oid() {
                // If the OID matches the Common Name (CN) OID
                if oid == OID_COMMON_NAME {
                    let (str_tag, string_content) = attr_seq.read_tag()?;
                    return decode_directory_string(str_tag, string_content);
                }
            }
        }
    }
    
    Err("Common Name (CN) not found in certificate".into())
}


fn parse_asn1_time(tag: u8, content: &[u8]) -> Result<u64, String> {

    let s = std::str::from_utf8(content).map_err(|_| "Invalid time string")?;
    let (y, mo, d, h, m, sec) = if tag == 0x17 { // UTCTime
        let y2 = s[0..2].parse::<u64>().unwrap_or(0);
        let y = if y2 < 50 { 2000 + y2 } else { 1900 + y2 };
        (y, s[2..4].parse().unwrap_or(1), s[4..6].parse().unwrap_or(1), s[6..8].parse().unwrap_or(0), s[8..10].parse().unwrap_or(0), s[10..12].parse().unwrap_or(0))
    } else if tag == 0x18 { // GeneralizedTime
        (s[0..4].parse().unwrap_or(1970), s[4..6].parse().unwrap_or(1), s[6..8].parse().unwrap_or(1), s[8..10].parse().unwrap_or(0), s[10..12].parse().unwrap_or(0), s[12..14].parse().unwrap_or(0))
    } else {
        return Err("Unknown time tag".into());
    };
    
    // Quick Unix Timestamp Calculation (Valid from 1970 to 2100)
    let mut days = 0;
    for year in 1970..y { days += if (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) { 366 } else { 365 }; }
    let days_in_month = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for month in 1..mo {
        let mut dim = days_in_month[month as usize];
        if month == 2 && ((y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)) { dim = 29; }
        days += dim;
    }
    days += d - 1;
    Ok(days * 86400 + h * 3600 + m * 60 + sec)
}


fn parse_x509_name(content: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut outer = DerReader::new(content);
    
    // Unpack the outer SEQUENCE envelope first
    if let Ok(mut seq) = outer.read_sequence() {
        while !seq.input.is_empty() {
            if let Ok((tag, set_data)) = seq.read_tag() {
                if tag == 0x31 { // Ensure it's a SET
                    let mut set_r = DerReader::new(set_data);
                    while !set_r.input.is_empty() {
                        if let Ok(mut attr) = set_r.read_sequence() {
                            if let Ok(oid) = attr.read_oid() {
                                let label = match oid {
                                    OID_COMMON_NAME => "CN",
                                    OID_COUNTRY => "C",
                                    OID_ORG => "O",
                                    OID_ORG_UNIT => "OU",
                                    _ => "Unknown"
                                };
                                if let Ok((str_tag, val)) = attr.read_tag() {
                                    if let Ok(s) = decode_directory_string(str_tag, val) {
                                        parts.push(format!("{}={}", label, s));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // Reverse to match standard RFC4514 representation (from most specific to least)
    parts.reverse();
    parts.join(",")
}


#[pyfunction]
pub fn get_x509_public_key(der_bytes: &[u8]) -> PyResult<Vec<u8>> {

    let mut cert = DerReader::new(der_bytes).read_sequence().map_err(PyValueError::new_err)?;
    let mut tbs = cert.read_sequence().map_err(PyValueError::new_err)?;

    let _ = tbs.read_optional_explicit(0); // Version
    let _ = tbs.read_integer_bytes();      // Serial
    let _ = tbs.read_sequence();           // Sig Alg
    let _ = tbs.read_sequence();           // Issuer
    let _ = tbs.read_sequence();           // Validity
    let _ = tbs.read_sequence();           // Subject
    
    // The next object is the SubjectPublicKeyInfo. We extract the raw DER bytes natively!
    let spki_der = tbs.read_tlv().map_err(PyValueError::new_err)?;
    Ok(spki_der.to_vec())
}

#[pyfunction]
pub fn get_x509_metadata<'py>(py: Python<'py>, der_bytes: &[u8]) -> PyResult<Bound<'py, PyDict>> {
    
    let mut cert = DerReader::new(der_bytes).read_sequence().map_err(PyValueError::new_err)?;
    let mut tbs = cert.read_sequence().map_err(PyValueError::new_err)?;
    let dict = PyDict::new(py);

    let _ = tbs.read_optional_explicit(0); // Version
    
    // 1. Serial Number (Parsed to BigInt Base-10 string just like cryptography does)
    if let Ok(serial_bytes) = tbs.read_integer_bytes() {
        let big_serial = BigUint::from_bytes_be(serial_bytes);
        dict.set_item("serial", big_serial.to_string())?;
    }

    let _ = tbs.read_sequence(); // Sig Alg
    
    // 2. Issuer Name
    if let Ok(issuer_der) = tbs.read_tlv() {
        dict.set_item("issuer", parse_x509_name(issuer_der))?;
    }

    // 3. Validity (Unix Timestamps)
    if let Ok(mut validity) = tbs.read_sequence() {
        if let Ok((t1, c1)) = validity.read_tag() {
            if let Ok(ts) = parse_asn1_time(t1, c1) { dict.set_item("not_before", ts)?; }
        }
        if let Ok((t2, c2)) = validity.read_tag() {
            if let Ok(ts) = parse_asn1_time(t2, c2) { dict.set_item("not_after", ts)?; }
        }
    }

    let _ = tbs.read_sequence(); // Subject
    let _ = tbs.read_tag();      // SPKI
    let _ = tbs.read_optional_implicit(1); // Issuer Unique ID
    let _ = tbs.read_optional_implicit(2); // Subject Unique ID

    // 4. Extensions (Extract AKI & Key Usages)
    let mut usages = Vec::new();
    if let Ok(Some(mut ext_wrapper)) = tbs.read_optional_explicit(3) {
        if let Ok(mut ext_seq) = ext_wrapper.read_sequence() {
            while !ext_seq.input.is_empty() {
                if let Ok(mut ext) = ext_seq.read_sequence() {
                    let oid = ext.read_oid().unwrap_or(&[]);
                    let (mut tag, mut content) = ext.read_tag().unwrap();
                    
                    if tag == 0x01 { // Skip boolean CRITICAL flag
                        let next = ext.read_tag().unwrap();
                        tag = next.0; content = next.1;
                    }
                    
                    if tag == 0x04 { // OCTET STRING containing the extension data
                        if oid == OID_KEY_USAGE {
                            if let Ok(bits) = DerReader::new(content).read_bit_string() {
                                if !bits.is_empty() {
                                    let b = bits[0];
                                    if b & (1 << 7) != 0 { usages.push("digitalSignature"); }
                                    if b & (1 << 6) != 0 { usages.push("nonRepudiation"); }
                                    if b & (1 << 5) != 0 { usages.push("keyEncipherment"); }
                                    if b & (1 << 4) != 0 { usages.push("dataEncipherment"); }
                                    if b & (1 << 3) != 0 { usages.push("keyAgreement"); }
                                    if b & (1 << 2) != 0 { usages.push("keyCertSign"); }
                                    if b & (1 << 1) != 0 { usages.push("cRLSign"); }
                                    if b & (1 << 0) != 0 { usages.push("encipherOnly"); }
                                    if bits.len() > 1 && bits[1] & (1 << 7) != 0 { usages.push("decipherOnly"); }
                                }
                            }
                        } else if oid == OID_AUTHORITY_KEY_IDENTIFIER {
                            let mut inner = DerReader::new(content);
                            if let Ok(mut aki_seq) = inner.read_sequence() {
                                // Extract the implicit [0] KeyIdentifier
                                if let Ok(Some(kid)) = aki_seq.read_optional_implicit(0) {
                                    let mut hex_str = String::with_capacity(kid.len() * 2);
                                    for byte in kid { hex_str.push_str(&format!("{:02X}", byte)); }
                                    dict.set_item("aki", hex_str)?;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    dict.set_item("key_usages", usages)?;

    Ok(dict)
}


pub fn oid_to_curve_info(oid_payload: &[u8]) -> Option<(&'static str, usize)> {
    match oid_payload {
        x if x == &OID_P256[2..] => Some(("P-256", 32)),
        x if x == &OID_P384[2..] => Some(("P-384", 48)),
        x if x == &OID_P521[2..] => Some(("P-521", 66)),
        x if x == &OID_SECP256K1[2..] => Some(("secp256k1", 32)),
        x if x == &OID_P192[2..] => Some(("P-192", 24)),
        _ => None,
    }
}


#[pyfunction(name="extract_ed25519_private_key")]
pub fn extract_ed25519_private_key_py(data: crate::BytesOrString) -> PyResult<Vec<u8>> {
    extract_ed25519_bytes(data.as_bytes()).map_err(|e| PyValueError::new_err(format!("{}", e)))
}

#[pyfunction(name = "extract_ed25519_public_key")]
pub fn extract_ed25519_public_key_py(data: crate::BytesOrString) -> PyResult<Vec<u8>> {
    extract_ed25519_bytes(data.as_bytes()).map_err(|e| PyValueError::new_err(format!("{}", e)))
}

#[pyfunction(name = "get_x509_subject")]
pub fn get_x509_subject_py(der_bytes: &[u8]) -> PyResult<String> {
    get_x509_subject_cn(der_bytes).map_err(PyValueError::new_err)
}


pub fn export_functions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(extract_ed25519_private_key_py, m)?)?;
    m.add_function(wrap_pyfunction!(extract_ed25519_public_key_py, m)?)?;
    m.add_function(wrap_pyfunction!(get_x509_subject_py, m)?)?; 
    m.add_function(wrap_pyfunction!(get_x509_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(get_x509_metadata, m)?)?;

     Ok(())
}