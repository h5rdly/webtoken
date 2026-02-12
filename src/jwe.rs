use serde_json::json;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crate::{WebtokenError, crypto};


pub fn encode_xc20p(payload: &[u8], key: &[u8]) -> Result<String, WebtokenError> {

    let header = json!({"alg": "dir", "enc": "XC20P", "typ": "JWT"});
    
    // erialize and Base64 Encode Header (This is the AAD)
    let header_json = serde_json::to_vec(&header)
        .map_err(|e| WebtokenError::Generic(format!("Header serialization failed: {}", e)))?;
    let encoded_header = URL_SAFE_NO_PAD.encode(&header_json);
    
    // The AAD is the ASCII bytes of the *encoded* header string
    let aad = encoded_header.as_bytes(); 
    let (ciphertext, tag, nonce) = crypto::encrypt_xchacha20(key, payload, aad)?;

    // Header..Nonce.Ciphertext.Tag
    Ok(format!("{}..{}.{}.{}", encoded_header, URL_SAFE_NO_PAD.encode(&nonce), 
        URL_SAFE_NO_PAD.encode(&ciphertext), URL_SAFE_NO_PAD.encode(&tag)
    ))
}


pub fn decode_xc20p(token: &str, key: &[u8]) -> Result<Vec<u8>, WebtokenError> {

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 5 {
        return Err(WebtokenError::InvalidToken);
    }

    let (encoded_header, encrypted_key, encoded_nonce, encoded_ciphertext, encoded_tag) = 
        (parts[0], parts[1], parts[2], parts[3], parts[4]);

    // "dir" mode
    if !encrypted_key.is_empty() {
        return Err(WebtokenError::Custom { 
            exc: "InvalidTokenError".into(), 
            msg: "Expected direct encryption (empty encrypted key)".into() 
        });
    }

    let header_bytes = URL_SAFE_NO_PAD.decode(encoded_header).map_err(|_| WebtokenError::InvalidToken)?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).map_err(|_| WebtokenError::InvalidToken)?;
    if header["alg"] != "dir" || header["enc"] != "XC20P" {
        return Err(WebtokenError::Custom {exc: "InvalidAlgorithm".into(), msg: "Expected alg='dir' and enc='XC20P'".into()
        });
    }

    let nonce = URL_SAFE_NO_PAD.decode(encoded_nonce).map_err(|_| WebtokenError::InvalidToken)?;
    let ciphertext = URL_SAFE_NO_PAD.decode(encoded_ciphertext).map_err(|_| WebtokenError::InvalidToken)?;
    let tag = URL_SAFE_NO_PAD.decode(encoded_tag).map_err(|_| WebtokenError::InvalidToken)?;

    let aad = encoded_header.as_bytes();
    crypto::decrypt_xchacha20(key, &ciphertext, aad, &nonce, &tag)
}

