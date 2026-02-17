use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crate::{WebtokenError, crypto};

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

// ============================================================================
//  v4 Local (Symmetric)
// ============================================================================

pub fn encrypt_v4_local(payload: &[u8], key: &[u8], footer: Option<&[u8]>, implicit_assertion: Option<&[u8]>
) -> Result<String, WebtokenError> {
    let key_arr: [u8; 32] = key.try_into().map_err(|_| WebtokenError::InvalidToken("Key must be 32 bytes".into()))?;
    let footer_bytes = footer.unwrap_or(b"");
    let assertion = implicit_assertion.unwrap_or(b"");

    // 1. Generate Nonce
    let nonce_vec = crypto::get_random_bytes(32)?;
    let nonce: [u8; 32] = nonce_vec.try_into().unwrap();

    // 2. Perform PASETO v4 Encryption (Delegate to crypto)
    let body = crypto::paseto_v4_encrypt(&key_arr, &nonce, payload, footer_bytes, assertion)?;

    // 3. Format: v4.local.base64(body).base64(footer)
    let mut token = String::from("v4.local.");
    token.push_str(&URL_SAFE_NO_PAD.encode(&body));
    
    if !footer_bytes.is_empty() {
        token.push('.');
        token.push_str(&URL_SAFE_NO_PAD.encode(footer_bytes));
    }

    Ok(token)
}

pub fn decrypt_v4_local(token: &str, key: &[u8], implicit_assertion: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), WebtokenError> {
    let key_arr: [u8; 32] = key.try_into().map_err(|_| WebtokenError::InvalidToken("Key must be 32 bytes".into()))?;
    
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

    // Delegate Core Decryption to crypto.rs
    let plaintext = crypto::paseto_v4_decrypt(&key_arr, &body, &footer_bytes, assertion)?;

    Ok((plaintext, footer_bytes))
}

// ============================================================================
//  v4 Public (Asymmetric)
// ============================================================================

pub fn sign_v4_public(payload: &[u8], key: &[u8], footer: Option<&[u8]>, implicit_assertion: Option<&[u8]>
) -> Result<String, WebtokenError> {
    let header = b"v4.public.";
    let footer_bytes = footer.unwrap_or(b"");
    let assertion = implicit_assertion.unwrap_or(b"");

    // 1. Prepare PAE
    let m2 = pae(&[header, payload, footer_bytes, assertion]);

    // 2. Sign using crypto.rs abstraction (Ed25519)
    let signature = crypto::sign("Ed25519", key, &m2)?;

    // 3. Assemble: v4.public.base64(payload || signature)
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

    if body.len() < 64 { // Ed25519 signature is 64 bytes
        return Err(WebtokenError::InvalidToken("Token too short".into()));
    }

    // Split payload and signature (Signature is trailing 64 bytes)
    let split_idx = body.len() - 64;
    let payload = &body[..split_idx];
    let signature = &body[split_idx..];

    // Reconstruct PAE
    let header = b"v4.public.";
    let assertion = implicit_assertion.unwrap_or(b"");
    let m2 = pae(&[header, payload, &footer_bytes, assertion]);

    // Verify
    crypto::verify("Ed25519", key, &m2, signature)?;

    Ok((payload.to_vec(), footer_bytes))
}