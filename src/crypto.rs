
use std::{net::{IpAddr, Ipv4Addr}, str::FromStr, time::Duration,
};

use base64::{engine::general_purpose::{URL_SAFE_NO_PAD}, Engine as _};

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::PyValueError;

// [GRAVIOLA] - Used for XChaCha20 and HMAC
use graviola::aead::{XChaCha20Poly1305, ChaCha20Poly1305};
use graviola::hashing::{Sha256, Sha384, Sha512, Hash, HashContext, hmac::Hmac}; 
use graviola::signing::eddsa::{Ed25519SigningKey, Ed25519VerifyingKey};

// [Key Agreement]
use graviola::key_agreement::x25519::{StaticPrivateKey, PublicKey as X25519PublicKey};

// [AWS-LC-RS] - Consolidated Imports
use aws_lc_rs::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM},
    cipher::{
        DecryptionContext, EncryptionContext, PaddedBlockDecryptingKey,
        PaddedBlockEncryptingKey, UnboundCipherKey, AES_128, AES_192, AES_256,
    },
    encoding::AsDer,
    iv::FixedLength,
    key_wrap::{AesKek, KeyWrap, AES_128 as KW_AES_128, AES_256 as KW_AES_256},
    rand::SystemRandom,
    rsa::{
        KeySize, OaepPrivateDecryptingKey, OaepPublicEncryptingKey, Pkcs1PrivateDecryptingKey,
        Pkcs1PublicEncryptingKey, PrivateDecryptingKey, PublicEncryptingKey,
        OAEP_SHA256_MGF1SHA256, OAEP_SHA384_MGF1SHA384, OAEP_SHA512_MGF1SHA512,
    },
    signature::{
        EcdsaKeyPair, KeyPair, RsaKeyPair, UnparsedPublicKey, ECDSA_P256K1_SHA256_FIXED,
        ECDSA_P256K1_SHA256_FIXED_SIGNING, ECDSA_P256_SHA256_ASN1_SIGNING,
        ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED,
        ECDSA_P384_SHA384_FIXED_SIGNING, ECDSA_P521_SHA512_FIXED,
        ECDSA_P521_SHA512_FIXED_SIGNING, RSA_PKCS1_2048_8192_SHA256,
        RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512, RSA_PKCS1_SHA256,
        RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_2048_8192_SHA256,
        RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384,
        RSA_PSS_SHA512,
    },
};

use x509_cert::{
    builder::{Builder, CertificateBuilder, profile::cabf::Root},
    ext::pkix::{name::GeneralName, SubjectAltName},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
    spki::{SubjectPublicKeyInfo, AlgorithmIdentifierOwned},
    der::{Any, asn1::BitString},
    der::Encode,
};

use signature::Keypair;
use blake2b_simd::Params as Blake2bParams;
use chacha20::{XChaCha20, cipher::{KeyIvInit, StreamCipher}};

use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};

use crate::{WebtokenError, BytesOrString};
use crate::crypto_parsing::{
    decode_key_bytes, wrap_pkcs1_as_pkcs8, extract_x25519_bytes, to_pem, ssh_to_pem
};


const XCHACHA_KEY_LEN: usize = 32;
const XCHACHA_NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

// [RNG] Use AWS-LC-RS
pub fn get_random_bytes(length: usize) -> Result<Vec<u8>, WebtokenError> {
    let mut out = vec![0u8; length];
    aws_lc_rs::rand::fill(&mut out).map_err(|_| WebtokenError::Generic("RNG failed".into()))?;
    Ok(out)
}


// ============================================================================
//  RSA Math (Manual for JWK)
// ============================================================================

fn gen_witness(n: &BigUint) -> Result<BigUint, WebtokenError> { 
    let byte_len = ((n.bits() + 7) / 8) as usize; 
    let mut bytes = vec![0u8; byte_len]; 
    for _ in 0..10 { 
        aws_lc_rs::rand::fill(&mut bytes).map_err(|_| WebtokenError::Generic("RNG failed".into()))?; 
        let mut g = BigUint::from_bytes_be(&bytes); 
        g %= n; 
        if g > BigUint::one() { return Ok(g); } 
    } 
    Err(WebtokenError::Generic("Failed to generate witness".into())) 
}

pub fn recover_primes(n: &BigUint, e: &BigUint, d: &BigUint) -> Result<(BigUint, BigUint), String> { 
    let k = d * e - BigUint::one(); 
    let mut r = k.clone(); 
    let mut t = 0; 
    while r.is_even() { r >>= 1; t += 1; } 
    for _ in 0..100 { 
        let Ok(g) = gen_witness(n) else { continue }; 
        let mut y = g.modpow(&r, n); 
        if y.is_one() || y == n - BigUint::one() { continue; } 
        for _ in 1..t { 
            let x = y.modpow(&BigUint::from(2u32), n); 
            if x.is_one() { 
                let p = (y - BigUint::one()).gcd(n); 
                return Ok((p.clone(), n / p)); 
            } 
            if x == n - BigUint::one() { break; } 
            y = x; 
        } 
    } 
    Err("Failed to recover primes".into()) 
}

pub fn compute_crt(_n: &BigUint, p: &BigUint, q: &BigUint, d: &BigUint) -> Result<(BigUint, BigUint, BigUint), String> { 
    let dp = d % (p - BigUint::one()); 
    let dq = d % (q - BigUint::one()); 
    let qi = mod_inverse(q, p).ok_or("Inverse failed")?; 
    Ok((dp, dq, qi)) 
}

fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> { 
    let (g, x, _) = extended_gcd(&BigInt::from_biguint(Sign::Plus, a.clone()), &BigInt::from_biguint(Sign::Plus, m.clone())); 
    if g != BigInt::one() { return None; } 
    let result = x % BigInt::from_biguint(Sign::Plus, m.clone()); 
    if result.sign() == Sign::Minus { (result + BigInt::from_biguint(Sign::Plus, m.clone())).to_biguint() } else { result.to_biguint() } 
}

fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) { 
    if b.is_zero() { (a.clone(), BigInt::one(), BigInt::zero()) } 
    else { let (g, x, y) = extended_gcd(b, &(a % b)); (g, y.clone(), x - (a / b) * y) } 
}

// ============================================================================
//  JWE Primitives
// ============================================================================

// --- RSA-OAEP Encryption ---

pub fn rsa_encrypt_oaep(pub_key_pem: &[u8], plaintext: &[u8], alg: &str) -> Result<Vec<u8>, WebtokenError> {
    let der = decode_key_bytes(pub_key_pem);
    let algorithm = match alg {
        "RSA-OAEP"|"RSA-OAEP-256" => &OAEP_SHA256_MGF1SHA256,
        "RSA-OAEP-384" => &OAEP_SHA384_MGF1SHA384,
        "RSA-OAEP-512" => &OAEP_SHA512_MGF1SHA512,
        _ => return Err(WebtokenError::InvalidAlgorithm("Unsupported RSA-OAEP alg".into()))
    };

    let key = PublicEncryptingKey::from_der(&der).map_err(|_| WebtokenError::InvalidToken("Invalid RSA Public Key".into()))?;
    let oaep_key = OaepPublicEncryptingKey::new(key).map_err(|_| WebtokenError::Generic("Failed to create OAEP key".into()))?;

    let mut out = vec![0u8; oaep_key.ciphertext_size()];
    let encrypted_slice = oaep_key.encrypt(algorithm, plaintext, &mut out, None)
        .map_err(|_| WebtokenError::Generic("RSA Encrypt failed".into()))?;
    
    let len = encrypted_slice.len();
    out.truncate(len);
    Ok(out)
}

pub fn rsa_decrypt_oaep(priv_key_pem: &[u8], ciphertext: &[u8], alg: &str) -> Result<Vec<u8>, WebtokenError> {
    let der = decode_key_bytes(priv_key_pem);
    let algorithm = match alg {
        "RSA-OAEP"|"RSA-OAEP-256" => &OAEP_SHA256_MGF1SHA256,
        "RSA-OAEP-384" => &OAEP_SHA384_MGF1SHA384,
        "RSA-OAEP-512" => &OAEP_SHA512_MGF1SHA512,
        _ => return Err(WebtokenError::InvalidAlgorithm("Unsupported RSA-OAEP alg".into())),
    };

    let key = PrivateDecryptingKey::from_pkcs8(&der)
        .or_else(|_| {
             let wrapped = wrap_pkcs1_as_pkcs8(&der);
             PrivateDecryptingKey::from_pkcs8(&wrapped)
        })
        .map_err(|_| WebtokenError::InvalidToken("Invalid RSA Private Key".into()))?;

    let oaep_key = OaepPrivateDecryptingKey::new(key).map_err(|_| WebtokenError::Generic("Failed to create OAEP key".into()))?;
    let mut out = vec![0u8; oaep_key.min_output_size()];
    let decrypted_slice = oaep_key.decrypt(algorithm, ciphertext, &mut out, None)
        .map_err(|_| WebtokenError::InvalidToken("RSA Decrypt failed".into()))?;
    
    let len = decrypted_slice.len();
    out.truncate(len);
    Ok(out)
}

// --- RSA-PKCS1 v1.5 Encryption ---

pub fn rsa_encrypt_pkcs1(pub_key_pem: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    let der = decode_key_bytes(pub_key_pem);
    let key = PublicEncryptingKey::from_der(&der).map_err(|_| WebtokenError::InvalidToken("Invalid RSA Public Key".into()))?;
    let pkcs1_key = Pkcs1PublicEncryptingKey::new(key).map_err(|_| WebtokenError::Generic("Failed to create PKCS1 key".into()))?;

    let mut out = vec![0u8; pkcs1_key.ciphertext_size()];
    let encrypted_slice = pkcs1_key.encrypt(plaintext, &mut out)
        .map_err(|_| WebtokenError::Generic("RSA PKCS1 Encrypt failed".into()))?;
    
    let len = encrypted_slice.len();
    out.truncate(len);
    Ok(out)
}

pub fn rsa_decrypt_pkcs1(priv_key_pem: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    let der = decode_key_bytes(priv_key_pem);
    let key = PrivateDecryptingKey::from_pkcs8(&der)
        .or_else(|_| {
             let wrapped = wrap_pkcs1_as_pkcs8(&der);
             PrivateDecryptingKey::from_pkcs8(&wrapped)
        })
        .map_err(|_| WebtokenError::InvalidToken("Invalid RSA Private Key".into()))?;

    let pkcs1_key = Pkcs1PrivateDecryptingKey::new(key).map_err(|_| WebtokenError::Generic("Failed to create PKCS1 key".into()))?;
    let mut out = vec![0u8; pkcs1_key.min_output_size()];
    let decrypted_slice = pkcs1_key.decrypt(ciphertext, &mut out)
        .map_err(|_| WebtokenError::InvalidToken("RSA PKCS1 Decrypt failed".into()))?;
    
    let len = decrypted_slice.len();
    out.truncate(len);
    Ok(out)
}

// --- AES Key Wrapping (A128KW, A256KW) ---

pub fn aes_key_wrap(kek: &[u8], data: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    let algo = match kek.len() {
        16 => &KW_AES_128,
        32 => &KW_AES_256,
        _ => return Err(WebtokenError::InvalidToken("AES-KW requires 128 or 256 bit key".into())),
    };
    let kw = AesKek::new(algo, kek).map_err(|_| WebtokenError::Generic("AES-KW Init failed".into()))?;
    let mut out = vec![0u8; data.len() + 8];
    kw.wrap(data, &mut out).map_err(|_| WebtokenError::Generic("AES-KW Wrap failed".into()))?;
    Ok(out)
}

pub fn aes_key_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    let algo = match kek.len() {
        16 => &KW_AES_128,
        32 => &KW_AES_256,
        _ => return Err(WebtokenError::InvalidToken("AES-KW requires 128 or 256 bit key".into())),
    };
    let kw = AesKek::new(algo, kek).map_err(|_| WebtokenError::Generic("AES-KW Init failed".into()))?;
    if wrapped.len() < 8 { return Err(WebtokenError::InvalidToken("Wrapped key too short".into())); }
    let mut out = vec![0u8; wrapped.len() - 8];
    kw.unwrap(wrapped, &mut out).map_err(|_| WebtokenError::Generic("AES-KW Unwrap failed".into()))?;
    Ok(out)
}

// --- AES-CBC Encryption ---

pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    let alg = match key.len() {
        16 => &AES_128,
        24 => &AES_192,
        32 => &AES_256,
        _ => return Err(WebtokenError::InvalidToken("Invalid AES Key Length".into())),
    };

    if iv.len() != 16 { return Err(WebtokenError::InvalidToken("IV must be 16 bytes".into())); }
    let mut iv_arr = [0u8; 16];
    iv_arr.copy_from_slice(iv);
    
    let unbound = UnboundCipherKey::new(alg, key).map_err(|_| WebtokenError::Generic("AES Init failed".into()))?;
    let enc_key = PaddedBlockEncryptingKey::cbc_pkcs7(unbound).map_err(|_| WebtokenError::Generic("AES CBC Init failed".into()))?;

    let mut in_out = plaintext.to_vec();
    let _ = enc_key.less_safe_encrypt(&mut in_out, EncryptionContext::Iv128(FixedLength::from(iv_arr)))
        .map_err(|_| WebtokenError::Generic("AES CBC Encrypt failed".into()))?;

    Ok(in_out)
}

pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    let alg = match key.len() {
        16 => &AES_128,
        24 => &AES_192,
        32 => &AES_256,
        _ => return Err(WebtokenError::InvalidToken("Invalid AES Key Length".into())),
    };

    if iv.len() != 16 { return Err(WebtokenError::InvalidToken("IV must be 16 bytes".into())); }
    let mut iv_arr = [0u8; 16];
    iv_arr.copy_from_slice(iv);

    let unbound = UnboundCipherKey::new(alg, key).map_err(|_| WebtokenError::Generic("AES Init failed".into()))?;
    let dec_key = PaddedBlockDecryptingKey::cbc_pkcs7(unbound).map_err(|_| WebtokenError::Generic("AES CBC Init failed".into()))?;

    let mut in_out = ciphertext.to_vec();
    let decrypted = dec_key.decrypt(&mut in_out, DecryptionContext::Iv128(FixedLength::from(iv_arr)))
        .map_err(|_| WebtokenError::InvalidToken("AES CBC Decrypt failed".into()))?;

    Ok(decrypted.to_vec())
}

// --- HMAC (Generic) ---

pub fn hmac_sign(key: &[u8], data: &[u8], alg: &str) -> Result<Vec<u8>, WebtokenError> {
    match alg {
        "HS256" => { let mut h = Hmac::<Sha256>::new(key); h.update(data); Ok(h.finish().as_ref().to_vec()) },
        "HS384" => { let mut h = Hmac::<Sha384>::new(key); h.update(data); Ok(h.finish().as_ref().to_vec()) },
        "HS512" => { let mut h = Hmac::<Sha512>::new(key); h.update(data); Ok(h.finish().as_ref().to_vec()) },
        _ => Err(WebtokenError::Generic("Unsupported HMAC".into()))
    }
}


pub fn aes_gcm_encrypt(
    key: &[u8], 
    nonce_opt: Option<&[u8]>, // Changed from &[u8] to Option<&[u8]>
    plaintext: &[u8], 
    aad: &[u8]
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), WebtokenError> {
    let algorithm = match key.len() {
        16 => &AES_128_GCM,
        32 => &AES_256_GCM,
        _ => return Err(WebtokenError::InvalidToken("AES-GCM Key must be 16 or 32 bytes".into())),
    };

    let unbound_key = UnboundKey::new(algorithm, key)
        .map_err(|_| WebtokenError::InvalidToken("Invalid AES-GCM Key".into()))?;
    let sealing_key = LessSafeKey::new(unbound_key);
    
    // Use provided nonce or generate random
    let nonce_vec = if let Some(n) = nonce_opt {
        if n.len() != 12 { return Err(WebtokenError::InvalidToken("AES-GCM Nonce must be 12 bytes".into())); }
        n.to_vec()
    } else {
        get_random_bytes(12)?
    };

    let nonce_obj = Nonce::try_assume_unique_for_key(&nonce_vec)
        .map_err(|_| WebtokenError::InvalidToken("Invalid Nonce".into()))?;
    
    let mut in_out = plaintext.to_vec();
    let tag = sealing_key.seal_in_place_separate_tag(nonce_obj, Aad::from(aad), &mut in_out)
        .map_err(|_| WebtokenError::Generic("AES-GCM Encrypt Failed".into()))?;
        
    Ok((in_out, tag.as_ref().to_vec(), nonce_vec))
}


pub fn aes_gcm_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], tag: &[u8], aad: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    let algorithm = match key.len() {
        16 => &AES_128_GCM,
        32 => &AES_256_GCM,
        _ => return Err(WebtokenError::InvalidToken("AES-GCM Key must be 16 or 32 bytes".into())),
    };

    let unbound_key = UnboundKey::new(algorithm, key).map_err(|_| WebtokenError::InvalidToken("Invalid AES-GCM Key".into()))?;
    let opening_key = LessSafeKey::new(unbound_key);
    let nonce_obj = Nonce::try_assume_unique_for_key(nonce).map_err(|_| WebtokenError::InvalidToken("Invalid Nonce".into()))?;
    
    let mut in_out = ciphertext.to_vec();
    in_out.extend_from_slice(tag);
    let plaintext_slice = opening_key.open_in_place(nonce_obj, Aad::from(aad), &mut in_out)
        .map_err(|_| WebtokenError::InvalidToken("AES-GCM Decrypt Failed".into()))?;
        
    Ok(plaintext_slice.to_vec())
}

pub fn c20p_encrypt(key: &[u8], nonce_opt: Option<&[u8]>, plaintext: &[u8], aad: &[u8]
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), WebtokenError> {
    
    let key_arr: [u8; 32] = key.try_into().map_err(|_| 
        WebtokenError::InvalidKey("C20P requires a 32-byte key".into())
    )?;

    let nonce_vec = if let Some(n) = nonce_opt {
        if n.len() != 12 { return Err(WebtokenError::InvalidToken("C20P Nonce must be 12 bytes".into())); }
        n.to_vec()
    } else {
        get_random_bytes(12)?
    };

    let nonce_arr: [u8; 12] = nonce_vec.clone().try_into().unwrap();
    let cipher = ChaCha20Poly1305::new(key_arr);
    
    let mut buffer = plaintext.to_vec();
    let mut tag = [0u8; 16];
    
    cipher.encrypt(&nonce_arr, aad, &mut buffer, &mut tag);
    
    Ok((buffer, tag.to_vec(), nonce_vec))
}


pub fn c20p_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], tag: &[u8], aad: &[u8]
    ) -> Result<Vec<u8>, WebtokenError> {
    
    let key_arr: [u8; 32] = key.try_into().map_err(|_| WebtokenError::InvalidKey("C20P requires a 32-byte key".into()))?;
    let nonce_arr: [u8; 12] = nonce.try_into().map_err(|_| WebtokenError::Generic("C20P Nonce must be 12 bytes".into()))?;
    let tag_arr: [u8; 16] = tag.try_into().map_err(|_| WebtokenError::Generic("C20P Tag must be 16 bytes".into()))?;

    let cipher = ChaCha20Poly1305::new(key_arr);
    let mut buffer = ciphertext.to_vec();
    
    if cipher.decrypt(&nonce_arr, aad, &mut buffer, &tag_arr).is_err() {
        return Err(WebtokenError::InvalidSignature);
    }
    
    Ok(buffer)
}

// ============================================================================
//  AEAD (XChaCha20 - Graviola)
// ============================================================================

pub fn encrypt_xchacha20_detached(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8], aad: &[u8]
) -> Result<(Vec<u8>, Vec<u8>), WebtokenError> {
    let cipher = XChaCha20Poly1305::new(*key);
    let mut buffer = plaintext.to_vec();
    let mut tag = [0u8; TAG_LEN];
    cipher.encrypt(nonce, aad, &mut buffer, &mut tag);
    Ok((buffer, tag.to_vec()))
}


pub fn encrypt_xchacha20(key: &[u8], plaintext: &[u8], aad: &[u8], nonce_opt: Option<&[u8]> 
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), WebtokenError> {

    let key_arr: [u8; XCHACHA_KEY_LEN] = key.try_into().map_err(|_|
        WebtokenError::InvalidKey(format!("XChaCha20 requires a {XCHACHA_KEY_LEN}-byte key"))
    )?;

    // Use provided nonce or generate random
    let nonce_vec = if let Some(n) = nonce_opt {
        if n.len() != XCHACHA_NONCE_LEN { return Err(WebtokenError::InvalidToken("XChaCha20 Nonce must be 24 bytes".into())); }
        n.to_vec()
    } else {
        get_random_bytes(XCHACHA_NONCE_LEN)?
    };
    
    let nonce_arr: [u8; 24] = nonce_vec.clone().try_into().unwrap();
    let (ciphertext, tag) = encrypt_xchacha20_detached(&key_arr, &nonce_arr, plaintext, aad)?;

    Ok((ciphertext, tag, nonce_vec))
}


pub fn decrypt_xchacha20_detached(key: &[u8; 32], nonce: &[u8; 24], ciphertext: &[u8], tag: &[u8; 16], aad: &[u8]
) -> Result<Vec<u8>, WebtokenError> {

    let cipher = XChaCha20Poly1305::new(*key);
    let mut buffer = ciphertext.to_vec();
    if cipher.decrypt(nonce, aad, &mut buffer, tag).is_err() {
        return Err(WebtokenError::InvalidSignature);
    }

    Ok(buffer)
}

pub fn decrypt_xchacha20(key: &[u8], ciphertext: &[u8], aad: &[u8], nonce: &[u8], tag: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    
    let key_arr: [u8; XCHACHA_KEY_LEN] = key.try_into().map_err(|_| WebtokenError::InvalidKey("Invalid key".into()))?;
    let nonce_arr: [u8; XCHACHA_NONCE_LEN] = nonce.try_into().map_err(|_| WebtokenError::Generic("Invalid nonce".into()))?;
    let tag_arr: [u8; TAG_LEN] = tag.try_into().map_err(|_| WebtokenError::Generic("Invalid tag".into()))?;
    
    decrypt_xchacha20_detached(&key_arr, &nonce_arr, ciphertext, &tag_arr, aad)
}

// ============================================================================
//  Key Agreement / KDFs
// ============================================================================

pub fn x25519_derive(private_key_bytes: &[u8], peer_public_key_bytes: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    let secret_bytes = extract_x25519_bytes(private_key_bytes)?;
    let public_bytes = extract_x25519_bytes(peer_public_key_bytes)?;

    let secret = StaticPrivateKey::try_from_slice(&secret_bytes).map_err(|_| WebtokenError::Generic("Invalid priv key".into()))?;
    let public = X25519PublicKey::try_from_slice(&public_bytes).map_err(|_| WebtokenError::Generic("Invalid pub key".into()))?;
    
    let shared_secret = secret.diffie_hellman(&public).map_err(|_| WebtokenError::Generic("ECDH failed".into()))?;
    Ok(shared_secret.0.to_vec())
}

pub fn x25519_public_from_private(private_key_bytes: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    let raw = extract_x25519_bytes(private_key_bytes)?;
    let secret = StaticPrivateKey::try_from_slice(&raw).map_err(|_| WebtokenError::Generic("Invalid priv key".into()))?;
    Ok(secret.public_key().as_bytes().to_vec())
}

pub fn ed25519_public_from_seed(seed: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    let key = Ed25519SigningKey::from_bytes(seed)
        .map_err(|_| WebtokenError::InvalidKey("Invalid Ed25519 seed".into()))?;
    Ok(key.public_key().as_bytes().to_vec())
}

pub fn hkdf_sha256(secret: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut h = Hmac::<Sha256>::new(salt);
    h.update(secret);
    let prk = h.finish();

    let mut okm = Vec::with_capacity(length);
    let mut last_t = Vec::new();
    let mut counter: u8 = 1;
    while okm.len() < length {
        let mut h = Hmac::<Sha256>::new(prk.as_ref());
        h.update(&last_t);
        h.update(info);
        h.update(&[counter]);
        let t = h.finish();
        last_t = t.as_ref().to_vec();
        okm.extend_from_slice(&last_t);
        counter += 1;
    }
    okm.truncate(length);
    okm
}

pub fn concat_kdf_sha256(shared_secret: &[u8], key_len_bits: u32, alg_id: &[u8], party_u_info: &[u8], party_v_info: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let target_len = (key_len_bits / 8) as usize;
    let mut counter = 1u32;
    let mut other_info = Vec::new();
    other_info.extend_from_slice(&(alg_id.len() as u32).to_be_bytes());
    other_info.extend_from_slice(alg_id);
    other_info.extend_from_slice(&(party_u_info.len() as u32).to_be_bytes());
    other_info.extend_from_slice(party_u_info);
    other_info.extend_from_slice(&(party_v_info.len() as u32).to_be_bytes());
    other_info.extend_from_slice(party_v_info);
    other_info.extend_from_slice(&(key_len_bits.to_be_bytes()));
    while out.len() < target_len {
        let mut ctx = Sha256::new();
        ctx.update(&counter.to_be_bytes()); 
        ctx.update(shared_secret); 
        ctx.update(&other_info);
        out.extend_from_slice(ctx.finish().as_ref());
        counter += 1;
    }
    out.truncate(target_len);
    out
}


pub fn pbkdf2_manual_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let block_size = 32;
    for (i, chunk) in out.chunks_mut(block_size).enumerate() {
        let mut h = Hmac::<Sha256>::new(password);
        h.update(salt); h.update(&((i as u32 + 1).to_be_bytes()));
        let u1 = h.finish();
        let mut block = [0u8; 32];
        block.copy_from_slice(u1.as_ref());
        let mut u_prev = u1;
        for _ in 1..iterations {
            let mut h = Hmac::<Sha256>::new(password);
            h.update(u_prev.as_ref());
            let u_next = h.finish();
            for (b, x) in block.iter_mut().zip(u_next.as_ref().iter()) { *b ^= *x; }
            u_prev = u_next;
        }
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
}

pub fn pbkdf2_manual_sha384(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let block_size = 48;
    for (i, chunk) in out.chunks_mut(block_size).enumerate() {
        let mut h = Hmac::<Sha384>::new(password);
        h.update(salt); h.update(&((i as u32 + 1).to_be_bytes()));
        let u1 = h.finish();
        let mut block = [0u8; 48];
        block.copy_from_slice(u1.as_ref());
        let mut u_prev = u1;
        for _ in 1..iterations {
            let mut h = Hmac::<Sha384>::new(password);
            h.update(u_prev.as_ref());
            let u_next = h.finish();
            for (b, x) in block.iter_mut().zip(u_next.as_ref().iter()) { *b ^= *x; }
            u_prev = u_next;
        }
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
}

pub fn pbkdf2_manual_sha512(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let block_size = 64;
    for (i, chunk) in out.chunks_mut(block_size).enumerate() {
        let mut h = Hmac::<Sha512>::new(password);
        h.update(salt); h.update(&((i as u32 + 1).to_be_bytes()));
        let u1 = h.finish();
        let mut block = [0u8; 64];
        block.copy_from_slice(u1.as_ref());
        let mut u_prev = u1;
        for _ in 1..iterations {
            let mut h = Hmac::<Sha512>::new(password);
            h.update(u_prev.as_ref());
            let u_next = h.finish();
            for (b, x) in block.iter_mut().zip(u_next.as_ref().iter()) { *b ^= *x; }
            u_prev = u_next;
        }
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
}


// ============================================================================
//  Sign/Verify (JWS)
// ============================================================================

pub fn sign(alg: &str, key_data: &[u8], message: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    let der = decode_key_bytes(key_data);
    
    // [AWS-LC-RS] Helper for RSA signing
    macro_rules! sign_aws_rsa {
        ($algo:expr) => {{
            let kp = RsaKeyPair::from_pkcs8(&der)
                .or_else(|_| RsaKeyPair::from_der(&der))
                .or_else(|_| {
                    let wrapped = wrap_pkcs1_as_pkcs8(&der);
                    RsaKeyPair::from_pkcs8(&wrapped)
                })
                .map_err(|_| WebtokenError::InvalidKey("Invalid RSA key".into()))?;
            
            let mut sig = vec![0u8; kp.public_modulus_len()];
            kp.sign($algo, &SystemRandom::new(), message, &mut sig).map_err(|_| WebtokenError::Generic("RSA sign failed".into()))?;
            Ok(sig)
        }}
    }

    // [AWS-LC-RS] Helper for EC signing
    macro_rules! sign_aws_ec {
        ($algo:expr) => {{
            let kp = EcdsaKeyPair::from_pkcs8($algo, &der).map_err(|_| WebtokenError::InvalidKey("Invalid EC key".into()))?;
            Ok(kp.sign(&SystemRandom::new(), message).map_err(|_| WebtokenError::Generic("EC sign failed".into()))?.as_ref().to_vec())
        }}
    }

    match alg {
        // [GRAVIOLA] HMAC
        "HS256" => { let mut h = Hmac::<Sha256>::new(&der); h.update(message); Ok(h.finish().as_ref().to_vec()) },
        "HS384" => { let mut h = Hmac::<Sha384>::new(&der); h.update(message); Ok(h.finish().as_ref().to_vec()) },
        "HS512" => { let mut h = Hmac::<Sha512>::new(&der); h.update(message); Ok(h.finish().as_ref().to_vec()) },

        // [AWS-LC-RS] RSA
        "RS256" => sign_aws_rsa!(&RSA_PKCS1_SHA256),
        "RS384" => sign_aws_rsa!(&RSA_PKCS1_SHA384),
        "RS512" => sign_aws_rsa!(&RSA_PKCS1_SHA512),
        "PS256" => sign_aws_rsa!(&RSA_PSS_SHA256),
        "PS384" => sign_aws_rsa!(&RSA_PSS_SHA384),
        "PS512" => sign_aws_rsa!(&RSA_PSS_SHA512),

        // [AWS-LC-RS] ECDSA
        "ES256" => sign_aws_ec!(&ECDSA_P256_SHA256_FIXED_SIGNING),
        "ES384" => sign_aws_ec!(&ECDSA_P384_SHA384_FIXED_SIGNING),
        "ES512" => sign_aws_ec!(&ECDSA_P521_SHA512_FIXED_SIGNING),
        "ES256K" => sign_aws_ec!(&ECDSA_P256K1_SHA256_FIXED_SIGNING),

        // [GRAVIOLA] EdDSA
        "EdDSA"|"Ed25519" => {
            let kp = if der.len() == 32 {
                Ed25519SigningKey::from_bytes(&der)
                    .map_err(|_| WebtokenError::InvalidKey("Invalid Ed25519 seed".into()))?
            } else {
                Ed25519SigningKey::from_pkcs8_der(&der)
                    .map_err(|_| WebtokenError::InvalidKey("Invalid Ed25519 PKCS8".into()))?
            };
            Ok(kp.sign(message).to_vec())
        },

        _ => Err(WebtokenError::InvalidAlgorithm("Algorithm not supported".into())),
    }
}

pub fn verify(alg: &str, key_data: &[u8], message: &[u8], signature: &[u8]) -> Result<(), WebtokenError> {
    let der = decode_key_bytes(key_data);
    match alg {
        "HS256" => { let mut h = Hmac::<Sha256>::new(&der); h.update(message); h.verify(signature).map_err(|_| WebtokenError::InvalidSignature) },
        "HS384" => { let mut h = Hmac::<Sha384>::new(&der); h.update(message); h.verify(signature).map_err(|_| WebtokenError::InvalidSignature) },
        "HS512" => { let mut h = Hmac::<Sha512>::new(&der); h.update(message); h.verify(signature).map_err(|_| WebtokenError::InvalidSignature) },

        "RS256" => { UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &der).verify(message, signature).map_err(|_| WebtokenError::InvalidSignature) },
        "RS384" => { UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA384, &der).verify(message, signature).map_err(|_| WebtokenError::InvalidSignature) },
        "RS512" => { UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, &der).verify(message, signature).map_err(|_| WebtokenError::InvalidSignature) },
        "PS256" => { UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, &der).verify(message, signature).map_err(|_| WebtokenError::InvalidSignature) },
        "PS384" => { UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, &der).verify(message, signature).map_err(|_| WebtokenError::InvalidSignature) },
        "PS512" => { UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA512, &der).verify(message, signature).map_err(|_| WebtokenError::InvalidSignature) },
        
        "ES256" => { UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &der).verify(message, signature).map_err(|_| WebtokenError::InvalidSignature) },
        "ES384" => { UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &der).verify(message, signature).map_err(|_| WebtokenError::InvalidSignature) },
        "ES512" => { UnparsedPublicKey::new(&ECDSA_P521_SHA512_FIXED, &der).verify(message, signature).map_err(|_| WebtokenError::InvalidSignature) },
        "ES256K" => { UnparsedPublicKey::new(&ECDSA_P256K1_SHA256_FIXED, &der).verify(message, signature).map_err(|_| WebtokenError::InvalidSignature) },

        // [GRAVIOLA] EdDSA
        "EdDSA"|"Ed25519" => {
            let vk = if der.len() == 32 {
                Ed25519VerifyingKey::from_bytes(&der)
                    .map_err(|_| WebtokenError::InvalidKey("Invalid Ed25519 public key bytes".into()))?
            } else {
                Ed25519VerifyingKey::from_spki_der(&der)
                    .map_err(|_| WebtokenError::InvalidKey("Invalid Ed25519 SPKI".into()))?
            };
            // argument order for Graviola: signature, message
            vk.verify(signature, message).map_err(|_| WebtokenError::InvalidSignature)
        },

        _ => Err(WebtokenError::InvalidAlgorithm("Algorithm not supported".into())),
    }
}

// ============================================================================
//  PASETO v4 Primitives
// ============================================================================

fn pae(pieces: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(pieces.len() as u64).to_le_bytes());
    for p in pieces {
        out.extend_from_slice(&(p.len() as u64).to_le_bytes());
        out.extend_from_slice(p);
    }
    out
}


pub fn paseto_v4_encrypt(
    key: &[u8; 32], 
    payload: &[u8], 
    footer: &[u8], 
    implicit: &[u8],
    nonce_opt: Option<&[u8]>
) -> Result<Vec<u8>, WebtokenError> {
    
    let nonce_vec = if let Some(n) = nonce_opt {
        if n.len() != 32 { return Err(WebtokenError::InvalidToken("nonce must be 32 bytes long.".into())); }
        n.to_vec()
    } else {
        get_random_bytes(32)?
    };
    let nonce: &[u8; 32] = nonce_vec.as_slice().try_into().unwrap();

    // 1. KDF for Encryption Key (ek) and Nonce (n2) - 56 bytes
    let tmp = Blake2bParams::new()
        .hash_length(56)
        .key(key)
        .to_state()
        .update(b"paseto-encryption-key")
        .update(nonce)
        .finalize();
    
    let tmp_bytes = tmp.as_bytes();
    let ek: [u8; 32] = tmp_bytes[0..32].try_into().unwrap();
    let n2: [u8; 24] = tmp_bytes[32..56].try_into().unwrap();

    // 2. KDF for Authentication Key (ak) - 32 bytes
    let ak_hash = Blake2bParams::new()
        .hash_length(32)
        .key(key)
        .to_state()
        .update(b"paseto-auth-key-for-aead")
        .update(nonce)
        .finalize();
    let ak: &[u8; 32] = ak_hash.as_bytes().try_into().unwrap();

    // 3. Encrypt payload using pure XChaCha20 stream cipher
    let mut ciphertext = payload.to_vec();
    let mut cipher = XChaCha20::new(&ek.into(), &n2.into());
    cipher.apply_keystream(&mut ciphertext);

    // 4. Calculate MAC over PAE
    let header = b"v4.local.";
    let pre_auth = pae(&[header, nonce, &ciphertext, footer, implicit]);
    
    let t_hash = Blake2bParams::new()
        .hash_length(32)
        .key(ak)
        .to_state()
        .update(&pre_auth)
        .finalize();

    // 5. Assemble
    let mut output = Vec::with_capacity(32 + ciphertext.len() + 32);
    output.extend_from_slice(nonce);
    output.extend_from_slice(&ciphertext);
    output.extend_from_slice(t_hash.as_bytes());
    Ok(output)
}


pub fn paseto_v4_decrypt(
    key: &[u8; 32], body: &[u8], footer: &[u8], implicit: &[u8]
) -> Result<Vec<u8>, WebtokenError> {
    if body.len() < 32 + 32 { return Err(WebtokenError::InvalidToken("Token too short".into())); }

    let nonce = &body[0..32];
    let t_len = body.len() - 32;
    let ciphertext = &body[32..t_len];
    let tag = &body[t_len..];

    // 1. KDF for Encryption Key (ek) and Nonce (n2)
    let tmp = Blake2bParams::new()
        .hash_length(56)
        .key(key)
        .to_state()
        .update(b"paseto-encryption-key")
        .update(nonce)
        .finalize();
    
    let tmp_bytes = tmp.as_bytes();
    let ek: [u8; 32] = tmp_bytes[0..32].try_into().unwrap();
    let n2: [u8; 24] = tmp_bytes[32..56].try_into().unwrap();

    // 2. KDF for Authentication Key (ak)
    let ak_hash = Blake2bParams::new()
        .hash_length(32)
        .key(key)
        .to_state()
        .update(b"paseto-auth-key-for-aead")
        .update(nonce)
        .finalize();
    let ak: &[u8; 32] = ak_hash.as_bytes().try_into().unwrap();

    // 3. Verify MAC
    let header = b"v4.local.";
    let pre_auth = pae(&[header, nonce, ciphertext, footer, implicit]);
    
    let calc_t = Blake2bParams::new()
        .hash_length(32)
        .key(ak)
        .to_state()
        .update(&pre_auth)
        .finalize();

    // Constant-time equality check (provided naturally by blake2b_simd::Hash)
    if !calc_t.eq(tag) { 
        return Err(WebtokenError::InvalidSignature); 
    }

    // 4. Decrypt payload using pure XChaCha20 stream cipher
    let mut plaintext = ciphertext.to_vec();
    let mut cipher = XChaCha20::new(&ek.into(), &n2.into());
    cipher.apply_keystream(&mut plaintext); 

    Ok(plaintext)
}


// ... (Python Bindings) ...
#[pyfunction]
#[pyo3(signature = (algorithm, key_size=None))]
pub fn generate_key_pair(algorithm: &str, key_size: Option<usize>) -> PyResult<(Vec<u8>, Vec<u8>)> {
    
    fn gen_rsa(size: KeySize) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let key = RsaKeyPair::generate(size).map_err(|_| PyValueError::new_err("RSA Gen failed"))?;
        Ok((
            to_pem("PRIVATE KEY", key.as_der().unwrap().as_ref()),
            to_pem("PUBLIC KEY", key.public_key().as_der().unwrap().as_ref())
        ))
    }

    match algorithm.to_uppercase().as_str() {
        // --- RSA ---
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => {
             match key_size.unwrap_or(2048) {
                2048 => gen_rsa(KeySize::Rsa2048),
                3072 => gen_rsa(KeySize::Rsa3072),
                4096 => gen_rsa(KeySize::Rsa4096),
                8192 => gen_rsa(KeySize::Rsa8192),
                _ => Err(PyValueError::new_err("Unsupported RSA key size")),
            }
        },

        // --- ECDSA ---
        "ES256" => {
            let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).map_err(|_| PyValueError::new_err("ES256 Gen failed"))?;
            Ok((
                to_pem("PRIVATE KEY", key.to_pkcs8v1().unwrap().as_ref()),
                to_pem("PUBLIC KEY", key.public_key().as_der().unwrap().as_ref())
            ))
        },
        "ES384" => {
            let key = EcdsaKeyPair::generate(&ECDSA_P384_SHA384_FIXED_SIGNING).map_err(|_| PyValueError::new_err("ES384 Gen failed"))?;
            Ok((
                to_pem("PRIVATE KEY", key.to_pkcs8v1().unwrap().as_ref()),
                to_pem("PUBLIC KEY", key.public_key().as_der().unwrap().as_ref())
            ))
        },
        "ES512" => {
            let key = EcdsaKeyPair::generate(&ECDSA_P521_SHA512_FIXED_SIGNING).map_err(|_| PyValueError::new_err("ES512 Gen failed"))?;
            Ok((
                to_pem("PRIVATE KEY", key.to_pkcs8v1().unwrap().as_ref()),
                to_pem("PUBLIC KEY", key.public_key().as_der().unwrap().as_ref())
            ))
        },
        "ES256K" | "SECP256K1" => {
            let key = EcdsaKeyPair::generate(&ECDSA_P256K1_SHA256_FIXED_SIGNING).map_err(|_| PyValueError::new_err("ES256K Gen failed"))?;
            Ok((
                to_pem("PRIVATE KEY", key.to_pkcs8v1().unwrap().as_ref()),
                to_pem("PUBLIC KEY", key.public_key().as_der().unwrap().as_ref())
            ))
        },

        // --- EdDSA (Ed25519) ---
        "EDDSA" | "ED25519" => {
            let key = Ed25519SigningKey::generate()
                .map_err(|_| PyValueError::new_err("Ed25519 Gen failed"))?;
            
            let mut pkcs8_buf = [0u8; 128];
            let pkcs8_slice = key.to_pkcs8_der(&mut pkcs8_buf)
                .map_err(|_| PyValueError::new_err("PKCS8 encode failed"))?;
            
            let mut spki_buf = [0u8; 128];
            let spki_slice = key.public_key().to_spki_der(&mut spki_buf)
                .map_err(|_| PyValueError::new_err("SPKI encode failed"))?;

            Ok((
                to_pem("PRIVATE KEY", pkcs8_slice),
                to_pem("PUBLIC KEY", spki_slice)
            ))
        },

        // --- X25519 (For ECDH-ES) ---
        "X25519" => {
            let priv_bytes = get_random_bytes(32).map_err(|_| PyValueError::new_err("RNG failed"))?;
            let pub_bytes = x25519_public_from_private(&priv_bytes).map_err(|_| PyValueError::new_err("X25519 Derive failed"))?;
            
            // Wrap in PKCS#8 (Private)
            let mut pkcs8_der = vec![
                0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x04, 0x22, 0x04, 0x20
            ];
            pkcs8_der.extend_from_slice(&priv_bytes);

            // Wrap in SPKI (Public)
            let mut spki_der = vec![
                0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00
            ];
            spki_der.extend_from_slice(&pub_bytes);

            Ok((
                to_pem("PRIVATE KEY", &pkcs8_der),
                to_pem("PUBLIC KEY", &spki_der)
            ))
        },

        other => Err(PyValueError::new_err(format!("Algo {} unsupported", other))),
    }
}


#[pyfunction]
#[pyo3(signature = (alg, key, message))]
fn sign_py<'py>(
    py: Python<'py>,
    alg: &str,
    key: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let sig = sign(alg, key, message)
        .map_err(|e| PyValueError::new_err(format!("Sign failed: {:?}", e)))?;
    Ok(PyBytes::new(py, &sig))
}

#[pyfunction]
#[pyo3(signature = (alg, key, message, signature))]
fn verify_py(alg: &str, key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<()> {
    verify(alg, key, message, signature)
        .map_err(|e| PyValueError::new_err(format!("Verify failed: {:?}", e)))
}

#[pyfunction]
fn digest(algorithm: &str, data: &[u8]) -> PyResult<Vec<u8>> {
    match algorithm.to_uppercase().as_str() {
        "SHA256" | "HS256" | "RS256" | "ES256" | "PS256" | "ES256K" => {
            Ok(Sha256::hash(data).as_ref().to_vec())
        }
        "SHA384" | "HS384" | "RS384" | "ES384" | "PS384" => {
            Ok(Sha384::hash(data).as_ref().to_vec())
        }
        "SHA512" | "HS512" | "RS512" | "ES512" | "PS512" => {
            Ok(Sha512::hash(data).as_ref().to_vec())
        }
        _ => Err(PyValueError::new_err("Unsupported hash algorithm")),
    }
}


#[pyfunction]
#[pyo3(signature = (data, password=None))]
fn load_pem_private_key(data: BytesOrString, password: Option<BytesOrString>,) -> PyResult<Vec<u8>> {

    if password.is_some() {
        return Err(PyValueError::new_err(
            "Encrypted keys not supported in test utils",
        ));
    }
    let s = std::str::from_utf8(data.as_bytes()).map_err(|_| PyValueError::new_err("Invalid UTF-8 in PEM"))?;

    if !s.trim().starts_with("-----BEGIN") {
        return Err(PyValueError::new_err("Invalid PEM format"));
    }
    Ok(data.as_bytes().to_vec())
}


#[pyfunction]
fn load_pem_public_key(data: BytesOrString) -> PyResult<Vec<u8>> {

    let s = std::str::from_utf8(data.as_bytes()).map_err(|_| PyValueError::new_err("Invalid UTF-8 in PEM"))?;
    if !s.trim().starts_with("-----BEGIN") {
        return Err(PyValueError::new_err("Invalid PEM format"));
    }
    Ok(data.as_bytes().to_vec())
}


#[pyfunction]
fn load_ssh_public_key<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let pem = ssh_to_pem(data).map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &pem))
}

#[pyfunction]
fn random_bytes<'py>(py: Python<'py>, length: usize) -> PyResult<Bound<'py, PyBytes>> {
    let out = get_random_bytes(length).map_err(PyErr::from)?;
    Ok(PyBytes::new(py, &out))
}

#[pyfunction]
pub fn generate_pkce_pair() -> PyResult<(String, String)> {
    let mut rand_bytes = [0u8; 32];
    aws_lc_rs::rand::fill(&mut rand_bytes).map_err(|_| PyValueError::new_err("RNG failed"))?;
    
    let verifier = URL_SAFE_NO_PAD.encode(rand_bytes);
    let hash = Sha256::hash(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hash.as_ref());
    
    Ok((verifier, challenge))
}

#[pyfunction]
#[pyo3(signature = (password, salt, iterations, length=32))]
fn pbkdf2_hmac_sha256<'py>(py: Python<'py>, password: &[u8], salt: &[u8], iterations: u32, length: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let mut out = vec![0u8; length];
    pbkdf2_manual_sha256(password, salt, iterations, &mut out);
    Ok(PyBytes::new(py, &out))
}

#[pyfunction]
#[pyo3(signature = (secret, salt, info, length=32))]
fn hkdf_sha256_py<'py>(
    py: Python<'py>,
    secret: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let out = hkdf_sha256(secret, salt, info, length);
    Ok(PyBytes::new(py, &out))
}

#[pyfunction]
#[pyo3(signature = (key, plaintext, aad=None))]
fn encrypt_aes_256_gcm<'py>(
    py: Python<'py>,
    key: &[u8],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err("AES-256-GCM key must be 32 bytes"));
    }
    
    let (buffer, tag, nonce) = aes_gcm_encrypt(key, None, plaintext, aad.unwrap_or(&[]))
        .map_err(|e| PyValueError::new_err(format!("{:?}", e)))?;
        
    let mut out_buffer = Vec::with_capacity(nonce.len() + buffer.len() + tag.len());
    out_buffer.extend_from_slice(&nonce);
    out_buffer.extend_from_slice(&buffer);
    out_buffer.extend_from_slice(&tag);
    
    Ok(PyBytes::new(py, &out_buffer))
}

#[pyfunction]
#[pyo3(signature = (key, ciphertext, aad=None))]
fn decrypt_aes_256_gcm<'py>(
    py: Python<'py>,
    key: &[u8],
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err("AES-256-GCM key must be 32 bytes"));
    }
    if ciphertext.len() < 28 {
        return Err(PyValueError::new_err("Ciphertext too short"));
    }
    
    let (nonce, rest) = ciphertext.split_at(12);
    let (encrypted_data, tag) = rest.split_at(rest.len() - 16);
    
    let plaintext = aes_gcm_decrypt(key, nonce, encrypted_data, tag, aad.unwrap_or(&[]))
        .map_err(|_| PyValueError::new_err("Decryption failed"))?;
        
    Ok(PyBytes::new(py, &plaintext))
}

#[pyfunction(name = "ed25519_public_from_seed")]
pub fn ed25519_public_from_seed_py(seed: BytesOrString) -> PyResult<Vec<u8>> {
    ed25519_public_from_seed(seed.as_bytes()).map_err(PyErr::from)
}


#[pyfunction(name = "x25519_public_from_private")]
pub fn x25519_public_from_private_py(private_key: &[u8]) -> PyResult<Vec<u8>> {
    x25519_public_from_private(private_key).map_err(PyErr::from)
}


#[pyfunction(name = "x25519_derive")]
pub fn x25519_derive_py(private_key: &[u8], peer_public_key: &[u8]) -> PyResult<Vec<u8>> {
    x25519_derive(private_key, peer_public_key).map_err(PyErr::from)
}


#[pyfunction(name = "paseto_v4_encrypt")]
#[pyo3(signature = (key, payload, footer=None, implicit=None, nonce=None))]
fn paseto_v4_encrypt_py<'py>(
    py: Python<'py>,
    key: &[u8],
    payload: &[u8],
    footer: Option<&[u8]>,
    implicit: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {

    let key_arr: &[u8; 32] = key.try_into().map_err(|_| PyValueError::new_err(
        "Key must be exactly 32 bytes"))?;

    let out = paseto_v4_encrypt(key_arr, payload, footer.unwrap_or(b""), implicit.unwrap_or(b""), nonce)
        .map_err(|e| PyValueError::new_err(format!("{}", e)))?;

    Ok(PyBytes::new(py, &out))
}


#[pyfunction(name = "paseto_v4_decrypt")]
#[pyo3(signature = (key, body, footer=None, implicit=None))]
fn paseto_v4_decrypt_py<'py>(py: Python<'py>, key: &[u8], body: &[u8], footer: Option<&[u8]>, implicit: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {

    let key_arr: &[u8; 32] = key.try_into().map_err(|_| PyValueError::new_err(
        "Key must be exactly 32 bytes"))?;

    let out = paseto_v4_decrypt(key_arr, body, footer.unwrap_or(b""), implicit.unwrap_or(b"")).map_err(|e| PyValueError::new_err(
        format!("{}", e)))?;

    Ok(PyBytes::new(py, &out))
}


#[pyfunction]
#[pyo3(signature = (seed))]
pub fn ed25519_seed_to_x25519_private(seed: &[u8]) -> PyResult<Vec<u8>> {

    if seed.len() != 32 {
        return Err(PyValueError::new_err("Ed25519 seed must be exactly 32 bytes"));
    }
    
    let digest = Sha512::hash(seed);
    let mut x25519_priv = digest.as_ref()[0..32].to_vec();
    
    // Curve25519 clamping
    x25519_priv[0] &= 248;
    x25519_priv[31] &= 127;
    x25519_priv[31] |= 64;
    
    Ok(x25519_priv)
}


#[pyfunction]
#[pyo3(signature = (key, plaintext, aad=None, nonce=None))]
fn encrypt_xc20p<'py>(
    py: Python<'py>, key: &[u8], plaintext: &[u8], aad: Option<&[u8]>, nonce: Option<&[u8]>
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (ciphertext, tag, _) = encrypt_xchacha20(key, plaintext, aad.unwrap_or(b""), nonce)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok((PyBytes::new(py, &ciphertext), PyBytes::new(py, &tag)))
}


#[pyfunction]
#[pyo3(signature = (key, ciphertext, tag, aad=None, nonce=None))]
fn decrypt_xc20p<'py>(
    py: Python<'py>, key: &[u8], ciphertext: &[u8], tag: &[u8], aad: Option<&[u8]>, nonce: Option<&[u8]>
) -> PyResult<Bound<'py, PyBytes>> {
    let plaintext = decrypt_xchacha20(key, ciphertext, aad.unwrap_or(b""), nonce.unwrap_or(b""), tag)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &plaintext))
}



struct AwsCertSigner {
    key: EcdsaKeyPair,
}

#[derive(Clone)]
struct AwsCertVerifier {
    pub_bytes: Vec<u8>,
}

impl Keypair for AwsCertSigner {
    type VerifyingKey = AwsCertVerifier;
    fn verifying_key(&self) -> Self::VerifyingKey {
        AwsCertVerifier {
            pub_bytes: self.key.public_key().as_ref().to_vec(),
        }
    }
}

impl x509_cert::spki::EncodePublicKey for AwsCertVerifier {
    fn to_public_key_der(&self) -> x509_cert::spki::Result<x509_cert::der::Document> {
        use x509_cert::der::Encode;
        
        // Wrap the raw AWS-LC Public Key into an x509-cert SPKI structure
        let spki_alg = AlgorithmIdentifierOwned {
            oid: x509_cert::der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
            parameters: Some(Any::encode_from(&x509_cert::der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7")).unwrap()),
        };
        
        let pub_key_info = SubjectPublicKeyInfo {
            algorithm: spki_alg,
            subject_public_key: BitString::from_bytes(&self.pub_bytes).unwrap(),
        };
        
        // Encode the full SPKI sequence to DER bytes, then return as a Document
        let der_bytes = pub_key_info.to_der().unwrap();
        Ok(x509_cert::der::Document::try_from(der_bytes.as_slice()).unwrap())
    }
}

impl x509_cert::spki::DynSignatureAlgorithmIdentifier for AwsCertSigner {
    // Return spki::Result instead of der::Result
    fn signature_algorithm_identifier(&self) -> x509_cert::spki::Result<AlgorithmIdentifierOwned> {
        Ok(AlgorithmIdentifierOwned {
            oid: x509_cert::der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            parameters: None,
        })
    }
}


#[pyfunction]
pub fn generate_localhost_cert() -> PyResult<(String, String)> {

    let rng = SystemRandom::new();
    let pkcs8_doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|e| PyValueError::new_err(format!("Key Gen err: {:?}", e)))?;
        
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_doc.as_ref())
        .map_err(|e| PyValueError::new_err(format!("Key Parse err: {:?}", e)))?;

    // Wrap the key in our custom struct
    let signer = AwsCertSigner { key: key_pair };

    let spki_alg = AlgorithmIdentifierOwned {
        oid: x509_cert::der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
        parameters: Some(Any::encode_from(&x509_cert::der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7")).unwrap()),
    };
    
    let pub_key_info = SubjectPublicKeyInfo {
        algorithm: spki_alg,
        subject_public_key: BitString::from_bytes(&signer.verifying_key().pub_bytes).unwrap(),
    };

    let subject = Name::from_str("CN=localhost,O=Localhost,C=US")
        .map_err(|e| PyValueError::new_err(format!("Name err: {}", e)))?;
        
    let mut serial_bytes = [0u8; 16];
    aws_lc_rs::rand::fill(&mut serial_bytes).unwrap();
    serial_bytes[0] &= 0x7f; 
    let serial = SerialNumber::new(&serial_bytes).unwrap();
    
    let validity = Validity::from_now(Duration::from_secs(3650 * 24 * 60 * 60))
        .map_err(|e| PyValueError::new_err(format!("Time err: {}", e)))?;

    let profile = Root::new(false, subject)
        .map_err(|e| PyValueError::new_err(format!("Profile err: {}", e)))?;
        
    let mut builder = CertificateBuilder::new(profile, serial, validity, pub_key_info)
        .map_err(|e| PyValueError::new_err(format!("Builder err: {}", e)))?;

    let san = SubjectAltName(vec![
        GeneralName::DnsName(x509_cert::der::asn1::Ia5String::new("localhost").unwrap()),
        GeneralName::from(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
    ]);
    
    builder.add_extension(&san)
        .map_err(|e| PyValueError::new_err(format!("SAN err: {}", e)))?;

    let tbs_blob = builder.finalize(&signer)
        .map_err(|e| PyValueError::new_err(format!("Finalize err: {}", e)))?;
        
    let signature = signer.key.sign(&rng, &tbs_blob)
        .map_err(|e| PyValueError::new_err(format!("Sign err: {:?}", e)))?;
        
    let cert = builder.assemble(BitString::from_bytes(signature.as_ref()).unwrap(), &signer)
        .map_err(|e| PyValueError::new_err(format!("Assemble err: {}", e)))?;

    let cert_der = cert.to_der().map_err(|e| PyValueError::new_err(format!("DER err: {}", e)))?;
    
    let cert_pem = String::from_utf8(to_pem("CERTIFICATE", &cert_der)).unwrap();
    let priv_key_pem = String::from_utf8(to_pem("PRIVATE KEY", pkcs8_doc.as_ref())).unwrap();

    Ok((cert_pem, priv_key_pem))
}


pub fn export_functions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(digest, m)?)?;
    m.add_function(wrap_pyfunction!(load_pem_private_key, m)?)?;
    m.add_function(wrap_pyfunction!(load_pem_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(load_ssh_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_aes_256_gcm, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_aes_256_gcm, m)?)?;
    m.add_function(wrap_pyfunction!(hkdf_sha256_py, m)?)?;
    m.add_function(wrap_pyfunction!(pbkdf2_hmac_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(random_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(generate_pkce_pair, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key_pair, m)?)?;
    m.add_function(wrap_pyfunction!(generate_localhost_cert, m)?)?;
    m.add_function(wrap_pyfunction!(sign_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_py, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_public_from_seed_py, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_seed_to_x25519_private, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_public_from_private_py, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_derive_py, m)?)?;
    m.add_function(wrap_pyfunction!(paseto_v4_encrypt_py, m)?)?;
    m.add_function(wrap_pyfunction!(paseto_v4_decrypt_py, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_xc20p, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_xc20p, m)?)?;
    
    Ok(())
}