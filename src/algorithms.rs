use crate::{WebtokenError};
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::{STANDARD,}};
use blake2::{Blake2bMac512, digest::{KeyInit, Mac}};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::hmac::{self, Key as HmacKey, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512};
use aws_lc_rs::signature::{
    // Base structures
    UnparsedPublicKey, EcdsaSigningAlgorithm, EcdsaKeyPair, 
    
    // ECDSA (Verification constants)
    ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED,
    ECDSA_P521_SHA512_FIXED, ECDSA_P256K1_SHA256_FIXED,

    // ECDSA (Signing constants)
    ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING,
    ECDSA_P521_SHA512_FIXED_SIGNING, ECDSA_P256K1_SHA256_FIXED_SIGNING,
    RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512,
    RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512,
    
    // RSA (PKCS#1)
    RsaKeyPair,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,

    // RSA (PSS)
    RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512,

    // EdDSA
    Ed25519KeyPair, ED25519
};
use aws_lc_rs::unstable::signature::{PqdsaKeyPair, ML_DSA_65, ML_DSA_65_SIGNING};


// for PASETO v4 MAC & key derivation
pub type Blake2bMac256 = blake2::Blake2bMac<blake2::digest::consts::U32>; 
pub type _Blake2bMac448 = blake2::Blake2bMac<blake2::digest::consts::U56>;  // For internal use


#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Algorithm {
    Hs256, Hs384, Hs512,
    Rs256, Rs384, Rs512,
    Ps256, Ps384, Ps512,
    EdDsa,
    Es256, Es384, 
    Es512, Es256k,
    MlDsa65,      
    Blake2b512, Blake2b256,

}
 

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Algorithm::Hs256 => "HS256", Algorithm::Hs384 => "HS384", Algorithm::Hs512 => "HS512",
            Algorithm::Rs256 => "RS256", Algorithm::Rs384 => "RS384", Algorithm::Rs512 => "RS512",
            Algorithm::Ps256 => "PS256", Algorithm::Ps384 => "PS384", Algorithm::Ps512 => "PS512",
            Algorithm::Es256 => "ES256", Algorithm::Es384 => "ES384", Algorithm::Es512 => "ES512", Algorithm::Es256k => "ES256K",
            Algorithm::EdDsa => "EdDSA",
            Algorithm::MlDsa65 => "ML-DSA-65",
            Algorithm::Blake2b512 => "BLAKE2b512",
            Algorithm::Blake2b256 => "BLAKE2b256",
        };
        write!(f, "{}", s)
    }
}


impl FromStr for Algorithm {
    type Err = WebtokenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "HS256" => Ok(Algorithm::Hs256),
            "HS384" => Ok(Algorithm::Hs384),
            "HS512" => Ok(Algorithm::Hs512),
            "RS256" => Ok(Algorithm::Rs256),
            "RS384" => Ok(Algorithm::Rs384),
            "RS512" => Ok(Algorithm::Rs512),
            "PS256" => Ok(Algorithm::Ps256),
            "PS384" => Ok(Algorithm::Ps384),
            "PS512" => Ok(Algorithm::Ps512),
            "ES256" => Ok(Algorithm::Es256),
            "ES384" => Ok(Algorithm::Es384),
            "ES512" => Ok(Algorithm::Es512),
            "ES256K" => Ok(Algorithm::Es256k),
            "EdDSA" | "Ed25519" => Ok(Algorithm::EdDsa),
            "ML-DSA-65" => Ok(Algorithm::MlDsa65),
            "BLAKE2b512" => Ok(Algorithm::Blake2b512),
            "BLAKE2b256" => Ok(Algorithm::Blake2b256),

            _ => Err(WebtokenError::InvalidAlgorithm),
        }
    }
}

// -- Helpers --

fn sign_hmac(alg: &'static hmac::Algorithm, key: &[u8], payload: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    let key = HmacKey::new(*alg, key);
    let tag = hmac::sign(&key, payload);
    Ok(tag.as_ref().to_vec())
}


fn verify_hmac(alg: &'static hmac::Algorithm, key: &[u8], payload: &[u8], sig: &[u8]) -> Result<bool, WebtokenError> {
    let key = HmacKey::new(*alg, key);
    Ok(hmac::verify(&key, payload, sig).is_ok())
}


fn sign_blake2<D: Mac + KeyInit>(key: &[u8], payload: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    let mut mac = <D as KeyInit>::new_from_slice(key)
        .map_err(|_| WebtokenError::Custom { 
            exc: "InvalidKeyError".into(), 
            msg: "Invalid key length for BLAKE2".into() 
        })?;

    mac.update(payload);
    Ok(mac.finalize().into_bytes().to_vec())
}


fn verify_blake2<D: Mac + KeyInit>(key: &[u8], payload: &[u8], sig: &[u8]) -> Result<bool, WebtokenError> {
    
    let mut mac = <D as KeyInit>::new_from_slice(key)
        .map_err(|_| WebtokenError::Custom { 
            exc: "InvalidKeyError".into(), 
            msg: "Invalid key length for BLAKE2".into() 
        })?;
        
    mac.update(payload);
    Ok(mac.verify_slice(sig).is_ok())
}


fn sign_rsa(
    alg: &'static aws_lc_rs::signature::RsaSignatureEncoding, 
    key_bytes: &[u8], 
    payload: &[u8]
) -> Result<Vec<u8>, WebtokenError> {
    // Try parsing as PKCS#8 first (standard), then fall back to DER/PKCS#1
    let key_pair = RsaKeyPair::from_pkcs8(key_bytes)
        .or_else(|_| RsaKeyPair::from_der(key_bytes))
        .map_err(|e| WebtokenError::Custom { 
            exc: "InvalidKeyError".into(), 
            msg: format!("Invalid RSA private key: {:?}", e) 
        })?;
    
    let rng = SystemRandom::new();
    let mut signature = vec![0u8; key_pair.public_modulus_len()];
    
    key_pair.sign(alg, &rng, payload, &mut signature)
        .map_err(|e| WebtokenError::Generic(format!("RSA Signing failed: {:?}", e)))?;
    
    Ok(signature)
}

fn sign_ecdsa(
    alg: &'static EcdsaSigningAlgorithm, 
    key_bytes: &[u8], 
    payload: &[u8], 
    alg_name: &str
) -> Result<Vec<u8>, WebtokenError> {

    // 1. Parse PEM/DER Key
    let key_pair = EcdsaKeyPair::from_pkcs8(alg, key_bytes)
        .map_err(|e| WebtokenError::Custom { 
            exc: "InvalidKeyError".into(), 
            msg: format!("Invalid {} private key (expected PKCS#8): {:?}", alg_name, e) 
        })?;
    
    // 2. Initialize Randomness
    let rng = SystemRandom::new();

    // 3. Sign
    let sig = key_pair.sign(&rng, payload)
        .map_err(|e| WebtokenError::Generic(format!("Signing failed: {:?}", e)))?;
    
    Ok(sig.as_ref().to_vec())
}

fn decode_maybe_pem(data: &[u8]) -> Result<Vec<u8>, WebtokenError> {
    // 1. Check for PEM header
    if let Ok(s) = std::str::from_utf8(data) {
        let s = s.trim();
        if s.starts_with("-----BEGIN") {
            let lines: Vec<&str> = s.lines()
                .filter(|line| !line.starts_with("-----"))
                .map(|line| line.trim())
                .collect();
            
            let base64_data = lines.join("");
            return STANDARD.decode(&base64_data).map_err(|e| WebtokenError::Custom {
                exc: "InvalidKeyError".into(),
                msg: crate::err_loc!("Failed to base64 decode PEM body: {}", e)
            });
        }
    }
    // 2. Assume it is already DER (or raw bytes for HMAC/Ed25519)
    Ok(data.to_vec())
}


impl Algorithm {
  
    pub fn sign(&self, payload: &[u8], key_bytes: &[u8]) -> Result<Vec<u8>, WebtokenError> {
        // NOTE: For HMAC, key_bytes are the raw secret. For asymmetric, they are DER/PEM.
        let der_bytes = decode_maybe_pem(key_bytes)?;
        
        match self {
            // HMAC
            Self::Hs256 => sign_hmac(&HMAC_SHA256, &der_bytes, payload),
            Self::Hs384 => sign_hmac(&HMAC_SHA384, &der_bytes, payload),
            Self::Hs512 => sign_hmac(&HMAC_SHA512, &der_bytes, payload),

            // BLAKE2
            Self::Blake2b512 => sign_blake2::<Blake2bMac512>(&der_bytes, payload),
            Self::Blake2b256 => sign_blake2::<Blake2bMac256>(&der_bytes, payload),

            // RSA PKCS#1
            Self::Rs256 => sign_rsa(&RSA_PKCS1_SHA256, &der_bytes, payload),
            Self::Rs384 => sign_rsa(&RSA_PKCS1_SHA384, &der_bytes, payload),
            Self::Rs512 => sign_rsa(&RSA_PKCS1_SHA512, &der_bytes, payload),

            // RSA PSS
            Self::Ps256 => sign_rsa(&RSA_PSS_SHA256, &der_bytes, payload),
            Self::Ps384 => sign_rsa(&RSA_PSS_SHA384, &der_bytes, payload),
            Self::Ps512 => sign_rsa(&RSA_PSS_SHA512, &der_bytes, payload),

            // EdDSA (Ed25519 only in aws-lc-rs currently)
            Self::EdDsa => {
                 // Try PKCS#8 first
                 if let Ok(key_pair) = Ed25519KeyPair::from_pkcs8(&der_bytes) {
                     return Ok(key_pair.sign(payload).as_ref().to_vec());
                 }
                 // If that fails, try Seed (Raw 32 bytes)
                 if let Ok(key_pair) = Ed25519KeyPair::from_seed_unchecked(&der_bytes) {
                     return Ok(key_pair.sign(payload).as_ref().to_vec());
                 }
                 Err(WebtokenError::Custom { 
                     exc: "InvalidKeyError".into(), 
                     msg: "Invalid Ed25519 key (Expected PKCS#8 or 32-byte seed)".into() 
                 })
            },

            // ECDSA
            Self::Es256 => sign_ecdsa(&ECDSA_P256_SHA256_FIXED_SIGNING, &der_bytes, payload, "ES256"),
            Self::Es384 => sign_ecdsa(&ECDSA_P384_SHA384_FIXED_SIGNING, &der_bytes, payload, "ES384"),
            Self::Es512 => sign_ecdsa(&ECDSA_P521_SHA512_FIXED_SIGNING, &der_bytes, payload, "ES512"),
            Self::Es256k => sign_ecdsa(&ECDSA_P256K1_SHA256_FIXED_SIGNING, &der_bytes, payload, "ES256K"),

            // PQ
            Self::MlDsa65 => {
                if let Ok(key_pair) = PqdsaKeyPair::from_pkcs8(&ML_DSA_65_SIGNING, &der_bytes) {
                    let mut sig = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
                    key_pair.sign(payload, &mut sig).map_err(|e| WebtokenError::Generic(format!("{:?}", e)))?;
                    Ok(sig)
                } else if let Ok(key_pair) = PqdsaKeyPair::from_raw_private_key(&ML_DSA_65_SIGNING, &der_bytes) {
                    let mut sig = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
                    key_pair.sign(payload, &mut sig).map_err(|e| WebtokenError::Generic(format!("{:?}", e)))?;
                    Ok(sig)
                } else {
                     Err(WebtokenError::Custom { exc: "InvalidKeyError".into(), msg: "Invalid ML-DSA-65 key".into() })
                }
            },
        }
    }


    pub fn verify(&self, payload: &[u8], sig_bytes: &[u8], key_bytes: &[u8]) -> Result<bool, WebtokenError> {
        let der_bytes = decode_maybe_pem(key_bytes)?;
        
        let valid = match self {
            // HMAC
            Self::Hs256 => verify_hmac(&HMAC_SHA256, &der_bytes, payload, sig_bytes)?,
            Self::Hs384 => verify_hmac(&HMAC_SHA384, &der_bytes, payload, sig_bytes)?,
            Self::Hs512 => verify_hmac(&HMAC_SHA512, &der_bytes, payload, sig_bytes)?,

            // BLAKE2
            Self::Blake2b512 => verify_blake2::<Blake2bMac512>(&der_bytes, payload, sig_bytes)?,
            Self::Blake2b256 => verify_blake2::<Blake2bMac256>(&der_bytes, payload, sig_bytes)?,

            // RSA PKCS#1
            Self::Rs256 => UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &der_bytes).verify(payload, sig_bytes).is_ok(),
            Self::Rs384 => UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA384, &der_bytes).verify(payload, sig_bytes).is_ok(),
            Self::Rs512 => UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, &der_bytes).verify(payload, sig_bytes).is_ok(),

            // RSA PSS
            Self::Ps256 => UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, &der_bytes).verify(payload, sig_bytes).is_ok(),
            Self::Ps384 => UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, &der_bytes).verify(payload, sig_bytes).is_ok(),
            Self::Ps512 => UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA512, &der_bytes).verify(payload, sig_bytes).is_ok(),

            // EdDSA
            Self::EdDsa => UnparsedPublicKey::new(&ED25519, &der_bytes).verify(payload, sig_bytes).is_ok(),

            // ECDSA
            Self::Es256 => UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &der_bytes).verify(payload, sig_bytes).is_ok(),
            Self::Es384 => UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &der_bytes).verify(payload, sig_bytes).is_ok(),
            Self::Es512 => UnparsedPublicKey::new(&ECDSA_P521_SHA512_FIXED, &der_bytes).verify(payload, sig_bytes).is_ok(),
            Self::Es256k => UnparsedPublicKey::new(&ECDSA_P256K1_SHA256_FIXED, &der_bytes).verify(payload, sig_bytes).is_ok(),

            // PQ
            Self::MlDsa65 => UnparsedPublicKey::new(&ML_DSA_65, &der_bytes).verify(payload, sig_bytes).is_ok(),
        };
        Ok(valid)
    }
}


pub fn perform_signature(payload: &[u8], key: &[u8], alg_name: &str) -> Result<Vec<u8>, WebtokenError> {
    let alg = alg_name.parse::<Algorithm>()
        .map_err(|_| WebtokenError::Generic(format!("Algorithm '{}' not supported", alg_name)))?;
    
    alg.sign(payload, key)
}

pub fn perform_verification(payload: &[u8], signature: &[u8], key: &[u8], alg_name: &str) -> Result<bool, WebtokenError> {
    let alg = alg_name.parse::<Algorithm>()
        .map_err(|_| WebtokenError::Generic("Unsupported Algorithm".into()))?;

    alg.verify(payload, signature, key)
}