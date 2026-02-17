use crate::WebtokenError;
use std::str::FromStr;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Algorithm {
    Hs256, Hs384, Hs512,
    Rs256, Rs384, Rs512,
    Ps256, Ps384, Ps512,
    EdDsa,
    Es256, Es384, 
    Es512, Es256k,
    Blake2b512, 
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Algorithm::Hs256 => "HS256", Algorithm::Hs384 => "HS384", Algorithm::Hs512 => "HS512",
            Algorithm::Rs256 => "RS256", Algorithm::Rs384 => "RS384", Algorithm::Rs512 => "RS512",
            Algorithm::Ps256 => "PS256", Algorithm::Ps384 => "PS384", Algorithm::Ps512 => "PS512",
            Algorithm::Es256 => "ES256", Algorithm::Es384 => "ES384", Algorithm::Es512 => "ES512", Algorithm::Es256k => "ES256K",
            Algorithm::EdDsa => "EdDSA",
            Algorithm::Blake2b512 => "BLAKE2b512",
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
            "BLAKE2b512" => Ok(Algorithm::Blake2b512),
            _ => Err(WebtokenError::InvalidAlgorithm("Invalid algorithm".into())),
        }
    }
}



pub fn is_supported_algorithm(alg: &str) -> bool {
    Algorithm::from_str(alg).is_ok()
}