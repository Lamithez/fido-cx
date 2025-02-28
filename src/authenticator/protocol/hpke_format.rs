use base64::prelude::BASE64_URL_SAFE;
use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HPKEParameters {
    pub mode: HPKEMode,
    pub kem: u16,
    pub kdf: u16,
    pub aead: u16,
    pub key: JWKS, //JWK as JSON string
}

pub struct JWK {
    pub enc: Option<Vec<u8>>,
    pub pk: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JWKS {
    pub enc: Option<String>,
    pub pke: Option<String>,
}

impl PartialEq for HPKEParameters {
    fn eq(&self, other: &Self) -> bool {
        self.mode == other.mode
            && self.kdf == other.kdf
            && self.aead == other.aead
            && self.kem == other.kem
    }
}

impl HPKEParameters {
    pub fn destruct_jwk(&self) -> JWK {
        JWK {
            enc: if let Some(s) = &self.key.enc {
                Some(BASE64_URL_SAFE.decode(s).expect("Decoding error"))
            } else {
                None
            },
            pk: if let Some(s) = &self.key.pke {
                Some(BASE64_URL_SAFE.decode(s).expect("Decoding error"))
            } else {
                None
            },
        }
    }
    pub fn construct_jwk(&mut self, key: Option<Vec<u8>>, pke: Option<Vec<u8>>) {
        self.key = JWKS {
            enc: if let Some(k) = key {
                Some(BASE64_URL_SAFE.encode(&k))
            } else {
                None
            },
            pke: if let Some(k) = pke {
                Some(BASE64_URL_SAFE.encode(&k))
            } else {
                None
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum HPKEMode {
    Base,
    Psk,
    Auth,
    AuthPsk,
}
