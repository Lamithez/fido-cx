use crate::authenticator::error::AuthenticatorError as AuthErr;
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
    pub pk: Option<String>,
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
    pub fn decode_jwk(&self) -> Result<JWK, AuthErr> {
        let decode = |s: &Option<String>| -> Result<Option<Vec<u8>>, AuthErr> {
            s.as_ref()
                .map(|s| {
                    BASE64_URL_SAFE
                        .decode(s)
                        .map_err(|e| AuthErr::CodeError(format!("Decode error:{}", e.to_string())))
                })
                .transpose()
        };
        Ok(JWK {
            enc: decode(&self.key.enc)?,
            pk: decode(&self.key.pk)?,
        })
    }
    pub fn encode_jwk(&mut self, key: Option<Vec<u8>>, pk: Option<Vec<u8>>) {
        let encode = |data: Option<Vec<u8>>| -> Option<String> {
            data.map(|bytes| BASE64_URL_SAFE.encode(&bytes))
        };
        self.key = JWKS {
            enc: encode(key),
            pk: encode(pk),
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
