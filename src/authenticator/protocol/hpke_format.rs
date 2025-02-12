use base64::prelude::BASE64_URL_SAFE;
use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HPKEParameters {
    pub mode: HPKEMode,
    pub kem: u16,
    pub kdf: u16,
    pub aead: u16,
    pub key: String, //JWT
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
    pub fn destruct_jwt(&self) -> Vec<u8> {
        BASE64_URL_SAFE.decode(&self.key).unwrap()
    }
    pub fn construct_jwt(&mut self, key: Vec<u8>) {
        self.key = BASE64_URL_SAFE.encode(&key)
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
