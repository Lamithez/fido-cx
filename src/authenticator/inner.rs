use crate::authenticator::error::AuthenticatorError as AuthError;
use crate::crypto::gen_key_pair;
use crate::protocol::archive::ArchiveAlgorithm;
use crate::protocol::credential::{ByteStreamCredential, Credential};
use crate::protocol::hpke_format::{HPKEMode, HPKEParameters};
use base64::prelude::BASE64_URL_SAFE;
use base64::Engine;

pub trait InnerAuthenticator {
    fn support_algorithms(&self) -> (Vec<HPKEParameters>, Vec<ArchiveAlgorithm>);
    fn get_credentials(&self) -> Result<impl Credential, AuthError>;
    fn store_credential(&self, credential: impl Credential) -> Result<(), AuthError>;

    fn key_pair(&self, kem: u16) -> (Vec<u8>, Vec<u8>);
}

pub struct FakeInner {
    pub sk: Vec<u8>,
    pub pk: Vec<u8>,
}

impl FakeInner {
    pub fn new() -> Self {
        let (sk, pk) = gen_key_pair(0x11).unwrap();
        Self { sk, pk }
    }
}

impl InnerAuthenticator for FakeInner {
    fn support_algorithms(&self) -> (Vec<HPKEParameters>, Vec<ArchiveAlgorithm>) {
        (
            vec![HPKEParameters {
                mode: HPKEMode::Base,
                kem: 0x11,
                kdf: 0x1,
                aead: 0x1,
                key: BASE64_URL_SAFE.encode(&self.pk),
            }],
            vec![ArchiveAlgorithm::Deflate],
        )
    }

    fn get_credentials(&self) -> Result<impl Credential, AuthError> {
        Ok(ByteStreamCredential(b"CRENDENTIAL".to_vec()))
    }

    fn store_credential(&self, credential: impl Credential) -> Result<(), AuthError> {
        todo!()
    }

    fn key_pair(&self, kem: u16) -> (Vec<u8>, Vec<u8>) {
        if kem != 0x11 {
            !unimplemented!()
        }
        (self.sk.clone(), self.pk.clone())
    }
}
