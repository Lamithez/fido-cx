use crate::authenticator::error::AuthenticatorError as AuthError;
use crate::authenticator::protocol::{
    archive::ArchiveAlgorithm, credential::Credential, hpke_format::HPKEParameters,
};

pub trait InnerAuthenticator {
    fn support_algorithms(&self) -> (Vec<HPKEParameters>, Vec<ArchiveAlgorithm>);
    fn get_credentials(&self) -> Result<Vec<impl Credential>, AuthError>;
    fn store_credential(&self, credential: impl Credential) -> Result<(), AuthError>;
    fn key_pair(&self, kem: u16) -> (Vec<u8>, Vec<u8>);
}
