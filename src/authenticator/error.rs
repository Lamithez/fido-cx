use crate::authenticator::error::AuthenticatorError::{CodeError, InternalError};
use base64::DecodeError;
use serde_json;

#[derive(Debug)]
pub enum AuthenticatorError {
    InnerAuthenticatorError(String),
    RequestNotAllowed(String),
    InternalError(String),
    UnsupportedAlgorithm,
    CryptoError(String),
    CodeError(String),
}

impl From<DecodeError> for AuthenticatorError {
    fn from(value: DecodeError) -> Self {
        CodeError(format!("Base64 Decode Error Occurred {}", value))
    }
}

impl From<serde_json::Error> for AuthenticatorError {
    fn from(value: serde_json::Error) -> Self {
        InternalError(format!("Json format error occurred.{}", value))
    }
}
