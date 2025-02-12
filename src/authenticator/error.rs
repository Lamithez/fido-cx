use crate::authenticator::error::AuthenticatorError::{CodeError, InternalError};
use base64::DecodeError;
use serde_json;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum AuthenticatorError {
    InnerAuthenticatorError(String),
    RequestNotAllowed(String),
    InternalError(String),
    UnsupportedAlgorithm,
    CryptoError(String),
    CodeError(String),
    CredentialNotFound,
}

impl Display for AuthenticatorError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}",
            match self {
                AuthenticatorError::InnerAuthenticatorError(e) => {
                    format!("内部验证器错误 {}", e)
                }
                AuthenticatorError::RequestNotAllowed(e) => {
                    format!("不支持的请求：{}", e)
                }
                InternalError(e) => {
                    format!("内部验证器错误 {}", e)
                }
                AuthenticatorError::UnsupportedAlgorithm => {
                    "不支持的算法".to_string()
                }
                AuthenticatorError::CryptoError(e) => {
                    format!("加密过程出现错误: {}", e)
                }
                CodeError(e) => {
                    format!("编码过程出现错误 {}", e)
                }
                AuthenticatorError::CredentialNotFound => {
                    "没有找到相应的凭证".to_string()
                }
            }
        )
    }
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

impl From<std::io::Error> for AuthenticatorError {
    fn from(value: std::io::Error) -> Self {
        InternalError(format!("IO Error Occurred {}", value))
    }
}
