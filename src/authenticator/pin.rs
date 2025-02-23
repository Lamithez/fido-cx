use crate::authenticator::crypto::gen_key_pair;
use crate::authenticator::error::AuthenticatorError as AuthError;
use crate::authenticator::inner::InnerAuthenticator;
use crate::authenticator::protocol::archive::ArchiveAlgorithm;
use crate::authenticator::protocol::credential::{Credential, StructuredSingleFileCredential};
use crate::authenticator::protocol::hpke_format::{HPKEMode, HPKEParameters, JWKS};
use base64::prelude::BASE64_URL_SAFE;
use base64::Engine;
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::collections::HashMap;
use std::fs;

pub struct PinInner {
    pub keys: HashMap<u16, (Vec<u8>, Vec<u8>)>,
}

impl PinInner {
    pub fn new() -> Self {
        let mut keys = HashMap::new();
        for kem in [0x10, 0x11, 0x12] {
            let k = gen_key_pair(kem).expect("Failed to generate key pair");
            keys.insert(kem, k);
        }
        PinInner { keys }
    }
    pub fn get_cred_lis(&self) -> HashMap<String, StructuredSingleFileCredential> {
        let mut creds = HashMap::new();
        if let Ok(path) = self.get_cx_files_in_current_dir() {
            for p in path {
                if let Ok(credential) = StructuredSingleFileCredential::from_file(&p) {
                    creds.insert(p, credential);
                }
            }
        }
        creds
    }
    fn get_cx_files_in_current_dir(&self) -> Result<Vec<String>, AuthError> {
        // 获取当前目录
        let current_dir =
            std::env::current_dir().map_err(|e| AuthError::InternalError(e.to_string()))?;

        // 用于存储匹配的文件路径
        let mut cx_files = Vec::new();

        // 遍历当前目录中的所有文件和子目录（非递归）
        for entry in
            fs::read_dir(current_dir).map_err(|e| AuthError::InternalError(e.to_string()))?
        {
            let entry = entry.map_err(|e| AuthError::InternalError(e.to_string()))?; // 解析目录条目
            let path = entry.path(); // 获取 PathBuf

            // 检查文件是否以 .cx 后缀结尾
            if let Some(extension) = path.extension() {
                if extension == "cx" {
                    if let Some(path_str) = path.to_str() {
                        cx_files.push(path_str.to_string());
                    }
                }
            }
        }
        Ok(cx_files)
    }
}
impl InnerAuthenticator for PinInner {
    fn support_algorithms(&self, mode: &HPKEMode) -> (Vec<HPKEParameters>, Vec<ArchiveAlgorithm>) {
        (
            self.keys
                .iter()
                .map(|(k, params)| HPKEParameters {
                    kem: *k,
                    mode: mode.clone(),
                    kdf: 0x1,
                    aead: 0x1,
                    key: serde_json::to_string(&JWKS {
                        enc: None,
                        pke: Some(BASE64_URL_SAFE.encode(&params.1)),
                    })
                    .unwrap(),
                })
                .collect(),
            vec![ArchiveAlgorithm::Deflate],
        )
    }
    fn get_credentials(&self) -> Result<Vec<impl Credential>, AuthError> {
        Ok(self.get_cred_lis().into_values().collect())
    }

    fn store_credential(&self, credential: impl Credential) -> Result<(), AuthError> {
        let random_string: String = rand::thread_rng()
            .sample_iter(&Alphanumeric) // 从 Alphanumeric（a-z, A-Z, 0-9）中生成随机字符
            .take(6) // 取 6 个字符
            .map(char::from) // 将 u8 转换为 char
            .collect();
        StructuredSingleFileCredential {
            rp_id: credential.get_rp_id(),
            credential: credential.get_credential(),
        }
        .to_file(&(random_string + ".cx"))
        .map_err(|err| AuthError::InternalError(err))?;
        Ok(())
    }

    fn key_pair(&self, kem: u16) -> (Vec<u8>, Vec<u8>) {
        self.keys.get(&kem).cloned().expect("Key pair not found")
    }
}
