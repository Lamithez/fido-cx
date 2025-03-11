use crate::authenticator::crypto::gen_key_pair;
use crate::authenticator::error::AuthenticatorError as AuthError;
use crate::authenticator::inner::InnerAuthenticator;
use crate::authenticator::protocol::archive::ArchiveAlgorithm;
use crate::authenticator::protocol::credential::{Credential, StructuredSingleFileCredential};
use crate::authenticator::protocol::hpke_format::HPKEMode::Auth;
use crate::authenticator::protocol::hpke_format::{HPKEMode, HPKEParameters, JWKS};
use base64::prelude::BASE64_URL_SAFE;
use base64::Engine;
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::collections::HashMap;
use std::fs;
const SUPPORTED_KEMS: &[u16] = &[0x10, 0x11, 0x12];
const DEFAULT_KDF: u16 = 1;
const DEFAULT_AEAD: u16 = 1;
pub struct PinInner {
    pub keys: HashMap<u16, (Vec<u8>, Vec<u8>)>,
    pub algorithms: Vec<HPKEParameters>,
}

impl PinInner {
    pub fn default() -> PinInner {
        let mut keys = HashMap::new();
        let mut algorithms = Vec::new();

        for kem in SUPPORTED_KEMS {
            let (sk, pk) = gen_key_pair(*kem).unwrap();
            keys.insert(*kem, (sk, pk.clone()));
            algorithms.push(HPKEParameters {
                kem: *kem,
                mode: Auth,
                kdf: DEFAULT_KDF,
                aead: DEFAULT_AEAD,
                key: JWKS {
                    enc: None,
                    pk: Some(BASE64_URL_SAFE.encode(&pk)),
                },
            });
        }
        PinInner { keys, algorithms }
    }
    pub fn new(kem: u16, kdf: u16, aead: u16, mode: &HPKEMode) -> Self {
        let mut keys = HashMap::new();

        let k = gen_key_pair(kem).expect("Failed to generate key pair");
        keys.insert(kem, k.clone());

        let algors: Vec<HPKEParameters> = vec![HPKEParameters {
            kem,
            mode: mode.clone(),
            kdf,
            aead,
            key: JWKS {
                enc: None,
                pk: Some(BASE64_URL_SAFE.encode(&k.1)),
            },
        }];
        PinInner {
            keys,
            algorithms: algors,
        }
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
    fn support_algorithms(&self) -> (Vec<HPKEParameters>, Vec<ArchiveAlgorithm>) {
        (self.algorithms.clone(), vec![ArchiveAlgorithm::Deflate])
    }
    fn get_credentials(&self) -> Result<Vec<impl Credential>, AuthError> {
        //下面这段在性能测试时使用，避免IO操作
        // Ok(vec![
        //     StructuredSingleFileCredential {
        //         rp_id: "www.example.com".to_string(),
        //         credential: Vec::from(b"yKpgJrQdfu8FyAVuZPvTovTYNFw7Qmv48R5Htu2G9mYbqLPTJXyuoxaXYHRHEIamvDPwA6wVG5G1f4gRkYU6qh6P88m5K9927p1wIstP9jWYNpSYiYhvVf89fddMHSWlqlWlNakbuHFpyAGz4GeTSLZVZMRVfmEHfGEDl2CBLZPjqrD7tSTpN1dqLOnuy9kwBIBZclILvfZsxpAO0CCqOzlKynKNI5BPqRvO2GoIGnCjIiAumW1vLbhJq2OmNxdcmUONQOWbdYTEgGBRfaPMQICTkIOqwt5L4CkEETzBE9iIQYusL2nSdQtSAsY3mvK6MoiaLcaXTmGtLHvRtOtC5VW3hewCpLItgoMlY7nmemGpmeosTHBTzT0Eqrn7kMpg0ulB2zhUkSWKXCCzuAQJOfxrhbRykCCrWNHdoXbRysHdPMc3iyHsspMQWP1MWtJo7J44XD5rSXsxYhXvWOZDrh73zq14Kzf4hzo1e6k0AsmieSkD06bDJi3pyfjNxLc4b599ZyDh1bJcMtPS0aDRiOEOiApj3474u4qJEKv8OthdhddIsrrWHRt9zZLmumYVTwoHASQOxU6wUuqcsFnRcJ6yDvkJsxTsMDa8VNpburtmu1Mbj03mb2LprBP25mFxeQ42btaMMnuM6A7X2gCjWJUwKHv3HYDCcS5ndAQwJd5bwiYGS01WyGv09LS1JC8pINBdyMEqQ53Nv62Gqe7C4e8Mn7RJXjZmLf1BKXaEnnz3QIqPNUEqFpFh84QaHgeRgoAYRjzdQwCHqAExjoPvdojL9HKFOXl9hT96nKv8pD9kltvNf6R4dZADORVXsYZAkepSZRnPhIYnrSkuVtcZrIlO9dd6AW9j35zPFlAk6RSABmcnTu6L0F6F9yvEnVvVNlLhKlBrzmubctF6xnGUrH0fQrmNg8CnSzmOoZKL0TjMOabeX34N7PIZlgOasrs52KBJIcACPE4lz7b01D3FBuJ0rDLIhwrbPFNkZKRlPzoAtAz4tPLoz7vQsbR2M6YY"),
        //     }
        // ])
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
