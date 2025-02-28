use crate::authenticator::crypto::{decrypt, encrypt};
use crate::authenticator::protocol::archive::ArchiveAlgorithm;
use crate::authenticator::protocol::credential::Credential;
use crate::authenticator::protocol::hpke_format::HPKEMode::{Auth, AuthPsk};
use crate::authenticator::protocol::hpke_format::{HPKEMode, HPKEParameters};
use crate::authenticator::protocol::request::{ExportRequest, ResponseMode};
use crate::authenticator::protocol::response::ExportResponse;
use base64::prelude::BASE64_URL_SAFE;
use base64::Engine;
use error::{AuthenticatorError as AuthError, AuthenticatorError::*};
use inner::InnerAuthenticator;
use protocol::credential::StructuredSingleFileCredential;

pub mod crypto;
mod error;
pub mod inner;
pub mod pin;
pub mod protocol;

/// 验证器实体，不包括Fido Client部分
pub struct Authenticator<T: InnerAuthenticator> {
    pub inner: T,
}

impl<T: InnerAuthenticator> Authenticator<T> {
    pub fn construct_export_request(
        &self,
        rp_id: String,
    ) -> Result<String, AuthError> {
        let (hpke_params, archive_algs) = self.inner.support_algorithms();
        let request = ExportRequest::new(
            hpke_params,
            ResponseMode::Direct,
            rp_id,
            archive_algs,
            None,
            None,
        );
        serde_json::to_string(&request).map_err(Into::into)
    }

    /// 处理请求，计算参数进行加密，并返回Json格式的字符串
    /// 传入收到的请求的字符串Json格式
    pub fn handle_request(&self, request: String) -> Result<String, AuthError> {
        let request: ExportRequest = serde_json::from_str(&request)?;

        let (mut hpke_param, archive_alg) =
            self.match_algorithm(&request.hpke_parameters, &request.archive)?;
        let rp = &request.importer;
        let credentials = self.inner.get_credentials()?;

        let credential = credentials
            .into_iter()
            .filter(|cred| cred.get_rp_id().eq(rp))
            .take(1)
            .next()
            .ok_or(CredentialNotFound)?;

        let data = credential.get_credential();

        let data = archive_alg.zip(&data).map_err(|e| CodeError(e))?;

        let (cipher, encapped_key) = encrypt(
            hpke_param.kem,
            hpke_param.kdf,
            hpke_param.aead,
            &data,
            &hpke_param.destruct_jwk().pk.unwrap(),
            &hpke_param.mode,
            &self.inner.key_pair(hpke_param.kem),
        )
        .map_err(|s| CryptoError(s))?;
        let pk = if hpke_param.mode == AuthPsk || hpke_param.mode == Auth {
            Some(self.inner.key_pair(hpke_param.kem).1)
        } else {
            None
        };
        hpke_param.construct_jwk(Some(encapped_key), pk);

        // let payload = archive_alg.zip(&cipher).map_err(|e| CodeError(e))?;

        let response = ExportResponse {
            version: 0,
            hpke_parameters: hpke_param,
            archive: archive_alg,
            exporter: request.importer,
            payload: BASE64_URL_SAFE.encode(&cipher),
        };

        serde_json::to_string(&response).map_err(Into::into)
    }

    ///处理传入的Export响应，解密
    pub fn handle_response_base(&self, response: String) -> Result<String, AuthError> {
        let response: ExportResponse = serde_json::from_str(&response)?;

        let cipher = &BASE64_URL_SAFE.decode(response.payload)?;

        let params = &response.hpke_parameters;

        let (sk, pk) = self.inner.key_pair(params.kem);

        let decrypted_text = decrypt(
            params.kem,
            params.kdf,
            params.aead,
            &cipher,
            &sk,
            &pk,
            &params.destruct_jwk().enc.unwrap(),
            &params.mode,
            &params.destruct_jwk().pk,
        )
        .map_err(|s| CryptoError(s))?;

        let credential = response
            .archive
            .unzip(&decrypted_text)
            .map_err(|e| CodeError(format!("Unzip Decoded error{:?}", e)))?;

        // println!("DECRYPT:{}", String::from_utf8(credential).unwrap());
        // self.inner
        //     .store_credential(StructuredSingleFileCredential {
        //         rp_id: response.exporter,
        //         credential: decrypted_text,
        //     })?;
        Ok(String::from_utf8(credential).unwrap())
    }
    // 匹配使用的算法
    // 匹配加密和压缩两个算法，分别输入两个算法的支持列表，支持列表与自身支持的列表进行比较，选取出第一个共同的算法
    // 如果两个里面任何一个无法匹配，则返回错误
    fn match_algorithm(
        &self,
        recv_hpke: &[HPKEParameters],
        recv_archive: &[ArchiveAlgorithm],
    ) -> Result<(HPKEParameters, ArchiveAlgorithm), AuthError> {
        let supported = self.inner.support_algorithms();

        let hpke = recv_hpke
            .iter()
            .find(|recv| supported.0.contains(recv))
            .cloned()
            .ok_or(UnsupportedAlgorithm)?;

        let archive = supported
            .1
            .iter()
            .find(|support| recv_archive.contains(support))
            .cloned()
            .ok_or(AuthError::UnsupportedAlgorithm)?;

        Ok((hpke, archive))
    }

    fn verify_request(request: &ExportRequest) -> Result<(), String> {
        todo!()
    }
}
