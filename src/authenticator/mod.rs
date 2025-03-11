use crate::authenticator::crypto::{decrypt, encrypt};
use crate::authenticator::protocol::archive::ArchiveAlgorithm;
use crate::authenticator::protocol::credential::Credential;
use crate::authenticator::protocol::hpke_format::HPKEMode::{Auth, AuthPsk};
use crate::authenticator::protocol::hpke_format::HPKEParameters;
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
    pub fn construct_export_request(&self, rp_id: String) -> Result<String, AuthError> {
        let (hpke_params, archive_algs) = self.inner.support_algorithms();
        let request = ExportRequest::new(
            hpke_params,
            ResponseMode::Direct,
            rp_id,
            archive_algs,
            None,
            None,
        );
        serde_json::to_string_pretty(&request).map_err(Into::into)
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
            .find(|cred| cred.get_rp_id().eq(rp))
            .ok_or(CredentialNotFound)?;
        let data = archive_alg
            .compress(&credential.get_credential())
            .map_err(|e| CodeError(e))?;

        let pk = &hpke_param.decode_jwk()?.pk.unwrap();
        let (cipher, encapped_key) = self.perform_encryption(&hpke_param, &data, &pk)?;

        hpke_param.encode_jwk(
            Some(encapped_key),
            matches!(hpke_param.mode, AuthPsk | Auth)
                .then(|| self.inner.key_pair(hpke_param.kem).1),
        );

        let response = ExportResponse {
            version: 0,
            hpke_parameters: hpke_param,
            archive: archive_alg,
            exporter: request.importer,
            payload: BASE64_URL_SAFE.encode(&cipher),
        };
        serde_json::to_string_pretty(&response).map_err(Into::into)
    }

    ///处理传入的Export响应，解密
    pub fn handle_response(&self, response: String) -> Result<String, AuthError> {
        let response: ExportResponse = serde_json::from_str(&response)?;
        let cipher = &BASE64_URL_SAFE.decode(response.payload)?;
        let params = &response.hpke_parameters;
        let (sk, pk) = self.inner.key_pair(params.kem);
        let enc = &params.decode_jwk()?.enc.unwrap();
        let decrypted_text = self.perform_decryption(params, &cipher, &sk, &pk, enc)?;
        let credential = response
            .archive
            .decompress(&decrypted_text)
            .map_err(|e| CodeError(format!("Unzip Decoded error{:?}", e)))?;
        // println!("DECRYPT:{}", String::from_utf8(credential.clone()).unwrap());
        // self.inner
        //     .store_credential(StructuredSingleFileCredential {
        //         rp_id: response.exporter,
        //         credential: credential.clone(),
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

    // fn verify_request(request: &ExportRequest) -> Result<(), String> {
    //     todo!()
    // }

    fn perform_encryption(
        &self,
        params: &HPKEParameters,
        data: &[u8],
        pk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), AuthError> {
        encrypt(
            params.kem,
            params.kdf,
            params.aead,
            data,
            pk,
            &params.mode,
            &self.inner.key_pair(params.kem),
        )
        .map_err(|s| CryptoError(s))
    }

    fn perform_decryption(
        &self,
        params: &HPKEParameters,
        cipher: &[u8],
        sk: &[u8],
        pk: &[u8],
        enc: &[u8],
    ) -> Result<Vec<u8>, AuthError> {
        let decoded_jwk = params.decode_jwk()?;
        decrypt(
            params.kem,
            params.kdf,
            params.aead,
            cipher,
            sk,
            pk,
            enc,
            &params.mode,
            &decoded_jwk.pk,
        )
        .map_err(|s| CryptoError(s))
    }
}
