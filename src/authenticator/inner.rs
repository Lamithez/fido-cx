use crate::authenticator::error::AuthenticatorError as AuthError;
use crate::authenticator::protocol::archive::ArchiveAlgorithm;
use crate::authenticator::protocol::credential::Credential;
use crate::authenticator::protocol::hpke_format::{HPKEMode, HPKEParameters};

pub trait InnerAuthenticator {
    fn support_algorithms(&self) -> (Vec<HPKEParameters>, Vec<ArchiveAlgorithm>);
    fn get_credentials(&self) -> Result<Vec<impl Credential>, AuthError>;
    fn store_credential(&self, credential: impl Credential) -> Result<(), AuthError>;
    fn key_pair(&self, kem: u16) -> (Vec<u8>, Vec<u8>);
}

// 仅用于测试
// 只支持一种算法 kem: 0x11,kdf: 0x1, aead: 0x1,
// 凭证的类型为字节流（测试用）
//
// pub struct FakeInner {
//     pub credential: ByteStreamCredential,
//     pub sk: Vec<u8>,
//     pub pk: Vec<u8>,
// }
//
// impl FakeInner {
//     pub fn new(credential: impl Into<Vec<u8>>) -> Self {
//         let (sk, pk) = gen_key_pair(0x11).unwrap();
//         Self {
//             credential: ByteStreamCredential(credential.into()),
//             sk,
//             pk,
//         }
//     }
// }
//
// impl InnerAuthenticator for FakeInner {
//     fn support_algorithms(&self,mode:&HPKEMode) -> (Vec<HPKEParameters>, Vec<ArchiveAlgorithm>) {
//         (
//             vec![HPKEParameters {
//                 mode: mode.clone(),
//                 kem: 0x11,
//                 kdf: 0x1,
//                 aead: 0x1,
//                 key: BASE64_URL_SAFE.encode(&self.pk),
//             }],
//             vec![ArchiveAlgorithm::Deflate],
//         )
//     }
//
//     fn get_credentials(&self) -> Result<Vec<impl Credential>, AuthError> {
//         Ok(vec![self.credential.clone()])
//     }
//
//     fn store_credential(&self, credential: impl Credential) -> Result<(), AuthError> {
//         todo!()
//     }
//
//     fn key_pair(&self, kem: u16) -> (Vec<u8>, Vec<u8>) {
//         if kem != 0x11 {
//             !unimplemented!()
//         }
//         (self.sk.clone(), self.pk.clone())
//     }
// }
