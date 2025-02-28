use crate::authenticator::pin::PinInner;
use crate::authenticator::protocol::hpke_format::HPKEMode::{Auth, AuthPsk, Base, Psk};
use crate::authenticator::Authenticator;
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::fs::File;
use std::io::Write;

fn gen_random_credential(rp_id: &str) -> String {
    // 生成一个长度随机的任意字符串
    let length: usize = rand::thread_rng().gen_range(1..1024);
    let random_string: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();
    let formatted_string = format!("{}\n{}", rp_id, random_string);

    let mut file = File::create("pint.cx").unwrap();
    file.write_all(formatted_string.as_bytes()).unwrap();
    random_string
}

#[test]
fn cx_test() {
    let kem_id = [0x10, 0x11, 0x12, 0x20];
    let kdf_id = [0x01, 0x02, 0x03];
    let aead_id = [0x01, 0x02, 0x03];
    kem_id.into_iter().for_each(|kem| {
        kdf_id.into_iter().for_each(|kdf| {
            aead_id.into_iter().for_each(|aead| {
                [Base, Auth, Psk, AuthPsk].into_iter().for_each(|mode| {
                    let importer = Authenticator { inner: PinInner::new(kem, kdf, aead, &mode), };
                    let exporter = Authenticator { inner: PinInner::new(kem, kdf, aead, &mode), };

                    let random_cred = gen_random_credential("www.example.com");

                    let export_request = importer
                        .construct_export_request("www.example.com".to_string())
                        .expect("Construct Error,Test Failed");

                    let export_response = exporter
                        .handle_request(export_request)
                        .expect("Handle Error,Test Failed");

                    let recv_cred = importer
                        .handle_response_base(export_response)
                        .expect("Handle Error，Test Failed");

                    assert_eq!(recv_cred, random_cred);
                })
            })
        })
    })
}

// #[test]
// fn process_test() {
//     let a = Authenticator {
//         inner: FakeInner::new(b"This is an fake credential."),
//     };
//
//     let export_request = a
//         .construct_export_request("www.example.com".to_string(),AuthPsk)
//         .expect("Construct Error");
//
//     let export_response = a.handle_request(export_request).expect("Handle Error");
//     a.handle_response_base(export_response)
//         .expect("Handle Error");
// }
