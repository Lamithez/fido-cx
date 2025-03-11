use crate::authenticator::pin::PinInner;
use crate::authenticator::protocol::hpke_format::HPKEMode::{Auth, AuthPsk, Base, Psk};
use crate::authenticator::Authenticator;
use itertools::iproduct;
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::fs::File;
use std::io::Write;
use std::time::{Duration, Instant};

pub(crate) fn gen_random_credential(rp_id: &str) -> String {
    // 生成一个长度随机的任意字符串
    // let length: usize = rand::thread_rng().gen_range(1..1024);
    let length = 1024;
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
    let modes = [Base, Auth, Psk, AuthPsk];

    for (kem, kdf, aead, mode) in iproduct!(kem_id, kdf_id, aead_id, modes) {
        let importer = Authenticator {
            inner: PinInner::new(kem, kdf, aead, &mode),
        };
        let exporter = Authenticator {
            inner: PinInner::new(kem, kdf, aead, &mode),
        };
        for _i in 0..100 {
            let random_cred = gen_random_credential("www.example.com");

            let export_request = importer
                .construct_export_request("www.example.com".to_string())
                .expect("Construct Error,Test Failed");

            let export_response = exporter
                .handle_request(export_request)
                .expect("Handle Error,Test Failed");

            let recv_cred = importer
                .handle_response(export_response)
                .expect("Handle Error，Test Failed");

            assert_eq!(recv_cred, random_cred);
        }
    }
}

#[test]
fn process_test() {
    let importer = Authenticator {
        inner: PinInner::default(),
    };
    let exporter = Authenticator {
        inner: PinInner::default(),
    };
    let random_cred = gen_random_credential("www.example.com");

    let export_request = importer
        .construct_export_request("www.example.com".to_string())
        .expect("Construct Error,Test Failed");

    let export_response = exporter
        .handle_request(export_request)
        .expect("Handle Error,Test Failed");

    let recv_cred = importer
        .handle_response(export_response)
        .expect("Handle Error，Test Failed");

    assert_eq!(recv_cred, random_cred);
}

#[allow(unused)]
fn time_test() {
    let kem_id = [0x10, 0x11, 0x12, 0x20];
    let kdf_id = [0x01, 0x02, 0x03];
    let aead_id = [0x01, 0x02, 0x03];
    [Base, Auth, Psk, AuthPsk].into_iter().for_each(|mode| {
        let mut sum_time = Duration::new(0, 0);
        kem_id.into_iter().for_each(|kem| {
            let mut kem_sum_time = Duration::new(0, 0);
            kdf_id.into_iter().for_each(|kdf| {
                aead_id.into_iter().for_each(|aead| {
                    let importer = Authenticator {
                        inner: PinInner::new(kem, kdf, aead, &mode),
                    };
                    let exporter = Authenticator {
                        inner: PinInner::new(kem, kdf, aead, &mode),
                    };

                    // let _ = test::gen_random_credential("www.example.com");

                    let start = Instant::now();
                    for _ in 0..1000 {
                        // let k = gen_key_pair(kem).expect("Failed to generate key pair");
                        let export_request = importer
                            .construct_export_request("www.example.com".to_string())
                            .expect("Construct Error,Test Failed");

                        let export_response = exporter
                            .handle_request(export_request)
                            .expect("Handle Error,Test Failed");

                        let _ = importer
                            .handle_response(export_response)
                            .expect("Handle Error，Test Failed");
                    }
                    let duration = start.elapsed();
                    sum_time += duration;
                    kem_sum_time += duration;
                })
            });
            println!(
                "Mode {:?} with kem {}use time {}",
                mode,
                kem,
                kem_sum_time.as_secs_f32()
            );
        });
        println!("Mode {:?} use time {}", mode, sum_time.as_secs_f32());
    })
}
