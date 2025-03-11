use crate::authenticator::protocol::hpke_format::HPKEMode::{Auth, AuthPsk, Base, Psk};
use std::time::{Duration, Instant};
use crate::authenticator::Authenticator;
use crate::authenticator::pin::PinInner;

// 常量定义
const TEST_ITERATIONS: usize = 5;
const TEST_DOMAIN: &str = "www.example.com";

#[test]
fn time_test() {
    let kem_id = [0x10, 0x11, 0x12, 0x20];
    let kdf_id = [0x01, 0x02, 0x03];
    let aead_id = [0x01, 0x02, 0x03];

    println!("开始性能测试，每个配置迭代 {} 次", TEST_ITERATIONS);
    println!("=================================================");

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

                    let start = Instant::now();
                    for _ in 0..TEST_ITERATIONS {
                        let export_request = importer
                            .construct_export_request(TEST_DOMAIN.to_string())
                            .expect("构建导出请求失败");

                        let export_response = exporter
                            .handle_request(export_request)
                            .expect("处理请求失败");

                        let _ = importer
                            .handle_response(export_response)
                            .expect("处理响应失败");
                    }

                    let duration = start.elapsed();
                    sum_time += duration;
                    kem_sum_time += duration;
                });
            });

            // 计算平均时间（毫秒）
            let total_iterations = TEST_ITERATIONS * kdf_id.len() * aead_id.len();
            let avg_ms = kem_sum_time.as_secs_f64() * 1000.0 / total_iterations as f64;

            println!(
                "模式 {:?} KEM 0x{:02X} - 总时间: {:.2}秒, 平均: {:.2}毫秒/次",
                mode,
                kem,
                kem_sum_time.as_secs_f32(),
                avg_ms
            );
        });

        // 为每个模式计算总体平均时间
        let total_iterations = TEST_ITERATIONS * kem_id.len() * kdf_id.len() * aead_id.len();
        let avg_ms = sum_time.as_secs_f64() * 1000.0 / total_iterations as f64;

        println!("=================================================");
        println!(
            "模式 {:?} 总时间: {:.2}秒, 总体平均: {:.2}毫秒/次",
            mode,
            sum_time.as_secs_f32(),
            avg_ms
        );
        println!("=================================================\n");
    });
}
