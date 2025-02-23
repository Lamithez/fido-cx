use crate::authenticator::inner::FakeInner;
use crate::authenticator::pin::PinInner;
use crate::authenticator::Authenticator;
use crate::authenticator::protocol::hpke_format::HPKEMode::AuthPsk;

#[test]
fn bin_test() {
    let a = Authenticator {
        inner: PinInner::new(),
    };
    let b = Authenticator {
        inner: PinInner::new(),
    };

    let export_request = a
        .construct_export_request("www.example.com".to_string(),AuthPsk)
        .expect("Construct Error");

    let export_response = b.handle_request(export_request).expect("Handle Error");
    a.handle_response_base(export_response)
        .expect("Handle Error");
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
