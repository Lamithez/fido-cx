use crate::authenticator::inner::FakeInner;
use crate::authenticator::Authenticator;

pub mod authenticator;
pub mod crypto;
pub mod protocol;

fn main() {
    let a = Authenticator {
        inner: FakeInner::new(),
    };

    let export_request = a
        .construct_export_request_base("Hello.com".to_string())
        .expect("Construct Error");

    let export_response = a.handle_request(export_request).expect("Handle Error");
    a.handle_response_base(export_response)
        .expect("Handle Error");
}
