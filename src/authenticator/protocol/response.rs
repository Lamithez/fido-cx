use crate::authenticator::protocol::archive::ArchiveAlgorithm;
use crate::authenticator::protocol::hpke_format::HPKEParameters;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExportResponse {
    pub version: u16,
    pub hpke_parameters: HPKEParameters,
    pub archive: ArchiveAlgorithm,
    pub exporter: String,
    pub payload: String, // Base64url encoded data
}
