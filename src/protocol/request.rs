use serde::{Deserialize, Serialize};
use crate::protocol::archive::ArchiveAlgorithm;
use crate::protocol::hpke_format::{HPKEMode, HPKEParameters};


#[derive(Serialize,Deserialize,Debug)]
pub struct ExportRequest {
    pub version: u16,
    pub hpke_parameters: Vec<HPKEParameters>,
    pub archive: Vec<ArchiveAlgorithm>,
    pub mode: HPKEMode,
    pub importer: String,
    pub credential_types: Option<Vec<String>>,
    pub known_extensions: Option<Vec<String>>,
}

impl ExportRequest {
    pub fn new(
        hpke_parameters: Vec<HPKEParameters>,
        mode: HPKEMode,
        importer: String,
        archive: Vec<ArchiveAlgorithm>,
        credential_types: Option<Vec<String>>,
        known_extensions: Option<Vec<String>>,
    ) -> Self {
        Self {
            version: 0,
            hpke_parameters,
            archive,
            mode,
            importer,
            credential_types,
            known_extensions,
        }
    }

}


impl From<ExportRequest> for String{
    fn from(request: ExportRequest) -> String {
        serde_json::to_string(&request).unwrap()
    }
}
