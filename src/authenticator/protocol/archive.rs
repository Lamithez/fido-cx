use flate2::{read::DeflateDecoder, write::DeflateEncoder, Compression};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

#[derive(Debug, Serialize, Deserialize, PartialEq, Copy, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum ArchiveAlgorithm {
    Deflate,
}

impl ArchiveAlgorithm {
    pub fn zip(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match &self {
            ArchiveAlgorithm::Deflate => deflate_zip(data),
        }
    }
    pub fn unzip(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match &self {
            ArchiveAlgorithm::Deflate => deflate_unzip(data),
        }
    }
}

fn deflate_zip(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut compressed_data = Vec::new();
    let mut encoder = DeflateEncoder::new(&mut compressed_data, Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| format!("zip error:{}", e.to_string()))?;
    encoder
        .finish()
        .map_err(|e| format!("zip error:{}", e.to_string()))?;
    Ok(compressed_data)
}

fn deflate_unzip(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut compressed_data = Vec::new();
    let mut decoder = DeflateDecoder::new(data);
    decoder
        .read_to_end(&mut compressed_data)
        .map_err(|e| format!("zip error:{}", e.to_string()))?;
    Ok(compressed_data)
}

#[cfg(test)]
mod tests {
    use crate::authenticator::protocol::archive::{deflate_unzip, deflate_zip};

    #[test]
    fn test_zip() {
        let data = b"RANDOMDATA:if you need to support cargo 1.38 or earlier, you can symlink `config` to `config.toml`".to_vec();
        let zipped = deflate_zip(&data).unwrap();
        let unzipped = deflate_unzip(&zipped).unwrap();
        assert_eq!(data, unzipped);
    }
}
