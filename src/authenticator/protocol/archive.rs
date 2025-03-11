use flate2::{read::DeflateDecoder, write::DeflateEncoder, Compression};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

#[derive(Debug, Serialize, Deserialize, PartialEq, Copy, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum ArchiveAlgorithm {
    Deflate,
}

impl ArchiveAlgorithm {
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match &self {
            ArchiveAlgorithm::Deflate => deflate_compress(data),
        }
    }
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match &self {
            ArchiveAlgorithm::Deflate => deflate_decompress(data),
        }
    }
}

fn deflate_compress(data: &[u8]) -> Result<Vec<u8>, String> {
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

fn deflate_decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut compressed_data = Vec::new();
    let mut decoder = DeflateDecoder::new(data);
    decoder
        .read_to_end(&mut compressed_data)
        .map_err(|e| format!("zip error:{}", e.to_string()))?;
    Ok(compressed_data)
}
