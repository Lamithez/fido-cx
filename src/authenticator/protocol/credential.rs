//! # FIDO Credential
//! Note: 为了简便，Credential没有按照CXF的格式规定进行
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

pub trait Credential {
    fn get_credential(&self) -> Vec<u8>;
    fn get_rp_id(&self) -> String;
}

#[derive(Debug, Clone)]
pub struct StructuredSingleFileCredential {
    pub rp_id: String,
    pub credential: Vec<u8>,
}

impl Credential for StructuredSingleFileCredential {
    fn get_credential(&self) -> Vec<u8> {
        self.credential.clone()
    }

    fn get_rp_id(&self) -> String {
        self.rp_id.clone()
    }
}

impl StructuredSingleFileCredential {
    pub fn new(rp_id: String, credential: Vec<u8>) -> Self {
        Self { rp_id, credential }
    }
    /// 从单个文件中读取凭证
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| e.to_string())?;
        let mut reader = BufReader::new(file);
        let mut rp = String::new();
        reader.read_line(&mut rp).map_err(|e| e.to_string())?;
        let mut data = Vec::<u8>::new();
        reader.read_to_end(&mut data).map_err(|e| e.to_string())?;
        Ok(Self {
            rp_id: rp.trim().to_string(),
            credential: data,
        })
    }

    /// 将凭证存储为单文件
    /// 格式为第一行为RPID，其余的所有部分为凭证的ID
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let mut file = File::create(path).map_err(|e| e.to_string())?;
        writeln!(file, "{}", self.rp_id).map_err(|e| e.to_string())?;
        file.write_all(self.credential.as_slice())
            .map_err(|e| e.to_string())
    }
}
