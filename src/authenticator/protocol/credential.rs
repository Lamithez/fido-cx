use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};

pub trait Credential {
    fn get_credential(&self) -> Vec<u8>;
    fn get_credential_type(&self) -> String;
    fn get_rp_id(&self) -> String;
}

#[derive(Clone)]
pub struct ByteStreamCredential(pub Vec<u8>);
impl Credential for ByteStreamCredential {
    fn get_credential(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn get_credential_type(&self) -> String {
        "ByteStreamCredential".to_string()
    }

    fn get_rp_id(&self) -> String {
        String::from("www.example.com")
    }
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

    fn get_credential_type(&self) -> String {
        "StructuredSingleFileCredential".to_string()
    }

    fn get_rp_id(&self) -> String {
        self.rp_id.clone()
    }
}

impl StructuredSingleFileCredential {
    pub fn from_file(path: &str) -> Result<Self, String> {
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

    pub fn to_file(&self, path: &str) -> Result<(), String> {
        let mut file = File::create(path).map_err(|e| e.to_string())?;
        writeln!(file, "{}", self.rp_id).map_err(|e| e.to_string())?;
        file.write_all(self.credential.as_slice())
            .map_err(|e| e.to_string())
    }
}
//
// #[test]
// fn credential_test() {
//     let s = StructuredSingleFileCredential::from_file("pint.cx.cx").unwrap();
//     s.to_file("credential").unwrap();
// }
