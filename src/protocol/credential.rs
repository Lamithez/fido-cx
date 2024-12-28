use std::fs::{self, File};
use std::io::Read;

pub trait Credential {
    fn get_credential(&self) -> Box<dyn Iterator<Item = Vec<u8>>>;
    fn get_credential_type(&self) -> String;
}

pub struct ByteStreamCredential(pub Vec<u8>);
impl Credential for ByteStreamCredential {
    fn get_credential(&self) -> Box<dyn Iterator<Item = Vec<u8>>> {
        Box::new(vec![self.0.clone()].into_iter())
    }

    fn get_credential_type(&self) -> String {
        "ByteStreamCredential".to_string()
    }
}

pub struct DirectoryCredential {
    pub dir_path: String,
}

impl Credential for DirectoryCredential {
    fn get_credential(&self) -> Box<dyn Iterator<Item = Vec<u8>>> {
        let dir_path = self.dir_path.clone();
        let entries = match fs::read_dir(&dir_path) {
            Ok(entries) => entries.collect::<Vec<_>>(),
            Err(_) => vec![],
        };

        Box::new(entries.into_iter().filter_map(move |entry| {
            if let Ok(entry) = entry {
                if entry.path().is_file() {
                    let file_path = entry.path();
                    if let Ok(mut file) = File::open(&file_path) {
                        let mut buffer = Vec::new();
                        if file.read_to_end(&mut buffer).is_ok() {
                            return Some(buffer);
                        }
                    }
                }
            }
            None
        }))
    }

    fn get_credential_type(&self) -> String {
        "DirectoryCredential".to_string()
    }
}
