use std::fs;

pub fn export_file(file_path: &str, content: String) -> Result<(), String> {
    fs::write(file_path, content).map_err(|e| e.to_string())
}
pub fn import_from_file(file_path: &str) -> Result<String, String> {
    fs::read_to_string(file_path).map_err(|e| e.to_string())
}
