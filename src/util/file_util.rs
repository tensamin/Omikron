use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};

use crate::log;
use crate::util::logger::PrintType;

#[allow(dead_code)]
pub fn delete_directory(path: &str) -> bool {
    let dir = Path::new(&get_directory()).join(path);
    delete_dir_recursive(&dir)
}

#[allow(dead_code)]
fn delete_dir_recursive(directory: &Path) -> bool {
    if !directory.exists() {
        return false;
    }
    if let Err(e) = fs::remove_dir_all(directory) {
        log!(
            0,
            PrintType::General,
            "[IMPORTANT] Couldn't delete directory {}: {}",
            directory.display(),
            e,
        );
        return false;
    }
    true
}

#[allow(dead_code)]
pub fn delete_user_directory(user_id: i64) {
    let user_dir = Path::new(&get_directory())
        .join("users")
        .join(user_id.to_string());
    let _ = delete_dir_recursive(&user_dir);
}

pub fn load_file_buf(path: &str, name: &str) -> io::Result<BufReader<File>> {
    let dir = Path::new(&get_directory()).join(path);
    let file_path = dir.join(name);

    // Ensure the directory exists, create if necessary
    if !dir.exists() {
        if let Err(_) = fs::create_dir_all(&dir) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Directory creation failed",
            ));
        }
    }

    // Create the file if it doesn't exist
    if !file_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "File creation failed",
        ));
    }

    // Open the file and return a BufReader for efficient reading
    let file = File::open(&file_path)?;
    Ok(BufReader::new(file))
}
pub fn has_file(path: &str, name: &str) -> bool {
    let dir = Path::new(&get_directory()).join(path);
    let file_path = dir.join(name);

    if !dir.exists() {
        return false;
    }

    if !file_path.exists() {
        return false;
    }

    true
}
pub fn has_dir(path: &str) -> bool {
    let dir = Path::new(&get_directory()).join(path);

    if !dir.exists() {
        return false;
    }

    true
}

pub fn load_file(path: &str, name: &str) -> String {
    let dir = Path::new(&get_directory()).join(path);
    let file_path = dir.join(name);

    if !dir.exists() {
        if let Err(e) = fs::create_dir_all(&dir) {
            log!(
                0,
                PrintType::General,
                "[IMPORTANT] Couldn't create directories: {}",
                e
            );
            return String::new();
        }
        return String::new();
    }

    if !file_path.exists() {
        if let Err(e) = File::create(&file_path) {
            log!(
                0,
                PrintType::General,
                "[IMPORTANT] Couldn't create file: {}",
                e
            );
        }
        return String::new();
    }

    let mut content = String::new();
    if let Ok(mut f) = File::open(&file_path) {
        let _ = f.read_to_string(&mut content);
    }
    content
}

pub fn load_file_vec(path: &str, name: &str) -> Result<Vec<u8>, std::io::Error> {
    let dir = Path::new(&get_directory()).join(path);
    let file_path = dir.join(name);

    std::fs::read(file_path)
}

pub fn save_file(path: &str, name: &str, value: &str) {
    let dir = Path::new(&get_directory()).join(path);
    let file_path = dir.join(name);

    if !dir.exists() {
        if let Err(e) = fs::create_dir_all(&dir) {
            log!(
                0,
                PrintType::General,
                "[IMPORTANT] Couldn't create directories: {}",
                e
            );
            return;
        }
    }

    if let Err(e) = fs::write(&file_path, value) {
        log!(
            0,
            PrintType::General,
            "[IMPORTANT] Couldn't write file {}: {}",
            file_path.display(),
            e
        );
    }
}

pub fn get_children(path: &str) -> Vec<String> {
    let dir = Path::new(&get_directory()).join(path);
    let mut children = Vec::new();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                children.push(entry.file_name().to_string_lossy().to_string());
            }
        }
    }
    children
}

pub fn get_directory() -> String {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    exe.parent()
        .unwrap_or(Path::new("."))
        .to_string_lossy()
        .to_string()
}
