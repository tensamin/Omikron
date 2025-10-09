use std::ffi::OsStr;
use std::fmt::Write as FmtWrite;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::SystemTime;
use sysinfo::System;
use uuid::Uuid;
use walkdir::WalkDir;

pub fn delete_file(path: &str, name: &str) -> bool {
    let dir = Path::new(&get_directory()).join(path);
    let file = dir.join(name);
    if !file.exists() {
        return false;
    }
    fs::remove_file(file).is_ok()
}

pub fn delete_directory(path: &str) -> bool {
    let dir = Path::new(&get_directory()).join(path);
    delete_dir_recursive(&dir)
}

fn delete_dir_recursive(directory: &Path) -> bool {
    if !directory.exists() {
        return false;
    }
    if let Err(e) = fs::remove_dir_all(directory) {
        println!(
            "[IMPORTANT] Couldn't delete directory {}: {}",
            directory.display(),
            e
        );
        return false;
    }
    true
}

pub fn delete_user_directory(user_id: Uuid) {
    let user_dir = Path::new(&get_directory())
        .join("users")
        .join(user_id.to_string());
    let _ = delete_dir_recursive(&user_dir);
}

pub fn load_file(path: &str, name: &str) -> String {
    let dir = Path::new(&get_directory()).join(path);
    let file_path = dir.join(name);

    if !dir.exists() {
        if let Err(e) = fs::create_dir_all(&dir) {
            println!("[IMPORTANT] Couldn't create directories: {}", e);
            return String::new();
        }
        return String::new();
    }

    if !file_path.exists() {
        if let Err(e) = File::create(&file_path) {
            println!("[IMPORTANT] Couldn't create file: {}", e);
        }
        return String::new();
    }

    let mut content = String::new();
    if let Ok(mut f) = File::open(&file_path) {
        let _ = f.read_to_string(&mut content);
    }
    content
}

pub fn save_file(path: &str, name: &str, value: &str) {
    let dir = Path::new(&get_directory()).join(path);
    let file_path = dir.join(name);

    if !dir.exists() {
        if let Err(e) = fs::create_dir_all(&dir) {
            println!("[IMPORTANT] Couldn't create directories: {}", e);
            return;
        }
    }

    if let Err(e) = fs::write(&file_path, value) {
        println!(
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

pub fn used_space() -> u64 {
    get_directory_size(&PathBuf::from(get_directory()))
}

pub fn get_directory_size(directory: &Path) -> u64 {
    let mut size = 0;
    for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            if let Ok(metadata) = path.metadata() {
                size += path.file_name().unwrap_or(OsStr::new("")).len() as u64;
                size += metadata.len();
            }
        }
    }
    size
}

pub fn get_designed_storage(user_id: Uuid) -> String {
    let user_dir = Path::new(&get_directory())
        .join("users")
        .join(user_id.to_string());
    design_byte(get_directory_size(&user_dir))
}

pub fn design_byte(bytes: u64) -> String {
    let mut hr_size = format!("{:.2}B", bytes as f64);
    let k = bytes as f64 / 1024.0;
    let m = k / 1024.0;
    let g = m / 1024.0;
    let t = g / 1024.0;

    if t >= 1.0 {
        hr_size = format!("{:.2}TB", t);
    } else if g >= 1.0 {
        hr_size = format!("{:.2}GB", g);
    } else if m >= 1.0 {
        hr_size = format!("{:.2}MB", m);
    } else if k >= 1.0 {
        hr_size = format!("{:.2}KB", k);
    }
    hr_size
}

pub fn get_used_ram() -> String {
    let mut sys = System::new_all();
    sys.refresh_all();
    let used = sys.used_memory() * 1024; // kB to bytes
    let total = sys.total_memory() * 1024;
    format!("{}/{}", design_byte(used), design_byte(total))
}
