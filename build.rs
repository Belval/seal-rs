// build.rs

extern crate cc;
extern crate git2;

use std::env;
use std::path::Path;
use std::fs;
use std::process::Command;

use git2::Repository;

fn main() {
    // Cloning the repo
    let url = "https://github.com/Microsoft/SEAL.git";
    
    let _repo = match Repository::clone(url, "./seal") {
        Ok(repo) => repo,
        Err(e) => panic!("Failed to clone SEAL: {}", e),
    };
    
    // Configuring before building
    env::set_current_dir(Path::new("./seal"));
    Command::new("cmake")
            .arg("./src/")
            .output()
            .expect("failed to execute process");
    env::set_current_dir(Path::new(".."));

    // Build SEAL
    let mut build = cc::Build::new();
    build.cpp(true);
    build.flag_if_supported("-std=c++17");
    build.flag_if_supported("-march=native");
    build.flag_if_supported("-msse4.1");
    let base_path = Path::new("./seal/src/seal/");
    let util_base_path = Path::new("./seal/src/seal/util/");
    add_cpp_files(&mut build, base_path);
    add_cpp_files(&mut build, util_base_path);
    build.include("./seal/src");
    build.compile("seal");

    // Cleanup
    fs::remove_dir_all("./seal");
}

fn add_cpp_files(build: &mut cc::Build, path: &Path) {
    for e in path.read_dir().unwrap() {
        let e = e.unwrap();
        let path = e.path();
        if e.file_type().unwrap().is_dir() {
        } else if path.extension().and_then(|s| s.to_str()) == Some("cpp") {
            build.file(&path);
        }
    }
}
