// build.rs

extern crate cc;
extern crate git2;

use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::fs;
use std::io::Write;
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
    // Setting working directory
    let _res = match env::set_current_dir(Path::new("./seal")) {
        Ok(r) => r,
        Err(e) => panic!("SEAL was not properly cloned: {}", e),
    };
    //Cmake
    Command::new("cmake")
            .arg("./src/")
            .output()
            .expect("failed to execute process");
    // Resetting working directory
    let _res = match env::set_current_dir(Path::new("..")) {
        Ok(r) => r,
        Err(e) => panic!("Unable to clean after cmaking the repo: {}", e)
    };

    //// Build SEAL
    let mut build = cc::Build::new();
    build.cpp(true);
    build.flag_if_supported("-std=c++17");
    build.flag_if_supported("-march=native");
    build.flag_if_supported("-fkeep-inline-functions");
    build.flag_if_supported("-fno-inline-functions");
    let base_path = Path::new("./seal/src/seal/");
    let util_base_path = Path::new("./seal/src/seal/util/");
    add_cpp_files(&mut build, base_path);
    add_cpp_files(&mut build, util_base_path);
    build.include("./seal/src");
    build.compile("seal");

    // Generate the bindings
    let bindings = bindgen::Builder::default()
        .generate_inline_functions(true)
        .derive_default(true)
        .header("./seal/src/seal/seal.h")
        .clang_arg("-I./seal/src/")
        .clang_arg("-std=c++17")
        .clang_arg("-x")
        .clang_arg("c++")
        .opaque_type("std::.*")
        .whitelist_type("seal::.*")
        .whitelist_function("seal::.*")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from("./src/");
    let mut bindings_string = bindings
        .to_string()
        // Dirty hack
        .replace("pub data_: seal_util_Pointer<T>", "pub data_: seal_util_Pointer<u64>");

    let mut file = fs::File::create("./src/bindings.rs").unwrap();
    file.write_all(bindings_string.as_bytes());
    file.sync_data();


    // Cleanup
    let _res = match fs::remove_dir_all("./seal") {
        Ok(r) => r,
        Err(e) => panic!("Unable to remove SEAL dir after build: {}", e)
    };
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
