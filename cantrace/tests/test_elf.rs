use std::fs::read;
use std::path::PathBuf;

use cantrace::elf::{get_load_base, get_start_exit};

#[test]
fn test_load_base_pie() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bin = &read(manifest_dir.clone().join("tests/bins/AIS-Lite-pie")).unwrap()[..];
    let load_base = get_load_base(bin);
    assert_eq!(load_base, 0x0);
}

#[test]
fn test_load_base_nopie() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bin = &read(manifest_dir.clone().join("tests/bins/AIS-Lite-nopie")).unwrap()[..];
    let load_base = get_load_base(bin);
    assert_eq!(load_base, 0x400000);
}

#[test]
fn test_start_exit_pie() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bin = &read(manifest_dir.clone().join("tests/bins/AIS-Lite-pie")).unwrap()[..];
    let load_base = get_load_base(bin);
    let start_exit = get_start_exit(bin, load_base);
    println!("{:x}", start_exit);
}

#[test]
fn test_start_exit_nopie() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bin = &read(manifest_dir.clone().join("tests/bins/AIS-Lite-nopie")).unwrap()[..];
    let load_base = get_load_base(bin);
    let start_exit = get_start_exit(bin, load_base);
    println!("{:x}", start_exit);
}
