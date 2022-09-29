use std::{
    fs::File,
    io::{self, Write},
    path::PathBuf,
};

const LIBJITHOOK: &[u8] = include_bytes!("../../target/release/libjithook.so");

pub fn generate_libjithook() -> PathBuf {
    let mut file = File::create("/tmp/libjithook.so").unwrap();
    file.write_all(LIBJITHOOK).unwrap();
    PathBuf::from("/tmp/libjithook.so")
}
