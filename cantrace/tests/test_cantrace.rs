use serial_test::serial;
use std::env::var;
use std::path::PathBuf;

use cantrace::trace;

#[test]
#[serial]
fn test_trace_pie() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    trace(
        PathBuf::from(manifest_dir.clone()).join("tests/bins/AIS-Lite-pie"),
        PathBuf::from(manifest_dir.clone()).join("tests/bundles/qemu/exodus/bin/qemu-x86_64"),
        PathBuf::from(manifest_dir.clone()).join("../target/release/libjitter_always.so"),
        Some(PathBuf::from(manifest_dir.clone()).join("tests/inputs/poll_AIS-Lite_0.poll")),
        Some(PathBuf::from(manifest_dir.clone()).join("tests/libs/")),
        Some(4),
        vec![],
    );
}

#[test]
#[serial]
fn test_trace_nopie() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    trace(
        PathBuf::from(manifest_dir.clone()).join("tests/bins/AIS-Lite-nopie"),
        PathBuf::from(manifest_dir.clone()).join("tests/bundles/qemu/exodus/bin/qemu-x86_64"),
        PathBuf::from(manifest_dir.clone()).join("../target/release/libjitter_always.so"),
        Some(PathBuf::from(manifest_dir.clone()).join("tests/inputs/poll_AIS-Lite_0.poll")),
        Some(PathBuf::from(manifest_dir.clone()).join("tests/libs/")),
        Some(4),
        vec![],
    );
}
