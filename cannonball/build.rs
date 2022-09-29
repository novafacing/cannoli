use std::env::var;
use std::fs::{copy, create_dir};
use std::io::Cursor;
use std::path::PathBuf;
use std::process::Command;

use curl::easy::Easy;
use tar::Archive;
use xz::read::XzDecoder;

const QEMU_REPO: &str = "https://github.com/qemu/qemu.git";

fn main() {
    // Check that we have git and exodus
    let qemu_targets: Vec<&str> = vec!["x86_64"];
    let out_dir = PathBuf::from(var("OUT_DIR").unwrap().as_str());
    let cannonball_sourcedir = PathBuf::from(var("CARGO_MANIFEST_DIR").unwrap().as_str());
    let cannonball_toplevel = cannonball_sourcedir.parent().unwrap();
    let jithook_sourcedir = cannonball_toplevel.join("jithook");
    let mut qemu_zip_content = Vec::new();
    let mut easy = Easy::new();
    easy.follow_location(true).unwrap();

    easy.url(QEMU_REPO).unwrap();
    {
        let mut transfer = easy.transfer();
        transfer
            .write_function(|data| {
                qemu_zip_content.extend_from_slice(data);
                Ok(data.len())
            })
            .unwrap();
        transfer.perform().unwrap();
    }

    let response_code = easy.response_code().unwrap();
    assert!(
        response_code == 200,
        "Failed to download qemu source: reponse code {}",
        response_code
    );

    let decoder = XzDecoder::new(Cursor::new(qemu_zip_content));
    let mut archive = Archive::new(decoder);

    create_dir(&out_dir.join("qemu")).unwrap_or_default();

    // archive.unpack(out_dir.as_path()).unwrap();
    for mut entry in archive.entries().unwrap().filter_map(|e| e.ok()) {
        let path = entry
            .path()
            .unwrap()
            .strip_prefix("qemu-7.1.0")
            .unwrap()
            .to_owned();
        entry.unpack(&out_dir.join("qemu").join(path)).unwrap();
    }

    if !out_dir.join("qemu").join("configure").is_file() {
        panic!(
            "Failed to find qemu configure script in {}",
            out_dir.join("qemu").to_string_lossy()
        );
    }

    let patches_path = cannonball_toplevel.join("qemu_patches.patch");
    let patches_pre_path = cannonball_toplevel.join("qemu_patches_pre_2dc7bf.patch");

    if !patches_path.clone().is_file() || !patches_pre_path.clone().is_file() {
        panic!(
            "Failed to find qemu_patches.patch in {}",
            patches_path.to_string_lossy()
        );
    }

    let mut patch_status = Command::new("patch")
        .arg("-p1")
        .arg("-i")
        .arg(patches_pre_path.as_os_str())
        .current_dir(out_dir.join("qemu"))
        .output()
        .expect("Failed to patch qemu");

    if !patch_status.status.success() {
        patch_status = Command::new("patch")
            .arg("-p1")
            .arg("-i")
            .arg(patches_path.as_os_str())
            .current_dir(out_dir.join("qemu"))
            .output()
            .expect("Failed to patch qemu");

        assert!(
            patch_status.status.success(),
            "Failed to patch qemu: stdout: {} / stderr: {}",
            String::from_utf8_lossy(&patch_status.stdout),
            String::from_utf8_lossy(&patch_status.stderr)
        );
    }

    let configure_status = Command::new("./configure")
        .arg("--extra-ldflags=-ldl")
        .arg(format!(
            "--with-cannoli={}",
            cannonball_toplevel.to_string_lossy()
        ))
        .arg(format!(
            "--target-list={}",
            qemu_targets
                .iter()
                .map(|t| format!("{}-linux-user", t))
                .collect::<Vec<String>>()
                .join(",")
        ))
        .arg("--static")
        .current_dir(out_dir.join("qemu"))
        .output()
        .expect("Failed to configure qemu");

    assert!(
        configure_status.status.success(),
        "Failed to configure qemu: stdout: {} / stderr: {}. Known issues: (big/little failed => you are missing glibc-static [fedora] or libc6-dev [ubuntu])",
        String::from_utf8_lossy(&configure_status.stdout),
        String::from_utf8_lossy(&configure_status.stderr)
    );

    let make_status = Command::new("make")
        .arg(format!("-j{}", num_cpus::get()))
        .current_dir(out_dir.join("qemu"))
        .output()
        .expect("Failed to compile qemu");

    assert!(
        make_status.status.success(),
        "Failed to compile qemu: stdout: {} / stderr: {}",
        String::from_utf8_lossy(&make_status.stdout),
        String::from_utf8_lossy(&make_status.stderr)
    );

    let qemu_build_dir = out_dir.join("qemu").join("build");
    let qemu_out_dir = cannonball_sourcedir.join("qemu");

    for target in qemu_targets {
        let target_exe = qemu_build_dir.join(format!("qemu-{}", target));

        if !target_exe.clone().is_file() {
            panic!(
                "Failed to build qemu in {} for {}",
                target_exe.to_string_lossy(),
                target
            );
        } else {
            println!("cargo:rerun-if-changed=build.rs");
        }

        // otherwise copy it to the source directory
        copy(
            target_exe.clone(),
            qemu_out_dir.join(format!("qemu-{}", target)),
        )
        .expect(
            format!(
                "Failed to copy qemu binary {} -> {}",
                target_exe.to_string_lossy(),
                qemu_out_dir.to_string_lossy()
            )
            .as_str(),
        );
    }

    // Build jithook library
    // Command::new("cargo")
    //     .arg("build")
    //     .arg("--release")
    //     .current_dir(jithook_sourcedir.clone())
    //     .output()
    //     .expect("Failed to build jithook");

    // let jithook_build_dir = cannonball_toplevel.join("target").join("release");

    // assert!(
    //     jithook_build_dir.join("libjithook.so").is_file(),
    //     "Failed to build jithook"
    // );

    // copy(
    //     jithook_build_dir.join("libjithook.so"),
    //     cannonball_sourcedir.join("jithook").join("libjithook.so"),
    // )
    // .expect(
    //     format!(
    //         "Failed to copy jithook library to {}",
    //         cannonball_sourcedir.to_string_lossy()
    //     )
    //     .as_str(),
    // );
}
