use std::env::var;
use std::fs::copy;
use std::path::PathBuf;
use std::process::Command;

const QEMU_REPO: &str = "https://github.com/qemu/qemu.git";

fn main() {
    // Check that we have git and exodus
    let qemu_targets: Vec<&str> = vec!["x86_64"];
    let out_dir = PathBuf::from(var("OUT_DIR").unwrap().as_str());
    let cannonball_sourcedir = PathBuf::from(var("CARGO_MANIFEST_DIR").unwrap().as_str());
    let cannonball_toplevel = cannonball_sourcedir.parent().unwrap();

    Command::new("git")
        .arg("clone")
        .arg(QEMU_REPO)
        .arg(out_dir.join("qemu"))
        .output()
        .expect("Failed to clone qemu");

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
        .arg(patches_path.as_os_str())
        .current_dir(out_dir.join("qemu"))
        .output()
        .expect("Failed to patch qemu");

    // assert!(
    //     patch_status.status.success(),
    //     "Failed to patch qemu: stdout: {} / stderr: {}",
    //     String::from_utf8_lossy(&patch_status.stdout),
    //     String::from_utf8_lossy(&patch_status.stderr)
    // );

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

    // Build jitter_always library
    // Command::new("cargo")
    //     .arg("build")
    //     .arg("--release")
    //     .current_dir(jitter_always_sourcedir.clone())
    //     .output()
    //     .expect("Failed to build jitter_always");

    // let jitter_always_build_dir = cannonball_toplevel.join("target").join("release");

    // assert!(
    //     jitter_always_build_dir.join("libjitter_always.so").is_file(),
    //     "Failed to build jitter_always"
    // );

    // copy(
    //     jitter_always_build_dir.join("libjitter_always.so"),
    //     cannonball_sourcedir.join("jitter_always").join("libjitter_always.so"),
    // )
    // .expect(
    //     format!(
    //         "Failed to copy jitter_always library to {}",
    //         cannonball_sourcedir.to_string_lossy()
    //     )
    //     .as_str(),
    // );
}
