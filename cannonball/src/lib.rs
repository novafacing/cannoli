#![feature(let_chains)]
#![feature(read_buf)]

pub mod cannonball_tracer;
pub mod cannonball_tracer_context;
pub mod cov;
pub mod elf;
pub mod maps;
pub mod qemu_exec;
pub mod trace_entry;

use std::env::set_var;
use std::fs::read;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread::spawn;

use cannonball_tracer::CannonballTracer;

use cannoli::create_cannoli;
use cov::Coverage;
use indicatif::ProgressBar;
use serde_json::to_string_pretty;
use uuid::Uuid;

use crate::qemu_exec::{exec_qemu, QemuArch};

pub fn trace(
    prog_path: PathBuf,
    jitter_path: PathBuf,
    input_path: Option<PathBuf>,
    ld_library_path: Option<PathBuf>,
    cannoli_threads: Option<usize>,
    args: Vec<String>,
) {
    let prog_path = prog_path.canonicalize().unwrap();
    let prog_path_str = prog_path.to_str().unwrap();

    if !prog_path.exists() {
        panic!("{:?} does not exist", prog_path.display());
    }

    if let Some(input) = &input_path {
        if !input.exists() {
            panic!("Input {:?} does not exist", input);
        }
    }

    let libjitter_always_path_str = jitter_path.to_str().unwrap();

    let sid = Uuid::new_v4().to_string();
    let tmppath = std::env::temp_dir().join(sid + ".sock");
    let stream = UnixListener::bind(tmppath.as_path()).unwrap();

    set_var("CANTRACE_PROG", prog_path.clone());
    set_var("CANTRACE_ARGS", args.join(" "));
    set_var("CANTRACE_USOCK", tmppath);

    let _handle = spawn(move || {
        if let Some(threads) = cannoli_threads {
            create_cannoli::<CannonballTracer>(threads).unwrap();
        } else {
            create_cannoli::<CannonballTracer>(4).unwrap();
        }
    });

    let mut qemu_args: Vec<String> = Vec::new();
    qemu_args.push("qemu-x86_64".to_string());

    if let Some(ref path) = ld_library_path {
        qemu_args.push("-E".to_string());
        qemu_args.push(format!(
            "LD_LIBRARY_PATH={}",
            path.canonicalize().unwrap().to_str().unwrap().to_string()
        ));
    }

    let mut inputs = Vec::new();

    if let Some(path) = input_path {
        if path.is_file() {
            inputs.push(Some(path));
        } else if path.is_dir() {
            for entry in std::fs::read_dir(path.clone()).unwrap() {
                let entry = entry.unwrap();
                let ipath = entry.path();

                if ipath.is_file() {
                    inputs.push(Some(ipath));
                }
            }
        }
    } else {
        inputs.push(None);
    }

    let bar = ProgressBar::new(u64::try_from(inputs.len()).ok().unwrap());

    qemu_args.push("-cannoli".to_string());
    qemu_args.push(libjitter_always_path_str.to_string());
    qemu_args.push(prog_path_str.to_string());
    qemu_args.extend(args.clone());

    for input in inputs {
        let mut input_bytes = Vec::new();

        if let Some(input) = input {
            input_bytes = read(input).unwrap();
        }

        println!("Running: {:?}", qemu_args);

        if let Some((_stdout, _stderr)) =
            exec_qemu(QemuArch::X86_64, qemu_args.clone(), Some(input_bytes), None)
        {}

        println!("Done");

        bar.inc(1);
    }
    bar.finish();

    /* read everything from stream */
    let mut buf = [0; 4096];
    let mut output = Vec::new();
    output.push(b'[');
    let (mut stream, _) = stream.accept().unwrap();
    loop {
        let n = stream.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        output.extend(&buf[..n]);
    }
    output.pop(); // Remove last comma
    output.push(b']');
    let covs: Vec<Coverage> = serde_json::from_slice(&output).unwrap();
    let full_cov = Coverage::from(covs);
    print!("{}", to_string_pretty(&full_cov).unwrap());
}
