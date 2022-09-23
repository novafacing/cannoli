#![feature(let_chains)]

pub mod can_tracer;
pub mod can_tracer_context;
pub mod cov;
pub mod elf;
pub mod maps;
pub mod trace_entry;

use std::env::set_var;
use std::fs::read;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread::spawn;

use can_tracer::CanTracer;

use cannoli::create_cannoli;
use cov::Coverage;
use indicatif::ProgressBar;
use serde_json::to_string_pretty;
use uuid::Uuid;

pub fn trace(
    prog_path: PathBuf,
    qemu_path: PathBuf,
    jitter_path: PathBuf,
    input_path: Option<PathBuf>,
    ld_library_path: Option<PathBuf>,
    cannoli_threads: Option<usize>,
    args: Vec<String>,
) {
    let prog_path = prog_path.canonicalize().unwrap();
    let prog_path_str = prog_path.to_str().unwrap();
    let qemu_path = qemu_path.canonicalize().unwrap();
    let qemu_path_str = qemu_path.to_str().unwrap();
    let jitter_path = jitter_path.canonicalize().unwrap();
    let jitter_path_str = jitter_path.to_str().unwrap();

    if !prog_path.exists() {
        panic!("{:?} does not exist", prog_path.display());
    }

    if !jitter_path.exists() {
        panic!("Jitter path {:?} does not exist", jitter_path);
    }

    if !qemu_path.exists() {
        panic!("QEMU binary {:?} does not exist", qemu_path);
    }

    if let Some(input) = &input_path {
        if !input.exists() {
            panic!("Input {:?} does not exist", input);
        }
    }

    let sid = Uuid::new_v4().to_string();
    let tmppath = std::env::temp_dir().join(sid + ".sock");
    let stream = UnixListener::bind(tmppath.as_path()).unwrap();

    set_var("CANTRACE_PROG", prog_path.clone());
    set_var("CANTRACE_ARGS", args.join(" "));
    set_var("CANTRACE_USOCK", tmppath);

    let _handle = spawn(move || {
        if let Some(threads) = cannoli_threads {
            create_cannoli::<CanTracer>(threads).unwrap();
        } else {
            create_cannoli::<CanTracer>(4).unwrap();
        }
    });

    let mut qemu_args: Vec<String> = Vec::new();

    if let Some(ref path) = ld_library_path {
        qemu_args.push("-E".to_string());
        let ld_lib_path = path.to_str().unwrap();
        let ld_library_path = format!("LD_LIBRARY_PATH={}", ld_lib_path);
        qemu_args.push(ld_library_path);
    }

    let mut inputs = Vec::new();

    if let Some(path) = input_path {
        if path.is_file() {
            inputs.push((Some(path), Stdio::piped()));
        } else if path.is_dir() {
            for entry in std::fs::read_dir(path.clone()).unwrap() {
                let entry = entry.unwrap();
                let ipath = entry.path();
                if ipath.is_file() {
                    inputs.push((Some(ipath), Stdio::piped()));
                }
            }
        }
    } else {
        inputs.push((None, Stdio::null()));
    }

    let bar = ProgressBar::new(u64::try_from(inputs.len()).ok().unwrap());

    for input in inputs {
        let mut qemu = Command::new(qemu_path_str)
            .stdin(input.1)
            .stdout(Stdio::null())
            .args(qemu_args.clone())
            .arg("-cannoli")
            .arg(jitter_path_str)
            .arg(prog_path_str)
            .args(args.clone())
            .spawn()
            .expect("Failed to spawn qemu");

        if let Some(infile) = input.0 {
            let mut qemu_stdin = qemu.stdin.take().expect("Failed to open qemu stdin");
            spawn(move || {
                qemu_stdin
                    .write_all(&read(infile).unwrap())
                    .expect("Failed to write qemu stdin");
            });
        }

        qemu.wait().expect("Failed to wait for qemu");
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
