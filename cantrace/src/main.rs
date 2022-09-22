use cannoli::create_cannoli;
use cantracer::CanTracer;
use clap::Parser;
use object::File;
use object::{Object, ObjectSection};
use std::env::set_var;
use std::fs::read;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::str::from_utf8;
use std::sync::Arc;
use std::thread::spawn;
use yaxpeax_arch::Decoder;
use yaxpeax_x86::long_mode::InstDecoder;

#[derive(Parser, Debug)]
struct Args {
    /// Target program to run
    #[clap()]
    prog: String,
    /// Jitter path
    #[clap(short, long)]
    jitter: PathBuf,
    /// QEMU binary
    #[clap(short, long)]
    qemu: PathBuf,
    /// Input file
    #[clap(short, long)]
    in_file: Option<PathBuf>,
    /// LD_LIBRARY_PATH for QEMU
    #[clap(short, long, required = false)]
    ld_library_path: Option<PathBuf>,
    /// Args to pass to the target program
    #[clap(multiple_values = true, last = true)]
    args: Vec<String>,
}

fn main() {
    let args = Args::parse();

    let prog_path = PathBuf::from(args.prog).canonicalize().unwrap();
    let prog_path_str = prog_path.to_str().unwrap();
    let qemu_path = args.qemu.canonicalize().unwrap();
    let qemu_path_str = qemu_path.to_str().unwrap();
    let jitter_path = args.jitter.canonicalize().unwrap();
    let jitter_path_str = jitter_path.to_str().unwrap();

    if !prog_path.exists() {
        panic!("{:?} does not exist", prog_path.display());
    }

    if !jitter_path.exists() {
        panic!("Jitter path {:?} does not exist", args.jitter);
    }

    if !qemu_path.exists() {
        panic!("QEMU binary {:?} does not exist", args.qemu);
    }

    if let Some(in_file) = &args.in_file {
        if !in_file.exists() {
            panic!("Input {:?} does not exist", in_file);
        }
    }

    set_var("CANTRACE_PROG", prog_path.clone());
    set_var("CANTRACE_ARGS", args.args.join(" "));

    let handle = spawn(|| {
        create_cannoli::<CanTracer>(2).unwrap();
    });

    let mut qemu_args: Vec<String> = Vec::new();

    if let Some(ref path) = args.ld_library_path {
        qemu_args.push("-E".to_string());
        let ld_lib_path = path.to_str().unwrap();
        let ld_library_path = format!("LD_LIBRARY_PATH={}", ld_lib_path);
        qemu_args.push(ld_library_path);
    }

    let mut inputs = Vec::new();

    if let Some(path) = args.in_file {
        if path.is_file() {
            println!("Got input: {:?}", path.clone());
            inputs.push((Some(path), Stdio::piped()));
        } else if path.is_dir() {
            for entry in std::fs::read_dir(path.clone()).unwrap() {
                let entry = entry.unwrap();
                let ipath = entry.path();
                println!("Got input: {:?}", ipath);
                if ipath.is_file() {
                    inputs.push((Some(ipath), Stdio::piped()));
                }
            }
        }
    } else {
        inputs.push((None, Stdio::null()));
    }

    for input in inputs {
        let mut qemu = Command::new(qemu_path_str)
            .stdin(input.1)
            .args(qemu_args.clone())
            .arg("-cannoli")
            .arg(jitter_path_str)
            .arg(prog_path_str)
            .args(args.args.clone())
            .spawn()
            .expect("Failed to spawn qemu");

        if let Some(infile) = input.0 {
            println!("Writing input to stdin");
            let mut qemu_stdin = qemu.stdin.take().expect("Failed to open qemu stdin");
            spawn(move || {
                qemu_stdin
                    .write_all(&read(infile).unwrap())
                    .expect("Failed to write qemu stdin");
            });

            let output = qemu.wait_with_output().expect("Failed to read qemu stdout");
            println!("{}", from_utf8(&output.stdout).unwrap());
        } else {
            qemu.wait().expect("Failed to wait for qemu");
        }
    }
}
