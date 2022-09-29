use nix::libc::{PIPE_BUF, STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO};
use nix::sys::memfd::{self, memfd_create, MemFdCreateFlag};
use nix::unistd::{chdir, close, dup2, fexecve, fork, pipe, read, write};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;

const QEMU_X86_64: &[u8] = include_bytes!("../qemu/qemu-x86_64");

pub enum QemuArch {
    X86_64,
}

/// LOL. LMAO. This rocks so hard
pub fn exec_qemu<T>(
    arch: QemuArch,
    args: Vec<String>,
    stdin: Option<T>,
    workdir: Option<PathBuf>,
) -> Option<(Vec<u8>, Vec<u8>)>
where
    T: Into<Vec<u8>>,
{
    let memfd = memfd_create(
        CStr::from_bytes_with_nul(b"qemu-x86_64\0").unwrap(),
        MemFdCreateFlag::MFD_CLOEXEC,
    )
    .unwrap();

    match arch {
        QemuArch::X86_64 => {
            if write(memfd, QEMU_X86_64).unwrap() != QEMU_X86_64.len() {
                panic!("Failed to write qemu binary to memfd");
            }
        }
    }

    let mut qemu_args = Vec::new();

    let qemu_byteargs = args
        .iter()
        .map(|arg| {
            let mut arg = arg.clone();
            arg.push_str("\0");
            arg
        })
        .collect::<Vec<String>>();

    for barg in qemu_byteargs.iter() {
        qemu_args.push(CStr::from_bytes_with_nul(barg.as_bytes()).unwrap());
    }

    let env = CString::new("").unwrap();

    unsafe {
        let pid = fork().unwrap();

        if pid.is_child() {
            println!("Child process");
            if let Some(workdir) = workdir {
                chdir(&workdir).unwrap();
            }

            println!("fexecve");

            if let Ok(_result) = fexecve(memfd, &qemu_args[..], &[env]) {
                None
            } else {
                println!("fexecve failed");
                None
            }
        } else {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            Some((stdout, stderr))
        }
    }
}
