use clap::Parser;

use std::path::PathBuf;

use cannonball::trace;

#[derive(Parser, Debug)]
struct Args {
    /// Target program to run
    #[clap()]
    prog: PathBuf,
    /// Jitter path
    #[clap(short, long)]
    jitter: PathBuf,
    /// QEMU binary
    #[clap(short, long)]
    qemu: PathBuf,
    /// Input seed file or directory of input seed files
    #[clap(short, long)]
    input: Option<PathBuf>,
    /// Number of threads to use for cannoli (defaults to 4)
    #[clap(short, long, required = false)]
    threads: Option<usize>,
    /// LD_LIBRARY_PATH for QEMU
    #[clap(short, long, required = false)]
    ld_library_path: Option<PathBuf>,
    /// Args to pass to the target program
    #[clap(multiple_values = true, last = true)]
    args: Vec<String>,
}

fn main() {
    let args = Args::parse();
    trace(
        args.prog,
        args.qemu,
        args.jitter,
        args.input,
        args.ld_library_path,
        args.threads,
        args.args,
    );
}
