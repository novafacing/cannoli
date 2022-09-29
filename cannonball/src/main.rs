use clap::Parser;

use std::path::PathBuf;

use cannonball::trace;

#[derive(Parser, Debug)]
struct Args {
    /// Input seed file or directory of input seed files
    #[clap(short, long, required = false)]
    input: Option<PathBuf>,
    /// Number of threads to use for cannoli (defaults to 4)
    #[clap(short, long, required = false)]
    threads: Option<usize>,
    /// LD_LIBRARY_PATH for QEMU
    #[clap(short, long, required = false)]
    ld_library_path: Option<PathBuf>,
    /// Target program to run
    #[clap()]
    prog: PathBuf,
    /// Args to pass to the target program
    #[clap(num_args = 1.., last = true)]
    args: Vec<String>,
}

fn main() {
    let args = Args::parse();
    trace(
        args.prog,
        args.input,
        args.ld_library_path,
        args.threads,
        args.args,
    );
}
