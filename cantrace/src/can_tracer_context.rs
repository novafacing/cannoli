use std::collections::HashMap;
use std::env::var;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use yaxpeax_x86::long_mode::InstDecoder;

use crate::cov::CodeLocation;
use crate::maps::MemoryMap;
use std::os::unix::net::UnixStream;

pub struct CanTracerContext {
    pub stream: Arc<Mutex<UnixStream>>,
    pub decoder: Arc<InstDecoder>,
    pub branches: Arc<Mutex<HashMap<u64, (CodeLocation, u64, u64)>>>,
    pub branch_targets: Arc<Mutex<Option<(u64, u64)>>>,
    pub last_cf: Arc<Mutex<Option<CodeLocation>>>,
    pub last_ret: Arc<Mutex<Option<CodeLocation>>>,
    pub causes: Arc<Mutex<HashMap<u64, CodeLocation>>>,
    pub returns: Arc<Mutex<HashMap<u64, CodeLocation>>>,
    pub cov: Arc<Mutex<HashMap<u64, u64>>>,
    pub ipath: PathBuf,
    pub fpath: PathBuf,
    pub bin: Vec<u8>,
    pub is_pie: bool,
    pub base: u64,
    pub max_addr: u64,
    pub text_base: u64,
    pub load_base: u64,
    pub stop_loc: u64,
    pub maps: Vec<MemoryMap>,
}

impl CanTracerContext {
    pub fn new(
        ipath: PathBuf,
        fpath: PathBuf,
        _bin: &[u8],
        is_pie: bool,
        base: u64,
        max_addr: u64,
        text_base: u64,
        load_base: u64,
        stop_loc: u64,
        maps: Vec<MemoryMap>,
    ) -> Self {
        let bin = _bin.clone();
        Self {
            stream: Arc::new(Mutex::new(
                UnixStream::connect(PathBuf::from(var("CANTRACE_USOCK").unwrap()).as_path())
                    .unwrap(),
            )),
            decoder: Arc::new(InstDecoder::default()),
            branches: Arc::new(Mutex::new(HashMap::new())),
            branch_targets: Arc::new(Mutex::new(None)),
            last_cf: Arc::new(Mutex::new(None)),
            last_ret: Arc::new(Mutex::new(None)),
            causes: Arc::new(Mutex::new(HashMap::new())),
            returns: Arc::new(Mutex::new(HashMap::new())),
            cov: Arc::new(Mutex::new(HashMap::new())),
            ipath: ipath.clone(),
            fpath: fpath.clone(),
            bin: bin.to_vec(),
            is_pie,
            base,
            max_addr,
            text_base,
            load_base,
            stop_loc,
            maps,
        }
    }

    pub fn translate(&self, addr: u64) -> Option<u64> {
        if addr >= self.base && addr < self.max_addr {
            if self.is_pie {
                return Some(addr - self.base);
            } else {
                return Some(addr - self.base);
            }
        }
        // println!("translate: 0x{:x}", addr);
        None
    }
}
