#![feature(let_chains)]

use cannoli::{Cannoli, ClientInfo};
use object::elf::{
    FileHeader64, DF_1_CONFALT, DF_1_DIRECT, DF_1_DISPRELDNE, DF_1_DISPRELPND, DF_1_EDITED,
    DF_1_ENDFILTEE, DF_1_GLOBAL, DF_1_GLOBAUDIT, DF_1_GROUP, DF_1_IGNMULDEF, DF_1_INITFIRST,
    DF_1_INTERPOSE, DF_1_LOADFLTR, DF_1_NODEFLIB, DF_1_NODELETE, DF_1_NODIRECT, DF_1_NODUMP,
    DF_1_NOHDR, DF_1_NOKSYMS, DF_1_NOOPEN, DF_1_NORELOC, DF_1_NOW, DF_1_ORIGIN, DF_1_PIE,
    DF_1_SINGLETON, DF_1_STUB, DF_1_SYMINTPOSE, DF_1_TRANS, DT_FLAGS, DT_FLAGS_1, DT_STRSZ,
    DT_STRTAB, PT_DYNAMIC,
};
use object::read::elf::{Dyn, FileHeader, ProgramHeader};
use object::{
    Endianness, File, FileKind, Object, ObjectKind, ObjectSection, ObjectSegment, StringTable,
};
use std::any::Any;
use std::collections::HashMap;
use std::ffi::CStr;
use std::fmt::{Display, Formatter, Result as DisplayResult};
use std::fs::{read, read_link, write};
use std::io::Read;
use std::mem::{size_of, MaybeUninit};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::str::from_utf8;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use yaxpeax_arch::Decoder;
use yaxpeax_x86::amd64::Instruction;
use yaxpeax_x86::long_mode::InstDecoder;

struct Flag<T> {
    value: T,
    name: &'static str,
}

macro_rules! flags {
    ($($name:ident),+ $(,)?) => ( [ $(Flag { value: $name, name: stringify!($name), }),+ ] )
}

static FLAGS_DF_1: &[Flag<u32>] = &flags!(
    DF_1_NOW,
    DF_1_GLOBAL,
    DF_1_GROUP,
    DF_1_NODELETE,
    DF_1_LOADFLTR,
    DF_1_INITFIRST,
    DF_1_NOOPEN,
    DF_1_ORIGIN,
    DF_1_DIRECT,
    DF_1_TRANS,
    DF_1_INTERPOSE,
    DF_1_NODEFLIB,
    DF_1_NODUMP,
    DF_1_CONFALT,
    DF_1_ENDFILTEE,
    DF_1_DISPRELDNE,
    DF_1_DISPRELPND,
    DF_1_NODIRECT,
    DF_1_IGNMULDEF,
    DF_1_NOKSYMS,
    DF_1_NOHDR,
    DF_1_EDITED,
    DF_1_NORELOC,
    DF_1_SYMINTPOSE,
    DF_1_GLOBAUDIT,
    DF_1_SINGLETON,
    DF_1_STUB,
    DF_1_PIE,
);

pub struct MemoryMap {
    start: u64,
    end: u64,
    read: bool,
    write: bool,
    execute: bool,
    private: bool,
    offset: u64,
    device: String,
    inode: u64,
    pathname: String,
}

impl Display for MemoryMap {
    fn fmt(&self, f: &mut Formatter) -> DisplayResult {
        write!(
            f,
            "{:016x}-{:016x} {}{}{} {}",
            self.start,
            self.end,
            if self.read { "R" } else { "-" },
            if self.write { "W" } else { "-" },
            if self.execute { "X" } else { "-" },
            self.pathname
        )
    }
}

pub fn get_maps(pid: i32, bin: PathBuf) -> Vec<MemoryMap> {
    let map_file = format!("/proc/{}/maps", pid);
    let maps_vec = read(map_file).unwrap();
    let maps: &str = from_utf8(&maps_vec).unwrap();
    /* Parse address maps from lines of the form:
     * 00400000-00452000 r-xp 00000000 08:02 173521      /usr/bin/dbus-daemon
     */
    let mut mappings = Vec::new();

    maps.split(|c| c == '\n').for_each(|line| {
        if line.len() > 6 {
            let mut parts = line.split_whitespace();
            let addr = parts.next().unwrap();
            let perms = parts.next().unwrap();
            let offset = parts.next().unwrap();
            let dev = parts.next().unwrap();
            let inode = parts.next().unwrap();
            let path = parts.next().unwrap_or("");
            let mut addr = addr.split("-");
            let start = addr.next().unwrap();
            let end = addr.next().unwrap();
            let start = u64::from_str_radix(start, 16).unwrap();
            let end = u64::from_str_radix(end, 16).unwrap();
            mappings.push(MemoryMap {
                start,
                end,
                read: perms.contains("r"),
                write: perms.contains("w"),
                execute: perms.contains("x"),
                private: perms.contains("p"),
                offset: u64::from_str_radix(offset, 16).unwrap(),
                device: dev.to_string(),
                inode: u64::from_str_radix(inode, 10).unwrap(),
                pathname: path.to_string(),
            });
        }
    });
    mappings
}

pub fn get_base(pid: i32, bin: PathBuf) -> u64 {
    let maps = get_maps(pid, bin.clone());
    let mut base = 0;
    for map in maps {
        if map.pathname == bin.as_os_str().to_string_lossy() {
            base = map.start;
            break;
        }
    }
    base
}

/// Get the address of the first loadable segment in the ELF file.
pub fn get_load_base(data: &[u8]) -> u64 {
    let binfile = File::parse(data).unwrap();
    for segment in binfile.segments() {
        return segment.address();
    }
    0
}

pub fn get_text(data: &[u8]) -> u64 {
    let binfile = File::parse(data).unwrap();
    binfile.section_by_name(".text").unwrap().address()
}

pub fn is_pie(data: &[u8]) -> bool {
    // let pic_bin_file = read(path).expect("failed to read test");
    // let data: &[u8] = &pic_bin_file[..];

    let kind = match FileKind::parse(data) {
        Ok(file) => file,
        Err(err) => {
            assert!(false, "failed to parse file kind: {}", err);
            unreachable!()
        }
    };

    match kind {
        FileKind::Elf64 => {
            if let Ok(elf) = FileHeader64::<Endianness>::parse(data) {
                if let Ok(endian) = elf.endian() {
                    if let Ok(segments) = elf.program_headers(endian, data) {
                        for segment in segments {
                            match segment.p_type(endian) {
                                PT_DYNAMIC => {
                                    if let Ok(Some(dynamic)) = segment.dynamic(endian, data) {
                                        let mut strtab = 0;
                                        let mut strsz = 0;
                                        for d in dynamic {
                                            let tag: u64 = d.d_tag(endian).into();
                                            if tag == DT_STRTAB.into() {
                                                strtab = d.d_val(endian);
                                            } else if tag == DT_STRSZ.into() {
                                                strsz = d.d_val(endian);
                                            }
                                        }
                                        for s in segments {
                                            if let Ok(Some(dynstr_data)) =
                                                s.data_range(endian, data, strtab, strsz)
                                            {
                                                let dynstr = StringTable::new(
                                                    dynstr_data,
                                                    0,
                                                    dynstr_data.len() as u64,
                                                );
                                                for d in dynamic {
                                                    let itag: u64 = d.d_tag(endian).into();
                                                    let val: u64 = d.d_val(endian).into();
                                                    if let Some(tag) = d.tag32(endian) {
                                                        if !d.is_string(endian) {
                                                            if itag == DT_FLAGS.into() {
                                                                // val, 0, flags_df
                                                            } else if itag == DT_FLAGS_1.into() {
                                                                // val, 0, flags_df_1
                                                                for flag in FLAGS_DF_1 {
                                                                    if val
                                                                        & <u32 as Into<u64>>::into(
                                                                            flag.value,
                                                                        )
                                                                        == flag.value.into()
                                                                    {
                                                                        return true;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        _ => {
            assert!(false, "unsupported file kind: {:?}", kind);
        }
    }
    return false;
}

pub struct CanTracer;

pub struct CanTracerContext {
    decoder: Arc<InstDecoder>,
    fpath: PathBuf,
    bin: Vec<u8>,
    is_pie: bool,
    base: u64,
    max_addr: u64,
    text_base: u64,
    load_base: u64,
    maps: Vec<MemoryMap>,
}

impl CanTracerContext {
    fn new(
        fpath: PathBuf,
        _bin: &[u8],
        is_pie: bool,
        base: u64,
        max_addr: u64,
        text_base: u64,
        load_base: u64,
        maps: Vec<MemoryMap>,
    ) -> Self {
        let bin = _bin.clone();
        Self {
            decoder: Arc::new(InstDecoder::default()),
            fpath: fpath.clone(),
            bin: bin.to_vec(),
            is_pie,
            base,
            max_addr,
            text_base,
            load_base,
            maps,
        }
    }

    fn translate(&self, addr: u64) -> Option<u64> {
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

pub struct Instr {
    pc: u64,
    offset: u64,
    instr: Instruction,
    bytes: Vec<u8>,
}

impl Cannoli for CanTracer {
    type Trace = Instr;
    type TidContext = CanTracerContext;
    type PidContext = ();

    fn init_pid(ci: &ClientInfo) -> Arc<Self::PidContext> {
        Arc::new(())
    }

    fn init_tid(_pid: &Self::PidContext, ci: &ClientInfo) -> (Self, Self::TidContext) {
        // println!("init_tid: {:?}", ci.);
        let qemu_realpath = read_link(format!("/proc/{}/exe", ci.pid)).unwrap();
        let cmdline_vec = read(format!("/proc/{}/cmdline", ci.pid)).unwrap();
        let cmdline = from_utf8(&cmdline_vec).unwrap();
        let realpath_name = cmdline.split('\0').collect::<Vec<&str>>();
        println!("realpath: {:?}", realpath_name[realpath_name.len() - 2]);
        let realpath = PathBuf::from(realpath_name[realpath_name.len() - 2]);
        let bin = &read(realpath.clone()).unwrap()[..];
        let is_pie = is_pie(bin.clone());
        let qemu_base = get_base(ci.pid, qemu_realpath.clone());
        let maps = get_maps(ci.pid, qemu_realpath.clone());

        for map in &maps {
            println!("map: {}", map);
        }

        let qemu_max_addr = maps
            .iter()
            .filter(|m| m.pathname == qemu_realpath.to_string_lossy())
            .map(|m| m.end)
            .max()
            .unwrap();

        let base = maps
            .iter()
            .filter(|m| m.pathname == "" && m.end < qemu_base)
            .next()
            .unwrap();

        let mut text_base = get_text(bin);
        let mut load_base = get_load_base(bin);

        if !is_pie {
            text_base -= base.start;
        }

        println!("cmdline: {:?}", cmdline);
        println!("realpath: {}", realpath.to_string_lossy());
        println!("is_pie: {}", is_pie);
        println!("base: {}", base);
        println!("text base: 0x{:x}", text_base);
        println!("load base: 0x{:x}", load_base);

        (
            Self,
            CanTracerContext::new(
                realpath.clone(),
                bin,
                is_pie,
                base.start,
                base.end,
                text_base,
                load_base,
                maps,
            ),
        )
    }

    fn exec(
        _pid: &Self::PidContext,
        tid: &Self::TidContext,
        pc: u64,
        trace: &mut Vec<Self::Trace>,
    ) {
        if let Some(offset) = tid.translate(pc) && let Ok(instr) = tid.decoder.decode_slice(&tid.bin[offset as usize..(offset as usize) + 16]) {
            trace.push(Instr { pc, offset, instr, bytes: tid.bin[offset as usize..(offset as usize) + 16].to_vec() });
        }
    }

    fn regs(
        _pid: &Self::PidContext,
        _tid: &Self::TidContext,
        _pc: u64,
        _regs: &[u8],
        _trace: &mut Vec<Self::Trace>,
    ) {
    }

    fn write(
        _pid: &Self::PidContext,
        _tid: &Self::TidContext,
        _pc: u64,
        _addr: u64,
        _val: u64,
        _sz: u8,
        _trace: &mut Vec<Self::Trace>,
    ) {
    }

    fn trace(&mut self, _pid: &Self::PidContext, _tid: &Self::TidContext, trace: &[Self::Trace]) {
        for instr_info in trace {
            println!(
                "{:x} {:x} {:?} {:?}",
                instr_info.pc,
                instr_info.offset,
                instr_info.instr.to_string(),
                instr_info.bytes
            );
        }
    }

    fn mmap(
        _pid: &Self::PidContext,
        _tid: &Self::TidContext,
        _base: u64,
        _len: u64,
        _anon: bool,
        _read: bool,
        _write: bool,
        _exec: bool,
        _path: &str,
        _offset: u64,
        _trace: &mut Vec<Self::Trace>,
    ) {
    }

    fn munmap(
        _pid: &Self::PidContext,
        _tid: &Self::TidContext,
        _base: u64,
        _len: u64,
        _trace: &mut Vec<Self::Trace>,
    ) {
    }
}
