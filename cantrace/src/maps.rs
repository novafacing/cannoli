use std::fmt::{Display, Formatter, Result as DisplayResult};
use std::fs::read;
use std::path::PathBuf;
use std::str::from_utf8;

pub struct MemoryMap {
    pub start: u64,
    pub end: u64,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub private: bool,
    pub offset: u64,
    pub device: String,
    pub inode: u64,
    pub pathname: String,
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
