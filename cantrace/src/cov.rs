use serde_derive::{Deserialize, Serialize};
use std::clone::Clone;
use std::collections::HashMap;
use std::fmt::Debug;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Branch {
    addr: u64,
    offset: u64,
    instr: String,
    bytes: Vec<u8>,
    next: u64,
    next_taken: u64,
    target: u64,
    target_taken: u64,
}

impl Branch {
    pub fn new(
        addr: u64,
        offset: u64,
        instr: String,
        bytes: Vec<u8>,
        next: u64,
        next_taken: u64,
        target: u64,
        target_taken: u64,
    ) -> Self {
        Self {
            addr,
            offset,
            instr,
            bytes,
            next,
            next_taken,
            target,
            target_taken,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Coverage {
    pub branches: Vec<Branch>,
}

impl Coverage {
    pub fn new() -> Self {
        Self {
            branches: Vec::new(),
        }
    }

    pub fn from(cov_list: Vec<Coverage>) -> Self {
        let mut branches = HashMap::new();
        for cov in cov_list {
            for branch in cov.branches {
                let entry = branches.entry(branch.addr).or_insert(branch.clone());
                entry.next_taken += branch.next_taken;
                entry.target_taken += branch.target_taken;
            }
        }
        Self {
            branches: branches.values().into_iter().cloned().collect(),
        }
    }
}
