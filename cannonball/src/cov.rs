use serde_derive::{Deserialize, Serialize};
use std::clone::Clone;
use std::collections::HashMap;
use std::fmt::Debug;
use yaxpeax_x86::amd64::Instruction;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CodeLocation {
    addr: u64,
    offset: u64,
    instr: String,
    bytes: Vec<u8>,
}

impl CodeLocation {
    pub fn new(addr: u64, offset: u64, instr: String, bytes: Vec<u8>) -> Self {
        Self {
            addr,
            offset,
            instr,
            bytes,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Branch {
    cause: Option<CodeLocation>,
    location: CodeLocation,
    next: u64,
    next_taken: u64,
    target: u64,
    target_taken: u64,
}

impl Branch {
    pub fn new(
        cause: Option<CodeLocation>,
        location: CodeLocation,
        next: u64,
        next_taken: u64,
        target: u64,
        target_taken: u64,
    ) -> Self {
        Self {
            cause,
            location,
            next,
            next_taken,
            target,
            target_taken,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Coverage {
    pub branch_count: usize,
    pub branches: Vec<Branch>,
}

impl Coverage {
    pub fn new() -> Self {
        Self {
            branch_count: 0,
            branches: Vec::new(),
        }
    }

    pub fn from(cov_list: Vec<Coverage>) -> Self {
        let mut branches = HashMap::new();
        for cov in cov_list {
            for branch in cov.branches {
                let entry = branches
                    .entry(branch.location.addr)
                    .or_insert(branch.clone());
                entry.next_taken += branch.next_taken;
                entry.target_taken += branch.target_taken;
            }
        }
        Self {
            branch_count: branches.len(),
            branches: branches.values().into_iter().cloned().collect(),
        }
    }
}
