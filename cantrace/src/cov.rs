use serde_derive::{Deserialize, Serialize};
use std::clone::Clone;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::fmt::Debug;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CodeLocation {
    pub addr: u64,
    pub offset: u64,
    pub instr: String,
    pub bytes: Vec<u8>,
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
    pub cause: Option<CodeLocation>,
    pub return_location: Option<CodeLocation>,
    pub location: CodeLocation,
    pub next: u64,
    pub next_taken: u64,
    pub target: u64,
    pub target_taken: u64,
    pub triggered_on: Vec<String>,
}

impl Branch {
    pub fn new(
        cause: Option<CodeLocation>,
        return_location: Option<CodeLocation>,
        location: CodeLocation,
        next: u64,
        next_taken: u64,
        target: u64,
        target_taken: u64,
        triggered_on: Vec<String>,
    ) -> Self {
        Self {
            cause,
            return_location,
            location,
            next,
            next_taken,
            target,
            target_taken,
            triggered_on,
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
                match branches.entry(branch.location.addr) {
                    Occupied(entry) => {
                        let mut e: &mut Branch = entry.into_mut();
                        e.next_taken += branch.next_taken;
                        e.target_taken += branch.target_taken;
                        e.triggered_on.extend(branch.triggered_on)
                    }
                    Vacant(entry) => {
                        entry.insert(branch.clone());
                    }
                }
            }
        }
        Self {
            branch_count: branches.len(),
            branches: branches.values().into_iter().cloned().collect(),
        }
    }
}
