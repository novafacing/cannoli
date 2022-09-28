use yaxpeax_x86::amd64::Instruction;

pub enum TraceEntry {
    Instr {
        pc: u64,
        offset: u64,
        instr: Instruction,
        bytes: Vec<u8>,
    },
    CFSet {
        pc: u64,
        offset: u64,
        instr: Instruction,
        bytes: Vec<u8>,
    },
    Branch {
        pc: u64,
        offset: u64,
        instr: Instruction,
        bytes: Vec<u8>,
        next: u64,
        target: u64,
    },
    Done {},
}
