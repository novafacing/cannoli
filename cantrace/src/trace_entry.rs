use yaxpeax_x86::amd64::Instruction;

pub enum TraceEntry {
    /// Normal instructions are normal, some things are checked but they are not
    /// semantically significant
    Instr {
        pc: u64,
        offset: u64,
        instr: Instruction,
        bytes: Vec<u8>,
    },
    /// Return locations are tracked such that when a CFSet event is encountered we
    /// check to see what function we returned from last to correlate return values
    /// to comparisons
    Return {
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
