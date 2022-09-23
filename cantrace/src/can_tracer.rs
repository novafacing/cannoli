use cannoli::{Cannoli, ClientInfo};
use yaxpeax_x86::amd64::{Opcode, Operand, DisplayStyle};
use yaxpeax_arch::LengthedInstruction;
use std::{sync::Arc, fs::{read_link, read}, env::var, path::PathBuf};

use crate::{trace_entry::TraceEntry, can_tracer_context::CanTracerContext, elf::{is_pie, get_text, get_load_base, get_start_exit}, maps::{get_base, get_maps}};

pub struct CanTracer;

impl Cannoli for CanTracer {
    type Trace = TraceEntry;
    type TidContext = CanTracerContext;
    type PidContext = ();

    fn init_pid(_ci: &ClientInfo) -> Arc<Self::PidContext> {
        Arc::new(())
    }

    fn init_tid(_pid: &Self::PidContext, ci: &ClientInfo) -> (Self, Self::TidContext) {
        // println!("init_tid: {:?}", ci.);
        let qemu_realpath = read_link(format!("/proc/{}/exe", ci.pid)).unwrap();
        let realpath = PathBuf::from(var("CANTRACE_PROG").unwrap());
        let bin = &read(realpath.clone()).unwrap()[..];
        let is_pie = is_pie(bin.clone());
        let qemu_base = get_base(ci.pid, qemu_realpath.clone());
        let maps = get_maps(ci.pid, qemu_realpath.clone());

        let base = maps
            .iter()
            .filter(|m| m.pathname == "" && m.end < qemu_base)
            .next()
            .unwrap();

        let mut text_base = get_text(bin);
        let load_base = get_load_base(bin);

        if !is_pie {
            text_base -= base.start;
        }

        let start_exit = get_start_exit(bin.clone(), base.start);

        // println!("cmdline: {:?}", cmdline);
        // println!("realpath: {}", realpath.to_string_lossy());
        // println!("is_pie: {}", is_pie);
        // println!("base: {}", base);
        // println!("text base: 0x{:x}", text_base);
        // println!("load base: 0x{:x}", load_base);
        // println!("start_exit: 0x{:x}", start_exit);

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
                start_exit,
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
        if let Some(offset) = tid.translate(pc) 
            && let Ok(instr) = tid.decoder.decode_slice(&tid.bin[offset as usize..(offset as usize) + 16]) {
            match instr.opcode() {
                Opcode::JA | Opcode::JB | Opcode::JRCXZ | Opcode::JG | Opcode::JGE
                | Opcode::JL | Opcode::JLE | Opcode::JNA | Opcode::JNB | Opcode::JNO
                | Opcode::JNP | Opcode::JNS | Opcode::JNZ | Opcode::JO | Opcode::JP
                | Opcode::JS | Opcode::JZ | Opcode::LOOP | Opcode::LOOPNZ
                | Opcode::LOOPZ => {
                    let isize = instr.len().to_const();
                    let next: u64 = pc + isize;
                    let target: u64 = (pc as i64 + isize as i64 +  match instr.operand(0) {
                        Operand::ImmediateI8(imm) => imm as i64,
                        Operand::ImmediateI16(imm) => imm as i64,
                        Operand::ImmediateI32(imm) => imm as i64,
                        Operand::ImmediateI64(imm) => imm as i64,
                        _ => { panic!("unsupported operand: {:?}", instr.operand(0)); }
                    }).try_into().unwrap();
                    trace.push(TraceEntry::Branch { pc, offset, instr, bytes: tid.bin[offset as usize..(offset as usize) + 16].to_vec(), next, target});
                }
                Opcode::RETURN => {
                    if offset == tid.start_exit {
                        trace.push(TraceEntry::Done { });
                    } else {
                        trace.push(TraceEntry::Instr { pc, offset, instr, bytes: tid.bin[offset as usize..(offset as usize) + 16].to_vec()});
                    }
                }
            
                _ => {
                    trace.push(TraceEntry::Instr { pc, offset, instr, bytes: tid.bin[offset as usize..(offset as usize) + 16].to_vec() });
                }

            }
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

    fn trace(&mut self, _pid: &Self::PidContext, tid: &Self::TidContext, trace: &[Self::Trace]) {
        let mut branch_targets: Option<(u64, u64)> = None;

        for entry in trace {
            match entry {
                TraceEntry::Instr { pc, offset: _, instr: _, bytes: _} => {
                    // println!(
                            //     "{:x}: {:?}",
                            //     entry.pc,
                            //     entry.instr.display_with(DisplayStyle::Intel).to_string(),
                            // );
                    if let Some((next, target)) = branch_targets {
                        let mut cov= tid.cov.lock().unwrap();
                        if *pc == next || *pc == target {
                            let curr = *cov.get(pc).unwrap();
                            cov.insert(*pc,  curr + 1);
                        } else {
                            // println!("branch_targets not found @ 0x{:x}: 0x{:x} 0x{:x}", pc, next, target);
                            panic!("branch_targets not found! Is addressing broken? @ 0x{:x}: 0x{:x} 0x{:x}", pc, next, target);
                        }
                    }

                    branch_targets = None;
                }
                TraceEntry::Branch {pc, offset: _, instr, bytes: _, next, target } => {
                    // println!(
                    //     "{:x}: {:?} -> 0x{:x} 0x{:x}",
                    //     pc,
                    //     instr.display_with(DisplayStyle::Intel).to_string(),
                    //     next,
                    //     target
                    // );
                    let mut branches = tid.branches.lock().unwrap();
                    let mut cov = tid.cov.lock().unwrap();

                    branch_targets = Some((*next, *target));

                    if !branches.contains_key(pc) {
                        // println!("new branch: {:x}", pc);
                        branches.insert(*pc, (*instr, *next, *target));
                    }

                    if !cov.contains_key(next) {
                        // println!("new cov: {:x}", next);
                        cov.insert(*next, 0);
                    }

                    if !cov.contains_key(target) {
                        // println!("new cov: {:x}", target);
                        cov.insert(*target, 0);
                    }
                }
                TraceEntry::Done { } => {
                    // println!();
                    // println!("done");
                    /* Print out coverage information  */
                    let cov = tid.cov.lock().unwrap();
                    let branches = tid.branches.lock().unwrap();

                    for (branch_addr, branches) in branches.iter() {
                        let (instr, next, target) = branches;
                        let next_cov = cov.get(next).unwrap();
                        let target_cov = cov.get(target).unwrap();
                        println!(
                            "0x{:x}: {} -> 0x{:x} ({} hits) 0x{:x} ({} hits)",
                            branch_addr,
                            instr.display_with(DisplayStyle::Intel).to_string(),
                            next,
                            next_cov,
                            target,
                            target_cov
                        );
                    }
                }
            }
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