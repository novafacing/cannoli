use cannoli::{Cannoli, ClientInfo};
use serde_json::to_string;
use yaxpeax_x86::amd64::{Opcode, Operand, DisplayStyle};
use yaxpeax_arch::LengthedInstruction;
use std::{sync::Arc, fs::{read_link, read}, env::var, path::PathBuf, io::Write, net::Shutdown};
use log::{info, debug, warn};

use crate::{trace_entry::TraceEntry, can_tracer_context::CanTracerContext, elf::{is_pie, get_text, get_load_base, get_trace_stop}, maps::{get_base, get_maps}, cov::{Branch, Coverage, CodeLocation}};

pub struct CanTracer;

impl Cannoli for CanTracer {
    type Trace = TraceEntry;
    type TidContext = CanTracerContext;
    type PidContext = ();

    fn init_pid(_ci: &ClientInfo) -> Arc<Self::PidContext> {
        Arc::new(())
    }

    fn init_tid(_pid: &Self::PidContext, ci: &ClientInfo) -> (Self, Self::TidContext) {
        info!("Initializing tracer for pid {}", ci.pid);

        let qemu_realpath = read_link(format!("/proc/{}/exe", ci.pid)).unwrap();
        let realpath = PathBuf::from(var("CANTRACE_PROG").unwrap());
        let inputpath= PathBuf::from("TEST_CANTRACE_INPUT"); // var("CANTRACE_INPUT").unwrap());
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

        let stop_loc= get_trace_stop(bin.clone(), base.start);

        info!("- Is PIE: {}", is_pie);
        info!("- Text Base: 0x{:x}", text_base);
        info!("- Load Base: 0x{:x}", load_base);
        info!("- Stopping At: 0x{:x}", stop_loc);

        (
            Self,
            CanTracerContext::new(
                inputpath.clone(),
                realpath.clone(),
                bin,
                is_pie,
                base.start,
                base.end,
                text_base,
                load_base,
                stop_loc,
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
            debug!("0x{:x}: {}", offset, instr.display_with(DisplayStyle::Intel).to_string());

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
                Opcode::RETURN | Opcode::RETF => {
                    if offset == tid.stop_loc {
                        trace.push(TraceEntry::Done { });
                    } else {
                        trace.push(TraceEntry::Instr { pc, offset, instr, bytes: tid.bin[offset as usize..(offset as usize) + 16].to_vec() });
                    }
                }
                Opcode::CMP
                | Opcode::CMPPD
                | Opcode::CMPS
                | Opcode::CMPSD
                | Opcode::CMPSS
                | Opcode::CMPXCHG16B
                | Opcode::COMISD
                | Opcode::COMISS
                | Opcode::FCOM
                | Opcode::FCOMI
                | Opcode::FCOMIP
                | Opcode::FCOMP
                | Opcode::FCOMPP
                | Opcode::FICOM
                | Opcode::FICOMP
                | Opcode::FTST
                | Opcode::FUCOM
                | Opcode::FUCOMI
                | Opcode::FUCOMIP
                | Opcode::FUCOMP
                | Opcode::FXAM
                | Opcode::PCMPEQB
                | Opcode::PCMPEQD
                | Opcode::PCMPEQW
                | Opcode::PCMPGTB
                | Opcode::PCMPGTD
                | Opcode::PCMPGTQ
                | Opcode::PCMPGTW
                | Opcode::PMAXSB
                | Opcode::PMAXSD
                | Opcode::PMAXUD
                | Opcode::PMAXUW
                | Opcode::PMINSB
                | Opcode::PMINSD
                | Opcode::PMINUD
                | Opcode::PMINUW
                | Opcode::TEST
                | Opcode::UCOMISD
                | Opcode::UCOMISS
                | Opcode::VPCMPB
                | Opcode::VPCMPD
                | Opcode::VPCMPQ
                | Opcode::VPCMPUB
                | Opcode::VPCMPUD
                | Opcode::VPCMPUQ
                | Opcode::VPCMPUW
                | Opcode::VPCMPW => {
                    trace.push(TraceEntry::CFSet { pc, offset, instr, bytes: tid.bin[offset as usize..(offset as usize) + 16].to_vec() });
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

        for entry in trace {
            match entry {
                TraceEntry::Instr { pc, offset: _, instr: _, bytes: _} => {
                    let mut branch_targets= tid.branch_targets.lock().unwrap();
                    // println!(
                            //     "{:x}: {:?}",
                            //     entry.pc,
                            //     entry.instr.display_with(DisplayStyle::Intel).to_string(),
                            // );
                    if let Some((next, target)) = *branch_targets {
                        let mut cov= tid.cov.lock().unwrap();
                        if *pc == next || *pc == target {
                            let curr = *cov.get(pc).unwrap();
                            cov.insert(*pc,  curr + 1);
                        } else {
                            // println!("branch_targets not found @ 0x{:x}: 0x{:x} 0x{:x}", pc, next, target);
                            panic!("branch_targets not found! Is addressing broken? @ 0x{:x}: 0x{:x} 0x{:x}", pc, next, target);
                        }
                    }

                    *branch_targets = None;
                }
                TraceEntry::Branch {pc, offset, instr, bytes, next, target } => {
                    let mut branch_targets= tid.branch_targets.lock().unwrap();
                    let mut lastcf = tid.last_cf.lock().unwrap();
                    // let mut lastret = tid.last_ret.lock().unwrap();
                    let mut branches = tid.branches.lock().unwrap();
                    let mut cov = tid.cov.lock().unwrap();
                    let mut causes = tid.causes.lock().unwrap();
                    let mut returns = tid.causes.lock().unwrap();

                    *branch_targets = Some((*next, *target));

                    if lastcf.is_some() && !causes.contains_key(pc) {
                        causes.insert(*pc, lastcf.clone().unwrap());
                    }

                    // if lastret.is_some() && !returns.contains_key(pc) {
                    //     returns.insert(*pc, lastret.clone().unwrap());
                    // }

                    if !branches.contains_key(pc) {
                        // println!("new branch: {:x}", pc);
                        let loc = CodeLocation::new(*pc, *offset, instr.display_with(DisplayStyle::Intel).to_string(), bytes.clone());
                        branches.insert(*pc, (loc, *next, *target));
                    }

                    if !cov.contains_key(next) {
                        // println!("new cov: {:x}", next);
                        cov.insert(*next, 0);
                    }

                    if !cov.contains_key(target) {
                        // println!("new cov: {:x}", target);
                        cov.insert(*target, 0);
                    }

                    *lastcf = None;
                    // *lastret = None;
                }
                TraceEntry::CFSet { pc, offset, instr, bytes } => {
                    let mut lastcf = tid.last_cf.lock().unwrap();
                    *lastcf = Some(CodeLocation::new(*pc, *offset, instr.display_with(DisplayStyle::Intel).to_string(), bytes.clone()));
                }
                TraceEntry::Return { pc, offset, instr, bytes } => {
                    // We only want to log a return if it comes *before* our most recently seen compare
                    // let lastcf = tid.last_cf.lock().unwrap();
                    // let mut lastret = tid.last_ret.lock().unwrap();
                    // if (lastcf.is_some() && *pc < lastcf.as_ref().unwrap().addr) || lastcf.is_none() {
                    //     *lastret = Some(CodeLocation::new(*pc, *offset, instr.display_with(DisplayStyle::Intel).to_string(), bytes.clone()));
                    // }
                }
                TraceEntry::Done { } => {
                    // println!();
                    // println!("done");
                    /* Print out coverage information  */
                    info!("Got done signal while tracing. Consolidating coverage information.");
                    let cov = tid.cov.lock().unwrap();
                    let branches = tid.branches.lock().unwrap();
                    let causes = tid.causes.lock().unwrap();
                    let returns = tid.causes.lock().unwrap();

                    let mut final_cov = Coverage::new();

                    for (branch_addr, branches) in branches.iter() {
                        let branch = Branch::new(
                            if causes.contains_key(branch_addr) { causes.get(branch_addr).clone().cloned() } else { None },
                            if returns.contains_key(branch_addr) { returns.get(branch_addr).clone().cloned() } else { None },
                            branches.0.clone(),
                            branches.1,
                            *cov.get(&branches.1).unwrap(),
                            branches.2,
                            *cov.get(&branches.2).unwrap(),
                            vec![tid.ipath.clone().to_string_lossy().to_string()],
                        );
                        final_cov.branches.push(branch);
                    }

                    let mut stream = tid.stream.lock().unwrap();
                    stream.write_all(to_string(&final_cov).unwrap().as_bytes()).unwrap();
                    stream.write_all(b",").unwrap();
                    stream.flush().unwrap();
                    stream.shutdown(Shutdown::Write).unwrap();
                }
            }
        }
    }

    fn mmap(
        _pid: &Self::PidContext,
        _tid: &Self::TidContext,
        base: u64,
        len: u64,
        anon: bool,
        read: bool,
        write: bool,
        exec: bool,
        path: &str,
        offset: u64,
        _trace: &mut Vec<Self::Trace>,
    ) {
        info!("mmap: {:x} {:x} {:?} {:?} {:?} {:?} {:?} {:?}", base, len, anon, read, write, exec, path, offset);
    }

    fn munmap(
        _pid: &Self::PidContext,
        _tid: &Self::TidContext,
        base: u64,
        len: u64,
        _trace: &mut Vec<Self::Trace>,
    ) {
        info!("munmap: {:x} {:x}", base, len);
    }
}