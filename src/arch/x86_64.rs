use super::common::*;
use iced_x86::{Decoder, DecoderOptions, Encoder, Instruction, InstructionInfoFactory, Register, FlowControl, ConditionCode};
use nix::{
    libc::*,
    sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal},
};
use std::{cell::Cell, ffi::c_void, sync::MutexGuard};

#[derive(Clone, Copy, Default)]
struct InstrPosition {
    orig_addr: usize,
    trunk_addr: usize,
    old_len: u8,
    new_len: u8,
    replace_reg: u8,
    replace_data: i64,
}

thread_local! {
    static G_CURRENT_REPLACE: Cell<InstrPosition> = const { Cell::new(InstrPosition{orig_addr: 0, trunk_addr: 0,old_len:0, new_len:0, replace_reg: Register::None as u8, replace_data: 0}) };
}

fn disassemble_instruction(ins: &[u8], addr: u64) -> Option<Instruction> {
    let mut decoder = Decoder::with_ip(64, ins, addr, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    if decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        Some(instruction)
    } else {
        None
    }
}

extern "C" fn handle_trap_signal(_: i32, _: *mut siginfo_t, ucontext: *mut c_void) {
    let ctx = ucontext as *mut ucontext_t;
    let rip = unsafe { (*ctx).uc_mcontext.gregs[REG_RIP as usize] as usize };
    let orig_addr = rip - 1;

    fn set_ip_register(ctx: *mut ucontext_t, new_func_addr: usize) {
        unsafe { (*ctx).uc_mcontext.gregs[REG_RIP as usize] = new_func_addr as i64 };
    }

    fn get_trunk_addr(old_func: usize) -> usize {
        *G_TRUNK_ADDR_TABLE.lock().unwrap().get(&old_func).unwrap()
    }

    if is_current_thread_mocked(orig_addr) {
        set_ip_register(ctx, get_new_func_addr(orig_addr));
    } else {
        let trunk_addr = get_trunk_addr(orig_addr);
        set_ip_register(ctx, trunk_addr + 3);
    }
}

fn save_old_instruction(ins: &Instruction, current_position: MutexGuard<Cell<usize>>) {
    let old_len = ins.len();
    let mut replace_reg = Register::None;
    let mut new_instruction = *ins;

    if ins.is_ip_rel_memory_operand() {
        replace_reg = get_replace_register(ins);
        new_instruction = make_new_instruction(*ins, replace_reg);
    }

    let next_ip = ins.ip() as usize + old_len;

    // Handle relative branches: convert to absolute indirection like AArch64 trampoline branch handling
    let flow = ins.flow_control();
    if matches!(flow, FlowControl::Call | FlowControl::UnconditionalBranch) {
        // Resolve absolute target address of the relative branch
        let target = ins.near_branch_target() as usize;

        // Build body:
        // - For CALL: call [rip+0]; jmp +8; dq target_abs
        //   The short jmp skips over the 8-byte literal upon return.
        // - For JMP:  jmp [rip+0]; dq target_abs
        //   No tail jump-back for JMP (control transfers away like original).
        let mut body: Vec<u8> = Vec::new();
        let mut tail_needed = false;

        if flow == FlowControl::Call {
            // CALL qword ptr [RIP+0]
            body.extend_from_slice(&[0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);
            // JMP +8 to skip 8-byte literal after call returns
            body.extend_from_slice(&[0xEB, 0x08]);
            // 8-byte absolute target literal
            body.extend_from_slice(&(target as u64).to_le_bytes());
            // After call returns, continue executing trampoline and jump back to next_ip
            tail_needed = true;
        } else {
            // JMP qword ptr [RIP+0]
            body.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
            // 8-byte absolute target literal
            body.extend_from_slice(&(target as u64).to_le_bytes());
            // For JMP, do not append tail (control leaves trampoline)
            tail_needed = false;
        }

        let body_len = body.len();
        let tail_len = if tail_needed { 6 + 8 } else { 0 }; // jmp [rip+0] + 8-byte literal
        let total_len = body_len + tail_len;

        let mut pos = current_position.get();
        if pos + 3 + total_len - *G_CODE_AREA.lock().unwrap().get_mut() >= get_code_area_size() {
            panic!("Code area overflow");
        }

        // Header: [old_len][body_len][replace_reg=0]
        write_memory(pos, &[old_len as u8]);
        pos += 1;
        write_memory(pos, &[body_len as u8]);
        pos += 1;
        write_memory(pos, &[Register::None as u8]);
        pos += 1;

        // Body
        write_memory(pos, &body);
        pos += body_len;

        // Optional tail: absolute jump back to next_ip to resume after original branch
        if tail_needed {
            let mut tail: Vec<u8> = Vec::new();
            tail.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]); // jmp qword ptr [rip+0]
            tail.extend_from_slice(&(next_ip as u64).to_le_bytes());
            write_memory(pos, &tail);
            pos += tail.len();
        }

        current_position.set(pos);
        return;
    }

    // Handle conditional branches (Jcc): invert condition to skip absolute jmp when not taken,
    // else perform absolute jump to the real target. Fall-through path uses the common tail to jump back to next_ip.
    if flow == FlowControl::ConditionalBranch {
        let target = ins.near_branch_target() as usize;

        // Map original condition to inverse short Jcc opcode (0x70..0x7F)
        let inv_jcc_opcode: u8 = match ins.condition_code() {
            ConditionCode::o => 0x71,   // JNO
            ConditionCode::no => 0x70,  // JO
            ConditionCode::b => 0x73,   // JAE (NB/NC)
            ConditionCode::ae => 0x72,  // JB (C/NAE)
            ConditionCode::e => 0x75,   // JNE
            ConditionCode::ne => 0x74,  // JE
            ConditionCode::be => 0x77,  // JA
            ConditionCode::a => 0x76,   // JBE
            ConditionCode::s => 0x79,   // JNS
            ConditionCode::ns => 0x78,  // JS
            ConditionCode::p => 0x7B,   // JNP
            ConditionCode::np => 0x7A,  // JP
            ConditionCode::l => 0x7D,   // JGE
            ConditionCode::ge => 0x7C,  // JL
            ConditionCode::le => 0x7F,  // JG
            ConditionCode::g => 0x7E,   // JLE
            _ => {
                // Fallback: if condition code not recognized, treat as non-branch (do nothing special)
                0
            }
        };

        if inv_jcc_opcode != 0 {
            let mut body: Vec<u8> = Vec::new();
            // Jcc.not +14 to skip over: [FF 25 00 00 00 00] + <8-byte target>
            body.push(inv_jcc_opcode);
            body.push(14u8);
            // JMP qword ptr [RIP+0]
            body.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
            // 8-byte absolute target literal
            body.extend_from_slice(&(target as u64).to_le_bytes());

            let body_len = body.len();
            // We need a tail to return to next_ip when the condition is NOT taken
            let tail_len = 6 + 8; // jmp [rip+0] + 8-byte literal
            let total_len = body_len + tail_len;

            let mut pos = current_position.get();
            if pos + 3 + total_len - *G_CODE_AREA.lock().unwrap().get_mut() >= get_code_area_size() {
                panic!("Code area overflow");
            }

            // Header: [old_len][body_len][replace_reg=0]
            write_memory(pos, &[old_len as u8]);
            pos += 1;
            write_memory(pos, &[body_len as u8]);
            pos += 1;
            write_memory(pos, &[Register::None as u8]);
            pos += 1;

            // Body
            write_memory(pos, &body);
            pos += body_len;

            // Tail: absolute jump back to next_ip to resume original fall-through path
            let mut tail: Vec<u8> = Vec::new();
            tail.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]); // jmp qword ptr [rip+0]
            tail.extend_from_slice(&(next_ip as u64).to_le_bytes());
            write_memory(pos, &tail);
            pos += tail.len();

            current_position.set(pos);
            return;
        }
        // If inv_jcc_opcode == 0, fall through to generic encoding
    }

    // Encode the (possibly rewritten) instruction
    let mut encoder = Encoder::new(64);
    match encoder.encode(&new_instruction, ins.ip()) {
        Ok(_enc_len) => {
            // Build the trampoline body: [optional push][optional mov reg, next_ip][instruction][optional pop]
            let mut body: Vec<u8> = Vec::new();

            // Inline push of the temp register (if any)
            if replace_reg != Register::None {
                match replace_reg {
                    Register::RAX => body.push(0x50),
                    Register::RCX => body.push(0x51),
                    Register::RDX => body.push(0x52),
                    Register::RBX => body.push(0x53),
                    Register::RSP => body.push(0x54),
                    Register::RBP => body.push(0x55),
                    Register::RSI => body.push(0x56),
                    Register::RDI => body.push(0x57),
                    Register::R8  => body.extend_from_slice(&[0x41, 0x50]),
                    Register::R9  => body.extend_from_slice(&[0x41, 0x51]),
                    Register::R10 => body.extend_from_slice(&[0x41, 0x52]),
                    Register::R11 => body.extend_from_slice(&[0x41, 0x53]),
                    Register::R12 => body.extend_from_slice(&[0x41, 0x54]),
                    Register::R13 => body.extend_from_slice(&[0x41, 0x55]),
                    Register::R14 => body.extend_from_slice(&[0x41, 0x56]),
                    Register::R15 => body.extend_from_slice(&[0x41, 0x57]),
                    _ => {}
                }

                let imm_bytes = (next_ip as u64).to_le_bytes();
                match replace_reg {
                    Register::RAX => { body.extend_from_slice(&[0x48, 0xB8]); body.extend_from_slice(&imm_bytes); }
                    Register::RCX => { body.extend_from_slice(&[0x48, 0xB9]); body.extend_from_slice(&imm_bytes); }
                    Register::RDX => { body.extend_from_slice(&[0x48, 0xBA]); body.extend_from_slice(&imm_bytes); }
                    Register::RBX => { body.extend_from_slice(&[0x48, 0xBB]); body.extend_from_slice(&imm_bytes); }
                    Register::RSP => { body.extend_from_slice(&[0x48, 0xBC]); body.extend_from_slice(&imm_bytes); }
                    Register::RBP => { body.extend_from_slice(&[0x48, 0xBD]); body.extend_from_slice(&imm_bytes); }
                    Register::RSI => { body.extend_from_slice(&[0x48, 0xBE]); body.extend_from_slice(&imm_bytes); }
                    Register::RDI => { body.extend_from_slice(&[0x48, 0xBF]); body.extend_from_slice(&imm_bytes); }
                    Register::R8  => { body.extend_from_slice(&[0x49, 0xB8]); body.extend_from_slice(&imm_bytes); }
                    Register::R9  => { body.extend_from_slice(&[0x49, 0xB9]); body.extend_from_slice(&imm_bytes); }
                    Register::R10 => { body.extend_from_slice(&[0x49, 0xBA]); body.extend_from_slice(&imm_bytes); }
                    Register::R11 => { body.extend_from_slice(&[0x49, 0xBB]); body.extend_from_slice(&imm_bytes); }
                    Register::R12 => { body.extend_from_slice(&[0x49, 0xBC]); body.extend_from_slice(&imm_bytes); }
                    Register::R13 => { body.extend_from_slice(&[0x49, 0xBD]); body.extend_from_slice(&imm_bytes); }
                    Register::R14 => { body.extend_from_slice(&[0x49, 0xBE]); body.extend_from_slice(&imm_bytes); }
                    Register::R15 => { body.extend_from_slice(&[0x49, 0xBF]); body.extend_from_slice(&imm_bytes); }
                    _ => {}
                }
            }

            // Append the re-encoded instruction bytes
            let inst_bytes = encoder.take_buffer();
            body.extend_from_slice(&inst_bytes);

            // Inline pop of the temp register (if any)
            if replace_reg != Register::None {
                match replace_reg {
                    Register::RAX => body.push(0x58),
                    Register::RCX => body.push(0x59),
                    Register::RDX => body.push(0x5A),
                    Register::RBX => body.push(0x5B),
                    Register::RSP => body.push(0x5C),
                    Register::RBP => body.push(0x5D),
                    Register::RSI => body.push(0x5E),
                    Register::RDI => body.push(0x5F),
                    Register::R8  => body.extend_from_slice(&[0x41, 0x58]),
                    Register::R9  => body.extend_from_slice(&[0x41, 0x59]),
                    Register::R10 => body.extend_from_slice(&[0x41, 0x5A]),
                    Register::R11 => body.extend_from_slice(&[0x41, 0x5B]),
                    Register::R12 => body.extend_from_slice(&[0x41, 0x5C]),
                    Register::R13 => body.extend_from_slice(&[0x41, 0x5D]),
                    Register::R14 => body.extend_from_slice(&[0x41, 0x5E]),
                    Register::R15 => body.extend_from_slice(&[0x41, 0x5F]),
                    _ => {}
                }
            }

            let body_len = body.len();

            // Tail: absolute jump back using RIP-relative indirect jmp
            let mut tail: Vec<u8> = Vec::new();
            tail.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]); // jmp qword ptr [rip + 0]
            tail.extend_from_slice(&(next_ip as u64).to_le_bytes());       // 8-byte absolute target

            let total_len = body_len + tail.len();

            let mut pos = current_position.get();
            if pos + 3 + total_len - *G_CODE_AREA.lock().unwrap().get_mut() >= get_code_area_size() {
                panic!("Code area overflow");
            }

            // Header: [old_len][body_len][replace_reg]
            write_memory(pos, &[old_len as u8]);
            pos += 1;
            write_memory(pos, &[body_len as u8]);
            pos += 1;
            write_memory(pos, &[replace_reg as u8]);
            pos += 1;

            // Body + tail
            write_memory(pos, &body);
            pos += body_len;
            write_memory(pos, &tail);
            pos += tail.len();

            current_position.set(pos);
        }
        Err(e) => {
            println!("{}", e);
            panic!("Failed to encode instruction block");
        }
    }
}

fn make_new_instruction(ins: Instruction, reg: Register) -> Instruction {
    let mut bak_ins = ins;
    if bak_ins.memory_base().is_ip() {
        // For RIP-relative addressing, iced-x86 encodes the displacement as a 32-bit
        // value relative to next_ip. After switching the base to a GPR whose value
        // we set to next_ip in the signal handler, the displacement we must encode
        // is EA - next_ip.
        bak_ins.set_memory_base(reg);
        bak_ins.set_memory_displacement64(
            ins.memory_displacement64().overflowing_sub(ins.next_ip()).0,
        );
    }
    bak_ins
}

fn get_replace_register(ins: &Instruction) -> Register {
    // Prefer caller-saved registers per System V x86_64 ABI.
    // Exclude any register (explicit or implicit) used by the instruction.
    let candidates = [
        Register::RAX,
        Register::RCX,
        Register::RDX,
        Register::RSI,
        Register::RDI,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
    ];
    let mut info_factory = InstructionInfoFactory::new();
    let info = info_factory.info(ins);
    let used: Vec<Register> = info.used_registers().iter().map(|u| u.register()).collect();

    *candidates
        .iter()
        .find(|&&r| !used.contains(&r))
        .expect("No available caller-saved register to use for RIP-relative rewrite")
}

fn write_memory(addr: usize, data: &[u8]) {
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
    }
}

fn init_mock() {
    G_INIT_FLAG.lock().unwrap().get_or_init(|| {
        setup_trap_handler();
        alloc_code_area();
    });
}

fn setup_trap_handler() {
    if let Err(err) = unsafe {
        sigaction(
            Signal::SIGTRAP,
            &SigAction::new(
                SigHandler::SigAction(handle_trap_signal),
                SaFlags::SA_SIGINFO | SaFlags::SA_ONSTACK,
                SigSet::empty(),
            ),
        )
    } {
        panic!("Failed to set signal handler: {:?}", err);
    }
}

impl Mocker {
    pub fn mock(old_func: usize, new_func: usize) -> Mocker {
        init_mock();

        {
            let mut addr_table = G_TRUNK_ADDR_TABLE.lock().unwrap();
            if addr_table.get(&old_func).is_none() {
                let ins_mem = read_memory(old_func, G_REPLACE_LEN).clone();

                if let Some(ins) = disassemble_instruction(&ins_mem, old_func as u64) {
                    let current_position = G_CURRENT_POSITION.lock().unwrap();
                    addr_table.insert(old_func, current_position.get());
                    save_old_instruction(&ins, current_position);
                    set_mem_writable(old_func, 1);
                    write_memory(old_func, [0xcc].as_slice());
                    set_mem_rx(old_func, 1);
                } else {
                    panic!("Failed to disassemble instruction at 0x{:x}", old_func);
                }
            }
        }

        G_THREAD_REPLACE_TABLE.with(|x| {
            let mut x = x.borrow_mut();
            if let Some(v) = x.get_mut(&old_func) {
                v.push(new_func);
            } else {
                x.insert(old_func, vec![new_func]);
            }
        });

        Mocker { old_func, new_func }
    }
}
