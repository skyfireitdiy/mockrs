use super::common::*;
use capstone::arch::{arm64, BuildsCapstone, BuildsCapstoneEndian};
use capstone::{Capstone, Endian, Insn, InsnId};
use nix::{
    libc::*,
    sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal},
};
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    sync::{Mutex, MutexGuard},
};

extern "C" fn handle_trap_signal(_: i32, _info: *mut siginfo_t, ucontext: *mut c_void) {
    let ctx = ucontext as *mut ucontext_t;
    let trap_addr = unsafe { (*ctx).uc_mcontext.pc as usize };

    let trunk_addr_option = G_TRUNK_ADDR_TABLE
        .lock()
        .unwrap()
        .borrow()
        .get(&trap_addr)
        .copied();

    if let Some(trunk_addr) = trunk_addr_option {
        if is_current_thread_mocked(trap_addr) {
            let new_func_addr = get_new_func_addr(trap_addr);
            unsafe {
                (*ctx).uc_mcontext.pc = new_func_addr as u64;
            }
        } else {
            unsafe {
                (*ctx).uc_mcontext.pc = trunk_addr as u64;
            }
        }
    } else {
        unsafe {
            (*ctx).uc_mcontext.pc += 4;
        }
    }
}

impl Mocker {
    pub fn mock(old_func: usize, new_func: usize) -> Mocker {
        init_mock();

        {
            let mut addr_table = G_TRUNK_ADDR_TABLE.lock().unwrap();
            if addr_table.borrow().get(&old_func).is_none() {
                let ins_mem = read_memory(old_func, G_REPLACE_LEN).clone();
                let cs = Capstone::new()
                    .arm64()
                    .mode(arm64::ArchMode::Arm)
                    .endian(Endian::Little)
                    .detail(true)
                    .build()
                    .unwrap();

                let disasm_result = cs.disasm_all(&ins_mem, old_func as u64);
                if let Ok(insns) = disasm_result {
                    if !insns.is_empty() {
                        let ins = &insns.as_ref()[0];
                        let current_position = G_CURRENT_POSITION.lock().unwrap();
                        let trunk_addr = save_old_instruction(&cs, ins, current_position);
                        addr_table.get_mut().insert(old_func, trunk_addr);
                        set_mem_writable(old_func, 4);
                        write_memory(old_func, &[0x00, 0x00, 0x20, 0xd4]);
                    } else {
                        panic!("Failed to disassemble instruction at 0x{old_func:x}");
                    }
                } else {
                    panic!("Failed to disassemble instruction at 0x{old_func:x}");
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

fn save_old_instruction(
    cs: &Capstone,
    ins: &Insn,
    current_position: MutexGuard<Cell<usize>>,
) -> usize {
    let detail = cs.insn_detail(ins).unwrap();
    let is_branch = detail.groups().iter().any(|&group| {
        u32::from(group.0) == capstone::arch::arm64::Arm64InsnGroup::ARM64_GRP_BRANCH_RELATIVE
    });

    if is_branch {
        unimplemented!(
            "PC-relative instruction relocation is not yet implemented for aarch64. Mnemonic: {}",
            ins.mnemonic().unwrap_or("?")
        );
    }

    let old_len = ins.bytes().len();
    let new_len = old_len;
    let jump_back_len = 16;

    let mut pos = current_position.get();
    if pos + 3 + new_len + jump_back_len - *G_CODE_AREA.lock().unwrap().get_mut()
        >= get_code_area_size()
    {
        panic!("Code area overflow");
    }

    write_memory(pos, &[old_len as u8]);
    pos += 1;
    write_memory(pos, &[new_len as u8]);
    pos += 1;
    write_memory(pos, &[0]);
    pos += 1;

    let trunk_addr = pos;

    let mut ins_bytes = ins.bytes().to_vec();

    if ins.id() == InsnId(arm64::Arm64Insn::ARM64_INS_ADRP as u32) {
        let detail = cs.insn_detail(ins).unwrap();
        let arch_detail = detail.arch_detail();
        let ops = arch_detail.operands();

        let target_page_addr = if let capstone::arch::ArchOperand::Arm64Operand(op) = &ops[1] {
            if let capstone::arch::arm64::Arm64OperandType::Imm(imm) = op.op_type {
                imm as usize
            } else {
                panic!("ADRP's second operand is not an immediate value");
            }
        } else {
            panic!("Unexpected operand type for ADRP");
        };

        let new_pc_page = trunk_addr & !0xFFF;
        let offset = target_page_addr.wrapping_sub(new_pc_page);

        if offset % 4096 != 0 {
            panic!("ADRP relocation failed: offset is not a multiple of 4096. This should not happen if capstone provides a page-aligned address.");
        }
        let imm21 = (offset >> 12) as i64;

        if (-(1 << 20)..(1 << 20)).contains(&imm21) {
            let immlo = (imm21 & 0x3) as u32;
            let immhi = ((imm21 >> 2) & 0x7FFFF) as u32;

            let mut ins_word = u32::from_le_bytes(ins_bytes.as_slice().try_into().unwrap());
            ins_word &= !((0x3 << 29) | (0x7FFFF << 5));
            ins_word |= immlo << 29;
            ins_word |= immhi << 5;

            ins_bytes = ins_word.to_le_bytes().to_vec();
        } else {
            let ins_word = u32::from_le_bytes(ins_bytes.as_slice().try_into().unwrap());
            let rd_idx = ins_word & 0x1F;
            let ldr_instr = 0x58000040 | rd_idx;
            let b_instr: u32 = 0x14000003;
            let mut new_bytes = Vec::new();
            new_bytes.extend_from_slice(&ldr_instr.to_le_bytes());
            new_bytes.extend_from_slice(&b_instr.to_le_bytes());
            new_bytes.extend_from_slice(&target_page_addr.to_le_bytes());
            ins_bytes = new_bytes;
        }
    }
    write_memory(pos, &ins_bytes);
    pos += ins_bytes.len();

    let jump_back_addr = ins.address() as usize + ins.len();
    let jump_instrs = [
        0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1f, 0xd6,
    ];
    write_memory(pos, &jump_instrs);
    pos += jump_instrs.len();

    write_memory(pos, &jump_back_addr.to_le_bytes());
    pos += 8;

    current_position.set(pos);

    trunk_addr
}

fn write_memory(addr: usize, data: &[u8]) {
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
    }
    flush_instruction_cache(addr, data.len());
}

fn flush_instruction_cache(addr: usize, len: usize) {
    let end = addr + len;
    let mut current = addr;
    let icache_line_size = 64;

    unsafe {
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
    }

    while current < end {
        unsafe {
            core::arch::asm!(
                "ic ivau, {}",
                in(reg) current,
                options(nostack, preserves_flags)
            );
        }
        current += icache_line_size;
    }
    unsafe {
        core::arch::asm!("isb", options(nostack, preserves_flags));
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
        panic!("Failed to set signal handler: {err:?}");
    }
}
