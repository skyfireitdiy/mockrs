use super::common::*;
use capstone::arch::{arm64, BuildsCapstone, BuildsCapstoneEndian};
use capstone::{Capstone, Endian, Insn, InsnId};
use nix::{
    libc::*,
    sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal},
};
use std::{cell::Cell, sync::MutexGuard};



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
        let arch_detail = detail.arch_detail();
        let ops = arch_detail.operands();

        let target_addr = if let capstone::arch::ArchOperand::Arm64Operand(op) = &ops[0] {
            if let capstone::arch::arm64::Arm64OperandType::Imm(imm) = op.op_type {
                imm as usize
            } else {
                panic!("Branch target is not an immediate value");
            }
        } else {
            panic!("Unexpected operand type for branch instruction");
        };

        let mut new_bytes = Vec::new();
        // LDR X17, #8
        new_bytes.extend_from_slice(&0x58000051_u32.to_le_bytes());

        if ins.id() == InsnId(arm64::Arm64Insn::ARM64_INS_BL as u32) {
            // BLR X17
            new_bytes.extend_from_slice(&0xd63f0220_u32.to_le_bytes());
        } else {
            // BR X17, for B, B.cond etc.
            new_bytes.extend_from_slice(&0xd61f0220_u32.to_le_bytes());
        }
        new_bytes.extend_from_slice(&target_addr.to_le_bytes());

        let old_len = ins.bytes().len();
        let new_len = new_bytes.len();

        let mut pos = current_position.get();
        if pos + 3 + new_len - *G_CODE_AREA.lock().unwrap().get_mut() >= get_code_area_size() {
            panic!("Code area overflow");
        }

        write_memory(pos, &[old_len as u8]);
        pos += 1;
        write_memory(pos, &[new_len as u8]);
        pos += 1;
        write_memory(pos, &[0]); // No register replacement
        pos += 1;

        let trunk_addr = pos;
        write_memory(pos, &new_bytes);
        pos += new_len;

        current_position.set(pos);
        return trunk_addr;
    }



    let old_len = ins.bytes().len();
    let jump_back_len = 16;

    let mut pos = current_position.get();

    // After writing 3-byte header, align code start to 4 bytes for AArch64
    let header_end = pos + 3;
    let pad = (4 - (header_end % 4)) % 4;
    let trunk_pc = header_end + pad;

    // Default to original bytes, but may rewrite for PC-relative cases below
    let mut ins_bytes = ins.bytes().to_vec();

    // Track the actual new_len to ensure capacity check is correct
    let mut new_len = ins_bytes.len();

    // Rewrites for PC-relative instructions executed in the trampoline
    // 1) ADRP: already handled previously but update new_len accordingly
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

        let new_pc_page = pos & !0xFFF;
        let offset = target_page_addr.wrapping_sub(new_pc_page);

        if offset % 4096 != 0 {
            panic!("ADRP relocation failed: offset is not a multiple of 4096. This should not happen if capstone provides a page-aligned address.");
        }
        let imm21 = (offset >> 12) as i64;

        if (-(1 << 20)..(1 << 20)).contains(&imm21) {
            let mut ins_word = u32::from_le_bytes(ins_bytes.as_slice().try_into().unwrap());

            // immlo at bits [30:29], immhi at [23:5]
            let immlo = (imm21 & 0x3) as u32;
            let immhi = ((imm21 >> 2) & 0x7FFFF) as u32;

            ins_word &= !((0x3 << 29) | (0x7FFFF << 5));
            ins_word |= immlo << 29;
            ins_word |= immhi << 5;

            ins_bytes = ins_word.to_le_bytes().to_vec();
            new_len = ins_bytes.len();
        } else {
            // Fallback: load absolute page address into Rd using a literal load
            let ins_word = u32::from_le_bytes(ins_bytes.as_slice().try_into().unwrap());
            let rd_idx = ins_word & 0x1F;

            let ldr_literal_xrd = 0x58000040 | rd_idx; // LDR Xd, #8
            let mut new_bytes = Vec::new();
            new_bytes.extend_from_slice(&ldr_literal_xrd.to_le_bytes());
            // Insert a branch to skip over the inlined 8-byte literal
            new_bytes.extend_from_slice(&0x14000003_u32.to_le_bytes()); // B +12
            // Inline the absolute page address literal
            new_bytes.extend_from_slice(&target_page_addr.to_le_bytes());

            ins_bytes = new_bytes;
            new_len = ins_bytes.len();
        }
    } else if ins.id() == InsnId(arm64::Arm64Insn::ARM64_INS_ADR as u32) {
        // ADR: Rd := PC + imm => rewrite to load absolute address into Rd
        let detail = cs.insn_detail(ins).unwrap();
        let arch_detail = detail.arch_detail();
        let ops = arch_detail.operands();

        let (rd_idx, target_addr) = if let (
            capstone::arch::ArchOperand::Arm64Operand(op_rd),
            capstone::arch::ArchOperand::Arm64Operand(op_imm),
        ) = (&ops[0], &ops[1])
        {
            let rd_idx = match op_rd.op_type {
                capstone::arch::arm64::Arm64OperandType::Reg(r) => (r.0 as u32) & 0x1F,
                _ => panic!("ADR's first operand is not a register"),
            };
            let target_addr = match op_imm.op_type {
                capstone::arch::arm64::Arm64OperandType::Imm(imm) => imm as usize,
                _ => panic!("ADR's second operand is not an immediate value"),
            };
            (rd_idx, target_addr)
        } else {
            panic!("Unexpected operand types for ADR");
        };

        // Encode: LDR Xd, #8; (literal load of absolute address)
        let ldr_literal_xrd = 0x58000040 | rd_idx;
        let mut new_bytes = Vec::new();
        new_bytes.extend_from_slice(&ldr_literal_xrd.to_le_bytes());
        // Insert a branch to skip over the inlined 8-byte literal
        new_bytes.extend_from_slice(&0x14000003_u32.to_le_bytes()); // B +12
        new_bytes.extend_from_slice(&target_addr.to_le_bytes());

        ins_bytes = new_bytes;
        new_len = ins_bytes.len();
    } else {
        // Detect LDR literal (PC-relative) and rewrite: LDR X17, #8; LDR <Rt>, [X17]; <abs addr>
        let detail = cs.insn_detail(ins).unwrap();
        let arch_detail = detail.arch_detail();
        let ops = arch_detail.operands();

        // Helper: check whether operand[1] is a PC-relative memory operand
        let is_pc_mem = {
            if ops.len() < 2 {
                false
            } else if let capstone::arch::ArchOperand::Arm64Operand(op) = &ops[1] {
                if let capstone::arch::arm64::Arm64OperandType::Mem(m) = op.op_type {
                    cs.reg_name(m.base()).as_deref() == Some("pc")
                } else {
                    false
                }
            } else {
                false
            }
        };

        // Temporarily disable LDR literal rewrites to avoid SIGILL under emulation; keep original bytes
        let is_ldr_literal = false && ins.id() == InsnId(arm64::Arm64Insn::ARM64_INS_LDR as u32) && is_pc_mem;
        let is_ldrsw_literal = false && ins.id() == InsnId(arm64::Arm64Insn::ARM64_INS_LDRSW as u32) && is_pc_mem;

        if is_ldr_literal || is_ldrsw_literal {
            // Extract destination register index and width, and compute absolute target address
            let (rd_idx, rd_is_32) = if let capstone::arch::ArchOperand::Arm64Operand(op0) = &ops[0] {
                match op0.op_type {
                    capstone::arch::arm64::Arm64OperandType::Reg(r) => {
                        let name_opt = cs.reg_name(r);
                        let is_w = name_opt.as_deref().map(|s| s.starts_with('w')).unwrap_or(false);
                        (((r.0 as u32) & 0x1F), is_w)
                    }
                    _ => panic!("LDR literal dest is not a GPR"),
                }
            } else {
                panic!("Unexpected operand type for LDR literal dest");
            };

            let mem = if let capstone::arch::ArchOperand::Arm64Operand(op1) = &ops[1] {
                match op1.op_type {
                    capstone::arch::arm64::Arm64OperandType::Mem(m) => m,
                    _ => panic!("LDR literal second operand is not Mem"),
                }
            } else {
                panic!("Unexpected operand type for LDR literal address");
            };

            let disp = mem.disp() as i64;
            let target_addr = (ins.address() as i64).wrapping_add(disp) as usize;

            // Prefer single LDR literal if encodable at the trampoline PC (aligned after header)
            let delta = (target_addr as isize).wrapping_sub(trunk_pc as isize);
            let mut new_bytes = Vec::new();

            // Force robust fallback path to avoid potential SIGILL under emulation
            let fits_imm = false;
            if fits_imm {
                let imm19 = (delta >> 2) as i64;
                if (-(1 << 18)..(1 << 18)).contains(&imm19) {
                    // Encode LDR literal with recalculated displacement
                    let base: u32 = if is_ldrsw_literal {
                        0x98000000 // LDRSW Xt, #imm
                    } else if rd_is_32 {
                        0x18000000 // LDR Wt, #imm
                    } else {
                        0x58000000 // LDR Xt, #imm
                    };
                    let ins_word: u32 =
                        base | (((imm19 as u32) & 0x7FFFF) << 5) | (rd_idx & 0x1F);
                    new_bytes.extend_from_slice(&ins_word.to_le_bytes());
                    ins_bytes = new_bytes;
                    new_len = ins_bytes.len();
                } else {
                    // Fallback: LDR X17, #8 ; LDR <dest>, [X17] ; <abs addr>
                    new_bytes.extend_from_slice(&0x58000051_u32.to_le_bytes()); // LDR X17, #8
                    let rn_bits = (17u32 & 0x1F) << 5; // Rn = X17
                    let ldr_from_x17_opcode = if is_ldrsw_literal {
                        0xB9800000u32 | rn_bits | rd_idx // LDRSW Xt, [X17]
                    } else if rd_is_32 {
                        0xB9400000u32 | rn_bits | rd_idx // LDR Wt, [X17]
                    } else {
                        0xF9400000u32 | rn_bits | rd_idx // LDR Xt, [X17]
                    };
                    new_bytes.extend_from_slice(&ldr_from_x17_opcode.to_le_bytes());
                    new_bytes.extend_from_slice(&target_addr.to_le_bytes()); // literal
                    ins_bytes = new_bytes;
                    new_len = ins_bytes.len();
                }
            } else {
                // Fallback: LDR X17, #8 ; LDR <dest>, [X17] ; <abs addr>
                new_bytes.extend_from_slice(&0x58000051_u32.to_le_bytes()); // LDR X17, #8
                let rn_bits = (17u32 & 0x1F) << 5; // Rn = X17
                let ldr_from_x17_opcode = if is_ldrsw_literal {
                    0xB9800000u32 | rn_bits | rd_idx // LDRSW Xt, [X17]
                } else if rd_is_32 {
                    0xB9400000u32 | rn_bits | rd_idx // LDR Wt, [X17]
                } else {
                    0xF9400000u32 | rn_bits | rd_idx // LDR Xt, [X17]
                };
                new_bytes.extend_from_slice(&ldr_from_x17_opcode.to_le_bytes());
                new_bytes.extend_from_slice(&target_addr.to_le_bytes()); // literal
                ins_bytes = new_bytes;
                new_len = ins_bytes.len();
            }
        }
    }

    // Capacity check with actual new_len and alignment padding
    if pos + 3 + pad + new_len + jump_back_len - *G_CODE_AREA.lock().unwrap().get_mut()
        >= get_code_area_size()
    {
        panic!("Code area overflow");
    }

    // Write header
    write_memory(pos, &[old_len as u8]);
    pos += 1;
    write_memory(pos, &[new_len as u8]);
    pos += 1;
    write_memory(pos, &[0]);
    pos += 1;

    // Write alignment padding to ensure instruction fetch alignment (4-byte)
    if pad > 0 {
        let zeros = vec![0u8; pad];
        write_memory(pos, &zeros);
        pos += pad;
    }

    let trunk_addr = pos;

    // Write transformed instruction(s)
    write_memory(pos, &ins_bytes);
    pos += ins_bytes.len();

    // Jump back to the next instruction of original address
    let jump_back_addr = ins.address() as usize + ins.len();
    let jump_instrs = [0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1f, 0xd6];
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
