use capstone::arch::{arm64, BuildsCapstone, BuildsCapstoneEndian};
use capstone::{Capstone, Endian, Insn, InsnId};
use lazy_static::lazy_static;
use nix::{
    libc::*,
    sys::{
        mman::{mmap_anonymous, mprotect, MapFlags, ProtFlags},
        signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal},
    },
};
use std::{
    cell::{Cell, OnceCell, RefCell},
    collections::HashMap,
    ffi::c_void,
    num::NonZeroUsize,
    ptr::NonNull,
    sync::{Mutex, MutexGuard},
};

/// `Mocker`结构体，用于模拟函数
pub struct Mocker {
    old_func: usize,
    new_func: usize,
}

lazy_static! {
    static ref G_TRUNK_ADDR_TABLE: Mutex<RefCell<HashMap<usize, usize>>> =
        Mutex::new(RefCell::new(HashMap::new()));
}
static G_REPLACE_LEN: usize = 16;
static G_INIT_FLAG: Mutex<OnceCell<()>> = Mutex::new(OnceCell::new());

static G_CODE_AREA: Mutex<RefCell<usize>> = Mutex::new(RefCell::new(0));

const PAGE_SIZE: usize = 4096;
const DEFAULT_CODE_AREA_SIZE: usize = 8 * PAGE_SIZE;

/// `Droper`结构体，用于释放资源
struct Droper {}

#[allow(dead_code)]
static G_DROPER: Droper = Droper {};

impl Drop for Droper {
    fn drop(&mut self) {
        let code_area: usize = *G_CODE_AREA.lock().unwrap().get_mut();
        if code_area != 0 {
            unsafe {
                munmap(code_area as *mut c_void, get_code_area_size());
            }
        }
    }
}

static G_CURRENT_POSITION: Mutex<Cell<usize>> = Mutex::new(Cell::new(0));

thread_local! {
    static G_THREAD_REPLACE_TABLE: RefCell<HashMap<usize, Vec<usize>>> = RefCell::new(HashMap::new());
}

extern "C" fn handle_trap_signal(_: i32, _info: *mut siginfo_t, ucontext: *mut c_void) {
    let ctx = ucontext as *mut ucontext_t;
    let trap_addr = unsafe { (*ctx).uc_mcontext.pc as usize };
    println!("[mockrs] handle_trap_signal: received trap at 0x{trap_addr:x}");

    let trunk_addr_option = G_TRUNK_ADDR_TABLE
        .lock()
        .unwrap()
        .borrow()
        .get(&trap_addr)
        .copied();

    if let Some(trunk_addr) = trunk_addr_option {
        // This is a trap from one of our hooked functions.
        if is_current_thread_mocked(trap_addr) {
            let new_func_addr = get_new_func_addr(trap_addr);
            println!(
                "[mockrs] handle_trap_signal: address is mocked, redirecting to 0x{new_func_addr:x}"
            );
            unsafe {
                (*ctx).uc_mcontext.pc = new_func_addr as u64;
            }
        } else {
            // Not mocked for this thread, so execute original instruction from trunk.
            println!("[mockrs] handle_trap_signal: address is not mocked for this thread, executing original code from trunk at 0x{trunk_addr:x}");
            unsafe {
                (*ctx).uc_mcontext.pc = trunk_addr as u64;
            }
        }
    } else {
        // This is not a trap from one of our hooks.
        // To avoid an infinite loop, we advance PC past the trapping instruction.
        // This assumes the unknown trap instruction is 4 bytes long.
        println!("[mockrs] handle_trap_signal: address is not hooked, advancing PC");
        unsafe {
            (*ctx).uc_mcontext.pc += 4;
        }
    }
}

#[allow(dead_code)]
fn get_bak_instruction_addr(old_func: usize) -> usize {
    let addr = *G_TRUNK_ADDR_TABLE
        .lock()
        .unwrap()
        .borrow()
        .get(&old_func)
        .unwrap();
    println!("[mockrs] get_bak_instruction_addr: for 0x{old_func:x} -> 0x{addr:x}");
    addr
}

fn get_new_func_addr(old_func: usize) -> usize {
    let addr = G_THREAD_REPLACE_TABLE.with(|x| *x.borrow().get(&old_func).unwrap().last().unwrap());
    println!("[mockrs] get_new_func_addr: for 0x{old_func:x} -> 0x{addr:x}");
    addr
}

fn is_current_thread_mocked(old_func: usize) -> bool {
    let result = G_THREAD_REPLACE_TABLE.with(|x| x.borrow().get(&old_func).is_some());
    println!("[mockrs] is_current_thread_mocked: for 0x{old_func:x} -> {result}");
    result
}

impl Mocker {
    pub fn mock(old_func: usize, new_func: usize) -> Mocker {
        println!("[mockrs] Mocker::mock: old_func=0x{old_func:x}, new_func=0x{new_func:x}");
        init_mock();

        {
            let mut addr_table = G_TRUNK_ADDR_TABLE.lock().unwrap();
            if addr_table.borrow().get(&old_func).is_none() {
                println!("[mockrs] Mocker::mock: no existing trunk for this function, creating one");
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
                        println!("[mockrs] Mocker::mock: first instruction to save: {ins}");
                        let current_position = G_CURRENT_POSITION.lock().unwrap();
                        let trunk_addr = save_old_instruction(&cs, ins, current_position);
                        addr_table.get_mut().insert(old_func, trunk_addr);
                        set_mem_writable(old_func, 4);
                        println!("[mockrs] Mocker::mock: writing brk #0 to 0x{old_func:x}");
                        // brk #0
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
    println!("[mockrs] save_old_instruction: saving instruction {ins}");
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
    let jump_back_len = 16; // 4 (ldr) + 4 (br) + 8 (addr)

    let mut pos = current_position.get();
    println!("[mockrs] save_old_instruction: current_pos_val=0x{pos:x}");
    if pos + 3 + new_len + jump_back_len - *G_CODE_AREA.lock().unwrap().get_mut()
        >= get_code_area_size()
    {
        panic!("Code area overflow");
    }

    // Metadata is not executable, so we write it first.
    write_memory(pos, &[old_len as u8]);
    pos += 1;
    write_memory(pos, &[new_len as u8]);
    pos += 1;
    write_memory(pos, &[0]);
    pos += 1;

    // The executable part of the trunk starts here.
    let trunk_addr = pos;

    // Write original instruction bytes.
    let mut ins_bytes = ins.bytes().to_vec();

    if ins.id() == InsnId(arm64::Arm64Insn::ARM64_INS_ADRP as u32) {
        println!("[mockrs] save_old_instruction: relocating ADRP instruction");
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
            // Offset is in range, re-encode the instruction
            println!("[mockrs] save_old_instruction: ADRP offset 0x{offset:x} is in range");
            let immlo = (imm21 & 0x3) as u32;
            let immhi = ((imm21 >> 2) & 0x7FFFF) as u32;

            let mut ins_word = u32::from_le_bytes(ins_bytes.as_slice().try_into().unwrap());
            ins_word &= !((0x3 << 29) | (0x7FFFF << 5)); // Clear immlo and immhi
            ins_word |= immlo << 29;
            ins_word |= immhi << 5;

            ins_bytes = ins_word.to_le_bytes().to_vec();
        } else {
            // Offset is out of range, generate a new instruction sequence
            println!("[mockrs] save_old_instruction: ADRP offset 0x{offset:x} out of range, generating LDR literal sequence");
            let ins_word = u32::from_le_bytes(ins_bytes.as_slice().try_into().unwrap());
            let rd_idx = ins_word & 0x1F;
            // LDR Xd, #8
            let ldr_instr = 0x58000040 | rd_idx;
            // B #12
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

    // Write jump-back sequence.
    let jump_back_addr = ins.address() as usize + ins.len();
    // ldr x16, #8  ; load from 8 bytes ahead (address literal)
    // br x16
    let jump_instrs = [
        0x50, 0x00, 0x00, 0x58, // ldr x16, #8
        0x00, 0x02, 0x1f, 0xd6, // br x16
    ];
    write_memory(pos, &jump_instrs);
    pos += jump_instrs.len();

    // Write the address literal for the jump.
    write_memory(pos, &jump_back_addr.to_le_bytes());
    pos += 8;

    current_position.set(pos);
    println!("[mockrs] save_old_instruction: new_pos=0x{:x}", current_position.get());

    trunk_addr
}

fn read_memory(addr: usize, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    unsafe {
        std::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), len);
    }
    buf
}

fn write_memory(addr: usize, data: &[u8]) {
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
    }
    flush_instruction_cache(addr, data.len());
}

/// Flush the instruction cache for the given memory range.
/// This is necessary to ensure that the CPU executes the newly written instructions.
fn flush_instruction_cache(addr: usize, len: usize) {
    let end = addr + len;
    let mut current = addr;
    let icache_line_size = 64; // A common cache line size for aarch64

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

fn get_code_area_size() -> usize {
    std::env::var("MOCKRS_CODE_AREA_SIZE_IN_PAGE")
        .map(|x| x.parse::<usize>().unwrap() * PAGE_SIZE)
        .unwrap_or(DEFAULT_CODE_AREA_SIZE)
}

fn alloc_code_area() {
    unsafe {
        let code_area = mmap_anonymous(
            None,
            NonZeroUsize::new(get_code_area_size()).unwrap(),
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
        )
        .unwrap()
        .as_ptr();
        *G_CODE_AREA.lock().unwrap().get_mut() = code_area as usize;
        G_CURRENT_POSITION
            .lock()
            .unwrap()
            .replace(code_area as usize);
    }
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

fn get_page_bound(addr: usize, len: usize) -> (usize, usize) {
    (addr & !(PAGE_SIZE - 1), (addr + len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1))
}

fn set_mem_writable(old_func: usize, len: usize) {
    let (low, high) = get_page_bound(old_func, len);
    unsafe {
        mprotect(
            NonNull::new(low as *mut c_void).unwrap(),
            high - low,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC,
        )
        .unwrap()
    };
}

impl Drop for Mocker {
    fn drop(&mut self) {
        G_THREAD_REPLACE_TABLE.with(|x| {
            let mut x = x.borrow_mut();
            let mut should_remove = false;
            if let Some(v) = x.get_mut(&self.old_func) {
                v.retain(|&new_func| new_func != self.new_func);
                if v.is_empty() {
                    should_remove = true;
                }
            }
            if should_remove {
                x.remove(&self.old_func);
            }
        });
    }
}

#[macro_export]
macro_rules! mock {
    ($old_func:expr, $new_func:expr) => {{
        $crate::Mocker::mock($old_func as usize, $new_func as usize)
    }};
}
