use capstone::arch::{arm64, BuildsCapstone, BuildsCapstoneEndian};
use capstone::{Capstone, Endian, Insn};
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

extern "C" fn handle_trap_signal(_: i32, info: *mut siginfo_t, ucontext: *mut c_void) {
    let trap_addr = unsafe { (*info).si_addr() } as usize;
    let ctx = ucontext as *mut ucontext_t;
    println!("[mockrs] handle_trap_signal: received trap at 0x{:x}", trap_addr);

    if is_current_thread_mocked(trap_addr) {
        let new_func_addr = get_new_func_addr(trap_addr);
        println!("[mockrs] handle_trap_signal: address is mocked, redirecting to 0x{:x}", new_func_addr);
        unsafe {
            (*ctx).uc_mcontext.pc = new_func_addr as u64;
        }
    } else {
        println!("[mockrs] handle_trap_signal: address is not mocked, advancing PC");
        // Not a trap we set, advance PC past the trapping instruction to avoid an infinite loop.
        // This assumes the unknown trap instruction is 4 bytes long.
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
    println!("[mockrs] get_bak_instruction_addr: for 0x{:x} -> 0x{:x}", old_func, addr);
    addr
}

fn get_new_func_addr(old_func: usize) -> usize {
    let addr = G_THREAD_REPLACE_TABLE.with(|x| x.borrow().get(&old_func).unwrap().last().unwrap().clone());
    println!("[mockrs] get_new_func_addr: for 0x{:x} -> 0x{:x}", old_func, addr);
    addr
}

fn is_current_thread_mocked(old_func: usize) -> bool {
    let result = G_THREAD_REPLACE_TABLE.with(|x| x.borrow().get(&old_func).is_some());
    println!("[mockrs] is_current_thread_mocked: for 0x{:x} -> {}", old_func, result);
    result
}

impl Mocker {
    pub fn mock(old_func: usize, new_func: usize) -> Mocker {
        println!("[mockrs] Mocker::mock: old_func=0x{:x}, new_func=0x{:x}", old_func, new_func);
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
                        println!("[mockrs] Mocker::mock: first instruction to save: {}", ins);
                        let current_position = G_CURRENT_POSITION.lock().unwrap();
                        addr_table
                            .get_mut()
                            .insert(old_func, current_position.get());
                        save_old_instruction(&cs, ins, current_position);
                        set_mem_writable(old_func, 4);
                        println!("[mockrs] Mocker::mock: writing brk #0 to 0x{:x}", old_func);
                        // brk #0
                        write_memory(old_func, &[0x00, 0x00, 0x20, 0xd4]);
                    } else {
                        panic!("Failed to disassemble instruction at 0x{:x}", old_func);
                    }
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

fn save_old_instruction(cs: &Capstone, ins: &Insn, current_position: MutexGuard<Cell<usize>>) {
    println!("[mockrs] save_old_instruction: saving instruction {}", ins);
    let detail = cs.insn_detail(ins).unwrap();
    let is_branch = detail.groups().iter().any(|&group| {
        u32::from(group.0) == capstone::arch::arm64::Arm64InsnGroup::ARM64_GRP_BRANCH_RELATIVE as u32
    });

    if is_branch {
        unimplemented!(
            "PC-relative instruction relocation is not yet implemented for aarch64. Mnemonic: {}",
            ins.mnemonic().unwrap_or("?")
        );
    }

    let old_len = ins.bytes().len();
    let new_len = old_len;

    let current_pos_val = current_position.get();
    println!("[mockrs] save_old_instruction: current_pos_val=0x{:x}", current_pos_val);
    if current_pos_val + 3 + new_len - *G_CODE_AREA.lock().unwrap().get_mut()
        >= get_code_area_size()
    {
        panic!("Code area overflow");
    }

    write_memory(current_pos_val, &[old_len as u8]);
    current_position.set(current_pos_val + 1);

    let current_pos_val = current_position.get();
    write_memory(current_pos_val, &[new_len as u8]);
    current_position.set(current_pos_val + 1);

    let current_pos_val = current_position.get();
    write_memory(current_pos_val, &[0]);
    current_position.set(current_pos_val + 1);

    let current_pos_val = current_position.get();
    write_memory(current_pos_val, ins.bytes());
    current_position.set(current_pos_val + new_len);
    println!("[mockrs] save_old_instruction: new_pos=0x{:x}", current_position.get());
}

fn read_memory(addr: usize, len: usize) -> Vec<u8> {
    let mut buf = vec, len);
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
        panic!("Failed to set signal handler: {:?}", err);
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
            x.get_mut(&self.old_func)
                .unwrap()
                .retain(|&new_func| new_func != self.new_func);
            if x.get(&self.old_func).unwrap().is_empty() {
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
