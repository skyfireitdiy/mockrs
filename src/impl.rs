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

use iced_x86::{Decoder, DecoderOptions, Encoder, Instruction, Register};

pub struct X8664Mocker {
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

#[derive(Clone, Copy)]
struct InstrPosition {
    orig_addr: usize,
    trunk_addr: usize,
    old_len: u8,
    new_len: u8,
    replace_reg: u8,
    replace_data: i64,
}

impl Default for InstrPosition {
    fn default() -> Self {
        Self {
            orig_addr: 0,
            trunk_addr: 0,
            old_len: 0,
            new_len: 0,
            replace_reg: 0,
            replace_data: 0,
        }
    }
}

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
    static G_CURRENT_REPLACE: Cell<InstrPosition> = const { Cell::new(InstrPosition{orig_addr: 0, trunk_addr: 0,old_len:0, new_len:0, replace_reg: Register::None as u8, replace_data: 0}) };
    static G_THREAD_REPLACE_TABLE: RefCell<HashMap<usize, Vec<usize>>> = RefCell::new(HashMap::new());
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

fn get_page_bound(addr: usize, len: usize) -> (usize, usize) {
    (addr & 0xfffffffff000, (addr + len + 0xfff) & 0xfffffffff000)
}

fn is_step_mode(eflags: i64) -> bool {
    eflags & 0x100 != 0
}

fn enter_step_mode(ctx: *mut ucontext_t) {
    unsafe { (*ctx).uc_mcontext.gregs[REG_EFL as usize] |= 0x100 };
}

fn leave_step_mode(ctx: *mut ucontext_t) {
    unsafe { (*ctx).uc_mcontext.gregs[REG_EFL as usize] &= !0x100 };
}

fn get_context_reg_index(reg: u8) -> i32 {
    if reg == Register::RAX as u8 {
        return REG_RAX;
    } else if reg == Register::RBX as u8 {
        return REG_RBX;
    } else if reg == Register::RCX as u8 {
        return REG_RCX;
    } else if reg == Register::RDX as u8 {
        return REG_RDX;
    } else if reg == Register::RDI as u8 {
        return REG_RDI;
    } else if reg == Register::RSI as u8 {
        return REG_RSI;
    }
    return -1;
}

extern "C" fn handle_trap_signal(_: i32, _: *mut siginfo_t, ucontext: *mut c_void) {
    let ctx = ucontext as *mut ucontext_t;
    let rip = unsafe { (*ctx).uc_mcontext.gregs[REG_RIP as usize] as usize };
    let eflags = unsafe { (*ctx).uc_mcontext.gregs[REG_EFL as usize] };

    if !is_step_mode(eflags) {
        let orig_addr = rip - 1;

        if is_current_thread_mocked(orig_addr) {
            set_ip_register(ctx, get_new_func_addr(orig_addr));
        } else {
            enter_step_mode(ctx);
            let trunk_addr = get_bak_instruction_addr(orig_addr);
            let mut patch = InstrPosition::default();
            patch.orig_addr = orig_addr;
            patch.trunk_addr = trunk_addr;
            let buf = read_memory(trunk_addr, 3);
            patch.old_len = buf[0];
            patch.new_len = buf[1];
            patch.replace_reg = buf[2];
            let r = get_context_reg_index(patch.replace_reg);

            if r != -1 {
                unsafe {
                    patch.replace_data = (*ctx).uc_mcontext.gregs[r as usize];
                    (*ctx).uc_mcontext.gregs[r as usize] = orig_addr as i64 + patch.old_len as i64;
                };
            }
            G_CURRENT_REPLACE.with(|x| x.set(patch));
            set_ip_register(ctx, trunk_addr + 3);
        }
    } else {
        leave_step_mode(ctx);
        let InstrPosition {
            orig_addr,
            trunk_addr,
            old_len,
            new_len,
            replace_reg,
            replace_data,
        } = G_CURRENT_REPLACE.with(|x| x.get());

        let r = get_context_reg_index(replace_reg);

        if r != -1 {
            unsafe {
                (*ctx).uc_mcontext.gregs[r as usize] = replace_data;
            }
        }
        if rip - (trunk_addr + 3) == new_len as usize {
            set_ip_register(ctx, orig_addr + old_len as usize);
        }
    }
}

fn get_bak_instruction_addr(old_func: usize) -> usize {
    *G_TRUNK_ADDR_TABLE
        .lock()
        .unwrap()
        .get_mut()
        .get(&old_func)
        .unwrap()
}

fn set_ip_register(ctx: *mut ucontext_t, new_func_addr: usize) {
    unsafe { (*ctx).uc_mcontext.gregs[REG_RIP as usize] = new_func_addr as i64 };
}

fn get_new_func_addr(old_func: usize) -> usize {
    G_THREAD_REPLACE_TABLE.with(|x| x.borrow().get(&old_func).unwrap().last().unwrap().clone())
}

fn is_current_thread_mocked(old_func: usize) -> bool {
    G_THREAD_REPLACE_TABLE.with(|x| x.borrow().get(&old_func).is_some())
}

impl X8664Mocker {
    /// Creates a new instance of `X8664Mocker` for mocking a function.
    ///
    /// # Arguments
    ///
    /// * `old_func` - The address of the original function to be mocked.
    /// * `new_func` - The address of the new function to replace the original function.
    ///
    /// # Returns
    ///
    /// A new instance of `X8664Mocker` that can be used to mock the function.
    ///
    /// # Example
    ///
    /// ```
    /// use mockrs::mock;
    /// fn add(a: i64, b: i64) -> i64 {
    ///     a + b
    /// }
    /// fn mock_add(_a: i64, _b: i64) -> i64 {
    ///     100
    /// }
    /// fn main() {
    ///     assert!(add(1, 2) == 3);
    ///     let mocker = mock!(add, mock_add);
    ///     assert!(add(1, 2) == 100);
    ///     drop(mocker);
    ///     assert!(add(1, 2) == 3);
    /// }
    /// ```
    pub fn mock(old_func: usize, new_func: usize) -> X8664Mocker {
        init_mock();

        {
            let mut addr_table = G_TRUNK_ADDR_TABLE.lock().unwrap();
            if addr_table.get_mut().get(&old_func).is_none() {
                let ins_mem = read_memory(old_func, G_REPLACE_LEN).clone();

                if let Some(ins) = disassemble_instruction(&ins_mem, old_func as u64) {
                    let current_position = G_CURRENT_POSITION.lock().unwrap();
                    addr_table
                        .get_mut()
                        .insert(old_func, current_position.get());
                    save_old_instruction(&ins, current_position);
                    set_mem_writable(old_func, 1);
                    write_memory(old_func, [0xcc].as_slice());
                    // 不去除内存的可写权限，因为在并法同时给一个函数进行mock的时候会有问题
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

        X8664Mocker { old_func, new_func }
    }
}

fn get_replace_register(ins: &Instruction) -> Register {
    let regs: Vec<Register> = (0..=4u32).map(|i| ins.op_register(i)).collect();
    *[
        Register::RAX,
        Register::RBX,
        Register::RCX,
        Register::RDX,
        Register::RDI,
        Register::RSI,
    ]
    .iter()
    .find(|r| regs.iter().find(|t| t == r).is_none())
    .unwrap()
}

fn make_new_instruction(ins: Instruction, reg: Register) -> Instruction {
    let mut bak_ins = ins.clone();
    if bak_ins.memory_base().is_ip() {
        bak_ins.set_memory_base(reg);
        bak_ins.set_memory_displacement64(
            ins.memory_displacement64().overflowing_sub(ins.next_ip()).0,
        );
    }
    bak_ins
}

fn save_old_instruction(ins: &Instruction, current_position: MutexGuard<Cell<usize>>) {
    let old_len = ins.len();
    let mut replace_reg = Register::None;
    let mut new_instruction = ins.clone();

    if ins.is_ip_rel_memory_operand() {
        replace_reg = get_replace_register(ins);
        new_instruction = make_new_instruction(ins.clone(), replace_reg);
    }

    let mut encoder = Encoder::new(64);
    match encoder.encode(&new_instruction, ins.ip()) {
        Ok(new_len) => {
            if current_position.get() + 3 + new_len - *G_CODE_AREA.lock().unwrap().get_mut()
                >= get_code_area_size()
            {
                panic!("Code area overflow");
            }

            write_memory(current_position.get(), &[old_len as u8]);
            current_position.set(current_position.get() + 1);

            write_memory(current_position.get(), &[new_len as u8]);
            current_position.set(current_position.get() + 1);

            write_memory(current_position.get(), &[replace_reg as u8]);
            current_position.set(current_position.get() + 1);

            write_memory(current_position.get(), &encoder.take_buffer());
            current_position.set(current_position.get() + new_len);
        }
        Err(e) => {
            println!("{}", e.to_string());
            panic!("Failed to encode instruction block");
        }
    }
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

impl Drop for X8664Mocker {
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

/// A macro to create a new instance of `X8664Mocker` for mocking a function.
///
/// # Arguments
///
/// * `$old_func`: The name of the original function to be mocked. This should be a function name without parentheses.
/// * `$new_func`: The name of the new function to replace the original function. This should be a function name without parentheses.
///
/// # Returns
///
/// A new instance of `X8664Mocker` that can be used to mock the function.
///
/// # Example
///
/// ```rust
/// use mockrs::mock;
/// fn add(a: i64, b: i64) -> i64 {
///     a + b
/// }
/// fn mock_add(_a: i64, _b: i64) -> i64 {
///     100
/// }
/// fn main() {
///     assert!(add(1, 2) == 3);
///     let mocker = mock!(add, mock_add);
///     assert!(add(1, 2) == 100);
///     drop(mocker);
///     assert!(add(1, 2) == 3);
/// }
/// ```
///
/// Note: This macro is only available when targeting the x86_64 architecture.
#[macro_export]
#[cfg(target_arch = "x86_64")]
macro_rules! mock {
    ($old_func:expr, $new_func:expr) => {{
        $crate::X8664Mocker::mock($old_func as usize, $new_func as usize)
    }};
}
