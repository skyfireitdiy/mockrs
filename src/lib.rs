//! 该模块提供了一个 `X8664Mocker` 结构体，用于模拟函数调用并拦截。
//! 示例：
//! ```
//! use mockrs::mock;
//! fn add(a: i64, b: i64) -> i64 {
//!     a + b
//! }
//! fn mock_add(_a: i64, _b: i64) -> i64 {
//!     100
//! }
//! fn main() {
//!     assert!(add(1, 2) == 3);
//!     let mocker = mock!(add, mock_add);
//!     assert!(add(1, 2) == 100);
//!     drop(mocker);
//!     assert!(add(1, 2) == 3);
//! }
//! ```

use lazy_static::lazy_static;
use nix::{
    libc::{siginfo_t, ucontext_t, REG_EFL, REG_RIP},
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
    sync::Mutex,
    thread::ThreadId,
};

pub struct X8664Mocker {
    old_func: usize,
}

lazy_static! {
    static ref TRUNK_ADDR_TABLE: Mutex<RefCell<HashMap<usize, usize>>> =
        Mutex::new(RefCell::new(HashMap::new()));
}
static REPLACE_LEN: usize = 8;
static INIT_FLAG: Mutex<OnceCell<()>> = Mutex::new(OnceCell::new());

static CODE_AREA: Mutex<RefCell<usize>> = Mutex::new(RefCell::new(0));

#[derive(Clone, Copy)]
struct InstrPosition {
    orig_addr: usize,
    trunk_addr: usize,
}

static CURRENT_POSITION: Mutex<Cell<usize>> = Mutex::new(Cell::new(0));

lazy_static! {
    static ref THREAD_REPLACE_TABLE: Mutex<HashMap<ThreadId, RefCell<HashMap<usize, usize>>>> =
        Mutex::new(HashMap::new());
}

thread_local! {
    static CURRENT_REPLACE: Cell<InstrPosition> = Cell::new(InstrPosition{orig_addr: 0, trunk_addr: 0});
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

extern "C" fn handle_trap_signal(_: i32, _: *mut siginfo_t, ucontext: *mut c_void) {
    let ctx = ucontext as *mut ucontext_t;
    let rip = (unsafe { *ctx }).uc_mcontext.gregs[REG_RIP as usize] as usize;
    let eflags = (unsafe { *ctx }).uc_mcontext.gregs[REG_EFL as usize];

    if !is_step_mode(eflags) {
        let orig_addr = rip - 1;

        if is_current_thread_mocked(orig_addr) {
            set_ip_reg(ctx, get_new_func_addr(orig_addr));
        } else {
            enter_step_mode(ctx);
            let trunk_addr = get_trunk_addr(orig_addr);
            CURRENT_REPLACE.with(|x| {
                x.set(InstrPosition {
                    orig_addr,
                    trunk_addr,
                });
            });
            set_ip_reg(ctx, trunk_addr);
        }
    } else {
        leave_step_mode(ctx);
        let InstrPosition {
            orig_addr,
            trunk_addr: code_trunk_addr,
        } = CURRENT_REPLACE.with(|x| x.get());
        let old_func_next_instr = orig_addr + (rip - code_trunk_addr);
        set_ip_reg(ctx, old_func_next_instr);
    }
}

fn get_trunk_addr(old_func: usize) -> usize {
    *TRUNK_ADDR_TABLE
        .lock()
        .unwrap()
        .get_mut()
        .get(&old_func)
        .unwrap()
}

fn set_ip_reg(ctx: *mut ucontext_t, new_func_addr: usize) {
    unsafe { (*ctx).uc_mcontext.gregs[REG_RIP as usize] = new_func_addr as i64 };
}

macro_rules! read_thread_local {
    ($name:expr) => {
        $name.lock().unwrap().get(&std::thread::current().id())
    };
}

macro_rules! create_thread_local {
    ($name:expr, $value:expr) => {
        if $name
            .lock()
            .unwrap()
            .get(&std::thread::current().id())
            .is_none()
        {
            $name
                .lock()
                .unwrap()
                .insert(std::thread::current().id(), $value);
        }
    };
}

fn get_new_func_addr(old_func: usize) -> usize {
    *read_thread_local!(THREAD_REPLACE_TABLE)
        .unwrap()
        .borrow_mut()
        .get(&old_func)
        .unwrap()
}

fn is_current_thread_mocked(old_func: usize) -> bool {
    if let Some(thread_info) = read_thread_local!(THREAD_REPLACE_TABLE) {
        thread_info.borrow().get(&old_func).is_some()
    } else {
        false
    }
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

        if !is_mocked(old_func) {
            save_func_trunk(old_func, read_memory(old_func, REPLACE_LEN).as_slice());
            set_mem_writable(old_func, 1);
            write_memory(old_func, [0xcc].as_slice());
            unset_mem_writable(old_func, 1);
        }

        create_thread_local!(THREAD_REPLACE_TABLE, RefCell::new(HashMap::new()));
        read_thread_local!(THREAD_REPLACE_TABLE)
            .unwrap()
            .borrow_mut()
            .insert(old_func, new_func);

        X8664Mocker { old_func }
    }
}

fn save_func_trunk(old_func: usize, trunk: &[u8]) {
    let current_position = CURRENT_POSITION.lock().unwrap();
    TRUNK_ADDR_TABLE
        .lock()
        .unwrap()
        .get_mut()
        .insert(old_func, current_position.get());
    write_memory(current_position.get(), trunk);
    current_position.set(current_position.get() + trunk.len());
}

fn is_mocked(addr: usize) -> bool {
    TRUNK_ADDR_TABLE
        .lock()
        .unwrap()
        .get_mut()
        .contains_key(&addr)
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
    INIT_FLAG.lock().unwrap().get_or_init(|| {
        setup_trap_handler();
        alloc_code_area();
    });
}

fn alloc_code_area() {
    unsafe {
        let code_area = mmap_anonymous(
            None,
            NonZeroUsize::new(0x1000).unwrap(),
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
        )
        .unwrap()
        .as_ptr();
        *CODE_AREA.lock().unwrap().get_mut() = code_area as usize;
        CURRENT_POSITION.lock().unwrap().replace(code_area as usize);
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

fn unset_mem_writable(old_func: usize, len: usize) {
    let (low, high) = get_page_bound(old_func, len);
    unsafe {
        mprotect(
            NonNull::new(low as *mut c_void).unwrap(),
            high - low,
            ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
        )
        .unwrap()
    };
}

impl Drop for X8664Mocker {
    fn drop(&mut self) {
        read_thread_local!(THREAD_REPLACE_TABLE)
            .unwrap()
            .borrow_mut()
            .remove(&self.old_func);
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
