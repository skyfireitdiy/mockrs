use lazy_static::lazy_static;
use nix::{
    libc::*,
    sys::mman::{mmap_anonymous, mprotect, MapFlags, ProtFlags},
};
use std::{
    cell::{Cell, OnceCell, RefCell},
    collections::HashMap,
    ffi::c_void,
    num::NonZeroUsize,
    ptr::NonNull,
    sync::Mutex,
};

/// `Mocker`结构体，用于模拟函数
pub struct Mocker {
    pub old_func: usize,
    pub new_func: usize,
}

lazy_static! {
    pub static ref G_TRUNK_ADDR_TABLE: Mutex<RefCell<HashMap<usize, usize>>> =
        Mutex::new(RefCell::new(HashMap::new()));
}

pub static G_REPLACE_LEN: usize = 16;
pub static G_INIT_FLAG: Mutex<OnceCell<()>> = Mutex::new(OnceCell::new());

pub static G_CODE_AREA: Mutex<RefCell<usize>> = Mutex::new(RefCell::new(0));

pub const PAGE_SIZE: usize = 4096;
pub const DEFAULT_CODE_AREA_SIZE: usize = 8 * PAGE_SIZE;

/// `Droper`结构体，用于释放资源
pub struct Droper {}

#[allow(dead_code)]
pub static G_DROPER: Droper = Droper {};

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

pub static G_CURRENT_POSITION: Mutex<Cell<usize>> = Mutex::new(Cell::new(0));

thread_local! {
    pub static G_THREAD_REPLACE_TABLE: RefCell<HashMap<usize, Vec<usize>>> = RefCell::new(HashMap::new());
}

/// 获取备份指令地址
pub fn get_bak_instruction_addr(old_func: usize) -> usize {
    *G_TRUNK_ADDR_TABLE
        .lock()
        .unwrap()
        .borrow()
        .get(&old_func)
        .unwrap()
}

/// 获取新函数地址
pub fn get_new_func_addr(old_func: usize) -> usize {
    G_THREAD_REPLACE_TABLE.with(|x| *x.borrow().get(&old_func).unwrap().last().unwrap())
}

/// 判断当前线程是否被模拟
pub fn is_current_thread_mocked(old_func: usize) -> bool {
    G_THREAD_REPLACE_TABLE.with(|x| x.borrow().get(&old_func).is_some())
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

/// 读取内存
pub fn read_memory(addr: usize, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    unsafe {
        std::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), len);
    }
    buf
}

/// 获取代码区域大小
pub fn get_code_area_size() -> usize {
    std::env::var("MOCKRS_CODE_AREA_SIZE_IN_PAGE")
        .map(|x| x.parse::<usize>().unwrap() * PAGE_SIZE)
        .unwrap_or(DEFAULT_CODE_AREA_SIZE)
}

/// 分配代码区域
pub fn alloc_code_area() {
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

/// 获取页面边界
pub fn get_page_bound(addr: usize, len: usize) -> (usize, usize) {
    (
        addr & !(PAGE_SIZE - 1),
        (addr + len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1),
    )
}

/// 设置内存可写
pub fn set_mem_writable(old_func: usize, len: usize) {
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
