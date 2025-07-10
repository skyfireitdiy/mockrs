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

mod arch;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub use arch::*;

/// 用于创建`Mocker`实例的宏
///
/// # 参数
///
/// * `$old_func`: 要模拟的原始函数的名称。这应该是一个不带括号的函数名称。
/// * `$new_func`: 要替换原始函数的新函数的名称。这应该是一个不带括号的函数名称。
///
/// # 返回
///
/// 可用于模拟函数的`Mocker`的新实例。
///
/// # 示例
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
#[macro_export]
macro_rules! mock {
    ($old_func:expr, $new_func:expr) => {{
        $crate::Mocker::mock($old_func as usize, $new_func as usize)
    }};
}
