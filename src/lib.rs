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

mod r#impl;
pub use r#impl::*;
