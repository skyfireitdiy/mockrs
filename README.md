# mockrs: 超越 Trait 的 Rust 函数模拟库

![Rust Test Status](https://github.com/skyfireitdiy/mockrs/actions/workflows/rust.yml/badge.svg)
![Crate.io Release](https://img.shields.io/crates/v/mockrs.svg)

## 📌 项目简介

`mockrs` 是一个强大且独具特色的 Rust 函数模拟（Mocking）库，
它突破了传统基于 Trait 模拟的限制，允许您在运行时**模拟（Mock）任何函数**，
包括独立的自由函数、具体实现的方法，甚至是 FFI 外部函数。

在标准的 Rust 测试实践中，我们通常依赖 `mockall` 等优秀的库，
但它们要求被模拟的函数必须是某个 Trait 的一部分。
这在面对无法修改的第三方代码、FFI 接口或需要重构才能测试的旧代码时，
会遇到极大的困难。`mockrs` 正是为了解决这一痛点而生，
它通过底层的运行时挂钩（Runtime Hooking）技术，直接在内存中替换函数实现，
提供了前所未有的灵活性。

## ✨ 核心特性

- **通用函数模拟**：可以模拟任何函数，无需依赖 Trait 或接口。
- **线程安全**：模拟作用域被严格限制在当前线程，绝不影响其他线程的正常执行，让并发测试安全无忧。
- **RAII 风格管理**：模拟的生命周期与一个对象绑定，当对象被 `drop` 时，目标函数将自动恢复其原始行为。
- **简洁的 API**：提供极简的 `mock!` 宏，屏蔽了所有底层复杂性。
- **跨架构支持**：同时支持 `x86_64` 和 `aarch64` 架构。

## 🚀 设计理念与实现原理

`mockrs` 的核心思想是“**全局提问，本地回答**”。
它通过在函数头部插入一条陷阱指令来“劫持”所有调用（全局提问），
然后在一个全局信号处理器中，根据**线程本地存储（Thread-Local Storage）**中的记录来决定
是执行模拟函数还是原始函数（本地回答）。

这种设计巧妙地实现了线程级别的行为隔离，同时利用 CPU 的调试功能和精确的指令重定位技术，保证了操作的安全性和稳定性。

**想深入了解其精妙的底层实现、架构图和技术挑战吗？请阅读我们的[详细方案介绍](doc/方案介绍.md)。**

## 🔧 使用方法

首先，将 `mockrs` 添加到您的 `Cargo.toml` 文件中：

```toml
[dependencies]
mockrs = "0.1" # 请使用 crates.io 上的最新版本
```

### 基础示例

下面是一个模拟简单 `add` 函数的例子：

```rust
use mockrs::mock;

fn add(a: i64, b: i64) -> i64 {
    a + b
}

fn mock_add(_a: i64, _b: i64) -> i64 {
    100
}

fn main() {
    // 原始行为
    assert_eq!(add(1, 2), 3);

    // 在此作用域内，add 函数被模拟
    {
        let _mocker = mock!(add, mock_add);
        assert_eq!(add(1, 2), 100);
    } // _mocker 在这里被 drop，函数行为自动恢复

    assert_eq!(add(1, 2), 3);
}
```

*当 `_mocker` 离开作用域时，`add` 函数的行为会自动恢复。*

## 💡 API 概览

### `mock!` 宏

这是使用 `mockrs` 的主要方式。

- `mock!($old_func:expr, $new_func:expr)`: 创建一个 `Mocker` 实例，
  将原始函数 `$old_func` 的行为替换为 `$new_func`。
  当返回的 `Mocker` 实例被 `drop` 时，模拟会自动解除。

## ⚠️ 安全须知

- `mockrs` 工作在底层，直接操作内存和信号。请确保您模拟的函数与原始函数有兼容的函数签名（参数和返回值类型），否则可能导致未定义行为。
- 更多关于安全性和底层实现的细节，请参考[详细方案介绍](doc/方案介绍.md)。

## 🤝 贡献

欢迎对 `mockrs` 做出贡献！无论是提交 Pull Request 还是创建 Issue 来报告 Bug 或提出新功能建议，我们都非常欢迎。

## 📜 许可证

`mockrs` 使用 MIT 许可证。详情请参阅 `LICENSE` 文件。
