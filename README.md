# mockrs Crate Documentation

## Overview

The `mockrs` crate provides a powerful tool for function mocking and interception in Rust, specifically designed for the x86_64 architecture. This utility is particularly useful for testing and debugging purposes, where you need to replace the behavior of a function temporarily.

## Key Features

- **Function Mocking**: Replace the functionality of a function with a mock implementation.
- **Thread-Local Storage**: Keeps track of mocks on a per-thread basis.

## Usage

To use the `mockrs`, include it in your `Cargo.toml` and then import it in your Rust code.

```toml
[dependencies]
mockrs = "1.*" # Replace with the actual version number
```


### Basic Example

Here's a simple example of how to use the `mockrs` to mock the `add` function:

```rust
use mockrs::mock;

fn add(a: i64, b: i64) -> i64 {
    a + b
}

fn mock_add(_a: i64, _b: i64) -> i64 {
    100
}

fn main() {
    assert_eq!(add(1, 2), 3);
    let mocker = mock!(add, mock_add);
    assert_eq!(add(1, 2), 100);
    drop(mocker);
    assert_eq!(add(1, 2), 3);
}
```

### API Reference

#### `X8664Mocker`

The `X8664Mocker` struct is the core of the crate, providing the functionality to mock functions.

- `pub fn mock(old_func: usize, new_func: usize) -> X8664Mocker`: Creates a new instance of `X8664Mocker` to mock the specified function.

#### `mock!` Macro

A convenient macro to create a new `X8664Mocker` instance.

- `mock!($old_func:expr, $new_func:expr)`: Replaces the original function `$old_func` with the new function `$new_func`.

### Safety and Considerations

- The `mockrs` operates at a low level, manipulating memory and handling signals. Use it with caution and ensure that the original and new functions have compatible signatures.
- This crate is designed for use on the x86_64 architecture only.


## Contribution

Contributions to the `mockrs` crate are welcome! Feel free to submit pull requests or create issues for bugs and feature requests.

## License

The `mockrs` crate is licensed under the MIT License. See [LICENSE](LICENSE) for more information.

---

This README is automatically generated based on the provided source code. For more detailed documentation, please refer to the inline comments within the code.
