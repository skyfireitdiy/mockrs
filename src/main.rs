use mockrs::*;
use std::thread;

fn main() {
    // Define two sets of original and mock functions
    fn original_function1() -> i32 {
        42
    }

    fn mock_function1() -> i32 {
        100
    }

    fn original_function2() -> f64 {
        std::f64::consts::PI
    }

    fn mock_function2() -> f64 {
        2.71
    }

    // Create a mocker for the first set of functions
    let mocker1 = mock!(original_function1, mock_function1);

    // Create a mocker for the second set of functions
    let mocker2 = mock!(original_function2, mock_function2);

    // Assert that the original functions return the expected values
    assert_eq!(original_function1(), 100);
    assert_eq!(original_function2(), 2.71);
    println!("Mocked functions return the correct values.");

    assert_eq!(thread::spawn(original_function1).join().unwrap(), 42);
    assert_eq!(thread::spawn(original_function2).join().unwrap(), std::f64::consts::PI);
    println!("Functions in new threads return original values.");

    // Drop the mockers to restore the original functions
    drop(mocker1);
    drop(mocker2);

    // Assert that the original functions return the expected values after dropping the mockers
    assert_eq!(original_function1(), 42);
    assert_eq!(original_function2(), std::f64::consts::PI);
    println!("Restored functions return the original values.");
}
