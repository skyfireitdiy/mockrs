#[cfg(test)]
mod mockrs_tests {
    use mockrs::*;
    use std::thread;

    #[test]
    fn test_mocker_different_thread_ids() {
        // Define the original and mock functions
        fn original_function() -> i32 {
            42
        }

        fn mock_function() -> i32 {
            100
        }

        // Create a mocker for the original function
        let mocker = mock!(original_function, mock_function);

        // Create two threads to call the original function
        let thread1 = thread::spawn(original_function);
        let thread2 = thread::spawn(original_function);

        // Assert that the original function returns the expected value in both threads
        assert_eq!(thread1.join().unwrap(), 42);
        assert_eq!(thread2.join().unwrap(), 42);
        assert_eq!(original_function(), 100);

        // Drop the mocker to restore the original function
        drop(mocker);

        // Assert that the original function returns the expected value after dropping the mocker
        assert_eq!(original_function(), 42);
    }

    #[test]
    fn test_mocker_different_functions() {
        // Define two sets of original and mock functions
        fn original_function1() -> i32 {
            42
        }

        fn mock_function1() -> i32 {
            100
        }

        fn original_function2() -> f64 {
            // println!("this is print");
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

        assert_eq!(thread::spawn(original_function1).join().unwrap(), 42);
        assert_eq!(
            thread::spawn(original_function2).join().unwrap(),
            std::f64::consts::PI
        );

        // Drop the mockers to restore the original functions
        drop(mocker1);
        drop(mocker2);

        // Assert that the original functions return the expected values after dropping the mockers
        assert_eq!(original_function1(), 42);
        assert_eq!(original_function2(), std::f64::consts::PI);
    }

    #[test]
    fn test_mocker_nested_mocks() {
        // Define a set of original and mock functions
        fn original_function1() -> i32 {
            42
        }

        fn mock_function1() -> i32 {
            100
        }

        fn original_function2() -> i32 {
            original_function1()
        }

        fn mock_function2() -> i32 {
            200
        }

        // Create a mocker for the first set of functions
        let mocker1 = mock!(original_function1, mock_function1);

        // Create a mocker for the second set of functions (nested)
        let mocker2 = mock!(original_function2, mock_function2);

        // Assert that the original functions return the expected values
        assert_eq!(original_function1(), 100);
        assert_eq!(original_function2(), 200);

        assert_eq!(thread::spawn(original_function1).join().unwrap(), 42);
        assert_eq!(thread::spawn(original_function2).join().unwrap(), 42);

        // Drop the mockers to restore the original functions
        drop(mocker2);
        drop(mocker1);

        // Assert that the original functions return the expected values after dropping the mockers
        assert_eq!(original_function1(), 42);
        assert_eq!(original_function2(), 42);
    }

    #[test]
    fn test_mocker_multiple_mocks_same_function() {
        // Define a set of original and mock functions
        fn original_function() -> i32 {
            42
        }

        fn mock_function1() -> i32 {
            100
        }

        fn mock_function2() -> i32 {
            200
        }

        // Create a mocker for the original function with the first mock function
        let mocker1 = mock!(original_function, mock_function1);

        // Create a mocker for the original function with the second mock function
        let mocker2 = mock!(original_function, mock_function2);

        // Assert that the original function returns the expected values
        assert_eq!(original_function(), 200);

        assert_eq!(thread::spawn(original_function).join().unwrap(), 42);

        // Drop the mockers to restore the original function
        drop(mocker2);

        assert_eq!(original_function(), 100);
        assert_eq!(thread::spawn(original_function).join().unwrap(), 42);

        drop(mocker1);

        // Assert that the original function returns the expected value after dropping the mockers
        assert_eq!(original_function(), 42);
        assert_eq!(thread::spawn(original_function).join().unwrap(), 42);
    }

    #[test]
    fn test_mocker_drop_behavior() {
        // Define the original and mock functions
        fn original_function() -> i32 {
            42
        }

        fn mock_function() -> i32 {
            100
        }

        // Create a mocker for the original function
        let mocker = mock!(original_function, mock_function);

        // Assert that the original function returns the expected value
        assert_eq!(original_function(), 100);

        // Drop the mocker to restore the original function
        drop(mocker);

        // Assert that the original function returns the expected value after dropping the mocker
        assert_eq!(original_function(), 42);
    }

    #[test]
    fn test_mocker_multiple_mocks_same_function_with_drop() {
        // Define a set of original and mock functions
        fn original_function() -> i32 {
            42
        }

        fn mock_function1() -> i32 {
            100
        }

        fn mock_function2() -> i32 {
            200
        }

        // Create a mocker for the original function with the first mock function
        let mocker1 = mock!(original_function, mock_function1);

        assert_eq!(original_function(), 100);

        // Create a mocker for the original function with the second mock function
        let mocker2 = mock!(original_function, mock_function2);

        // Assert that the original function returns the expected values
        assert_eq!(original_function(), 200);

        // Drop the mockers to restore the original function
        drop(mocker1);

        assert_eq!(original_function(), 200);

        drop(mocker2);

        // Assert that the original function returns the expected value after dropping the mockers
        assert_eq!(original_function(), 42);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_mock_function_with_relative_jump() {
        use std::arch::asm;

        #[inline(never)]
        fn original_function() -> i32 {
            unsafe {
                asm!(
                    "b 1f",        // Branch to label 1
                    "nop",         // This part will be skipped
                    "1:",          // Label 1
                    "mov x0, #42", // Return 42
                );
            }
            // The return value is in x0, which is the standard return register
            // Rust will handle the rest of the function epilogue
            // We need a return statement to satisfy the type checker
            42
        }

        fn mock_function() -> i32 {
            100
        }

        // The assembly function always returns 42
        assert_eq!(original_function(), 42);

        let mocker = mock!(original_function, mock_function);

        // After mocking, it should return 100
        assert_eq!(original_function(), 100);

        drop(mocker);

        // After dropping the mocker, it should return 42 again
        assert_eq!(original_function(), 42);
    }
}
