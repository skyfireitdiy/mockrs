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
        let thread1 = thread::spawn(|| original_function());
        let thread2 = thread::spawn(|| original_function());

        // Assert that the original function returns the expected value in both threads
        assert_eq!(thread1.join().unwrap(), 42);
        assert_eq!(thread2.join().unwrap(), 42);

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
            println!("this is print");
            3.14
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

        // Drop the mockers to restore the original functions
        drop(mocker1);
        drop(mocker2);

        // Assert that the original functions return the expected values after dropping the mockers
        assert_eq!(original_function1(), 42);
        assert_eq!(original_function2(), 3.14);
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

        // Drop the mockers to restore the original function
        drop(mocker2);
        drop(mocker1);

        // Assert that the original function returns the expected value after dropping the mockers
        assert_eq!(original_function(), 42);
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
}
