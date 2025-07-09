use mockrs::mock;

fn add(a: i32, b: i32) -> i32 {
    a + b
}

fn mock_add(a: i32, b: i32) -> i32 {
    println!("mock_add called with: a={}, b={}", a, b);
    100
}

fn main() {
    println!("Original add(1, 2) = {}", add(1, 2));

    let _mocker = mock!(add, mock_add);

    println!("Mocked add(1, 2) = {}", add(1, 2));
}
