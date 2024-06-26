use mockrs::mock;

fn add(a: i32, b: i32) -> i32 {
    a + b
}

fn mock_add() -> i32 {
    100
}

fn main() {
    let m = mock!(add, mock_add);
    println!("1 + 2 = {}", add(1, 2));
    drop(m);
    println!("1 + 2 = {}", add(1, 2)); // should print 100
}
