#[cfg(target_arch = "aarch64")]
mod aarch64_bl_tests {
    use mockrs::mock;
    extern "C" {
        fn bl_first_bl() -> i64;
    }
    extern "C" fn ret_100() -> i64 { 100 }

    #[test]
    #[ignore]
    fn test_bl_trampoline_behavior() {
        unsafe {
            // 基线：未安装 mock 时，BL 返回 7，然后加 3 => 10
            assert_eq!(bl_first_bl(), 10);
        }

        // 安装 mock，但仅在当前线程生效
        let _m = mock!(bl_first_bl, ret_100);

        // 新线程（未命中 TLS 的 mock）：应走蹦床路径，仍返回 10
        let handle = std::thread::spawn(|| unsafe { bl_first_bl() });
        let val = handle.join().unwrap();
        assert_eq!(val, 10);

        // 当前线程（命中 TLS 的 mock）：直接跳到 ret_100
        unsafe {
            assert_eq!(bl_first_bl(), 100);
        }
    }
}
