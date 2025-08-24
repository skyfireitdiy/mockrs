#[cfg(target_arch = "x86_64")]
mod jcc_tests {
    use mockrs::mock;
    extern "C" {
        fn jcc_first_je() -> i64;
        fn jcc_call_with_zf1() -> i64;
        fn jcc_call_with_zf0() -> i64;
    }
    extern "C" fn ret_100() -> i64 { 100 }

    #[test]
    fn test_jcc_trampoline_behavior() {
        unsafe {
            // 基线：未安装断点时的真实行为
            assert_eq!(jcc_call_with_zf1(), 7);
            assert_eq!(jcc_call_with_zf0(), 3);
        }

        // 安装断点与蹦床，但当前线程命中 mock；新线程未命中，走蹦床路径
        let _m = mock!(jcc_first_je, ret_100);

        // 新线程（未命中 mock）：应经由蹦床改写的 Jcc 实现原语义
        let handle = std::thread::spawn(|| unsafe {
            (jcc_call_with_zf1(), jcc_call_with_zf0())
        });
        let (taken, not_taken) = handle.join().unwrap();
        assert_eq!(taken, 7);
        assert_eq!(not_taken, 3);

        // 当前线程（命中 mock）：无论条件，均跳转到 ret_100
        unsafe {
            assert_eq!(jcc_call_with_zf1(), 100);
            assert_eq!(jcc_call_with_zf0(), 100);
        }
    }
}
