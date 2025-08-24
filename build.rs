fn main() {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    println!("cargo:rerun-if-changed=tests/asm/x86_64_jcc.S");
    println!("cargo:rerun-if-changed=tests/asm/aarch64_bl.S");
    if arch == "x86_64" {
        cc::Build::new()
            .file("tests/asm/x86_64_jcc.S")
            .compile("jcc_asm");
    } else if arch == "aarch64" {
        cc::Build::new()
            .file("tests/asm/aarch64_bl.S")
            .compile("aarch64_bl_asm");
    }
}
