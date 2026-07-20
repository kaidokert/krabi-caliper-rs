fn main() {
    println!("cargo:rustc-check-cfg=cfg(krabi_caliper_armv6m)");

    if std::env::var("TARGET").is_ok_and(|target| target.starts_with("thumbv6m-")) {
        println!("cargo:rustc-cfg=krabi_caliper_armv6m");
    }
}
