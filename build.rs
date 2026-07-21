fn main() {
    println!("cargo:rustc-check-cfg=cfg(krabi_caliper_armv6m)");
    println!("cargo:rustc-check-cfg=cfg(krabi_caliper_armv7m)");
    println!("cargo:rustc-check-cfg=cfg(krabi_caliper_armv7em)");
    println!("cargo:rustc-check-cfg=cfg(krabi_caliper_armv8m_base)");
    println!("cargo:rustc-check-cfg=cfg(krabi_caliper_armv8m_main)");

    if let Ok(target) = std::env::var("TARGET") {
        let architecture = if target.starts_with("thumbv6m-") {
            Some("krabi_caliper_armv6m")
        } else if target.starts_with("thumbv7m-") {
            Some("krabi_caliper_armv7m")
        } else if target.starts_with("thumbv7em-") {
            Some("krabi_caliper_armv7em")
        } else if target.starts_with("thumbv8m.base-") {
            Some("krabi_caliper_armv8m_base")
        } else if target.starts_with("thumbv8m.main-") {
            Some("krabi_caliper_armv8m_main")
        } else {
            None
        };
        if let Some(architecture) = architecture {
            println!("cargo:rustc-cfg={architecture}");
        }
    }
}
