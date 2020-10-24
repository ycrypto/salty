use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {

    println!("cargo:rerun-if-changed=build.rs");

    // Cortex-M33 is compatible with Cortex-M4 and its DSP extension instruction UMAAL.
    let target = env::var("TARGET")?;
    let cortex_m4 = target.starts_with("thumbv7em") || target.starts_with("thumbv8m.main");
    let fast_cortex_m4 = cortex_m4 && !cfg!(feature = "slow-motion");

    if fast_cortex_m4 {
        // According to the ARMv7-M Architecture Reference Manual,
        // there are two architecture extensions:
        // - the DSP extension: this is what we need, it is also called
        //   "an ARMv7E-M implementation".
        // - the floating-extension: we don't use this
        //
        // The Cortex-M4 processor implements the ARMV7E-M architecture,
        // and according to its Technical Reference Manual (section 3.3.1),
        // the UMAAL instruction takes exactly 1 cycle.
        //
        // In the ARMv8-M Architecture Reference Manual, we read that
        // there are several extensions: main, security, floating-point,
        // DSP,... and that the main extension is a prerequisite for the
        // DSP extension. The Cortex-M33 Technical Reference Manual (section B1.3)
        // states that the DSP extension is optional, so technically
        // `thumbv8m.main-none-eabi[hf]` is not sufficiently specified.
        // It does *not* contain any data on the number of cycles for UMAAL.
        //
        // We treat Cortex-M33 as Cortex-M4 with possibly extra features.

        let target = std::env::var("TARGET")?;

        if !(target.starts_with("thumbv7em") || target.starts_with("thumbv8m.main")) {
            panic!(concat!(
                "Target `{}` is not a Cortex-M processor with the DSP extension.\n",
                "Try `--target thumbv7em-none-eabi` or `--target thumbv8m.main-none-eabi`\n",
            ), target);
        }

        let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
        std::fs::copy("bin/salty-asm.a", out_dir.join("libsalty-asm.a")).unwrap();

        println!("cargo:rustc-link-lib=static={}", "salty-asm");
        println!("cargo:rustc-link-search={}", out_dir.display());

        println!("cargo:rerun-if-changed=bin/salty-asm.a");

        println!("cargo:rustc-cfg=haase");
    } else {
        println!("cargo:rustc-cfg=tweetnacl");
    }

    Ok(())
}
