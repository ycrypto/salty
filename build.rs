extern crate cbindgen;

use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // https://github.com/japaric/heapless/blob/531432b7/build.rs
    let target = std::env::var("TARGET")?;

    if target.starts_with("thumbv7em-") {
        println!("cargo:rustc-cfg=cortex_m3");
    }
    if target.starts_with("thumbv7em-") {
        // want to detect Cortex-M4 in reality, since
        // - the armv7[e]-m docs give no info about cycle counts
        // - want to have UMAAL to exist with constant execution time
        println!("cargo:rustc-cfg=cortex_m4");

        println!("cargo:rerun-if-changed=haase/cortex_m4_mpy_fe25519.S");
        println!("cargo:rerun-if-changed=haase/cortex_m4_sqr_fe25519.S");

        cc::Build::new()
            .file("haase/cortex_m4_mpy_fe25519.S")
            .file("haase/cortex_m4_sqr_fe25519.S")
            .opt_level_str("s")  // probably unnecessary, it's assembly :)
            .compile("haase");
    }

    println!("cargo:rerun-if-changed=build.rs");

    /*
    let bindings = bindgen::Builder::default()
        .header("haase.h")
        .use_core()
        .ctypes_prefix("cty")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("haase.rs"))
        .expect("Couldn't write bindings!");
    */

    // C bindings
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    cbindgen::Builder::new()
      .with_crate(crate_dir)
      .generate()
      .expect("Unable to generate bindings")
      .write_to_file("salty.h");
    Ok(())
}
