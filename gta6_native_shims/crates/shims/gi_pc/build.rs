fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-cdylib-link-arg=/DEF:{manifest_dir}\\gi_pc.def");
    println!("cargo:rerun-if-changed=gi_pc.def");
}
