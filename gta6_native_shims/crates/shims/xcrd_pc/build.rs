fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-cdylib-link-arg=/DEF:{manifest_dir}\\xcrd_pc.def");
    println!("cargo:rerun-if-changed=xcrd_pc.def");
}
