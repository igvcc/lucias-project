fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-cdylib-link-arg=/DEF:{manifest_dir}\\xgameruntime.def");
    println!("cargo:rerun-if-changed=xgameruntime.def");
}
