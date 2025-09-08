fn main() {
    // Garante que o build.rs seja re-executado se mudar
    println!("cargo:rerun-if-changed=build.rs");
}