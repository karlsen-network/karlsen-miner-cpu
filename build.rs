fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-changed=src/asm");
    tonic_build::configure()
        .build_server(false)
        .compile_protos(&["proto/rpc.proto", "proto/messages.proto"], &["proto"])?;
    Ok(())
}
