fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: build scripts are single-threaded at this point.
    unsafe { std::env::set_var("PROTOC", protoc) };
    println!("cargo:rerun-if-changed=proto");
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/payserver/chain/v1/chain.proto"], &["proto"])?;
    Ok(())
}
