fn main() {
    tonic_build::configure()
        .build_server(false) // client only — no server stub
        .compile_protos(&["proto/service.proto"], &["proto"])
        .expect("tonic_build::compile_protos failed");
}
