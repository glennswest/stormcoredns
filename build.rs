fn main() {
    println!("cargo:rerun-if-changed=proto/dns.proto");
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/dns.proto"], &["proto"])
        .expect("compiling proto/dns.proto (protoc required)");
    if let Ok(out) = std::process::Command::new("git").args(["rev-parse", "--short", "HEAD"]).output() {
        if out.status.success() {
            println!("cargo:rustc-env=STORMCOREDNS_GIT_SHA={}", String::from_utf8_lossy(&out.stdout).trim());
        }
    }
}
