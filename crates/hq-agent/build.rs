//! Build script: generate tonic client code from the canonical HQ agent.proto.
//!
//! Source of truth: Acadia-HQ `proto/acadiahq/agent.proto`. This copy carries a
//! provenance header; HQ and the device must move together for any contract
//! change (doc/hq-pairing-contract.md §Compatibility gate).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "proto/acadiahq/agent.proto";
    println!("cargo:rerun-if-changed={proto}");
    tonic_build::configure()
        .build_client(false) // the RPC is named Connect — collides with the
        .build_server(false) // generated client constructor; we hand-write the
        // client wrapper in GrpcConnector instead
        .compile_protos(&[proto], &["proto"])?;
    Ok(())
}
