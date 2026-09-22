fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Verbatim copies of Acadia-Instrumentation's published contract protos
    // (proto schema v3; see contracts/device-contract-v1.json there and the
    // drift-guard test in tests/proto_contract.rs). istate.proto imports
    // telemetry/faults/logmanager, so the full import set is compiled.
    tonic_build::configure()
        .build_client(true)
        .build_server(false)
        .compile_protos(
            &[
                "proto/common.proto",
                "proto/telemetry.proto",
                "proto/faults.proto",
                "proto/logmanager.proto",
                "proto/istate.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
