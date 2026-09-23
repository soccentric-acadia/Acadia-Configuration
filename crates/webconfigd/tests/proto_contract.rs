//! Proto contract drift guard (task 009, P1.3).
//!
//! `proto/*.proto` are VERBATIM copies of Acadia-Instrumentation's published
//! device contract (proto schema v3). A hand edit here silently breaks the
//! wire contract — the failure mode that produced task 009 findings C2/C4/C5
//! (a trimmed, divergent copy that could not call 13 of 17 ConfigurationApi
//! RPCs and mis-modeled HealthScoreReply). This test pins:
//!
//! 1. the SHA-256 of every copied file, against the values recorded at copy
//!    time from `Acadia-Instrumentation/proto/`; when Instrumentation changes
//!    its protos, re-copy and update the constants here in the same change;
//! 2. the service surface of `ConfigurationApi` (all 17 RPCs) by text scan.

use sha2::Digest;

const PINNED: &[(&str, &str)] = &[
    (
        "common.proto",
        "2279530e2fb5ec160e72aa1592b0dd02a1fa48f599893bbec85c760f6376752b",
    ),
    (
        "istate.proto",
        "01966126ec746425c7e4b7aebdc00def47f20d9c46e2062847debcb5e7a6e617",
    ),
    (
        "telemetry.proto",
        "11383024a4b87aaa46b926f84b0c961f9f298ec024b14d9203afba355b44ab76",
    ),
    (
        "faults.proto",
        "fb30837940e64d4c021658e60b4d6f1a594280bbc6450f40d02813b338dbf84e",
    ),
    (
        "logmanager.proto",
        "94624bbebd48189190dd33945c0ceb9f17281fe03ea2868ee1f975209d0b868b",
    ),
];

/// Every RPC the published `ConfigurationApi` contract carries. istate
/// implements all of them; a copy that drops one silently strands that call.
const REQUIRED_RPCS: &[&str] = &[
    "Heartbeat",
    "GetPeerStatus",
    "ListOperations",
    "Control",
    "GetSystemInfo",
    "GetConfig",
    "SetConfig",
    "ListSpokes",
    "SpokeControl",
    "Reset",
    "StreamEvents",
    "StreamLogs",
    "GetHealthScore",
    "GetEnrollmentStatus",
    "RotateKey",
    "RelayCommand",
    "Budgets",
    "StreamDeviceData",
];

fn proto_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"))
        .join("proto")
}

#[test]
fn proto_copies_match_the_published_instrumentation_contract() {
    let dir = proto_dir();
    for (name, pinned_sha) in PINNED {
        let text = std::fs::read_to_string(dir.join(name))
            .unwrap_or_else(|e| panic!("missing contract proto copy {name}: {e}"));
        let digest = format!("{:x}", sha2::Sha256::digest(text.as_bytes()));
        assert_eq!(
            digest, *pinned_sha,
            "{name} diverges from the Acadia-Instrumentation contract; \
             re-copy it verbatim and update the pin here in the same change"
        );
    }
}

#[test]
fn configuration_api_surface_is_complete() {
    let istate = std::fs::read_to_string(proto_dir().join("istate.proto")).expect("istate.proto");
    // Bound the scan to the ConfigurationApi service block so HqPeer/Application
    // RPCs do not satisfy the check.
    let start = istate
        .find("service ConfigurationApi")
        .expect("ConfigurationApi service must exist");
    let end = istate[start..]
        .find('}')
        .map(|off| start + off)
        .expect("service block terminated");
    let block = &istate[start..end];
    for rpc in REQUIRED_RPCS {
        assert!(
            block.contains(&format!("rpc {rpc}(")),
            "ConfigurationApi is missing rpc {rpc} — the proto copy is stale"
        );
    }
}
