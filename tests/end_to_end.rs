//! Runs the real binary: generates the demo telemetry and checks that the
//! search finds the three injected chains, and only the exact one with the
//! exact-sequence baseline.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_ttpblast");

fn run(args: &[&str]) -> Vec<u8> {
    let out = Command::new(BIN)
        .args(args)
        .output()
        .expect("ttpblast arranca");
    assert!(
        out.status.success(),
        "ttpblast {args:?} falló:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn temp_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("ttpblast-{name}-{}", std::process::id()))
}

#[test]
fn demo_finds_the_three_injected_chains() {
    let dir = temp_dir("e2e");
    let events = dir.join("events.ndjson");
    run(&["synth", "--out", dir.to_str().unwrap()]);
    let out = run(&[
        "search",
        "--query",
        "queries/phishing-lateral.txt",
        "--events",
        events.to_str().unwrap(),
        "--json",
    ]);
    let result: Value = serde_json::from_slice(&out).expect("salida JSON válida");
    let hits = result["hits"].as_array().expect("lista de hits");

    let top: Vec<&str> = hits
        .iter()
        .take(3)
        .map(|h| h["host"].as_str().unwrap())
        .collect();
    for host in ["ws-legal-02", "ws-finance-04", "ws-sales-03"] {
        assert!(
            top.contains(&host),
            "{host} no está entre los 3 primeros: {top:?}"
        );
        let hit = hits.iter().find(|h| h["host"] == host).unwrap();
        assert!(
            hit["evalue"].as_f64().unwrap() < 0.05,
            "{host}: {}",
            hit["evalue"]
        );
    }
    // What comes next is noise: no better than chance.
    assert!(hits[3]["evalue"].as_f64().unwrap() > 1.0, "{}", hits[3]);

    let baseline: Vec<&str> = result["baseline"]["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["host"].as_str().unwrap())
        .collect();
    assert_eq!(baseline, ["ws-legal-02"]);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn reports_missing_files_as_errors() {
    let out = Command::new(BIN)
        .args([
            "search",
            "--query",
            "queries/phishing-lateral.txt",
            "--events",
            "no-existe.ndjson",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no-existe.ndjson"));
}
