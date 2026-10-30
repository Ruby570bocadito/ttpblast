//! Runs the real binary on the demo telemetry: the search finds the injected
//! chains (and the exact baseline only the exact one), each host is judged
//! against its own routine, the results do not depend on the number of
//! threads, and the demo, the English output and the HTML report work.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_ttpblast");

fn output(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("ttpblast arranca")
}

fn run(args: &[&str]) -> String {
    let out = output(args);
    assert!(
        out.status.success(),
        "ttpblast {args:?} falló:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("salida UTF-8")
}

/// Inside target/, where cargo keeps scratch space for integration tests.
fn temp_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("ttpblast-{name}-{}", std::process::id()))
}

/// The demo telemetry, generated once for all the tests that search it.
fn demo_events() -> &'static str {
    static EVENTS: OnceLock<String> = OnceLock::new();
    EVENTS.get_or_init(|| {
        let dir = temp_dir("e2e");
        run(&["synth", "--out", dir.to_str().unwrap()]);
        dir.join("events.ndjson").to_str().unwrap().to_string()
    })
}

fn search_json(query: &str, extra: &[&str]) -> Value {
    let mut args = vec![
        "search",
        "--query",
        query,
        "--events",
        demo_events(),
        "--json",
    ];
    args.extend(extra);
    serde_json::from_str(&run(&args)).expect("salida JSON válida")
}

fn host<'a>(hits: &'a [Value], name: &str) -> &'a Value {
    hits.iter()
        .find(|h| h["host"] == name)
        .unwrap_or_else(|| panic!("{name} no aparece"))
}

#[test]
fn demo_finds_the_three_injected_chains() {
    let result = search_json("queries/phishing-lateral.txt", &[]);
    let hits = result["hits"].as_array().expect("lista de hits");

    let top: Vec<&str> = hits
        .iter()
        .take(3)
        .map(|h| h["host"].as_str().unwrap())
        .collect();
    for name in ["ws-legal-02", "ws-finance-04", "ws-sales-03"] {
        assert!(
            top.contains(&name),
            "{name} no está entre los 3 primeros: {top:?}"
        );
        let evalue = host(hits, name)["evalue"].as_f64().unwrap();
        assert!(evalue < 0.05, "{name}: {evalue}");
    }
    // What comes next is noise: no better than chance.
    assert!(hits[3]["evalue"].as_f64().unwrap() > 1.0, "{}", hits[3]);
    assert_eq!(
        result["summary"]["strong"].as_array().unwrap().len(),
        3,
        "{}",
        result["summary"]
    );

    let baseline: Vec<&str> = result["baseline"]["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["host"].as_str().unwrap())
        .collect();
    assert_eq!(baseline, ["ws-legal-02"]);
}

#[test]
fn each_host_is_judged_against_its_own_routine() {
    // srv-backup-01 compresses and uploads every night: the last two steps
    // of the query are routine there, however well they align.
    let result = search_json(
        "queries/exfiltracion.txt",
        &["--evalue", "1e9", "--max-hits", "100"],
    );
    let hits = result["hits"].as_array().unwrap();
    assert_eq!(hits[0]["host"], "ws-hr-02", "{}", hits[0]);
    assert!(hits[0]["evalue"].as_f64().unwrap() < 0.05, "{}", hits[0]);
    let backup = host(hits, "srv-backup-01");
    assert!(backup["evalue"].as_f64().unwrap() > 1.0, "{backup}");
    assert!(backup["score"].as_i64().unwrap() >= 10, "{backup}");
}

#[test]
fn same_results_with_one_or_many_threads() {
    let mut one = search_json("queries/phishing-lateral.txt", &["--threads", "1"]);
    let mut many = search_json("queries/phishing-lateral.txt", &["--threads", "8"]);
    assert_eq!(one["hits"], many["hits"]);
    one["settings"] = Value::Null;
    many["settings"] = Value::Null;
    assert_eq!(one, many);
}

#[test]
fn english_output_and_html_report() {
    let dir = temp_dir("html");
    std::fs::create_dir_all(&dir).unwrap();
    let report = dir.join("report.html");
    let text = run(&[
        "search",
        "--query",
        "queries/phishing-lateral.txt",
        "--events",
        demo_events(),
        "--details",
        "1",
        "--lang",
        "en",
        "--html",
        report.to_str().unwrap(),
    ]);
    for expected in [
        "Hits with E ≤ 10",
        "Verdict",
        "far beyond chance",
        "this chain",
    ] {
        assert!(text.contains(expected), "falta «{expected}» en:\n{text}");
    }
    assert!(!text.contains('\x1b'), "sin colores fuera de una terminal");

    let html = std::fs::read_to_string(&report).unwrap();
    let data = embedded_json(&html);
    assert_eq!(data["lang"], "en");
    assert_eq!(data["hits"][0]["host"], "ws-legal-02");
    assert!(
        data["hits"][0]["null"]["histogram"]
            .as_array()
            .unwrap()
            .len()
            > 3
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// The JSON inside the report's data block.
fn embedded_json(html: &str) -> Value {
    let start = html.find("id=\"ttpblast-data\">").expect("bloque de datos") + 19;
    let end = start + html[start..].find("</script>").unwrap();
    serde_json::from_str(&html[start..end]).expect("JSON del informe")
}

#[test]
fn demo_grades_itself_against_the_truth() {
    let dir = temp_dir("demo");
    let text = run(&[
        "demo",
        "--out",
        dir.to_str().unwrap(),
        "--details",
        "0",
        "--lang",
        "es",
    ]);
    assert!(text.contains("4 de 4 cadenas"), "{text}");
    assert!(text.contains("Fíjate en srv-backup-01"), "{text}");
    for report in ["informe-phishing-lateral.html", "informe-exfiltracion.html"] {
        assert!(Path::new(&dir).join(report).exists(), "falta {report}");
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn reports_missing_files_as_errors() {
    let out = output(&[
        "search",
        "--query",
        "queries/phishing-lateral.txt",
        "--events",
        "no-existe.ndjson",
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no-existe.ndjson"));
}

#[test]
fn typos_get_a_suggestion() {
    let out = output(&["serch", "--lang", "en"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("did you mean «search»"));
    let out = output(&["search", "--evalu", "3", "--lang", "es"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("--evalue"));
}

#[test]
fn hunt_runs_the_whole_library_and_points_at_the_attacked_hosts() {
    let text = run(&["hunt", "--events", demo_events(), "--lang", "es"]);
    assert!(text.contains("8 consultas"), "{text}");
    assert!(text.contains("3 hosts muy por encima del azar"), "{text}");
    let doc: Value = serde_json::from_str(&run(&["hunt", "--events", demo_events(), "--json"]))
        .expect("JSON de hunt");
    let queries = doc["queries"].as_array().unwrap();
    assert_eq!(queries.len(), 8);
    let phishing = queries
        .iter()
        .find(|q| q["query"] == "phishing-lateral")
        .unwrap();
    assert_eq!(phishing["strong"].as_array().unwrap().len(), 3);
    // Every host that several queries flag is one of the attacked ones.
    let attacked = ["ws-legal-02", "ws-finance-04", "ws-sales-03", "ws-hr-02"];
    let repeated = doc["repeated"].as_array().unwrap();
    assert!(!repeated.is_empty());
    for entry in repeated {
        let host = entry["host"].as_str().unwrap();
        assert!(attacked.contains(&host), "{host} no es un host atacado");
    }
}
