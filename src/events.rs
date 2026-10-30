//! Loads telemetry: NDJSON (one JSON event per line), Windows event log
//! files (.evtx), or a folder with any number of both. Nested objects are
//! flattened to dotted keys, so `{"process": {"name": "x"}}` and
//! `{"process.name": "x"}` look the same to the rules.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::{evtx, sysmon, time, windows};

/// What a folder is searched for.
const EXTENSIONS: [&str; 4] = ["evtx", "ndjson", "jsonl", "json"];

/// ECS first; then Winlogbeat 7 and 6, and flat Sysmon exports such as
/// OTRF's Security Datasets. Keys keep their case: only values are lowercased.
const HOST_KEYS: [&str; 6] = [
    "host.name",
    "host.hostname",
    "agent.hostname",
    "winlog.computer_name",
    "computer_name",
    "Hostname",
];
/// `UtcTime` is Sysmon's own field, for exports without `@timestamp`.
const TIME_KEYS: [&str; 5] = [
    "@timestamp",
    "timestamp",
    "UtcTime",
    "winlog.event_data.UtcTime",
    "event_data.UtcTime",
];

pub struct Event {
    pub ts: Option<i64>,
    pub host: String,
    /// Flattened fields. Values are lowercased so rules match without caring
    /// about case, as Windows paths and process names usually require.
    pub fields: HashMap<String, String>,
}

impl Event {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }

    pub fn from_json(value: &Value) -> Option<Event> {
        let mut fields = HashMap::new();
        flatten("", value, &mut fields);
        Self::from_fields(fields)
    }

    /// From flat fields with lowercased values, as `flatten` and the .evtx
    /// reader produce them. `None` without a host name.
    pub fn from_fields(mut fields: HashMap<String, String>) -> Option<Event> {
        sysmon::normalize(&mut fields);
        windows::normalize(&mut fields);
        let host = HOST_KEYS.iter().find_map(|k| fields.get(*k))?.clone();
        let ts = TIME_KEYS
            .iter()
            .find_map(|k| fields.get(*k))
            .and_then(|s| time::parse_rfc3339(s));
        Some(Event { ts, host, fields })
    }
}

pub struct Loaded {
    pub events: Vec<Event>,
    /// Lines that were not JSON, records that could not be read, and
    /// events without a host name.
    pub skipped: usize,
}

/// A file (NDJSON or .evtx, told apart by its first bytes) or a folder,
/// whose .evtx, .ndjson, .jsonl and .json files are all read, in name order.
pub fn load(path: &str) -> Result<Loaded, String> {
    let meta = fs::metadata(path)
        .map_err(|e| tr!("no se puede abrir {path}: {e}", "cannot open {path}: {e}"))?;
    if !meta.is_dir() {
        return load_file(Path::new(path));
    }
    let mut files: Vec<PathBuf> = fs::read_dir(path)
        .map_err(|e| tr!("no se puede leer {path}: {e}", "cannot read {path}: {e}"))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| EXTENSIONS.contains(&e.to_lowercase().as_str()))
        })
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(tr!(
            "{path} no tiene ficheros .evtx, .ndjson, .jsonl ni .json",
            "{path} has no .evtx, .ndjson, .jsonl or .json files"
        ));
    }
    let mut all = Loaded {
        events: Vec::new(),
        skipped: 0,
    };
    for file in files {
        let loaded = load_file(&file)?;
        all.events.extend(loaded.events);
        all.skipped += loaded.skipped;
    }
    Ok(all)
}

fn load_file(path: &Path) -> Result<Loaded, String> {
    let shown = path.display();
    let open = |path: &Path| {
        File::open(path)
            .map_err(|e| tr!("no se puede abrir {shown}: {e}", "cannot open {shown}: {e}"))
    };
    let mut magic = [0u8; 8];
    let read = open(path)?.read(&mut magic).unwrap_or(0);
    if evtx::is_evtx(&magic[..read]) {
        let bytes = fs::read(path)
            .map_err(|e| tr!("no se puede leer {shown}: {e}", "cannot read {shown}: {e}"))?;
        let (records, failed) = evtx::records(&bytes);
        let total = records.len();
        let events: Vec<Event> = records.into_iter().filter_map(Event::from_fields).collect();
        let skipped = failed + total - events.len();
        return Ok(Loaded { events, skipped });
    }
    let mut events = Vec::new();
    let mut skipped = 0;
    for (n, line) in BufReader::new(open(path)?).lines().enumerate() {
        let line = line.map_err(|e| format!("{shown}:{}: {e}", n + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(&line)
            .ok()
            .as_ref()
            .and_then(Event::from_json)
        {
            Some(event) => events.push(event),
            None => skipped += 1,
        }
    }
    Ok(Loaded { events, skipped })
}

fn flatten(prefix: &str, value: &Value, out: &mut HashMap<String, String>) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                let key = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten(&key, inner, out);
            }
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().filter_map(scalar).collect();
            if !parts.is_empty() {
                out.insert(prefix.to_string(), parts.join(","));
            }
        }
        other => {
            if let Some(text) = scalar(other) {
                out.insert(prefix.to_string(), text);
            }
        }
    }
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.to_lowercase()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_and_dotted_keys_are_equivalent() {
        let nested: Value = serde_json::from_str(
            r#"{"@timestamp":"2026-10-13T09:14:03Z","host":{"name":"WS-01"},"process":{"name":"CMD.exe","parent":{"name":"winword.exe"}},"destination":{"port":445}}"#,
        )
        .unwrap();
        let dotted: Value = serde_json::from_str(
            r#"{"@timestamp":"2026-10-13T09:14:03Z","host.name":"ws-01","process.name":"cmd.exe","process.parent.name":"WINWORD.EXE","destination.port":445}"#,
        )
        .unwrap();
        let (a, b) = (
            Event::from_json(&nested).unwrap(),
            Event::from_json(&dotted).unwrap(),
        );
        assert_eq!(a.host, "ws-01");
        assert_eq!(a.host, b.host);
        assert_eq!(a.ts, b.ts);
        assert!(a.ts.is_some());
        for key in ["process.name", "process.parent.name", "destination.port"] {
            assert_eq!(a.get(key), b.get(key), "{key}");
        }
        assert_eq!(a.get("destination.port"), Some("445"));
    }

    #[test]
    fn events_without_host_are_rejected() {
        let v: Value = serde_json::from_str(r#"{"process":{"name":"cmd.exe"}}"#).unwrap();
        assert!(Event::from_json(&v).is_none());
    }
}
