//! Loads telemetry as NDJSON (one JSON event per line). Nested objects are
//! flattened to dotted keys, so `{"process": {"name": "x"}}` and
//! `{"process.name": "x"}` look the same to the rules.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

use serde_json::Value;

use crate::{sysmon, time};

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
        sysmon::normalize(&mut fields);
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
    /// Lines that were not JSON or had no host name.
    pub skipped: usize,
}

pub fn load_ndjson(path: &str) -> Result<Loaded, String> {
    let file = File::open(path)
        .map_err(|e| tr!("no se puede abrir {path}: {e}", "cannot open {path}: {e}"))?;
    let mut events = Vec::new();
    let mut skipped = 0;
    for (n, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| format!("{path}:{}: {e}", n + 1))?;
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
