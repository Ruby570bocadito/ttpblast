//! Sysmon events (exported with scripts/export-sysmon.ps1, shipped by
//! Winlogbeat 6 or 7, or flat exports like OTRF's Security Datasets) carry
//! Sysmon's own field names: Image, ParentImage, TargetObject... This fills
//! in the ECS-style fields the alphabet uses. Fields already present are
//! kept, so ECS data passes through untouched.

use std::collections::HashMap;

pub fn normalize(fields: &mut HashMap<String, String>) {
    let Some(id) = event_id(fields) else {
        return;
    };
    let data = |name: &str| -> Option<String> {
        [
            name.to_string(),
            format!("winlog.event_data.{name}"),
            format!("event_data.{name}"),
        ]
        .iter()
        .find_map(|key| fields.get(key))
        .filter(|v| !v.is_empty() && v.as_str() != "-")
        .cloned()
    };
    let process = |key: &str| data(key).map(|path| file_name(&path).to_string());

    let mut derived: Vec<(&str, Option<String>)> = Vec::new();
    match id.as_str() {
        "1" => derived.extend([
            ("event.category", Some("process".into())),
            ("event.action", Some("start".into())),
            ("process.name", process("Image")),
            ("process.parent.name", process("ParentImage")),
        ]),
        "3" => {
            // Inbound connections have this host as the destination, and the
            // alphabet describes what the host itself does: no category, so
            // no symbol encodes them.
            if data("Initiated").as_deref() == Some("false") {
                derived.extend([
                    ("network.direction", Some("inbound".into())),
                    ("process.name", process("Image")),
                ]);
            } else {
                derived.extend([
                    ("event.category", Some("network".into())),
                    ("event.action", Some("connection".into())),
                    ("process.name", process("Image")),
                    ("destination.port", data("DestinationPort")),
                    (
                        "destination.address",
                        data("DestinationHostname").or_else(|| data("DestinationIp")),
                    ),
                ]);
            }
        }
        "10" => derived.extend([
            ("event.category", Some("process".into())),
            ("event.action", Some("access".into())),
            ("process.name", process("SourceImage")),
            ("process.target.name", process("TargetImage")),
        ]),
        "11" => {
            let path = data("TargetFilename");
            let extension = path
                .as_deref()
                .and_then(|p| file_name(p).rsplit_once('.'))
                .map(|(_, ext)| ext.to_string());
            derived.extend([
                ("event.category", Some("file".into())),
                ("event.action", Some("creation".into())),
                ("process.name", process("Image")),
                ("file.path", path),
                ("file.extension", extension),
            ]);
        }
        "12" | "13" | "14" => derived.extend([
            ("event.category", Some("registry".into())),
            ("event.action", Some("modification".into())),
            ("process.name", process("Image")),
            ("registry.path", data("TargetObject")),
        ]),
        _ => return,
    }
    for (key, value) in derived {
        if let Some(value) = value {
            fields.entry(key.to_string()).or_insert(value);
        }
    }
}

/// The Sysmon event ID, from our exporter or from another layout. Other
/// Windows logs reuse the same small numbers, so those events must name
/// Sysmon as their provider or channel.
fn event_id(fields: &HashMap<String, String>) -> Option<String> {
    if let Some(id) = fields.get("sysmon.event_id") {
        return Some(id.clone());
    }
    // (provider or channel, event ID): Winlogbeat 7, Winlogbeat 6, flat exports.
    const LAYOUTS: [(&str, &str); 5] = [
        ("winlog.provider_name", "winlog.event_id"),
        ("winlog.channel", "winlog.event_id"),
        ("source_name", "event_id"),
        ("SourceName", "EventID"),
        ("Channel", "EventID"),
    ];
    LAYOUTS.iter().find_map(|(source, id)| {
        fields
            .get(*source)
            .filter(|s| s.contains("sysmon"))
            .and(fields.get(*id))
            .cloned()
    })
}

/// `c:\windows\system32\cmd.exe` -> `cmd.exe`.
fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use crate::alphabet::Alphabet;
    use crate::events::Event;

    fn encode(json: &str) -> Option<String> {
        let alphabet = Alphabet::default_set();
        let event = Event::from_json(&serde_json::from_str(json).unwrap()).unwrap();
        alphabet
            .encode(&event)
            .map(|s| alphabet.code(s).to_string())
    }

    #[test]
    fn process_creation() {
        let word_spawns_ps = r#"{"@timestamp":"2026-10-17T09:14:03.1234567Z","host.name":"PC-RAFA","sysmon.event_id":1,
            "Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "ParentImage":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"}"#;
        assert_eq!(encode(word_spawns_ps).as_deref(), Some("UEX"));
        let plain_cmd = r#"{"host.name":"pc","sysmon.event_id":1,"Image":"C:\\Windows\\System32\\cmd.exe","ParentImage":"C:\\Windows\\explorer.exe"}"#;
        assert_eq!(encode(plain_cmd).as_deref(), Some("CMD"));
    }

    #[test]
    fn network_only_outbound() {
        let outbound = r#"{"host.name":"pc","sysmon.event_id":3,"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "Initiated":"true","DestinationIp":"10.0.0.5","DestinationHostname":"-","DestinationPort":"445"}"#;
        assert_eq!(encode(outbound).as_deref(), Some("SMB"));
        let inbound = r#"{"host.name":"pc","sysmon.event_id":3,"Image":"System",
            "Initiated":"false","DestinationIp":"10.0.0.9","DestinationPort":"5985"}"#;
        assert_eq!(encode(inbound), None);
    }

    #[test]
    fn files_registry_and_process_access() {
        let dll = r#"{"host.name":"pc","sysmon.event_id":11,"Image":"C:\\Windows\\System32\\certutil.exe",
            "TargetFilename":"C:\\Users\\Public\\x.DLL"}"#;
        assert_eq!(encode(dll).as_deref(), Some("ITT"));
        let run_key = r#"{"host.name":"pc","sysmon.event_id":13,"Image":"C:\\Users\\u\\AppData\\Local\\app.exe",
            "TargetObject":"HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\App"}"#;
        assert_eq!(encode(run_key).as_deref(), Some("RUN"));
        let lsass = r#"{"host.name":"pc","sysmon.event_id":10,"SourceImage":"C:\\Temp\\tool.exe",
            "TargetImage":"C:\\Windows\\system32\\lsass.exe"}"#;
        assert_eq!(encode(lsass).as_deref(), Some("LSA"));
    }

    #[test]
    fn winlogbeat_layout() {
        let sysmon = r#"{"host":{"name":"pc"},"winlog":{"provider_name":"Microsoft-Windows-Sysmon","event_id":"1",
            "event_data":{"Image":"C:\\Windows\\System32\\whoami.exe","ParentImage":"C:\\Windows\\System32\\cmd.exe"}}}"#;
        assert_eq!(encode(sysmon).as_deref(), Some("USR"));
        // Event 1 of another provider is not a Sysmon process creation.
        let other = r#"{"host":{"name":"pc"},"winlog":{"provider_name":"Service Control Manager","event_id":"1",
            "event_data":{"Image":"C:\\Windows\\System32\\whoami.exe"}}}"#;
        assert_eq!(encode(other), None);
    }

    #[test]
    fn flat_and_winlogbeat6_layouts() {
        // Sysmon fields at the root, as in OTRF's Security Datasets.
        let flat = r#"{"@timestamp":"2020-09-21T19:03:22.123Z","Hostname":"WORKSTATION5.theshire.local",
            "SourceName":"Microsoft-Windows-Sysmon","Channel":"Microsoft-Windows-Sysmon/Operational","EventID":1,
            "Image":"C:\\Windows\\System32\\net.exe","ParentImage":"C:\\Windows\\System32\\cmd.exe"}"#;
        assert_eq!(encode(flat).as_deref(), Some("ACD"));
        let event = Event::from_json(&serde_json::from_str(flat).unwrap()).unwrap();
        assert_eq!(event.host, "workstation5.theshire.local");
        assert!(event.ts.is_some());
        // Without @timestamp, Sysmon's UtcTime (UTC, space-separated).
        let utc_only = r#"{"Hostname":"pc","Channel":"Microsoft-Windows-Sysmon/Operational","EventID":1,
            "UtcTime":"2020-09-21 19:03:22.123","Image":"C:\\Windows\\System32\\whoami.exe"}"#;
        let event = Event::from_json(&serde_json::from_str(utc_only).unwrap()).unwrap();
        assert_eq!(event.ts, crate::time::parse_rfc3339("2020-09-21T19:03:22Z"));
        // Security log event 4688 has an Image-like field too, but is not Sysmon.
        let security = r#"{"Hostname":"pc","Channel":"Security","EventID":1,"Image":"C:\\Windows\\System32\\whoami.exe"}"#;
        assert_eq!(encode(security), None);
        let winlogbeat6 = r#"{"computer_name":"PC-6","source_name":"Microsoft-Windows-Sysmon","event_id":10,
            "event_data":{"SourceImage":"C:\\Temp\\x.exe","TargetImage":"C:\\Windows\\System32\\lsass.exe"}}"#;
        assert_eq!(encode(winlogbeat6).as_deref(), Some("LSA"));
    }

    #[test]
    fn existing_ecs_fields_win() {
        let mixed = r#"{"host.name":"pc","sysmon.event_id":1,"process.name":"pwsh.exe","Image":"C:\\x\\cmd.exe"}"#;
        assert_eq!(encode(mixed).as_deref(), Some("PSH"));
    }
}
