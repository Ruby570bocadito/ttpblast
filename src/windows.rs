//! Windows' own logs, for machines without Sysmon: process creation
//! (Security 4688), registry values written (4657), connections the Windows
//! Filtering Platform allowed (5156) and services installed (System 7045).
//! The first three only exist with the matching audit policy on
//! ("Process Creation", "Registry" with a SACL, "Filtering Platform
//! Connection"). Like `sysmon`, this fills in the ECS-style fields the
//! alphabet uses and keeps any that are already there.

use std::collections::HashMap;

pub fn normalize(fields: &mut HashMap<String, String>) {
    let Some((channel, id)) = channel_and_id(fields) else {
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

    let derived: Vec<(&str, Option<String>)> = match (channel.as_str(), id.as_str()) {
        ("security", "4688") => vec![
            ("event.category", Some("process".into())),
            ("event.action", Some("start".into())),
            ("process.name", process("NewProcessName")),
            // Only from Windows 10 and Server 2016 on.
            ("process.parent.name", process("ParentProcessName")),
        ],
        ("security", "4657") => {
            let key = data("ObjectName").map(|key| {
                // Sysmon and the alphabet say CurrentControlSet.
                let key = key
                    .replace(r"\registry\machine\", r"hklm\")
                    .replace(r"\registry\user\", r"hku\")
                    .replace(r"\controlset001\", r"\currentcontrolset\");
                match data("ObjectValueName") {
                    Some(value) => format!(r"{key}\{value}"),
                    None => key,
                }
            });
            vec![
                ("event.category", Some("registry".into())),
                ("event.action", Some("modification".into())),
                ("process.name", process("ProcessName")),
                ("registry.path", key),
            ]
        }
        // Direction %%14593 is outbound; inbound connections are what other
        // machines do to this one, so they get no category.
        ("security", "5156") if data("Direction").is_some_and(|d| d.contains("14593")) => vec![
            ("event.category", Some("network".into())),
            ("event.action", Some("connection".into())),
            ("process.name", process("Application")),
            ("destination.port", data("DestPort")),
            ("destination.address", data("DestAddress")),
        ],
        // A service installed is a new key under Services: what Sysmon would log.
        ("system", "7045") => vec![
            ("event.category", Some("registry".into())),
            ("event.action", Some("modification".into())),
            ("process.name", Some("services.exe".into())),
            (
                "registry.path",
                data("ServiceName")
                    .map(|name| format!(r"hklm\system\currentcontrolset\services\{name}")),
            ),
            ("service.path", data("ImagePath")),
        ],
        _ => return,
    };
    for (key, value) in derived {
        if let Some(value) = value {
            fields.entry(key.to_string()).or_insert(value);
        }
    }
}

/// (channel, event ID) from an .evtx record or a flat export, Winlogbeat 7
/// or Winlogbeat 6. Channel names are lowercased like every value.
fn channel_and_id(fields: &HashMap<String, String>) -> Option<(String, String)> {
    const LAYOUTS: [(&str, &str); 3] = [
        ("Channel", "EventID"),
        ("winlog.channel", "winlog.event_id"),
        ("log_name", "event_id"),
    ];
    LAYOUTS
        .iter()
        .find_map(|(channel, id)| Some((fields.get(*channel)?.clone(), fields.get(*id)?.clone())))
}

/// `c:\windows\system32\cmd.exe` and `\device\harddiskvolume3\…\cmd.exe` -> `cmd.exe`.
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
    fn process_creation_from_the_security_log() {
        let whoami = r#"{"Hostname":"PC","Channel":"Security","EventID":4688,
            "NewProcessName":"C:\\Windows\\System32\\whoami.exe","ParentProcessName":"C:\\Windows\\System32\\cmd.exe"}"#;
        assert_eq!(encode(whoami).as_deref(), Some("USR"));
        let from_word = r#"{"winlog":{"channel":"Security","event_id":"4688","computer_name":"PC",
            "event_data":{"NewProcessName":"C:\\Windows\\System32\\cmd.exe","ParentProcessName":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"}}}"#;
        assert_eq!(encode(from_word).as_deref(), Some("UEX"));
        // Another log with the same ID is not a process creation.
        let other = r#"{"Hostname":"PC","Channel":"Application","EventID":4688,"NewProcessName":"C:\\x\\whoami.exe"}"#;
        assert_eq!(encode(other), None);
    }

    #[test]
    fn registry_network_and_services() {
        let run_key = r#"{"Hostname":"PC","Channel":"Security","EventID":4657,"ProcessName":"C:\\Users\\u\\evil.exe",
            "ObjectName":"\\REGISTRY\\USER\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","ObjectValueName":"updater"}"#;
        assert_eq!(encode(run_key).as_deref(), Some("RUN"));
        let smb = r#"{"Hostname":"PC","Channel":"Security","EventID":5156,"Direction":"%%14593",
            "Application":"\\device\\harddiskvolume3\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
            "DestAddress":"10.0.4.23","DestPort":"445"}"#;
        assert_eq!(encode(smb).as_deref(), Some("SMB"));
        let inbound = smb.replace("%%14593", "%%14592");
        assert_eq!(encode(&inbound), None);
        let service = r#"{"Hostname":"PC","Channel":"System","EventID":7045,"ServiceName":"PSEXESVC",
            "ImagePath":"%SystemRoot%\\PSEXESVC.exe"}"#;
        assert_eq!(encode(service).as_deref(), Some("SVC"));
    }
}
