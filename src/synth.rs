//! `ttpblast synth`: synthetic telemetry for the demo. 40 Windows hosts over
//! two weeks: routine activity (most of which no rule encodes), admins whose
//! daily work resembles parts of an intrusion, servers with nightly backups,
//! and three injected chains: one identical to the demo query, one variant
//! (substituted techniques and extra steps) and one cut short. All of it is
//! made up and uses example domains and private addresses.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

use serde_json::{Map, Value, json};

use crate::rng::Rng;
use crate::time;

const START: &str = "2026-10-05T00:00:00Z"; // a Monday
const DAY: i64 = 86_400;
const HOUR: i64 = 3_600;
const MINUTE: i64 = 60;
const DEPARTMENTS: [&str; 7] = ["finance", "legal", "sales", "hr", "eng", "ops", "mkt"];
const WORKSTATIONS: usize = 34;
const OTHER_HOSTS: [&str; 6] = [
    "it-admin-01",
    "it-admin-02",
    "it-admin-03",
    "srv-backup-01",
    "srv-app-01",
    "srv-app-02",
];

/// What happened, with the fields an EDR would log.
#[derive(Clone, Copy)]
enum Kind {
    /// Process start: (process, parent).
    Start(&'static str, &'static str),
    /// Network connection: (process, destination, port).
    Net(&'static str, &'static str, u16),
    /// File creation: (process, path, extension).
    File(&'static str, &'static str, &'static str),
    /// Registry write: (process, key path).
    Reg(&'static str, &'static str),
    /// Process handle opened on another process: (process, target).
    Access(&'static str, &'static str),
}

use Kind::{Access, File as FileWrite, Net, Reg, Start};

/// Everyday events that no symbol of the default alphabet encodes.
const NOISE: [Kind; 14] = [
    Start("chrome.exe", "explorer.exe"),
    Start("outlook.exe", "explorer.exe"),
    Start("winword.exe", "explorer.exe"),
    Start("excel.exe", "explorer.exe"),
    Start("teams.exe", "explorer.exe"),
    Start("notepad.exe", "explorer.exe"),
    Net("chrome.exe", "intranet.example.com", 443),
    Net("chrome.exe", "docs.example.org", 443),
    Net("outlook.exe", "mail.example.com", 443),
    Net("teams.exe", "chat.example.net", 443),
    Net("explorer.exe", "fs01.corp.example", 445),
    FileWrite(
        "winword.exe",
        "c:\\users\\u\\documents\\informe.docx",
        "docx",
    ),
    FileWrite("excel.exe", "c:\\users\\u\\documents\\cuentas.xlsx", "xlsx"),
    FileWrite("chrome.exe", "c:\\users\\u\\downloads\\manual.pdf", "pdf"),
];

/// Legitimate activity that the alphabet *does* encode: (mean per workday, event).
const WORKSTATION_ACTIVITY: [(f64, Kind); 14] = [
    (0.40, Start("cmd.exe", "explorer.exe")),
    (0.50, Start("powershell.exe", "svchost.exe")), // IT management script
    (0.30, Net("powershell.exe", "it-updates.example.com", 443)),
    (0.30, Start("schtasks.exe", "updater.exe")),
    (
        0.05,
        Reg(
            "teams.exe",
            "hkcu\\software\\microsoft\\windows\\currentversion\\run\\teams",
        ),
    ),
    (
        0.03,
        Reg(
            "msiexec.exe",
            "hklm\\system\\currentcontrolset\\services\\vendorsvc",
        ),
    ),
    (0.10, Start("splwow64.exe", "winword.exe")), // printing from Word
    (0.05, Start("systeminfo.exe", "cmd.exe")),
    (0.08, Start("whoami.exe", "cmd.exe")),
    (
        0.03,
        FileWrite(
            "powershell.exe",
            "c:\\programdata\\it\\agent-setup.exe",
            "exe",
        ),
    ),
    (0.03, Access("msmpeng.exe", "lsass.exe")), // antivirus scan
    (0.10, Start("7z.exe", "explorer.exe")),
    (0.05, Start("mstsc.exe", "explorer.exe")),
    (0.05, Start("wscript.exe", "userinit.exe")), // logon script
];

const ADMIN_ACTIVITY: [(f64, Kind); 4] = [
    (1.0, Net("powershell.exe", "it-updates.example.com", 443)),
    (2.0, Start("cmd.exe", "explorer.exe")),
    (1.0, Start("schtasks.exe", "mmc.exe")),
    (0.5, Net("powershell.exe", "fs01.corp.example", 445)),
];

const SERVER_ACTIVITY: [(f64, Kind); 5] = [
    (1.0, Start("schtasks.exe", "svchost.exe")),
    (1.0, Start("powershell.exe", "svchost.exe")),
    (
        0.1,
        Reg(
            "msiexec.exe",
            "hklm\\system\\currentcontrolset\\services\\appsvc",
        ),
    ),
    (0.5, Net("powershell.exe", "it-updates.example.com", 443)),
    (0.05, Access("msmpeng.exe", "lsass.exe")),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Workstation,
    Admin,
    Server,
    Backup,
}

struct Record {
    ts: i64,
    host: usize,
    kind: Kind,
}

struct Scenario {
    label: &'static str,
    host: &'static str,
    /// Index into the list of working days.
    workday: usize,
    /// Seconds after midnight of the first step.
    at: i64,
    /// (symbol the step should encode to, event). An empty code marks a
    /// routine event that happens to fall in the middle of the chain.
    steps: Vec<(&'static str, Kind)>,
}

fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            label: "exacta",
            host: "ws-legal-02",
            workday: 2,
            at: 10 * HOUR + 2 * MINUTE,
            steps: vec![
                ("UEX", Start("powershell.exe", "winword.exe")),
                ("PSH", Start("powershell.exe", "powershell.exe")),
                ("C2W", Net("powershell.exe", "cdn-sync.example.net", 443)),
                (
                    "ITT",
                    FileWrite("powershell.exe", "c:\\users\\public\\libsync.dll", "dll"),
                ),
                (
                    "RUN",
                    Reg(
                        "powershell.exe",
                        "hkcu\\software\\microsoft\\windows\\currentversion\\run\\libsync",
                    ),
                ),
                ("ACD", Start("whoami.exe", "powershell.exe")),
                ("SID", Start("systeminfo.exe", "powershell.exe")),
                ("LSA", Access("rundll32.exe", "lsass.exe")),
                ("SMB", Net("powershell.exe", "10.0.4.23", 445)),
            ],
        },
        Scenario {
            label: "variante",
            host: "ws-finance-04",
            workday: 5,
            at: 9 * HOUR + 14 * MINUTE,
            steps: vec![
                ("UEX", Start("cmd.exe", "winword.exe")),
                ("CMD", Start("cmd.exe", "cmd.exe")),
                ("C2W", Net("rundll32.exe", "cdn-sync.example.net", 443)),
                (
                    "ITT",
                    FileWrite("certutil.exe", "c:\\users\\public\\svc.exe", "exe"),
                ),
                ("TSK", Start("schtasks.exe", "cmd.exe")),
                ("ACD", Start("whoami.exe", "cmd.exe")),
                ("", Start("powershell.exe", "svchost.exe")),
                ("SID", Start("systeminfo.exe", "cmd.exe")),
                ("RSD", Start("nltest.exe", "cmd.exe")),
                ("LSA", Access("rundll32.exe", "lsass.exe")),
                ("WRM", Net("powershell.exe", "10.0.4.31", 5985)),
            ],
        },
        Scenario {
            label: "parcial",
            host: "ws-sales-03",
            workday: 7,
            at: 15 * HOUR + 40 * MINUTE,
            steps: vec![
                ("UEX", Start("powershell.exe", "excel.exe")),
                ("PSH", Start("powershell.exe", "powershell.exe")),
                ("C2W", Net("powershell.exe", "cdn-sync.example.net", 443)),
                (
                    "ITT",
                    FileWrite("powershell.exe", "c:\\users\\public\\libsync.dll", "dll"),
                ),
            ],
        },
    ]
}

pub struct Options {
    pub out: String,
    pub days: i64,
    pub seed: u64,
}

pub fn run(opts: &Options) -> Result<(), String> {
    if opts.days < 10 {
        return Err(
            "--days debe ser al menos 10: los escenarios caen en distintos días laborables".into(),
        );
    }
    let start = time::parse_rfc3339(START).expect("fecha fija válida");
    let hosts = host_names();
    let mut rng = Rng::new(opts.seed);
    let mut records = Vec::new();

    for (host, name) in hosts.iter().enumerate() {
        let role = role_of(name);
        for day in 0..opts.days {
            routine(
                &mut rng,
                role,
                day % 7 < 5,
                start + day * DAY,
                host,
                &mut records,
            );
        }
    }

    let workdays: Vec<i64> = (0..opts.days).filter(|d| d % 7 < 5).collect();
    let mut truth = Vec::new();
    for scenario in scenarios() {
        let host = hosts
            .iter()
            .position(|h| h == scenario.host)
            .ok_or_else(|| format!("el escenario usa un host que no existe: {}", scenario.host))?;
        let mut ts = start + workdays[scenario.workday] * DAY + scenario.at;
        let first = ts;
        let mut chain = Vec::new();
        for (i, &(code, kind)) in scenario.steps.iter().enumerate() {
            if i > 0 {
                ts += rng.range(40, 240);
            }
            records.push(Record { ts, host, kind });
            if !code.is_empty() {
                chain.push(code);
            }
        }
        truth.push(json!({
            "escenario": scenario.label,
            "host": scenario.host,
            "inicio": time::format_rfc3339(first),
            "fin": time::format_rfc3339(ts),
            "pasos": chain,
        }));
    }
    records.sort_by_key(|r| (r.ts, r.host));

    let dir = Path::new(&opts.out);
    fs::create_dir_all(dir).map_err(|e| format!("no se puede crear {}: {e}", dir.display()))?;
    let events_path = dir.join("events.ndjson");
    let file = File::create(&events_path)
        .map_err(|e| format!("no se puede escribir {}: {e}", events_path.display()))?;
    let mut writer = BufWriter::new(file);
    for record in &records {
        writeln!(writer, "{}", to_json(record, &hosts)).map_err(|e| e.to_string())?;
    }
    writer.flush().map_err(|e| e.to_string())?;

    let truth_path = dir.join("truth.json");
    let truth_text = serde_json::to_string_pretty(&truth).map_err(|e| e.to_string())?;
    fs::write(&truth_path, truth_text + "\n")
        .map_err(|e| format!("no se puede escribir {}: {e}", truth_path.display()))?;

    println!(
        "{} eventos sintéticos de {} hosts en {} días → {}",
        records.len(),
        hosts.len(),
        opts.days,
        events_path.display()
    );
    println!(
        "Escenarios inyectados (la verdad, para evaluar) → {}",
        truth_path.display()
    );
    for t in &truth {
        println!(
            "  {:<9} {:<14} {}  {}",
            t["escenario"].as_str().unwrap_or(""),
            t["host"].as_str().unwrap_or(""),
            t["inicio"].as_str().unwrap_or(""),
            t["pasos"]
                .as_array()
                .map(|p| p
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" "))
                .unwrap_or_default()
        );
    }
    Ok(())
}

fn host_names() -> Vec<String> {
    let mut names: Vec<String> = (0..WORKSTATIONS)
        .map(|i| {
            format!(
                "ws-{}-{:02}",
                DEPARTMENTS[i % DEPARTMENTS.len()],
                i / DEPARTMENTS.len() + 1
            )
        })
        .collect();
    names.extend(OTHER_HOSTS.iter().map(|s| s.to_string()));
    names
}

fn role_of(name: &str) -> Role {
    if name.starts_with("ws-") {
        Role::Workstation
    } else if name.starts_with("it-admin") {
        Role::Admin
    } else if name.starts_with("srv-backup") {
        Role::Backup
    } else {
        Role::Server
    }
}

fn routine(
    rng: &mut Rng,
    role: Role,
    workday: bool,
    day_start: i64,
    host: usize,
    out: &mut Vec<Record>,
) {
    let (noise, window) = match (role, workday) {
        (Role::Workstation, true) => (80.0, (8 * HOUR, 18 * HOUR)),
        (Role::Admin, true) => (60.0, (7 * HOUR, 19 * HOUR)),
        (Role::Workstation | Role::Admin, false) => (4.0, (0, DAY)),
        (Role::Server | Role::Backup, _) => (20.0, (0, DAY)),
    };
    let mut push = |rng: &mut Rng, kind: Kind| {
        let ts = day_start + rng.range(window.0, window.1);
        out.push(Record { ts, host, kind });
    };

    for _ in 0..rng.poisson(noise) {
        let kind = NOISE[rng.below(NOISE.len() as u64) as usize];
        push(rng, kind);
    }

    let lists: &[&[(f64, Kind)]] = match role {
        Role::Workstation => &[&WORKSTATION_ACTIVITY],
        Role::Admin => &[&WORKSTATION_ACTIVITY, &ADMIN_ACTIVITY],
        Role::Server | Role::Backup => &[&SERVER_ACTIVITY],
    };
    let scale = if workday || matches!(role, Role::Server | Role::Backup) {
        1.0
    } else {
        0.1
    };
    for &(mean, kind) in lists.iter().flat_map(|l| l.iter()) {
        for _ in 0..rng.poisson(mean * scale) {
            push(rng, kind);
        }
    }

    if role == Role::Admin && workday {
        for _ in 0..rng.poisson(3.0) {
            let start = day_start + rng.range(window.0, window.1);
            admin_session(rng, start, host, out);
        }
    }
    if role == Role::Backup {
        let ts = day_start + HOUR + rng.range(0, 600);
        out.push(Record {
            ts,
            host,
            kind: Start("7z.exe", "backup.exe"),
        });
        let ts = ts + rng.range(300, 900);
        out.push(Record {
            ts,
            host,
            kind: Net("rclone.exe", "backup.example.net", 443),
        });
    }
}

/// An admin checking a machine: PowerShell, some discovery, then a remote
/// connection. Legitimate, but it shares several steps with an intrusion.
fn admin_session(rng: &mut Rng, start: i64, host: usize, out: &mut Vec<Record>) {
    let mut ts = start;
    out.push(Record {
        ts,
        host,
        kind: Start("powershell.exe", "explorer.exe"),
    });
    let discovery = [
        Start("whoami.exe", "powershell.exe"),
        Start("systeminfo.exe", "powershell.exe"),
        Start("nltest.exe", "powershell.exe"),
    ];
    for kind in discovery {
        if rng.unit() < 0.6 {
            ts += rng.range(20, 240);
            out.push(Record { ts, host, kind });
        }
    }
    ts += rng.range(30, 300);
    let remote = match rng.below(3) {
        0 => Net("powershell.exe", "10.0.8.15", 5985),
        1 => Start("mstsc.exe", "explorer.exe"),
        _ => Net("powershell.exe", "fs01.corp.example", 445),
    };
    out.push(Record {
        ts,
        host,
        kind: remote,
    });
}

fn to_json(record: &Record, hosts: &[String]) -> Value {
    let (category, action, fields) = match record.kind {
        Start(process, parent) => (
            "process",
            "start",
            json!({"process": {"name": process, "parent": {"name": parent}}}),
        ),
        Net(process, destination, port) => (
            "network",
            "connection",
            json!({"process": {"name": process}, "destination": {"address": destination, "port": port}}),
        ),
        FileWrite(process, path, extension) => (
            "file",
            "creation",
            json!({"process": {"name": process}, "file": {"path": path, "extension": extension}}),
        ),
        Reg(process, path) => (
            "registry",
            "modification",
            json!({"process": {"name": process}, "registry": {"path": path}}),
        ),
        Access(process, target) => (
            "process",
            "access",
            json!({"process": {"name": process, "target": {"name": target}}}),
        ),
    };
    let mut object = Map::new();
    object.insert("@timestamp".into(), time::format_rfc3339(record.ts).into());
    object.insert("host".into(), json!({"name": hosts[record.host]}));
    object.insert(
        "event".into(),
        json!({"category": category, "action": action}),
    );
    if let Value::Object(rest) = fields {
        object.extend(rest);
    }
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alphabet::Alphabet;
    use crate::events::Event;

    #[test]
    fn scenario_hosts_exist() {
        let hosts = host_names();
        assert_eq!(hosts.len(), 40);
        for s in scenarios() {
            assert!(hosts.iter().any(|h| h == s.host), "{}", s.host);
        }
    }

    #[test]
    fn scenario_steps_encode_to_their_symbols() {
        let alphabet = Alphabet::default_set();
        let hosts = host_names();
        for s in scenarios() {
            for (code, kind) in s.steps {
                let event = Event::from_json(&to_json(
                    &Record {
                        ts: 0,
                        host: 0,
                        kind,
                    },
                    &hosts,
                ))
                .unwrap();
                let got = alphabet
                    .encode(&event)
                    .map(|i| alphabet.code(i).to_string());
                if code.is_empty() {
                    assert!(
                        got.is_some(),
                        "el evento rutinario intercalado también se codifica"
                    );
                } else {
                    assert_eq!(got.as_deref(), Some(code), "{}: {code}", s.label);
                }
            }
        }
    }

    #[test]
    fn noise_is_not_encoded() {
        let alphabet = Alphabet::default_set();
        let hosts = host_names();
        for kind in NOISE {
            let event = Event::from_json(&to_json(
                &Record {
                    ts: 0,
                    host: 0,
                    kind,
                },
                &hosts,
            ))
            .unwrap();
            assert!(alphabet.encode(&event).is_none(), "{:?}", event.fields);
        }
    }
}
