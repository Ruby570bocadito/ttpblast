//! `ttpblast synth`: synthetic telemetry for the demo. 40 Windows hosts over
//! two weeks: routine activity (most of which no rule encodes), admins whose
//! daily work resembles parts of an intrusion, a backup server that
//! compresses and uploads data every night, and four injected chains: one
//! identical to the demo query, one variant (substituted techniques and extra
//! steps), one cut short, and a data theft that looks a lot like the backup
//! server's routine. All of it is made up and uses example domains and
//! private addresses.

use std::fs::{self, File};
use std::io::{BufWriter, Write};

use serde_json::{Map, Value, json};

use crate::i18n::{self, t};
use crate::rng::{self, Rng};
use crate::time;
use crate::ui::{Style, paint};

pub const OUT: &str = "data/demo";
pub const DAYS: i64 = 14;
pub const SEED: u64 = 7;

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

// Routine activity added in v0.2, for the symbols v0.2 added: tools as
// ordinary as net.exe or ipconfig.exe must not look rare in the demo.
const WORKSTATION_ACTIVITY_V2: [(f64, Kind); 4] = [
    (0.15, Start("net.exe", "cmd.exe")), // `net use` in logon scripts
    (0.10, Start("ipconfig.exe", "cmd.exe")),
    (0.05, Start("tasklist.exe", "cmd.exe")),
    (0.03, Start("netstat.exe", "cmd.exe")),
];

const ADMIN_ACTIVITY_V2: [(f64, Kind); 5] = [
    (1.0, Start("net.exe", "powershell.exe")),
    (0.5, Start("ipconfig.exe", "powershell.exe")),
    (0.3, Start("tasklist.exe", "powershell.exe")),
    (0.2, Start("netstat.exe", "powershell.exe")),
    (0.2, Start("wevtutil.exe", "powershell.exe")),
];

/// What an attacker (or chance) might slip between two steps of a chain to
/// hide it: ordinary commands that the alphabet does encode.
const PADDING: [Kind; 8] = [
    Start("cmd.exe", "explorer.exe"),
    Start("powershell.exe", "svchost.exe"),
    Start("schtasks.exe", "updater.exe"),
    Start("7z.exe", "explorer.exe"),
    Start("ipconfig.exe", "cmd.exe"),
    Start("tasklist.exe", "cmd.exe"),
    Start("wscript.exe", "userinit.exe"),
    Start("mstsc.exe", "explorer.exe"),
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
    label_en: &'static str,
    /// The query (file stem in `queries/`) that this chain is a version of.
    query: &'static str,
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
            label_en: "exact",
            query: "phishing-lateral",
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
                ("USR", Start("whoami.exe", "powershell.exe")),
                ("SID", Start("systeminfo.exe", "powershell.exe")),
                ("LSA", Access("rundll32.exe", "lsass.exe")),
                ("SMB", Net("powershell.exe", "10.0.4.23", 445)),
            ],
        },
        Scenario {
            label: "variante",
            label_en: "variant",
            query: "phishing-lateral",
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
                ("USR", Start("whoami.exe", "cmd.exe")),
                ("", Start("powershell.exe", "svchost.exe")),
                ("SID", Start("systeminfo.exe", "cmd.exe")),
                ("RSD", Start("nltest.exe", "cmd.exe")),
                ("LSA", Access("rundll32.exe", "lsass.exe")),
                ("WRM", Net("powershell.exe", "10.0.4.31", 5985)),
            ],
        },
        Scenario {
            label: "parcial",
            label_en: "partial",
            query: "phishing-lateral",
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
        // Friday, half past five: the office empties and someone packs up
        // HR's files. The last two steps are what srv-backup-01 does every
        // night; only the host's own history tells them apart.
        Scenario {
            label: "exfiltración",
            label_en: "exfiltration",
            query: "exfiltracion",
            host: "ws-hr-02",
            workday: 4,
            at: 17 * HOUR + 31 * MINUTE,
            steps: vec![
                ("USR", Start("whoami.exe", "cmd.exe")),
                ("ACD", Start("net.exe", "cmd.exe")),
                ("RSD", Start("nltest.exe", "cmd.exe")),
                ("ARC", Start("rar.exe", "cmd.exe")),
                ("EXF", Net("rclone.exe", "storage.example.org", 443)),
            ],
        },
    ]
}

pub struct Options {
    pub out: String,
    pub days: i64,
    pub seed: u64,
    /// Ordinary commands slipped between consecutive steps of each injected
    /// chain, to measure how much it takes to hide one.
    pub padding: usize,
}

/// An injected chain: the ground truth to grade a search against.
pub struct Truth {
    pub label: &'static str,
    pub label_en: &'static str,
    pub query: &'static str,
    pub host: &'static str,
    pub start: i64,
    pub end: i64,
    pub steps: Vec<&'static str>,
}

impl Truth {
    pub fn label(&self) -> &'static str {
        t(self.label, self.label_en)
    }
}

pub struct Generated {
    pub events_path: String,
    pub truth_path: String,
    pub events: usize,
    pub hosts: usize,
    pub truth: Vec<Truth>,
}

pub fn run(opts: &Options) -> Result<(), String> {
    let g = generate(opts)?;
    println!(
        "{}",
        tr!(
            "{} eventos sintéticos de {} hosts en {} días → {}",
            "{} synthetic events from {} hosts over {} days → {}",
            i18n::count(g.events),
            g.hosts,
            opts.days,
            g.events_path
        )
    );
    println!(
        "{}",
        tr!(
            "Cadenas inyectadas (la verdad, para evaluar) → {}",
            "Injected chains (the truth, to grade a search) → {}",
            g.truth_path
        )
    );
    print_truth(&g.truth);
    Ok(())
}

pub fn print_truth(truth: &[Truth]) {
    for chain in truth {
        println!(
            "  {:<13} {:<14} {}  {}",
            chain.label(),
            chain.host,
            paint(time::format_human(chain.start), Style::Quiet),
            paint(chain.steps.join(" "), Style::Query)
        );
    }
}

pub fn generate(opts: &Options) -> Result<Generated, String> {
    if opts.days < 10 {
        return Err(tr!(
            "--days debe ser al menos 10: los escenarios caen en distintos días laborables",
            "--days must be at least 10: the scenarios fall on different working days"
        ));
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
    // Activity added later draws from its own streams, so for a given seed
    // the events of earlier versions stay exactly the same (and so do the
    // numbers published with them).
    let mut later = Rng::new(opts.seed ^ rng::fnv1a("rutina v0.2"));
    for (host, name) in hosts.iter().enumerate() {
        let role = role_of(name);
        for day in 0..opts.days {
            routine_v2(
                &mut later,
                role,
                day % 7 < 5,
                start + day * DAY,
                host,
                &mut records,
            );
        }
    }

    let workdays: Vec<i64> = (0..opts.days).filter(|d| d % 7 < 5).collect();
    let mut padding = Rng::new(opts.seed ^ rng::fnv1a("relleno"));
    let mut truth = Vec::new();
    for scenario in scenarios() {
        let host = hosts
            .iter()
            .position(|h| h == scenario.host)
            .expect("los escenarios usan hosts que existen");
        let mut ts = start + workdays[scenario.workday] * DAY + scenario.at;
        let first = ts;
        let mut chain = Vec::new();
        for (i, &(code, kind)) in scenario.steps.iter().enumerate() {
            if i > 0 {
                let previous = ts;
                ts += rng.range(40, 240);
                // Padding goes evenly between the two steps, so the chain's
                // own times are the same with or without it.
                for k in 1..=opts.padding as i64 {
                    let at = previous + (ts - previous) * k / (opts.padding as i64 + 1);
                    let kind = PADDING[padding.below(PADDING.len() as u64) as usize];
                    records.push(Record { ts: at, host, kind });
                }
            }
            records.push(Record { ts, host, kind });
            if !code.is_empty() {
                chain.push(code);
            }
        }
        truth.push(Truth {
            label: scenario.label,
            label_en: scenario.label_en,
            query: scenario.query,
            host: scenario.host,
            start: first,
            end: ts,
            steps: chain,
        });
    }
    records.sort_by_key(|r| (r.ts, r.host));

    fs::create_dir_all(&opts.out).map_err(|e| {
        tr!(
            "no se puede crear {}: {e}",
            "cannot create {}: {e}",
            opts.out
        )
    })?;
    let events_path = join(&opts.out, "events.ndjson");
    let file = File::create(&events_path).map_err(|e| {
        tr!(
            "no se puede escribir {events_path}: {e}",
            "cannot write {events_path}: {e}"
        )
    })?;
    let mut writer = BufWriter::new(file);
    for record in &records {
        writeln!(writer, "{}", to_json(record, &hosts)).map_err(|e| e.to_string())?;
    }
    writer.flush().map_err(|e| e.to_string())?;

    let truth_path = join(&opts.out, "truth.json");
    let truth_json: Vec<Value> = truth
        .iter()
        .map(|chain| {
            json!({
                "escenario": chain.label,
                "consulta": chain.query,
                "host": chain.host,
                "inicio": time::format_rfc3339(chain.start),
                "fin": time::format_rfc3339(chain.end),
                "pasos": chain.steps,
                "relleno": opts.padding,
            })
        })
        .collect();
    let truth_text = serde_json::to_string_pretty(&truth_json).map_err(|e| e.to_string())?;
    fs::write(&truth_path, truth_text + "\n").map_err(|e| {
        tr!(
            "no se puede escribir {truth_path}: {e}",
            "cannot write {truth_path}: {e}"
        )
    })?;

    Ok(Generated {
        events_path,
        truth_path,
        events: records.len(),
        hosts: hosts.len(),
        truth,
    })
}

/// `dir` + `name` with the separator the user already typed, so "data/demo"
/// gives "data/demo/events.ndjson" on Windows too (which accepts both).
pub fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        return name.to_string();
    }
    if dir.ends_with(['/', '\\']) {
        return format!("{dir}{name}");
    }
    let separator = if dir.contains('/') {
        '/'
    } else if dir.contains('\\') {
        '\\'
    } else {
        std::path::MAIN_SEPARATOR
    };
    format!("{dir}{separator}{name}")
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

/// Hours of activity and expected noise events for a role on a given day.
fn schedule(role: Role, workday: bool) -> (f64, (i64, i64)) {
    match (role, workday) {
        (Role::Workstation, true) => (80.0, (8 * HOUR, 18 * HOUR)),
        (Role::Admin, true) => (60.0, (7 * HOUR, 19 * HOUR)),
        (Role::Workstation | Role::Admin, false) => (4.0, (0, DAY)),
        (Role::Server | Role::Backup, _) => (20.0, (0, DAY)),
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
    let (noise, window) = schedule(role, workday);
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

/// The v0.2 part of a host's day, from its own random stream.
fn routine_v2(
    rng: &mut Rng,
    role: Role,
    workday: bool,
    day_start: i64,
    host: usize,
    out: &mut Vec<Record>,
) {
    let (_, window) = schedule(role, workday);
    let lists: &[&[(f64, Kind)]] = match role {
        Role::Workstation => &[&WORKSTATION_ACTIVITY_V2],
        Role::Admin => &[&WORKSTATION_ACTIVITY_V2, &ADMIN_ACTIVITY_V2],
        Role::Server | Role::Backup => &[],
    };
    let scale = if workday { 1.0 } else { 0.1 };
    for &(mean, kind) in lists.iter().flat_map(|l| l.iter()) {
        for _ in 0..rng.poisson(mean * scale) {
            let ts = day_start + rng.range(window.0, window.1);
            out.push(Record { ts, host, kind });
        }
    }
    if role == Role::Backup {
        // The backup software lists the shadow copies before it starts.
        let ts = day_start + HOUR - rng.range(60, 300);
        out.push(Record {
            ts,
            host,
            kind: Start("vssadmin.exe", "backup.exe"),
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

    fn encode(kind: Kind) -> Option<String> {
        let alphabet = Alphabet::default_set();
        let hosts = host_names();
        let event = Event::from_json(&to_json(
            &Record {
                ts: 0,
                host: 0,
                kind,
            },
            &hosts,
        ))
        .unwrap();
        alphabet
            .encode(&event)
            .map(|i| alphabet.code(i).to_string())
    }

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
        for s in scenarios() {
            for (code, kind) in s.steps {
                let got = encode(kind);
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
    fn scenario_queries_exist_and_match_their_chains() {
        let alphabet = Alphabet::default_set();
        for s in scenarios() {
            let path = format!("{}/queries/{}.txt", env!("CARGO_MANIFEST_DIR"), s.query);
            let text = fs::read_to_string(&path).unwrap_or_else(|_| panic!("falta {path}"));
            let query = crate::search::parse_query(&text, &alphabet).unwrap();
            assert!(!query.is_empty(), "{path}");
        }
    }

    #[test]
    fn noise_is_not_encoded() {
        for kind in NOISE {
            assert!(encode(kind).is_none());
        }
    }

    #[test]
    fn later_activity_and_padding_are_encoded() {
        let lists = [
            &WORKSTATION_ACTIVITY_V2[..],
            &ADMIN_ACTIVITY_V2[..],
            &WORKSTATION_ACTIVITY[..],
        ];
        for &(_, kind) in lists.iter().flat_map(|l| l.iter()) {
            assert!(encode(kind).is_some());
        }
        for kind in PADDING {
            assert!(encode(kind).is_some());
        }
        assert_eq!(encode(Start("net.exe", "cmd.exe")).as_deref(), Some("ACD"));
        assert_eq!(
            encode(Start("vssadmin.exe", "backup.exe")).as_deref(),
            Some("VSS")
        );
    }

    fn lines(dir: &std::path::Path) -> Vec<String> {
        fs::read_to_string(dir.join("events.ndjson"))
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn padding_only_adds_events_around_the_chains() {
        let base = std::env::temp_dir().join(format!("ttpblast-synth-{}", std::process::id()));
        let options = |padding: usize, name: &str| Options {
            out: base.join(name).to_string_lossy().into_owned(),
            days: 14,
            seed: 7,
            padding,
        };
        let plain = generate(&options(0, "plain")).unwrap();
        let padded = generate(&options(2, "padded")).unwrap();
        let steps: usize = scenarios().iter().map(|s| s.steps.len() - 1).sum();
        assert_eq!(padded.events, plain.events + 2 * steps);
        // Every event of the plain data is still there, in the same order.
        let (a, b) = (lines(&base.join("plain")), lines(&base.join("padded")));
        let mut rest = b.iter();
        assert!(a.iter().all(|line| rest.any(|other| other == line)));
        for (x, y) in plain.truth.iter().zip(&padded.truth) {
            assert_eq!((x.start, x.end, &x.steps), (y.start, y.end, &y.steps));
        }
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn join_keeps_the_separator() {
        assert_eq!(
            join("data/demo", "events.ndjson"),
            "data/demo/events.ndjson"
        );
        assert_eq!(join("data\\demo", "x"), "data\\demo\\x");
        assert_eq!(join("data/", "x"), "data/x");
    }
}
