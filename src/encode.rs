//! `ttpblast encode`: each host's "genome", its events written as symbols in
//! time order, and what the alphabet is not seeing in the data.

use std::collections::HashMap;

use crate::alphabet::Alphabet;
use crate::events::{self, Event};
use crate::i18n::{self, t};
use crate::sequence;
use crate::ui::{Style, paint};

pub struct Options {
    pub events: String,
    pub host: Option<String>,
    pub alphabet: Option<String>,
    pub unmatched: usize,
}

pub fn run(opts: &Options) -> Result<(), String> {
    let alphabet = crate::search::load_alphabet(opts.alphabet.as_deref())?;
    let loaded = events::load_ndjson(&opts.events)?;
    let wanted = opts.host.as_deref().map(str::to_lowercase);
    let seqs = sequence::build(&loaded.events, &alphabet);
    // The first line is the first host's sequence: scripts (the Sysmon lab
    // in CI) read it.
    for seq in &seqs {
        if wanted.as_ref().is_some_and(|h| *h != seq.host) {
            continue;
        }
        let codes: Vec<&str> = seq.symbols.iter().map(|&s| alphabet.code(s)).collect();
        println!(
            "{} {:>4}  {}",
            paint(format!("{:<16}", seq.host), Style::Bold),
            codes.len(),
            paint(codes.join(" "), Style::Query)
        );
    }
    if let Some(host) = &wanted
        && !seqs.iter().any(|s| s.host == *host)
    {
        println!(
            "{}",
            tr!(
                "(ningún evento de {host} encaja con el alfabeto)",
                "(no event of {host} matches the alphabet)"
            )
        );
    }
    let encoded: usize = seqs.iter().map(|s| s.symbols.len()).sum();
    println!(
        "\n{}",
        paint(
            tr!(
                "{} eventos leídos · {} con símbolo, en {} · {} ignoradas (sin JSON válido o sin host)",
                "{} events read · {} with a symbol, on {} · {} skipped (not valid JSON or no host)",
                i18n::count(loaded.events.len()),
                i18n::count(encoded),
                i18n::plural(seqs.len(), "host", "hosts"),
                i18n::plural(loaded.skipped, t("línea", "line"), t("líneas", "lines"))
            ),
            Style::Quiet
        )
    );
    if encoded == 0 && opts.unmatched == 0 {
        println!(
            "{}",
            t(
                "Ningún evento encaja con el alfabeto. Con poca actividad es normal; \
                 `--unmatched 10` enseña qué tipos de eventos hay.",
                "No event matches the alphabet. With little activity that is normal; \
                 `--unmatched 10` shows which kinds of events there are."
            )
        );
    }
    if opts.unmatched > 0 {
        print_unmatched(&loaded.events, &alphabet, opts.unmatched);
    }
    Ok(())
}

/// The most frequent kinds of events that no symbol encodes: what the
/// alphabet is not seeing in this data.
fn print_unmatched(events: &[Event], alphabet: &Alphabet, top: usize) {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for event in events.iter().filter(|e| alphabet.encode(e).is_none()) {
        *counts.entry(event_kind(event)).or_default() += 1;
    }
    let mut kinds: Vec<(String, usize)> = counts.into_iter().collect();
    kinds.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    println!(
        "\n{}",
        paint(
            t(
                "Eventos sin símbolo más frecuentes:",
                "Most frequent events without a symbol:"
            ),
            Style::Bold
        )
    );
    if kinds.is_empty() {
        println!(
            "  {}",
            t("(ninguno: todos encajan)", "(none: all of them match)")
        );
    }
    for (kind, count) in kinds.iter().take(top) {
        println!("  {count:>7}  {kind}");
    }
}

/// "process/start  powershell.exe ← explorer.exe", "file/creation  chrome.exe .pdf"...
fn event_kind(event: &Event) -> String {
    let what = match (event.get("event.category"), event.get("event.action")) {
        (Some(category), Some(action)) => format!("{category}/{action}"),
        _ if event.get("network.direction") == Some("inbound") => {
            t("network/entrante", "network/inbound").to_string()
        }
        _ => match event.get("sysmon.event_id") {
            Some(id) => tr!("sysmon evento {id}", "sysmon event {id}"),
            None => t("sin categoría", "no category").to_string(),
        },
    };
    let process = event.get("process.name").unwrap_or("?");
    let detail = if let Some(parent) = event.get("process.parent.name") {
        format!(" ← {parent}")
    } else if let Some(target) = event.get("process.target.name") {
        format!(" → {target}")
    } else if let Some(port) = event.get("destination.port") {
        tr!(" → puerto {port}", " → port {port}")
    } else if let Some(extension) = event.get("file.extension") {
        format!(" .{extension}")
    } else {
        String::new()
    };
    format!("{what:<20} {process}{detail}")
}
