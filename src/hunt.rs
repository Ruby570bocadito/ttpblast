//! `ttpblast hunt`: every query of the library (or of a folder) against the
//! same telemetry, read once, with one line of verdict per query. It is the
//! triage view, before looking at any search in detail; hosts that several
//! queries point at come out on their own line.

use std::collections::BTreeMap;
use std::fs;
use std::time::Instant;

use serde_json::{Value, json};

use crate::events;
use crate::i18n::{self, t};
use crate::library::LIBRARY;
use crate::search::{self, Ranked, Summary};
use crate::synth;
use crate::ui::{self, Style, paint};

pub struct Options {
    pub events: String,
    /// A folder of `.txt` queries instead of the built-in library.
    pub queries: Option<String>,
    /// A folder for one HTML report per query.
    pub html: Option<String>,
    pub json: bool,
    /// Settings shared by every search (query, events and output are set here).
    pub search: search::Options,
}

/// (stem, path as shown, text).
type Query = (String, String, String);

pub fn run(opts: &Options) -> Result<(), String> {
    let started = Instant::now();
    let queries = match &opts.queries {
        Some(dir) => read_queries(dir)?,
        None => LIBRARY
            .iter()
            .map(|q| (q.stem.to_string(), q.path.to_string(), q.text.to_string()))
            .collect(),
    };
    if let Some(dir) = &opts.html {
        fs::create_dir_all(dir)
            .map_err(|e| tr!("no se puede crear {dir}: {e}", "cannot create {dir}: {e}"))?;
    }
    let loaded = events::load(&opts.events)?;
    let progress = ui::Progress::start(true, queries.len(), ui::Kind::Queries);
    let mut results = Vec::new();
    for (stem, path, text) in &queries {
        let settings = search::Options {
            query_label: path.clone(),
            query_text: text.clone(),
            events: opts.events.clone(),
            details: 0,
            json: false,
            quiet: true,
            html: opts
                .html
                .as_ref()
                .map(|dir| synth::join(dir, &format!("{stem}.html"))),
            ..opts.search.clone()
        };
        let summary = search::run_on(&settings, &loaded).map_err(|e| format!("{path}: {e}"))?;
        results.push((stem.as_str(), path.as_str(), summary));
        progress.tick(0);
    }
    progress.finish();

    let mut hosts: Vec<&str> = loaded.events.iter().map(|e| e.host.as_str()).collect();
    hosts.sort_unstable();
    hosts.dedup();
    if opts.json {
        let doc = json!({
            "ttpblast": env!("CARGO_PKG_VERSION"),
            "events": opts.events,
            "telemetry": { "events": loaded.events.len(), "hosts": hosts.len() },
            "queries": results.iter().map(|(stem, path, summary)| query_json(stem, path, summary)).collect::<Vec<_>>(),
            "repeated": repeated(&results).into_iter().map(|(host, stems)| json!({ "host": host, "queries": stems })).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?
        );
        return Ok(());
    }

    println!(
        "{} {}\n{}\n",
        paint("ttpblast hunt", Style::Brand),
        tr!(
            "· {} contra {}",
            "· {} against {}",
            i18n::plural(
                results.len(),
                t("consulta", "query"),
                t("consultas", "queries")
            ),
            opts.events
        ),
        paint(
            format!(
                "{} · {} · {} s",
                i18n::plural(
                    loaded.events.len(),
                    t("evento", "event"),
                    t("eventos", "events")
                ),
                i18n::plural(hosts.len(), "host", "hosts"),
                i18n::decimal(started.elapsed().as_secs_f64(), 2)
            ),
            Style::Quiet
        )
    );
    let width = results
        .iter()
        .map(|(stem, ..)| stem.chars().count())
        .max()
        .unwrap_or(0);
    let mut rows = Vec::new();
    for (stem, _, summary) in &results {
        let (strong, weak) = tiers(summary);
        let (dot, style, verdict) = if !strong.is_empty() {
            (
                "●",
                Style::Alert,
                tr!(
                    "{} muy por encima del azar",
                    "{} far beyond chance",
                    count_hosts(strong.len())
                ),
            )
        } else if !weak.is_empty() {
            (
                "◐",
                Style::Warn,
                tr!("{} a revisar", "{} worth a look", count_hosts(weak.len())),
            )
        } else {
            (
                "○",
                Style::Quiet,
                t("nada se aleja del azar", "nothing stands out").to_string(),
            )
        };
        let shown: Vec<&Ranked> = if strong.is_empty() { weak } else { strong };
        let hosts_text = if shown.is_empty() {
            summary
                .ranking
                .iter()
                .find(|r| r.score > 0)
                .map(|best| {
                    tr!(
                        "(el mejor, {}, tiene E = {})",
                        "(the best, {}, has E = {})",
                        best.host,
                        i18n::evalue(best.evalue)
                    )
                })
                .unwrap_or_default()
        } else {
            let mut text = shown
                .iter()
                .take(4)
                .map(|r| format!("{} {}", r.host, i18n::evalue(r.evalue)))
                .collect::<Vec<_>>()
                .join(" · ");
            if shown.len() > 4 {
                text.push_str(&tr!(" y {} más", " and {} more", shown.len() - 4));
            }
            text
        };
        rows.push((dot, style, stem, verdict, shown.is_empty(), hosts_text));
    }
    let verdict_width = rows.iter().map(|r| r.3.chars().count()).max().unwrap_or(0);
    for (dot, style, stem, verdict, quiet, hosts_text) in rows {
        println!(
            "  {} {:<width$}  {}  {}",
            paint(dot, style),
            stem,
            paint(format!("{verdict:<verdict_width$}"), style),
            if quiet {
                paint(hosts_text, Style::Quiet)
            } else {
                hosts_text
            }
        );
    }

    let repeated = repeated(&results);
    println!();
    if !repeated.is_empty() {
        println!(
            "{}",
            paint(
                t(
                    "Hosts que señalan varias consultas (lo primero que miraría):",
                    "Hosts that several queries point at (where I would look first):"
                ),
                Style::Brand
            )
        );
        for (host, stems) in &repeated {
            println!(
                "  {} {host}: {}",
                paint("◆", Style::Alert),
                stems.join(", ")
            );
        }
        println!();
    }
    if let Some(dir) = &opts.html {
        println!(
            "{}",
            paint(
                tr!(
                    "Informes HTML, uno por consulta → {dir}",
                    "HTML reports, one per query → {dir}"
                ),
                Style::Quiet
            )
        );
    }
    if let Some((_, path, _)) = results.first() {
        println!(
            "{}",
            paint(
                tr!(
                    "Detalle de una consulta: ttpblast search --query {path} --events {}",
                    "One query in detail: ttpblast search --query {path} --events {}",
                    opts.events
                ),
                Style::Quiet
            )
        );
    }
    Ok(())
}

fn count_hosts(n: usize) -> String {
    i18n::plural(n, "host", "hosts")
}

/// (far beyond chance, worth a look), best first.
fn tiers(summary: &Summary) -> (Vec<&Ranked>, Vec<&Ranked>) {
    let aligned = || summary.ranking.iter().filter(|r| r.score > 0);
    (
        aligned().filter(|r| r.evalue <= ui::STRONG).collect(),
        aligned()
            .filter(|r| r.evalue > ui::STRONG && r.evalue <= ui::WEAK)
            .collect(),
    )
}

/// Hosts flagged (E <= 1) by more than one query, with those queries.
fn repeated<'a>(results: &'a [(&'a str, &'a str, Summary)]) -> Vec<(&'a str, Vec<&'a str>)> {
    let mut by_host: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (stem, _, summary) in results {
        let (strong, weak) = tiers(summary);
        for r in strong.into_iter().chain(weak) {
            by_host.entry(r.host.as_str()).or_default().push(stem);
        }
    }
    by_host
        .into_iter()
        .filter(|(_, stems)| stems.len() > 1)
        .collect()
}

fn query_json(stem: &str, path: &str, summary: &Summary) -> Value {
    let (strong, weak) = tiers(summary);
    let hosts = |list: &[&Ranked]| {
        list.iter()
            .map(|r| json!({ "host": r.host, "score": r.score, "evalue": r.evalue }))
            .collect::<Vec<_>>()
    };
    json!({
        "query": stem,
        "file": path,
        "strong": hosts(&strong),
        "weak": hosts(&weak),
        "best": summary.ranking.first().filter(|r| r.score > 0).map(|r| json!({ "host": r.host, "evalue": r.evalue })),
        "baseline": summary.baseline,
    })
}

/// The `.txt` files of a folder, in name order.
fn read_queries(dir: &str) -> Result<Vec<Query>, String> {
    let mut paths: Vec<_> = fs::read_dir(dir)
        .map_err(|e| tr!("no se puede leer {dir}: {e}", "cannot read {dir}: {e}"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("txt")))
        .collect();
    paths.sort();
    if paths.is_empty() {
        return Err(tr!(
            "{dir} no tiene consultas (ficheros .txt)",
            "{dir} has no queries (.txt files)"
        ));
    }
    paths
        .into_iter()
        .map(|p| {
            let stem = p
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let shown = synth::join(dir, &format!("{stem}.txt"));
            let text = fs::read_to_string(&p)
                .map_err(|e| tr!("no se puede leer {shown}: {e}", "cannot read {shown}: {e}"))?;
            Ok((stem, shown, text))
        })
        .collect()
}
