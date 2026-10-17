//! `ttpblast search`: aligns a query chain against every host, estimates how
//! surprising each score is, and prints a BLAST-style report next to an
//! exact-sequence baseline.

use std::fs;
use std::ops::Range;

use crate::align::{self, Alignment, Scoring, Step};
use crate::alphabet::Alphabet;
use crate::events::{self, Event};
use crate::rng::{self, Rng};
use crate::sequence::{self, HostSeq};
use crate::stats::{self, Gumbel, Tail};
use crate::time;

pub struct Options {
    pub query: String,
    pub events: String,
    pub alphabet: Option<String>,
    pub shuffles: usize,
    pub block: usize,
    pub seed: u64,
    pub max_evalue: f64,
    pub max_hits: usize,
    pub details: usize,
    pub baseline: bool,
    pub maxspan: i64,
    pub max_gap: i64,
    pub null_model: NullModel,
}

#[derive(Clone, Copy)]
pub enum NullModel {
    Tail,
    Gumbel,
}

impl NullModel {
    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "cola" | "tail" => Ok(NullModel::Tail),
            "gumbel" => Ok(NullModel::Gumbel),
            other => Err(format!(
                "--null: modelo desconocido «{other}» (usa cola o gumbel)"
            )),
        }
    }
}

enum Null {
    Tail { fit: Tail, misfit: f64 },
    Gumbel { fit: Gumbel, ks: f64 },
    Empirical,
    NotNeeded,
}

struct Hit<'a> {
    seq: &'a HostSeq,
    alignment: Option<Alignment>,
    p: f64,
    evalue: f64,
    null: Null,
}

impl Hit<'_> {
    fn score(&self) -> i32 {
        self.alignment.as_ref().map_or(0, |a| a.score)
    }
}

pub fn load_alphabet(path: Option<&str>) -> Result<Alphabet, String> {
    match path {
        Some(path) => Alphabet::from_json(&read(path)?),
        None => Ok(Alphabet::default_set()),
    }
}

/// A query is a list of symbol codes or technique IDs, separated by spaces,
/// commas or arrows. `#` starts a comment.
pub fn parse_query(text: &str, alphabet: &Alphabet) -> Result<Vec<usize>, String> {
    let mut symbols = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let content = line.split('#').next().unwrap_or("");
        let tokens = content
            .split(|c: char| c.is_whitespace() || matches!(c, ',' | '-' | '>' | '→'))
            .filter(|t| !t.is_empty());
        for token in tokens {
            let symbol = alphabet.lookup(token).ok_or_else(|| {
                format!(
                    "línea {}: símbolo desconocido «{token}» (usa `ttpblast alphabet` para ver los válidos)",
                    n + 1
                )
            })?;
            symbols.push(symbol);
        }
    }
    if symbols.is_empty() {
        return Err("la consulta no tiene pasos".into());
    }
    Ok(symbols)
}

pub fn run(opts: &Options) -> Result<(), String> {
    let alphabet = load_alphabet(opts.alphabet.as_deref())?;
    let query = parse_query(&read(&opts.query)?, &alphabet)?;
    let loaded = events::load_ndjson(&opts.events)?;
    let seqs = sequence::build(&loaded.events, &alphabet);
    if seqs.is_empty() {
        return Err("ningún evento encaja con el alfabeto".into());
    }
    let counts = sequence::symbol_counts(&seqs, alphabet.symbols.len());
    let scoring = Scoring::from_background(&alphabet, &counts);

    let segments: Vec<Vec<Range<usize>>> = seqs
        .iter()
        .map(|seq| sequence::segments(seq, &loaded.events, opts.max_gap))
        .collect();
    let mut hits: Vec<Hit> = seqs
        .iter()
        .zip(&segments)
        .map(|(seq, segs)| evaluate(seq, segs, &query, &scoring, opts, seqs.len()))
        .collect();
    hits.sort_by(|a, b| {
        a.evalue
            .total_cmp(&b.evalue)
            .then(b.score().cmp(&a.score()))
            .then(a.seq.host.cmp(&b.seq.host))
    });

    let encoded: usize = counts.iter().sum();
    let mut all_hosts: Vec<&str> = loaded.events.iter().map(|e| e.host.as_str()).collect();
    all_hosts.sort_unstable();
    all_hosts.dedup();

    println!(
        "ttpblast {} · alineamiento local de cadenas de ataque\n",
        env!("CARGO_PKG_VERSION")
    );
    println!("Consulta      {} · {} pasos", opts.query, query.len());
    println!("              {}", codes(&alphabet, &query));
    println!(
        "Telemetría    {} · {} eventos · {} hosts{}",
        opts.events,
        fmt_count(loaded.events.len()),
        all_hosts.len(),
        if loaded.skipped > 0 {
            format!(" · {} líneas ignoradas", fmt_count(loaded.skipped))
        } else {
            String::new()
        }
    );
    println!(
        "Alfabeto      {} símbolos · {} eventos codificados ({} %) · {} hosts con símbolos",
        alphabet.symbols.len(),
        fmt_count(encoded),
        fmt_decimal(100.0 * encoded as f64 / loaded.events.len().max(1) as f64),
        seqs.len()
    );
    println!(
        "Tramos        {} tramos de actividad (se corta tras {})",
        fmt_count(segments.iter().map(Vec::len).sum()),
        if opts.max_gap > 0 {
            format!("más de {} min sin símbolos", opts.max_gap / 60)
        } else {
            "nada: un tramo por host".to_string()
        }
    );
    println!(
        "Puntuación    idéntico +{}…+{} según rareza · misma táctica +{} · otra táctica {} · hueco -{} (-{} por paso más)",
        scoring.identity.iter().min().unwrap_or(&0),
        scoring.identity.iter().max().unwrap_or(&0),
        align::SAME_TACTIC,
        align::OTHER_TACTIC,
        scoring.gap_open,
        scoring.gap_extend
    );
    println!(
        "Significación {} barajados por host (bloques de {}{}) · {} · E = p × {} hosts\n",
        opts.shuffles,
        opts.block,
        if opts.block > 1 {
            ", la región alineada símbolo a símbolo"
        } else {
            ""
        },
        match opts.null_model {
            NullModel::Tail => "cola exponencial",
            NullModel::Gumbel => "ajuste Gumbel",
        },
        seqs.len()
    );

    let shown: Vec<&Hit> = hits
        .iter()
        .filter(|h| h.alignment.is_some() && h.evalue <= opts.max_evalue)
        .take(opts.max_hits)
        .collect();
    print_table(&shown, &query, &loaded.events, opts.max_evalue);

    if opts.baseline {
        print_baseline(&seqs, &query, &loaded.events, opts.maxspan);
    }

    for hit in shown.iter().take(opts.details) {
        print_detail(
            hit,
            &query,
            &alphabet,
            &scoring,
            &loaded.events,
            opts.shuffles,
        );
    }
    Ok(())
}

fn evaluate<'a>(
    seq: &'a HostSeq,
    segments: &[Range<usize>],
    query: &[usize],
    scoring: &Scoring,
    opts: &Options,
    db_size: usize,
) -> Hit<'a> {
    // Best alignment over the host's stretches of activity (first one on ties).
    let mut alignment: Option<Alignment> = None;
    for range in segments {
        if let Some(found) = align::align(query, &seq.symbols[range.clone()], scoring)
            && alignment
                .as_ref()
                .is_none_or(|best| found.score > best.score)
        {
            alignment = Some(found.shifted(range.start));
        }
    }
    let score = alignment.as_ref().map_or(0, |a| a.score);
    let (p, null) = if score == 0 {
        (1.0, Null::NotNeeded)
    } else {
        // Each host gets its own null model from shuffles of its own symbols,
        // so a host that runs discovery commands all day is not surprising.
        let mut rng = Rng::new(opts.seed ^ rng::fnv1a(&seq.host));
        // Shuffled symbols, cut into stretches of the same lengths as the real ones.
        let hit = alignment.as_ref().map(|a| a.host_span());
        let null: Vec<i32> = (0..opts.shuffles)
            .map(|_| {
                let symbols = shuffled(&seq.symbols, opts.block, hit, &mut rng);
                segments
                    .iter()
                    .map(|range| align::best_score(query, &symbols[range.clone()], scoring))
                    .max()
                    .unwrap_or(0)
            })
            .collect();
        let empirical = stats::empirical_p(&null, score);
        match opts.null_model {
            NullModel::Tail => match Tail::fit(&null) {
                // Inside the bulk the shuffles answer directly; the model is
                // only needed to extrapolate beyond them.
                Some(fit) => {
                    let p = if score >= fit.threshold {
                        fit.sf(score)
                    } else {
                        empirical
                    };
                    (
                        p,
                        Null::Tail {
                            fit,
                            misfit: fit.misfit(&null),
                        },
                    )
                }
                None => (empirical, Null::Empirical),
            },
            NullModel::Gumbel => match Gumbel::fit(&null) {
                Some(fit) => (
                    fit.sf(score),
                    Null::Gumbel {
                        fit,
                        ks: fit.ks(&null),
                    },
                ),
                None => (empirical, Null::Empirical),
            },
        }
    };
    Hit {
        seq,
        alignment,
        p,
        evalue: p * db_size as f64,
        null,
    }
}

/// Shuffles the sequence in blocks of `block` symbols. Blocks bigger than one
/// keep some of the local order (bursts of routine activity) in the null model,
/// but they would also keep pieces of a real chain together. `hit`, the host
/// span of the best alignment, is therefore shuffled symbol by symbol: the
/// composition stays the same and the chain's own order is broken. (Leaving
/// the span out altogether was tried and makes every host look significant,
/// because the null loses the very symbols its score is made of.)
fn shuffled(
    symbols: &[usize],
    block: usize,
    hit: Option<(usize, usize)>,
    rng: &mut Rng,
) -> Vec<usize> {
    let block = block.max(1);
    let mut chunks: Vec<&[usize]> = match hit {
        Some((first, last)) if block > 1 => {
            let mut chunks: Vec<&[usize]> = symbols[..first].chunks(block).collect();
            chunks.extend(symbols[first..=last].chunks(1));
            chunks.extend(symbols[last + 1..].chunks(block));
            chunks
        }
        _ => symbols.chunks(block).collect(),
    };
    rng.shuffle(&mut chunks);
    chunks.concat()
}

/// Exact ordered match, like an EQL `sequence ... with maxspan`: every query
/// step, in order, with anything in between, all within `maxspan` seconds.
fn exact_sequence(
    query: &[usize],
    seq: &HostSeq,
    events: &[Event],
    maxspan: i64,
) -> Option<(usize, usize)> {
    for start in 0..seq.symbols.len() {
        if seq.symbols[start] != query[0] {
            continue;
        }
        let t0 = events[seq.events[start]].ts;
        let (mut next, mut last) = (1, start);
        for pos in start + 1..seq.symbols.len() {
            if next == query.len() {
                break;
            }
            if let (Some(a), Some(b)) = (t0, events[seq.events[pos]].ts)
                && b - a > maxspan
            {
                break;
            }
            if seq.symbols[pos] == query[next] {
                next += 1;
                last = pos;
            }
        }
        if next == query.len() {
            return Some((start, last));
        }
    }
    None
}

fn print_table(hits: &[&Hit], query: &[usize], events: &[Event], max_evalue: f64) {
    println!("Resultados con E ≤ {}", fmt_evalue(max_evalue));
    if hits.is_empty() {
        println!("  (ninguno)\n");
        return;
    }
    println!(
        "  {:>2}  {:<16} {:>6} {:>9} {:>6} {:>4} {:>4} {:>7} {:>9}",
        "#", "host", "punt.", "E-value", "pasos", "=", "~", "huecos", "duración"
    );
    for (i, hit) in hits.iter().enumerate() {
        let Some(aln) = &hit.alignment else { continue };
        let (identical, similar, gaps) = counts(aln, query, hit.seq);
        let covered = aln.pairs().count();
        let query_len = query.len();
        println!(
            "  {:>2}  {:<16} {:>6} {:>9} {:>6} {:>4} {:>4} {:>7} {:>9}",
            i + 1,
            hit.seq.host,
            aln.score,
            fmt_evalue(hit.evalue),
            format!("{covered}/{query_len}"),
            identical,
            similar,
            gaps,
            duration(aln, hit.seq, events)
        );
    }
    println!("  (= pasos idénticos · ~ pasos sustituidos · huecos = pasos extra o que faltan)\n");
}

fn print_baseline(seqs: &[HostSeq], query: &[usize], events: &[Event], maxspan: i64) {
    let found: Vec<String> = seqs
        .iter()
        .filter_map(|seq| {
            let (a, b) = exact_sequence(query, seq, events, maxspan)?;
            let span = match (events[seq.events[a]].ts, events[seq.events[b]].ts) {
                (Some(ta), Some(tb)) => {
                    format!(" ({} → {})", time::format_human(ta), time::format_clock(tb))
                }
                _ => String::new(),
            };
            Some(format!("{}{span}", seq.host))
        })
        .collect();
    println!(
        "Línea base    secuencia exacta, en orden, en ≤ {} min (como `sequence … with maxspan` de EQL): {} host{}",
        maxspan / 60,
        found.len(),
        if found.len() == 1 { "" } else { "s" }
    );
    for host in &found {
        println!("              {host}");
    }
    println!();
}

fn print_detail(
    hit: &Hit,
    query: &[usize],
    alphabet: &Alphabet,
    scoring: &Scoring,
    events: &[Event],
    shuffles: usize,
) {
    let Some(aln) = &hit.alignment else { return };
    let seq = hit.seq;
    println!(
        "▸ {} · puntuación {} · E = {} (p = {})",
        seq.host,
        aln.score,
        fmt_evalue(hit.evalue),
        fmt_evalue(hit.p)
    );
    let (first, last) = aln.host_span();
    if let (Some(ta), Some(tb)) = (events[seq.events[first]].ts, events[seq.events[last]].ts) {
        println!(
            "  {} → {} ({})",
            time::format_human(ta),
            time::format_clock(tb),
            duration(aln, seq, events)
        );
    }
    match &hit.null {
        Null::Tail { fit, misfit } => println!(
            "  modelo nulo: cola exponencial desde {} ({} % de {shuffles} barajados) · λ = {} · desajuste {}",
            fit.threshold,
            fmt_decimal_n(100.0 * fit.p_threshold, 0),
            fmt_decimal_n(fit.lambda, 2),
            fmt_misfit(*misfit, stats::ks_critical(fit.count))
        ),
        Null::Gumbel { fit, ks } => println!(
            "  modelo nulo: Gumbel μ = {} · λ = {} ({shuffles} barajados) · desajuste {}",
            fmt_decimal(fit.mu),
            fmt_decimal_n(fit.lambda, 2),
            fmt_misfit(*ks, stats::ks_critical(shuffles))
        ),
        Null::Empirical => println!(
            "  modelo nulo: p empírico ({shuffles} barajados, sin dispersión para ajustar Gumbel)"
        ),
        Null::NotNeeded => {}
    }
    println!();

    // Alignment in three rows, BLAST-style.
    let (mut top, mut mid, mut bottom) = (
        String::from("  consulta "),
        String::from("           "),
        String::from("  host     "),
    );
    for step in &aln.steps {
        let (q, m, t) = match *step {
            Step::Pair { q, t } => {
                let (a, b) = (query[q], seq.symbols[t]);
                let marker = if a == b {
                    "|"
                } else if scoring.score(a, b) > 0 {
                    "+"
                } else {
                    " "
                };
                (alphabet.code(a), marker, alphabet.code(b))
            }
            Step::Extra { t } => ("---", " ", alphabet.code(seq.symbols[t])),
            Step::Missing { q } => (alphabet.code(query[q]), " ", "---"),
        };
        top.push_str(&format!(" {q:<4}"));
        mid.push_str(&format!("  {m:<3}"));
        bottom.push_str(&format!(" {t:<4}"));
    }
    println!(
        "{}\n{}\n{}\n",
        top.trim_end(),
        mid.trim_end(),
        bottom.trim_end()
    );

    // The evidence: the host's events behind each aligned symbol.
    for step in &aln.steps {
        match *step {
            Step::Pair { q, t } => {
                let (a, b) = (query[q], seq.symbols[t]);
                let relation = if a == b {
                    "idéntico".to_string()
                } else if scoring.score(a, b) > 0 {
                    format!("similar a {}", alphabet.code(a))
                } else {
                    format!("distinto de {}", alphabet.code(a))
                };
                print_evidence(
                    &format!("paso {}", q + 1),
                    b,
                    &relation,
                    seq.events[t],
                    alphabet,
                    events,
                );
            }
            Step::Extra { t } => {
                print_evidence(
                    "extra",
                    seq.symbols[t],
                    "paso extra",
                    seq.events[t],
                    alphabet,
                    events,
                );
            }
            Step::Missing { q } => println!(
                "  {:<8}  {:<7}  {} {:<10} {:<15}  no aparece en el host",
                "",
                format!("paso {}", q + 1),
                alphabet.code(query[q]),
                alphabet.symbols[query[q]].technique,
                "falta"
            ),
        }
    }
    println!();
}

fn print_evidence(
    label: &str,
    symbol: usize,
    relation: &str,
    event: usize,
    alphabet: &Alphabet,
    events: &[Event],
) {
    let event = &events[event];
    let clock = event
        .ts
        .map(time::format_clock)
        .unwrap_or_else(|| "--:--:--".into());
    let s = &alphabet.symbols[symbol];
    println!(
        "  {clock:<8}  {label:<7}  {} {:<10} {relation:<15}  {}",
        s.code,
        s.technique,
        describe(event)
    );
}

/// One line saying what the event was, from the fields the alphabet uses.
fn describe(event: &Event) -> String {
    let process = event.get("process.name").unwrap_or("?");
    if let Some(target) = event.get("process.target.name") {
        return format!("{process} abre {target}");
    }
    if let Some(port) = event.get("destination.port") {
        let dest = [
            "destination.address",
            "destination.domain",
            "destination.ip",
        ]
        .iter()
        .find_map(|k| event.get(k))
        .unwrap_or("?");
        return format!("{process} → {dest}:{port}");
    }
    if let Some(path) = event.get("registry.path") {
        return format!("{process} escribe {path}");
    }
    if let Some(path) = event.get("file.path") {
        return format!("{process} crea {path}");
    }
    match event.get("process.parent.name") {
        Some(parent) => format!("{parent} → {process}"),
        None => process.to_string(),
    }
}

/// (identical pairs, substituted pairs, gap positions).
fn counts(aln: &Alignment, query: &[usize], seq: &HostSeq) -> (usize, usize, usize) {
    let identical = aln
        .pairs()
        .filter(|&(q, t)| query[q] == seq.symbols[t])
        .count();
    let substituted = aln.pairs().count() - identical;
    let gaps = aln.steps.len() - identical - substituted;
    (identical, substituted, gaps)
}

fn duration(aln: &Alignment, seq: &HostSeq, events: &[Event]) -> String {
    let (first, last) = aln.host_span();
    match (events[seq.events[first]].ts, events[seq.events[last]].ts) {
        (Some(a), Some(b)) => {
            let secs = b - a;
            if secs < 3600 {
                format!("{} min", (secs + 30) / 60)
            } else {
                format!("{} h", fmt_decimal(secs as f64 / 3600.0))
            }
        }
        _ => "—".into(),
    }
}

fn codes(alphabet: &Alphabet, symbols: &[usize]) -> String {
    symbols
        .iter()
        .map(|&s| alphabet.code(s))
        .collect::<Vec<_>>()
        .join(" ")
}

fn read(path: &str) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("no se puede leer {path}: {e}"))
}

/// 61234 -> "61.234".
fn fmt_count(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push('.');
        }
        out.push(c);
    }
    out
}

/// "0,04 (< 0,17)" or "0,21 (> 0,17) ⚠ ajuste dudoso".
fn fmt_misfit(misfit: f64, critical: f64) -> String {
    if misfit > critical {
        format!(
            "{} (> {}) ⚠ ajuste dudoso",
            fmt_decimal_n(misfit, 2),
            fmt_decimal_n(critical, 2)
        )
    } else {
        format!(
            "{} (< {})",
            fmt_decimal_n(misfit, 2),
            fmt_decimal_n(critical, 2)
        )
    }
}

fn fmt_decimal(x: f64) -> String {
    fmt_decimal_n(x, 1)
}

fn fmt_decimal_n(x: f64, decimals: usize) -> String {
    format!("{x:.decimals$}").replace('.', ",")
}

/// E-values and p-values: scientific notation when small, as BLAST does.
fn fmt_evalue(x: f64) -> String {
    if x >= 10.0 {
        format!("{x:.0}")
    } else if x >= 0.01 {
        fmt_decimal_n(x, 2)
    } else {
        format!("{x:.1e}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_accepts_codes_techniques_and_arrows() {
        let a = Alphabet::default_set();
        let q = parse_query("# comentario\nUEX -> psh, T1071.001 → ITT\n", &a).unwrap();
        assert_eq!(codes(&a, &q), "UEX PSH C2W ITT");
        assert!(parse_query("UEX XYZ", &a).is_err());
        assert!(parse_query("# nada", &a).is_err());
    }

    #[test]
    fn hit_is_shuffled_symbol_by_symbol() {
        // With one block as big as the sequence, only the hit's symbols move.
        let symbols: Vec<usize> = (0..12).collect();
        let mut moved = false;
        for seed in 0..20 {
            let out = shuffled(&symbols, 100, Some((4, 7)), &mut Rng::new(seed));
            let pos = |x: usize| out.iter().position(|&y| y == x).unwrap();
            // Outside the hit, each block stays in one piece and in order.
            assert!(pos(1) == pos(0) + 1 && pos(3) == pos(0) + 3);
            assert!(pos(9) == pos(8) + 1 && pos(11) == pos(8) + 3);
            moved |= (4..=7).any(|x| pos(x) != x);
        }
        assert!(moved);
    }

    #[test]
    fn block_shuffle_keeps_composition() {
        let mut rng = Rng::new(5);
        let symbols: Vec<usize> = (0..23).map(|i| i % 7).collect();
        for (block, hit) in [(1, None), (3, None), (50, None), (3, Some((4, 9)))] {
            let mut a = shuffled(&symbols, block, hit, &mut rng);
            let mut b = symbols.clone();
            a.sort_unstable();
            b.sort_unstable();
            assert_eq!(a, b);
        }
    }

    #[test]
    fn formats() {
        assert_eq!(fmt_count(61_234), "61.234");
        assert_eq!(fmt_count(999), "999");
        assert_eq!(fmt_evalue(3.4e-8), "3.4e-8");
        assert_eq!(fmt_evalue(0.5), "0,50");
    }
}
