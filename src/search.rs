//! `ttpblast search`: aligns a query chain against every host, estimates how
//! surprising each score is, and prints a BLAST-style report next to an
//! exact-sequence baseline. The same results can come out as JSON or as a
//! self-contained HTML report.

use std::fs;
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::align::{self, Alignment, Scoring, Step};
use crate::alphabet::Alphabet;
use crate::events::{self, Event, Loaded};
use crate::i18n::{self, t};
use crate::report;
use crate::rng::{self, Rng};
use crate::sequence::{self, HostSeq};
use crate::stats::{self, Gumbel, Tail};
use crate::time;
use crate::ui::{self, Style, paint};

use serde_json::{Value, json};

pub const SHUFFLES: usize = 200;
pub const BLOCK: usize = 3;
pub const SEED: u64 = 1;
pub const MAX_EVALUE: f64 = 10.0;
pub const MAX_HITS: usize = 10;
pub const DETAILS: usize = 3;
pub const MAXSPAN: i64 = 7200;
pub const MAX_GAP: i64 = 3600;
/// With `--mask`, a query technique that a host repeats this many times is
/// routine there.
pub const ROUTINE: usize = 2;

#[derive(Clone)]
pub struct Options {
    /// Where the query comes from, as the user should see it (usually a path).
    pub query_label: String,
    pub query_text: String,
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
    /// Costs of missing query steps.
    pub gap_open: i32,
    pub gap_extend: i32,
    /// Costs of extra host steps.
    pub extra_open: i32,
    pub extra_extend: i32,
    /// Skip each host's routine for free (`sequence::routine`).
    pub mask: bool,
    pub routine: usize,
    pub null_model: NullModel,
    /// 0 = one per core.
    pub threads: usize,
    pub json: bool,
    pub html: Option<String>,
    /// Print nothing (the HTML report is still written): for `hunt`.
    pub quiet: bool,
}

impl Options {
    pub fn new(query_label: &str, query_text: &str, events: &str) -> Self {
        Options {
            query_label: query_label.to_string(),
            query_text: query_text.to_string(),
            events: events.to_string(),
            alphabet: None,
            shuffles: SHUFFLES,
            block: BLOCK,
            seed: SEED,
            max_evalue: MAX_EVALUE,
            max_hits: MAX_HITS,
            details: DETAILS,
            baseline: true,
            maxspan: MAXSPAN,
            max_gap: MAX_GAP,
            gap_open: align::GAP_OPEN,
            gap_extend: align::GAP_EXTEND,
            extra_open: align::EXTRA_OPEN,
            extra_extend: align::EXTRA_EXTEND,
            mask: false,
            routine: ROUTINE,
            null_model: NullModel::Tail,
            threads: 0,
            json: false,
            html: None,
            quiet: false,
        }
    }
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
            other => Err(tr!(
                "--null: modelo desconocido «{other}» (usa cola o gumbel)",
                "--null: unknown model «{other}» (use tail or gumbel)"
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
    /// Best score of the query against each shuffled version of the host.
    null_scores: Vec<i32>,
}

impl Hit<'_> {
    fn score(&self) -> i32 {
        self.alignment.as_ref().map_or(0, |a| a.score)
    }
}

/// What a search found, for whoever ran it (the demo grades it against the
/// truth): every host with symbols, best first.
pub struct Summary {
    pub ranking: Vec<Ranked>,
    /// Hosts the exact baseline matches, if it ran.
    pub baseline: Option<Vec<String>>,
}

pub struct Ranked {
    pub host: String,
    pub score: i32,
    pub evalue: f64,
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
                let line = n + 1;
                tr!(
                    "línea {line}: símbolo desconocido «{token}» (usa `ttpblast alphabet` para ver los válidos)",
                    "line {line}: unknown symbol «{token}» (`ttpblast alphabet` lists the valid ones)"
                )
            })?;
            symbols.push(symbol);
        }
    }
    if symbols.is_empty() {
        return Err(tr!("la consulta no tiene pasos", "the query has no steps"));
    }
    Ok(symbols)
}

/// Everything a search produced, for the text, JSON and HTML views.
struct Search<'a> {
    opts: &'a Options,
    alphabet: &'a Alphabet,
    query: &'a [usize],
    events: &'a [Event],
    skipped: usize,
    seqs: &'a [HostSeq],
    segments: &'a [Vec<Range<usize>>],
    scoring: &'a Scoring,
    hits: &'a [Hit<'a>],
    baseline: Option<&'a [(&'a HostSeq, usize, usize)]>,
    /// Hosts in the telemetry, with symbols or not.
    hosts: usize,
    encoded: usize,
    /// Encoded events that `--mask` treats as routine.
    masked: usize,
}

pub fn run(opts: &Options) -> Result<Summary, String> {
    run_on(opts, &events::load(&opts.events)?)
}

/// The search on telemetry already loaded: `hunt` reads it once for every
/// query in the library.
pub fn run_on(opts: &Options, loaded: &Loaded) -> Result<Summary, String> {
    let started = Instant::now();
    if opts.gap_open < 1 || opts.gap_extend < 0 || opts.gap_extend > opts.gap_open {
        return Err(tr!(
            "--gap-open debe ser al menos 1, y --gap-extend estar entre 0 y --gap-open",
            "--gap-open must be at least 1, and --gap-extend between 0 and --gap-open"
        ));
    }
    if opts.extra_open < 0 || opts.extra_extend < 0 || opts.extra_extend > opts.extra_open {
        return Err(tr!(
            "--extra-open no puede ser negativo, y --extra-extend debe estar entre 0 y --extra-open",
            "--extra-open cannot be negative, and --extra-extend must be between 0 and --extra-open"
        ));
    }
    if opts.routine < 1 {
        return Err(tr!(
            "--routine debe ser al menos 1",
            "--routine must be at least 1"
        ));
    }
    let alphabet = load_alphabet(opts.alphabet.as_deref())?;
    let query = parse_query(&opts.query_text, &alphabet)?;
    let Loaded { events, skipped } = loaded;
    let skipped = *skipped;
    let seqs = sequence::build(events, &alphabet);
    if seqs.is_empty() {
        return Err(tr!(
            "ningún evento de {} encaja con el alfabeto (`ttpblast encode --events {} --unmatched 10` enseña qué hay)",
            "no event in {} matches the alphabet (`ttpblast encode --events {} --unmatched 10` shows what is there)",
            opts.events,
            opts.events
        ));
    }
    let counts = sequence::symbol_counts(&seqs, alphabet.symbols.len());
    let scoring = Scoring::from_background(&alphabet, &counts)
        .with_gaps(opts.gap_open, opts.gap_extend)
        .with_extras(opts.extra_open, opts.extra_extend);
    let segments: Vec<Vec<Range<usize>>> = seqs
        .iter()
        .map(|seq| sequence::segments(seq, events, opts.max_gap))
        .collect();
    let masks: Vec<Vec<bool>> = seqs
        .iter()
        .map(|seq| {
            if opts.mask {
                sequence::routine(seq, &query, opts.routine, alphabet.symbols.len())
            } else {
                Vec::new()
            }
        })
        .collect();
    let masked = seqs
        .iter()
        .zip(&masks)
        .map(|(seq, mask)| {
            seq.symbols
                .iter()
                .filter(|&&s| mask.get(s) == Some(&true))
                .count()
        })
        .sum();

    let threads = worker_count(opts.threads, seqs.len());
    let mut hits = evaluate_all(&seqs, &segments, &masks, &query, &scoring, opts, threads);
    hits.sort_by(|a, b| {
        a.evalue
            .total_cmp(&b.evalue)
            .then(b.score().cmp(&a.score()))
            .then(a.seq.host.cmp(&b.seq.host))
    });
    let baseline = opts
        .baseline
        .then(|| baseline_matches(&seqs, &query, events, opts.maxspan));

    let mut hosts: Vec<&str> = events.iter().map(|e| e.host.as_str()).collect();
    hosts.sort_unstable();
    hosts.dedup();
    let search = Search {
        opts,
        alphabet: &alphabet,
        query: &query,
        events,
        skipped,
        seqs: &seqs,
        segments: &segments,
        scoring: &scoring,
        hits: &hits,
        baseline: baseline.as_deref(),
        hosts: hosts.len(),
        encoded: counts.iter().sum(),
        masked,
    };

    if opts.json {
        let text = serde_json::to_string_pretty(&search.json()).map_err(|e| e.to_string())?;
        println!("{text}");
    } else if !opts.quiet {
        search.print(started.elapsed(), threads);
    }
    if let Some(path) = &opts.html {
        report::write(path, &search.json())?;
        let note = tr!(
            "Informe HTML → {path} (ábrelo en el navegador)",
            "HTML report → {path} (open it in a browser)"
        );
        // Keep stdout pure JSON when it is JSON.
        if opts.json {
            eprintln!("{note}");
        } else if !opts.quiet {
            println!("{}", paint(note, Style::Quiet));
        }
    }

    Ok(Summary {
        ranking: hits
            .iter()
            .map(|h| Ranked {
                host: h.seq.host.clone(),
                score: h.score(),
                evalue: h.evalue,
            })
            .collect(),
        baseline: baseline.map(|b| b.iter().map(|(seq, ..)| seq.host.clone()).collect()),
    })
}

fn worker_count(requested: usize, hosts: usize) -> usize {
    let wanted = match requested {
        0 => std::thread::available_parallelism().map_or(1, |n| n.get()),
        n => n,
    };
    wanted.clamp(1, hosts.max(1))
}

/// Evaluates every host, spread over `threads` threads that take the next
/// host as they finish one. Each host's shuffles have their own seed, so the
/// result does not depend on how the work was split.
fn evaluate_all<'a>(
    seqs: &'a [HostSeq],
    segments: &[Vec<Range<usize>>],
    masks: &[Vec<bool>],
    query: &[usize],
    scoring: &Scoring,
    opts: &Options,
    threads: usize,
) -> Vec<Hit<'a>> {
    let progress = ui::Progress::start(!opts.quiet, seqs.len(), ui::Kind::Hosts);
    let next = AtomicUsize::new(0);
    let work = || {
        let mut done = Vec::new();
        loop {
            let i = next.fetch_add(1, Ordering::Relaxed);
            let Some(seq) = seqs.get(i) else { break };
            let host = Host {
                seq,
                segments: &segments[i],
                masked: &masks[i],
            };
            let hit = evaluate(&host, query, scoring, opts, seqs.len());
            progress.tick(hit.null_scores.len());
            done.push((i, hit));
        }
        done
    };
    let mut slots: Vec<Option<Hit>> = std::iter::repeat_with(|| None).take(seqs.len()).collect();
    std::thread::scope(|scope| {
        let workers: Vec<_> = (1..threads).map(|_| scope.spawn(work)).collect();
        let mut done = work();
        for worker in workers {
            done.extend(worker.join().expect("un hilo de búsqueda falló"));
        }
        for (i, hit) in done {
            slots[i] = Some(hit);
        }
    });
    progress.finish();
    slots
        .into_iter()
        .map(|hit| hit.expect("cada host se evalúa una vez"))
        .collect()
}

/// One host as a search sees it.
struct Host<'a, 'b> {
    seq: &'a HostSeq,
    /// Its stretches of activity.
    segments: &'b [Range<usize>],
    /// Its routine for this query, by symbol (empty without `--mask`).
    masked: &'b [bool],
}

impl Host<'_, '_> {
    /// Best alignment over the host's stretches of activity (first one on ties).
    fn best(&self, query: &[usize], scoring: &Scoring, masked: &[bool]) -> Option<Alignment> {
        let mut alignment: Option<Alignment> = None;
        for range in self.segments {
            if let Some(found) =
                align::align(query, &self.seq.symbols[range.clone()], scoring, masked)
                && alignment
                    .as_ref()
                    .is_none_or(|best| found.score > best.score)
            {
                alignment = Some(found.shifted(range.start));
            }
        }
        alignment
    }
}

fn evaluate<'a>(
    host: &Host<'a, '_>,
    query: &[usize],
    scoring: &Scoring,
    opts: &Options,
    db_size: usize,
) -> Hit<'a> {
    let seq = host.seq;
    let mut alignment = host.best(query, scoring, host.masked);
    // A host whose best alignment skips no routine is judged as without
    // `--mask`: skipping for free would only make its shuffles score higher.
    // (Choosing the null model after aligning depends on the data; what that
    // costs in false alarms is measured in the README.)
    let mut masked = host.masked;
    if !masked.is_empty()
        && alignment
            .as_ref()
            .is_none_or(|a| a.masked().next().is_none())
    {
        masked = &[];
        alignment = host.best(query, scoring, masked);
    }
    let score = alignment.as_ref().map_or(0, |a| a.score);
    if score == 0 {
        return Hit {
            seq,
            alignment,
            p: 1.0,
            evalue: db_size as f64,
            null: Null::NotNeeded,
            null_scores: Vec::new(),
        };
    }
    // Each host gets its own null model from shuffles of its own symbols,
    // so a host that runs discovery commands all day is not surprising.
    let mut rng = Rng::new(opts.seed ^ rng::fnv1a(&seq.host));
    // The routine that the alignment skipped inside the chain (an attacker's
    // padding, if it is one) is left out of the shuffles: it would lengthen
    // the chain's stretch, and a long stretch of shuffled symbols resembles
    // the query more easily.
    let skipped: Vec<usize> = alignment.iter().flat_map(|a| a.masked()).collect();
    let hit = alignment.as_ref().map(|a| a.host_span());
    let base = without(&seq.symbols, host.segments, hit, &skipped);
    // Shuffled symbols, cut into stretches of the same lengths as the real ones.
    let null: Vec<i32> = (0..opts.shuffles)
        .map(|_| {
            let shuffled = shuffled(&base.symbols, opts.block, base.hit, &mut rng);
            base.segments
                .iter()
                .map(|range| align::best_score(query, &shuffled[range.clone()], scoring, masked))
                .max()
                .unwrap_or(0)
        })
        .collect();
    let empirical = stats::empirical_p(&null, score);
    let (p, model) = match opts.null_model {
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
    };
    Hit {
        seq,
        alignment,
        p,
        evalue: p * db_size as f64,
        null: model,
        null_scores: null,
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

/// What a host's shuffles start from.
struct Base {
    symbols: Vec<usize>,
    segments: Vec<Range<usize>>,
    /// The span of the best alignment.
    hit: Option<(usize, usize)>,
}

/// The host's symbols without the positions in `skipped` (sorted), with its
/// stretches and the aligned span moved to match.
fn without(
    symbols: &[usize],
    segments: &[Range<usize>],
    hit: Option<(usize, usize)>,
    skipped: &[usize],
) -> Base {
    let before = |position: usize| skipped.partition_point(|&s| s < position);
    Base {
        symbols: symbols
            .iter()
            .enumerate()
            .filter(|(i, _)| skipped.binary_search(i).is_err())
            .map(|(_, &symbol)| symbol)
            .collect(),
        segments: segments
            .iter()
            .map(|r| r.start - before(r.start)..r.end - before(r.end))
            .filter(|r| !r.is_empty())
            .collect(),
        hit: hit.map(|(first, last)| (first - before(first), last - before(last))),
    }
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

/// Hosts where the exact baseline matches, with the matched span.
fn baseline_matches<'a>(
    seqs: &'a [HostSeq],
    query: &[usize],
    events: &[Event],
    maxspan: i64,
) -> Vec<(&'a HostSeq, usize, usize)> {
    seqs.iter()
        .filter_map(|seq| exact_sequence(query, seq, events, maxspan).map(|(a, b)| (seq, a, b)))
        .collect()
}

/// How a query step relates to the host symbol it is paired with.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Relation {
    Identical,
    Similar,
    Different,
}

impl Relation {
    fn of(scoring: &Scoring, query: usize, host: usize) -> Self {
        if query == host {
            Relation::Identical
        } else if scoring.score(query, host) > 0 {
            Relation::Similar
        } else {
            Relation::Different
        }
    }

    fn style(self) -> Style {
        match self {
            Relation::Identical => Style::Same,
            Relation::Similar => Style::Similar,
            Relation::Different => Style::Different,
        }
    }

    fn marker(self) -> &'static str {
        match self {
            Relation::Identical => "|",
            Relation::Similar => "+",
            Relation::Different => " ",
        }
    }

    fn key(self) -> &'static str {
        match self {
            Relation::Identical => "identical",
            Relation::Similar => "similar",
            Relation::Different => "different",
        }
    }
}

/// The verdict: which hosts stand out from chance, and how much.
struct Verdict<'a> {
    strong: Vec<&'a Hit<'a>>,
    weak: Vec<&'a Hit<'a>>,
    /// The best host that does not stand out, to show how close chance gets.
    next: Option<&'a Hit<'a>>,
}

impl<'a> Search<'a> {
    fn shown(&self) -> Vec<&'a Hit<'a>> {
        self.hits
            .iter()
            .filter(|h| h.alignment.is_some() && h.evalue <= self.opts.max_evalue)
            .take(self.opts.max_hits)
            .collect()
    }

    fn verdict(&self) -> Verdict<'a> {
        let aligned = || self.hits.iter().filter(|h| h.alignment.is_some());
        Verdict {
            strong: aligned().filter(|h| h.evalue <= ui::STRONG).collect(),
            weak: aligned()
                .filter(|h| h.evalue > ui::STRONG && h.evalue <= ui::WEAK)
                .collect(),
            next: aligned().find(|h| h.evalue > ui::WEAK),
        }
    }

    fn stretches(&self) -> usize {
        self.segments.iter().map(Vec::len).sum()
    }

    fn time_of(&self, seq: &HostSeq, position: usize) -> Option<i64> {
        self.events[seq.events[position]].ts
    }

    // ---------------------------------------------------------------- text

    fn print(&self, elapsed: Duration, threads: usize) {
        let o = self.opts;
        let label =
            |es: &'static str, en: &'static str| paint(format!("{:<13}", t(es, en)), Style::Quiet);
        println!(
            "{} {} · {}\n",
            paint("ttpblast", Style::Brand),
            env!("CARGO_PKG_VERSION"),
            t(
                "alineamiento local de cadenas de ataque",
                "local alignment of attack chains"
            )
        );
        println!(
            "{} {} · {}",
            label("Consulta", "Query"),
            o.query_label,
            i18n::plural(self.query.len(), t("paso", "step"), t("pasos", "steps"))
        );
        println!("{:<13} {}", "", self.codes_painted(self.query));
        println!(
            "{} {} · {} · {}{}",
            label("Telemetría", "Telemetry"),
            o.events,
            i18n::plural(
                self.events.len(),
                t("evento", "event"),
                t("eventos", "events")
            ),
            i18n::plural(self.hosts, "host", "hosts"),
            if self.skipped > 0 {
                tr!(
                    " · {} ignorados (ilegibles o sin host)",
                    " · {} skipped (unreadable or without a host)",
                    i18n::count(self.skipped)
                )
            } else {
                String::new()
            }
        );
        println!(
            "{} {}",
            label("Alfabeto", "Alphabet"),
            tr!(
                "{} símbolos · {} eventos codificados ({} %) · {} hosts con símbolos",
                "{} symbols · {} encoded events ({} %) · {} hosts with symbols",
                self.alphabet.symbols.len(),
                i18n::count(self.encoded),
                i18n::decimal(
                    100.0 * self.encoded as f64 / self.events.len().max(1) as f64,
                    1
                ),
                self.seqs.len()
            )
        );
        let cut = if o.max_gap > 0 {
            tr!(
                "se corta tras más de {} min sin símbolos",
                "cut after more than {} min without symbols",
                o.max_gap / 60
            )
        } else {
            t(
                "sin cortes: un tramo por host",
                "no cuts: one stretch per host",
            )
            .to_string()
        };
        println!(
            "{} {}",
            label("Tramos", "Stretches"),
            tr!(
                "{} tramos de actividad ({cut})",
                "{} stretches of activity ({cut})",
                i18n::count(self.stretches())
            )
        );
        // Only the query's symbols matter here; symbols absent from the data
        // all sit at the maximum and would say nothing.
        let identity = || self.query.iter().map(|&s| self.scoring.identity[s]);
        let (low, high) = (identity().min().unwrap_or(0), identity().max().unwrap_or(0));
        let sc = self.scoring;
        let gaps = if (sc.gap_open, sc.gap_extend) == (sc.extra_open, sc.extra_extend) {
            tr!(
                "hueco -{} (-{} por paso más)",
                "gap -{} (-{} per further step)",
                sc.gap_open,
                sc.gap_extend
            )
        } else {
            tr!(
                "paso que falta -{} (-{} por cada otro) · pasos de más -{} (-{} por cada otro)",
                "missing step -{} (-{} for each other) · extra steps -{} (-{} for each other)",
                sc.gap_open,
                sc.gap_extend,
                sc.extra_open,
                sc.extra_extend
            )
        };
        println!(
            "{} {}",
            label("Puntuación", "Scoring"),
            tr!(
                "idéntico +{low}…+{high} según rareza · misma táctica +{} · otra táctica {} · {gaps}",
                "identical +{low}…+{high} by rarity · same tactic +{} · other tactic {} · {gaps}",
                align::SAME_TACTIC,
                align::OTHER_TACTIC
            )
        );
        if o.mask {
            println!(
                "{} {}",
                label("Máscara", "Mask"),
                tr!(
                    "la rutina se salta gratis: lo que no es de la consulta y sus técnicas que un host repite ({} veces o más); {} % de los símbolos",
                    "routine is skipped for free: what is not in the query, and its techniques a host repeats ({} times or more); {} % of the symbols",
                    o.routine,
                    i18n::decimal(100.0 * self.masked as f64 / self.encoded.max(1) as f64, 0)
                )
            );
        }
        let block = if o.block > 1 {
            tr!(
                "bloques de {}, la región alineada símbolo a símbolo",
                "blocks of {}, the aligned region symbol by symbol",
                o.block
            )
        } else {
            t("símbolo a símbolo", "symbol by symbol").to_string()
        };
        let model = match o.null_model {
            NullModel::Tail => t("cola exponencial", "exponential tail"),
            NullModel::Gumbel => t("ajuste Gumbel", "Gumbel fit"),
        };
        println!(
            "{} {}\n",
            label("Significación", "Significance"),
            tr!(
                "{} barajados por host ({block}) · {model} · E = p × {} hosts",
                "{} shuffles per host ({block}) · {model} · E = p × {} hosts",
                o.shuffles,
                self.seqs.len()
            )
        );

        self.print_table();
        if let Some(found) = self.baseline {
            self.print_baseline(found);
        }
        for hit in self.shown().iter().take(o.details) {
            self.print_detail(hit);
        }
        self.print_verdict(elapsed, threads);
    }

    fn codes_painted(&self, symbols: &[usize]) -> String {
        symbols
            .iter()
            .map(|&s| paint(self.alphabet.code(s), Style::Query))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn print_table(&self) {
        let shown = self.shown();
        println!(
            "{}",
            paint(
                tr!(
                    "Resultados con E ≤ {}",
                    "Hits with E ≤ {}",
                    i18n::evalue(self.opts.max_evalue)
                ),
                Style::Brand
            )
        );
        if shown.is_empty() {
            println!("  {}\n", paint(t("(ninguno)", "(none)"), Style::Quiet));
            return;
        }
        let width = shown
            .iter()
            .map(|h| h.seq.host.chars().count())
            .max()
            .unwrap_or(0)
            .clamp(16, 40);
        println!(
            "{}",
            paint(
                format!(
                    "  {:>2}  {:<width$} {:>6} {:>9}  {:<8} {:>6} {:>4} {:>4} {:>7} {:>9}",
                    "#",
                    "host",
                    t("punt.", "score"),
                    "E-value",
                    t("señal", "signal"),
                    t("pasos", "steps"),
                    "=",
                    "~",
                    t("huecos", "gaps"),
                    t("duración", "duration")
                ),
                Style::Quiet
            )
        );
        // A midrule under the column heads, as a statistical table has. Width
        // matches the header format above (2-space indent + 66 + the host
        // column); dim, because the guide maps separators to the border colour.
        println!("  {}", paint("─".repeat(66 + width), Style::Quiet));
        for (i, hit) in shown.iter().enumerate() {
            let Some(aln) = &hit.alignment else { continue };
            let (identical, similar, gaps) = counts(aln, self.query, hit.seq);
            let style = ui::evalue_style(hit.evalue);
            let host = format!("{:<width$}", hit.seq.host);
            println!(
                "  {:>2}  {} {:>6} {}  {} {:>6} {:>4} {:>4} {:>7} {:>9}",
                i + 1,
                if style == Style::Alert {
                    paint(host, Style::Bold)
                } else {
                    host
                },
                aln.score,
                paint(format!("{:>9}", i18n::evalue(hit.evalue)), style),
                paint(ui::signal_bar(hit.evalue, 8), style),
                format!("{}/{}", aln.pairs().count(), self.query.len()),
                identical,
                similar,
                gaps,
                self.duration(aln, hit.seq)
            );
        }
        println!(
            "  {}\n  {}\n",
            paint(
                t(
                    "(= pasos idénticos · ~ pasos sustituidos · huecos = pasos extra o que faltan)",
                    "(= identical steps · ~ substituted steps · gaps = extra or missing steps)"
                ),
                Style::Quiet
            ),
            paint(
                t(
                    "(señal: un bloque por cada orden de magnitud de E por debajo de 1)",
                    "(signal: one block per order of magnitude of E below 1)"
                ),
                Style::Quiet
            )
        );
    }

    fn print_baseline(&self, found: &[(&HostSeq, usize, usize)]) {
        let hosts: Vec<String> = found
            .iter()
            .map(|&(seq, a, b)| {
                let span = match (self.time_of(seq, a), self.time_of(seq, b)) {
                    (Some(ta), Some(tb)) => {
                        format!(" ({} → {})", time::format_human(ta), time::format_clock(tb))
                    }
                    _ => String::new(),
                };
                format!("{}{span}", seq.host)
            })
            .collect();
        println!(
            "{} {}",
            paint(format!("{:<13}", t("Línea base", "Baseline")), Style::Quiet),
            tr!(
                "secuencia exacta, en orden, en ≤ {} min (como `sequence … with maxspan` de EQL): {}",
                "exact sequence, in order, within {} min (like EQL's `sequence … with maxspan`): {}",
                self.opts.maxspan / 60,
                i18n::plural(found.len(), "host", "hosts")
            )
        );
        for host in &hosts {
            println!("{:<13} {host}", "");
        }
        println!();
    }

    fn print_detail(&self, hit: &Hit) {
        let Some(aln) = &hit.alignment else { return };
        let seq = hit.seq;
        let style = ui::evalue_style(hit.evalue);
        println!(
            "{} {} · {} · {}",
            paint("▸", style),
            paint(&seq.host, Style::Bold),
            tr!("puntuación {}", "score {}", aln.score),
            paint(
                format!(
                    "E = {} (p = {})",
                    i18n::evalue(hit.evalue),
                    i18n::evalue(hit.p)
                ),
                style
            )
        );
        let (first, last) = aln.host_span();
        if let (Some(ta), Some(tb)) = (self.time_of(seq, first), self.time_of(seq, last)) {
            println!(
                "  {} → {} ({})",
                time::format_human(ta),
                time::format_clock(tb),
                self.duration(aln, seq)
            );
        }
        let masked = aln.masked().count();
        if masked > 0 {
            println!(
                "  {}",
                tr!(
                    "rutina saltada gratis: {}, que tampoco entran en los barajados",
                    "routine skipped for free: {}, also left out of the shuffles",
                    i18n::plural(masked, t("evento", "event"), t("eventos", "events"))
                )
            );
        }
        let shuffles = hit.null_scores.len();
        let model = match &hit.null {
            Null::Tail { fit, misfit } => Some(tr!(
                "modelo nulo: cola exponencial desde {} ({} % de {shuffles} barajados) · λ = {} · desajuste {}",
                "null model: exponential tail from {} ({} % of {shuffles} shuffles) · λ = {} · misfit {}",
                fit.threshold,
                i18n::decimal(100.0 * fit.p_threshold, 0),
                i18n::decimal(fit.lambda, 2),
                misfit_text(*misfit, stats::ks_critical(fit.count))
            )),
            Null::Gumbel { fit, ks } => Some(tr!(
                "modelo nulo: Gumbel μ = {} · λ = {} ({shuffles} barajados) · desajuste {}",
                "null model: Gumbel μ = {} · λ = {} ({shuffles} shuffles) · misfit {}",
                i18n::decimal(fit.mu, 1),
                i18n::decimal(fit.lambda, 2),
                misfit_text(*ks, stats::ks_critical(shuffles))
            )),
            Null::Empirical => Some(tr!(
                "modelo nulo: p empírico ({shuffles} barajados, sin dispersión suficiente para ajustar un modelo)",
                "null model: empirical p ({shuffles} shuffles, too little spread to fit a model)"
            )),
            Null::NotNeeded => None,
        };
        if let Some(model) = model {
            println!("  {model}");
        }
        if let Some(strip) = null_strip(&hit.null_scores, aln.score, style) {
            println!("{strip}");
        }
        println!();

        // Alignment in three rows, BLAST-style. Pad, then paint. A run of
        // masked routine takes one column, with how many events it hides.
        let (mut top, mut mid, mut bottom) = (
            format!("  {:<9}", t("consulta", "query")),
            " ".repeat(11),
            format!("  {:<9}", "host"),
        );
        let cell = |text: &str, style: Style| paint(format!(" {text:<4}"), style);
        let mut run = 0;
        for (i, step) in aln.steps.iter().enumerate() {
            if let Step::Masked { .. } = step {
                run += 1;
                if !matches!(aln.steps.get(i + 1), Some(Step::Masked { .. })) {
                    top.push_str(&cell("···", Style::Quiet));
                    mid.push_str("     ");
                    bottom.push_str(&cell(&format!("({run})"), Style::Quiet));
                    run = 0;
                }
                continue;
            }
            match *step {
                Step::Pair { q, t } => {
                    let (a, b) = (self.query[q], seq.symbols[t]);
                    let relation = Relation::of(self.scoring, a, b);
                    top.push_str(&cell(self.alphabet.code(a), Style::Query));
                    mid.push_str(&paint(
                        format!("  {:<3}", relation.marker()),
                        relation.style(),
                    ));
                    bottom.push_str(&cell(self.alphabet.code(b), relation.style()));
                }
                Step::Extra { t } => {
                    top.push_str(&cell("---", Style::Quiet));
                    mid.push_str("     ");
                    bottom.push_str(&cell(self.alphabet.code(seq.symbols[t]), Style::Quiet));
                }
                Step::Missing { q } => {
                    top.push_str(&cell(self.alphabet.code(self.query[q]), Style::Query));
                    mid.push_str("     ");
                    bottom.push_str(&cell("---", Style::Quiet));
                }
                Step::Masked { .. } => {}
            }
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
                    let (a, b) = (self.query[q], seq.symbols[t]);
                    let relation = Relation::of(self.scoring, a, b);
                    let text = match relation {
                        Relation::Identical => i18n::t("idéntico", "identical").to_string(),
                        Relation::Similar => {
                            tr!("similar a {}", "similar to {}", self.alphabet.code(a))
                        }
                        Relation::Different => {
                            tr!("distinto de {}", "unlike {}", self.alphabet.code(a))
                        }
                    };
                    self.print_evidence(
                        &tr!("paso {}", "step {}", q + 1),
                        b,
                        &paint(format!("{text:<15}"), relation.style()),
                        seq.events[t],
                    );
                }
                Step::Extra { t } => self.print_evidence(
                    "extra",
                    seq.symbols[t],
                    &paint(
                        format!("{:<15}", i18n::t("paso extra", "extra step")),
                        Style::Quiet,
                    ),
                    seq.events[t],
                ),
                Step::Masked { t } => self.print_evidence(
                    i18n::t("rutina", "routine"),
                    seq.symbols[t],
                    &paint(
                        format!("{:<15}", i18n::t("se salta gratis", "skipped, free")),
                        Style::Quiet,
                    ),
                    seq.events[t],
                ),
                Step::Missing { q } => {
                    let s = &self.alphabet.symbols[self.query[q]];
                    println!(
                        "  {:<8}  {:<7}  {} {:<10} {}  {}",
                        "",
                        tr!("paso {}", "step {}", q + 1),
                        s.code,
                        s.technique,
                        paint(format!("{:<15}", t("falta", "missing")), Style::Quiet),
                        paint(
                            t("no aparece en el host", "not seen on the host"),
                            Style::Quiet
                        )
                    );
                }
            }
        }
        println!();
    }

    fn print_evidence(&self, label: &str, symbol: usize, relation: &str, event: usize) {
        let event = &self.events[event];
        let clock = event
            .ts
            .map(time::format_clock)
            .unwrap_or_else(|| "--:--:--".into());
        let s = &self.alphabet.symbols[symbol];
        println!(
            "  {}  {label:<7}  {} {:<10} {relation}  {}",
            paint(format!("{clock:<8}"), Style::Quiet),
            s.code,
            s.technique,
            describe(event)
        );
    }

    fn print_verdict(&self, elapsed: Duration, threads: usize) {
        let v = self.verdict();
        println!("{}", paint(t("Veredicto", "Verdict"), Style::Brand));
        let names = |hits: &[&Hit]| {
            let names: Vec<&str> = hits.iter().take(6).map(|h| h.seq.host.as_str()).collect();
            let more = hits.len() - names.len();
            let mut text = names.join(", ");
            if more > 0 {
                text.push_str(&tr!(" y {more} más", " and {more} more"));
            }
            text
        };
        if !v.strong.is_empty() {
            println!(
                "  {} {}",
                paint("●", Style::Alert),
                tr!(
                    "{} muy por encima del azar (E ≤ {}): {}",
                    "{} far beyond chance (E ≤ {}): {}",
                    i18n::plural(v.strong.len(), "host", "hosts"),
                    i18n::decimal(ui::STRONG, 2),
                    paint(names(&v.strong), Style::Bold)
                )
            );
        }
        if !v.weak.is_empty() {
            println!(
                "  {} {}",
                paint("◐", Style::Warn),
                tr!(
                    "{} a revisar (E ≤ 1): {}",
                    "{} worth a second look (E ≤ 1): {}",
                    i18n::plural(v.weak.len(), "host", "hosts"),
                    names(&v.weak)
                )
            );
        }
        let flagged = v.strong.len() + v.weak.len();
        let rest = self.seqs.len() - flagged;
        match (flagged, v.next) {
            (0, Some(next)) => println!(
                "  {} {}",
                paint("○", Style::Quiet),
                tr!(
                    "Ningún host se aleja del azar: el mejor, {}, tiene E = {}. En equipos sin intrusiones es lo esperable.",
                    "No host stands out from chance: the best, {}, has E = {}. On machines without intrusions, that is what to expect.",
                    next.seq.host,
                    i18n::evalue(next.evalue)
                )
            ),
            (0, None) => println!(
                "  {} {}",
                paint("○", Style::Quiet),
                t(
                    "Ningún host tiene nada parecido a la consulta.",
                    "No host has anything resembling the query."
                )
            ),
            (_, Some(next)) => println!(
                "  {} {}",
                paint("○", Style::Quiet),
                tr!(
                    "El resto ({}) no se distingue del azar: el mejor, {}, tiene E = {}.",
                    "The rest ({}) is indistinguishable from chance: the best, {}, has E = {}.",
                    i18n::plural(rest, "host", "hosts"),
                    next.seq.host,
                    i18n::evalue(next.evalue)
                )
            ),
            (_, None) if rest > 0 => println!(
                "  {} {}",
                paint("○", Style::Quiet),
                tr!(
                    "El resto ({}) no tiene nada parecido a la consulta.",
                    "The rest ({}) has nothing resembling the query.",
                    i18n::plural(rest, "host", "hosts")
                )
            ),
            _ => {}
        }
        if let Some(found) = self.baseline {
            let hosts: Vec<&str> = found.iter().map(|(seq, ..)| seq.host.as_str()).collect();
            let text = if hosts.is_empty() {
                t(
                    "La búsqueda exacta no encuentra nada.",
                    "The exact search finds nothing.",
                )
                .to_string()
            } else {
                tr!(
                    "La búsqueda exacta encuentra {}: {}.",
                    "The exact search finds {}: {}.",
                    i18n::plural(hosts.len(), "host", "hosts"),
                    hosts.join(", ")
                )
            };
            println!("  {} {text}", paint("◇", Style::Quiet));
        }
        println!(
            "  {}",
            paint(
                tr!(
                    "({} s · {})",
                    "({} s · {})",
                    i18n::decimal(elapsed.as_secs_f64(), 2),
                    i18n::plural(threads, t("hilo", "thread"), t("hilos", "threads"))
                ),
                Style::Quiet
            )
        );
    }

    fn duration(&self, aln: &Alignment, seq: &HostSeq) -> String {
        let (first, last) = aln.host_span();
        match (self.time_of(seq, first), self.time_of(seq, last)) {
            (Some(a), Some(b)) => {
                let secs = b - a;
                if secs < 3600 {
                    format!("{} min", (secs + 30) / 60)
                } else {
                    format!("{} h", i18n::decimal(secs as f64 / 3600.0, 1))
                }
            }
            _ => "—".into(),
        }
    }

    // ---------------------------------------------------------------- JSON

    /// The whole search as JSON: `--json` prints it and `--html` embeds it.
    fn json(&self) -> Value {
        let o = self.opts;
        let symbol = |s: usize| {
            let symbol = &self.alphabet.symbols[s];
            json!({
                "code": symbol.code,
                "technique": symbol.technique,
                "tactic": symbol.tactic,
                "name": symbol.name(),
            })
        };
        let v = self.verdict();
        let hosts_of = |hits: &[&Hit]| hits.iter().map(|h| h.seq.host.clone()).collect::<Vec<_>>();
        json!({
            "ttpblast": env!("CARGO_PKG_VERSION"),
            "lang": i18n::current().code(),
            "query": {
                "file": o.query_label,
                "steps": self.query.iter().map(|&s| self.alphabet.code(s)).collect::<Vec<_>>(),
                "symbols": self.query.iter().map(|&s| symbol(s)).collect::<Vec<_>>(),
            },
            "telemetry": {
                "file": o.events,
                "events": self.events.len(),
                "skipped_lines": self.skipped,
                "hosts": self.hosts,
                "encoded_events": self.encoded,
                "hosts_with_symbols": self.seqs.len(),
                "stretches": self.stretches(),
                "alphabet_size": self.alphabet.symbols.len(),
                "masked_events": self.masked,
            },
            "settings": {
                "shuffles": o.shuffles,
                "block": o.block,
                "seed": o.seed,
                "null": match o.null_model { NullModel::Tail => "tail", NullModel::Gumbel => "gumbel" },
                "max_gap": o.max_gap,
                "max_evalue": o.max_evalue,
                "gap_open": self.scoring.gap_open,
                "gap_extend": self.scoring.gap_extend,
                "extra_open": self.scoring.extra_open,
                "extra_extend": self.scoring.extra_extend,
                "same_tactic": align::SAME_TACTIC,
                "other_tactic": align::OTHER_TACTIC,
                "mask": o.mask,
                "routine": o.routine,
            },
            "summary": {
                "strong_threshold": ui::STRONG,
                "weak_threshold": ui::WEAK,
                "strong": hosts_of(&v.strong),
                "weak": hosts_of(&v.weak),
                "best_of_the_rest": v.next.map(|h| json!({ "host": h.seq.host, "evalue": h.evalue })),
            },
            "hits": self.shown().iter().enumerate().map(|(i, hit)| self.hit_json(i + 1, hit)).collect::<Vec<_>>(),
            "baseline": self.baseline.map(|found| json!({
                "maxspan": o.maxspan,
                "matches": found.iter().map(|&(seq, a, b)| json!({
                    "host": seq.host,
                    "start": self.time_of(seq, a).map(time::format_rfc3339),
                    "end": self.time_of(seq, b).map(time::format_rfc3339),
                })).collect::<Vec<_>>(),
            })),
        })
    }

    /// A hit as JSON: summary, null model and the alignment with its evidence.
    fn hit_json(&self, rank: usize, hit: &Hit) -> Value {
        let Some(aln) = &hit.alignment else {
            return Value::Null;
        };
        let seq = hit.seq;
        let time_of = |t: usize| self.time_of(seq, t).map(time::format_rfc3339);
        let host_symbol = |t: usize| &self.alphabet.symbols[seq.symbols[t]];
        let steps: Vec<Value> = aln
            .steps
            .iter()
            .map(|step| match *step {
                Step::Pair { q, t } => {
                    let (a, b) = (self.query[q], seq.symbols[t]);
                    let s = host_symbol(t);
                    json!({
                        "kind": "pair",
                        "query_step": q + 1,
                        "query": self.alphabet.code(a),
                        "host": s.code,
                        "technique": s.technique,
                        "tactic": s.tactic,
                        "name": s.name(),
                        "relation": Relation::of(self.scoring, a, b).key(),
                        "score": self.scoring.score(a, b),
                        "time": time_of(t),
                        "event": describe(&self.events[seq.events[t]]),
                    })
                }
                Step::Extra { t } | Step::Masked { t } => {
                    let s = host_symbol(t);
                    json!({
                        "kind": if matches!(step, Step::Masked { .. }) { "masked" } else { "extra" },
                        "host": s.code,
                        "technique": s.technique,
                        "tactic": s.tactic,
                        "name": s.name(),
                        "time": time_of(t),
                        "event": describe(&self.events[seq.events[t]]),
                    })
                }
                Step::Missing { q } => {
                    let s = &self.alphabet.symbols[self.query[q]];
                    json!({
                        "kind": "missing",
                        "query_step": q + 1,
                        "query": s.code,
                        "technique": s.technique,
                        "tactic": s.tactic,
                        "name": s.name(),
                    })
                }
            })
            .collect();
        let histogram: Vec<[i32; 2]> = histogram(&hit.null_scores)
            .into_iter()
            .map(|(score, n)| [score, n as i32])
            .collect();
        let null_model = match &hit.null {
            Null::Tail { fit, misfit } => json!({
                "model": "tail",
                "threshold": fit.threshold,
                "p_threshold": fit.p_threshold,
                "lambda": fit.lambda,
                "misfit": misfit,
                "critical": stats::ks_critical(fit.count),
                "shuffles": hit.null_scores.len(),
                "histogram": histogram,
            }),
            Null::Gumbel { fit, ks } => json!({
                "model": "gumbel",
                "mu": fit.mu,
                "lambda": fit.lambda,
                "misfit": ks,
                "critical": stats::ks_critical(hit.null_scores.len()),
                "shuffles": hit.null_scores.len(),
                "histogram": histogram,
            }),
            Null::Empirical => json!({
                "model": "empirical",
                "shuffles": hit.null_scores.len(),
                "histogram": histogram,
            }),
            Null::NotNeeded => Value::Null,
        };
        let (identical, substituted, gaps) = counts(aln, self.query, seq);
        let (first, last) = aln.host_span();
        json!({
            "rank": rank,
            "host": seq.host,
            "score": aln.score,
            "evalue": hit.evalue,
            "p": hit.p,
            "start": time_of(first),
            "end": time_of(last),
            "steps_covered": aln.pairs().count(),
            "identical": identical,
            "substituted": substituted,
            "gaps": gaps,
            "masked": aln.masked().count(),
            "null": null_model,
            "alignment": steps,
        })
    }
}

/// Where the real score falls among the shuffled ones, in two lines: the
/// shuffles as a histogram, and a ▲ under the real score. One column per
/// score while they fit in 48 columns, bins of several scores beyond that.
fn null_strip(null: &[i32], score: i32, style: Style) -> Option<String> {
    const WIDTH: usize = 48;
    const LEVELS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let (low, high) = (*null.iter().min()?, *null.iter().max()?);
    let top = high.max(score);
    let span = (top - low + 1) as usize;
    let per_column = span.div_ceil(WIDTH);
    let columns = span.div_ceil(per_column);
    let column = |s: i32| (s - low) as usize / per_column;
    let mut bins = vec![0usize; columns];
    for &s in null {
        bins[column(s)] += 1;
    }
    let tallest = *bins.iter().max()?;
    let bars: String = bins
        .iter()
        .map(|&n| match n {
            0 => '·',
            n => LEVELS[((n * 8).div_ceil(tallest) - 1).min(7)],
        })
        .collect();
    let label = t("azar", "chance");
    let indent = 2 + label.chars().count() + 1;
    let marker = " ".repeat(indent + column(score.max(low)));
    Some(format!(
        "  {} {}  {}\n{marker}{} {}",
        paint(label, Style::Quiet),
        paint(bars, Style::Quiet),
        paint(
            tr!(
                "{} barajados, de {low} a {high}",
                "{} shuffles, {low} to {high}",
                null.len()
            ),
            Style::Quiet
        ),
        paint("▲", style),
        paint(
            tr!("{score}, esta cadena", "{score}, this chain"),
            Style::Quiet
        )
    ))
}

/// (score, how many shuffles reached exactly it), by score.
fn histogram(scores: &[i32]) -> Vec<(i32, usize)> {
    let mut sorted = scores.to_vec();
    sorted.sort_unstable();
    let mut out: Vec<(i32, usize)> = Vec::new();
    for s in sorted {
        match out.last_mut() {
            Some((last, n)) if *last == s => *n += 1,
            _ => out.push((s, 1)),
        }
    }
    out
}

/// One line saying what the event was, from the fields the alphabet uses.
fn describe(event: &Event) -> String {
    let process = event.get("process.name").unwrap_or("?");
    if let Some(target) = event.get("process.target.name") {
        return tr!("{process} abre {target}", "{process} opens {target}");
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
        return tr!("{process} escribe {path}", "{process} writes {path}");
    }
    if let Some(path) = event.get("file.path") {
        return tr!("{process} crea {path}", "{process} creates {path}");
    }
    match event.get("process.parent.name") {
        Some(parent) => format!("{parent} → {process}"),
        None => process.to_string(),
    }
}

/// (identical pairs, substituted pairs, gap positions). Masked routine is not
/// a gap: it costs nothing.
fn counts(aln: &Alignment, query: &[usize], seq: &HostSeq) -> (usize, usize, usize) {
    let identical = aln
        .pairs()
        .filter(|&(q, t)| query[q] == seq.symbols[t])
        .count();
    let substituted = aln.pairs().count() - identical;
    let gaps = aln.steps.len() - identical - substituted - aln.masked().count();
    (identical, substituted, gaps)
}

fn read(path: &str) -> Result<String, String> {
    fs::read_to_string(path)
        .map_err(|e| tr!("no se puede leer {path}: {e}", "cannot read {path}: {e}"))
}

/// "0,04 (< 0,17)" or "0,21 (> 0,17) ⚠ ajuste dudoso".
fn misfit_text(misfit: f64, critical: f64) -> String {
    let (m, c) = (i18n::decimal(misfit, 2), i18n::decimal(critical, 2));
    if misfit > critical {
        format!(
            "{m} (> {c}) {}",
            paint(t("⚠ ajuste dudoso", "⚠ doubtful fit"), Style::Warn)
        )
    } else {
        format!("{m} (< {c})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(alphabet: &Alphabet, symbols: &[usize]) -> String {
        symbols
            .iter()
            .map(|&s| alphabet.code(s))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn query_accepts_codes_techniques_and_arrows() {
        let a = Alphabet::default_set();
        let q = parse_query("# comentario\nUEX -> psh, T1071.001 → ITT\n", &a).unwrap();
        assert_eq!(codes(&a, &q), "UEX PSH C2W ITT");
        assert!(parse_query("UEX XYZ", &a).is_err());
        assert!(parse_query("# nada", &a).is_err());
    }

    fn pc_events() -> Vec<Event> {
        (0..3)
            .map(|i| {
                Event::from_json(&json!({
                    "@timestamp": time::format_rfc3339(1_800_000_000 + i * 60),
                    "host": { "name": "pc" },
                    "event": { "action": "start" },
                    "process": { "name": "cmd.exe", "parent": { "name": "explorer.exe" } },
                }))
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn hit_json_reports_alignment_and_null_model() {
        let alphabet = Alphabet::default_set();
        let code = |c: &str| alphabet.lookup(c).unwrap();
        let events = pc_events();
        let seqs = vec![HostSeq {
            host: "pc".into(),
            symbols: vec![code("CMD"), code("USR"), code("SID")],
            events: vec![0, 1, 2],
        }];
        let query = vec![code("PSH"), code("SID")];
        let scoring = Scoring::from_background(&alphabet, &vec![1; alphabet.symbols.len()]);
        let hits = vec![Hit {
            seq: &seqs[0],
            alignment: Some(Alignment {
                score: 3,
                steps: vec![
                    Step::Pair { q: 0, t: 0 },
                    Step::Extra { t: 1 },
                    Step::Pair { q: 1, t: 2 },
                ],
            }),
            p: 0.5,
            evalue: 0.5,
            null: Null::Empirical,
            null_scores: vec![1, 3, 3, 2],
        }];
        let opts = Options::new("q.txt", "PSH SID", "e.ndjson");
        let segments = vec![vec![0..3]];
        let search = Search {
            opts: &opts,
            alphabet: &alphabet,
            query: &query,
            events: &events,
            skipped: 0,
            seqs: &seqs,
            segments: &segments,
            scoring: &scoring,
            hits: &hits,
            baseline: None,
            hosts: 1,
            encoded: 3,
            masked: 0,
        };
        let v = search.hit_json(1, &hits[0]);
        assert_eq!(v["host"], "pc");
        assert_eq!(v["null"]["model"], "empirical");
        assert_eq!(v["null"]["histogram"], json!([[1, 1], [2, 1], [3, 2]]));
        assert_eq!(v["identical"], 1);
        assert_eq!(v["substituted"], 1);
        assert_eq!(v["gaps"], 1);
        assert_eq!(v["alignment"][0]["relation"], "similar");
        assert_eq!(v["alignment"][0]["tactic"], "execution");
        assert_eq!(v["alignment"][1]["kind"], "extra");
        assert_eq!(v["start"], time::format_rfc3339(1_800_000_000));
        assert_eq!(v["end"], time::format_rfc3339(1_800_000_120));

        let doc = search.json();
        assert_eq!(doc["summary"]["weak"], json!(["pc"]));
        assert_eq!(doc["query"]["symbols"][1]["technique"], "T1082");

        // Masked routine is listed, but it is not a gap.
        let masked = Hit {
            seq: &seqs[0],
            alignment: Some(Alignment {
                score: 3,
                steps: vec![
                    Step::Pair { q: 0, t: 0 },
                    Step::Masked { t: 1 },
                    Step::Pair { q: 1, t: 2 },
                ],
            }),
            p: 0.5,
            evalue: 0.5,
            null: Null::Empirical,
            null_scores: vec![1, 3, 3, 2],
        };
        let v = search.hit_json(1, &masked);
        assert_eq!(v["alignment"][1]["kind"], "masked");
        assert_eq!(v["alignment"][1]["host"], "USR");
        assert_eq!(
            (v["gaps"].as_u64(), v["masked"].as_u64()),
            (Some(0), Some(1))
        );
    }

    /// A workstation's two weeks, compressed: routine in stretches of three
    /// and, in a stretch of its own, the demo chain with `padding` routine
    /// commands between every two steps.
    fn padded_host(padding: usize) -> (Alphabet, Vec<usize>, HostSeq, Vec<Range<usize>>) {
        let alphabet = Alphabet::default_set();
        let code = |c: &str| alphabet.lookup(c).unwrap();
        let query: Vec<usize> = [
            "UEX", "PSH", "C2W", "ITT", "RUN", "USR", "SID", "LSA", "SMB",
        ]
        .iter()
        .map(|c| code(c))
        .collect();
        let routine = [
            "CMD", "PSH", "TSK", "NCD", "PRC", "WSH", "ARC", "C2W", "ACD",
        ];
        let mut rng = Rng::new(11);
        let mut symbols: Vec<usize> = (0..60)
            .map(|_| code(routine[rng.below(routine.len() as u64) as usize]))
            .collect();
        let mut segments: Vec<Range<usize>> = (0..20).map(|i| 3 * i..3 * i + 3).collect();
        let start = symbols.len();
        for (i, &step) in query.iter().enumerate() {
            if i > 0 {
                for _ in 0..padding {
                    symbols.push(code(["CMD", "TSK", "NCD", "PRC"][rng.below(4) as usize]));
                }
            }
            symbols.push(step);
        }
        segments.push(start..symbols.len());
        let seq = HostSeq {
            host: "ws-legal-02".into(),
            events: vec![0; symbols.len()],
            symbols,
        };
        (alphabet, query, seq, segments)
    }

    fn evaluate_padded(padding: usize, mask: bool) -> (i32, usize, f64) {
        let (alphabet, query, seq, segments) = padded_host(padding);
        // Every symbol equally rare, so that padding does not change the scores.
        let scoring = Scoring::from_background(&alphabet, &vec![5; alphabet.symbols.len()]);
        let masked = if mask {
            sequence::routine(&seq, &query, ROUTINE, alphabet.symbols.len())
        } else {
            Vec::new()
        };
        let host = Host {
            seq: &seq,
            segments: &segments,
            masked: &masked,
        };
        let hit = evaluate(&host, &query, &scoring, &Options::new("q", "", "e"), 40);
        let aln = hit.alignment.as_ref().unwrap();
        (aln.score, aln.masked().count(), hit.evalue)
    }

    #[test]
    fn the_mask_sees_through_padding() {
        let (plain, _, e_plain) = evaluate_padded(0, false);
        let (padded, _, e_padded) = evaluate_padded(2, false);
        let (masked, skipped, e_masked) = evaluate_padded(2, true);
        // Padding sinks the score; with the mask, the 16 commands are
        // skipped for free and the chain scores as if they were not there.
        assert!(padded < plain - 10, "{padded} vs {plain}");
        assert_eq!((masked, skipped), (plain, 16));
        assert!(e_padded > 1.0, "{e_padded}");
        assert!(e_masked < 0.01 && e_plain < 0.01, "{e_masked} {e_plain}");
    }

    #[test]
    fn the_mask_changes_nothing_when_nothing_is_skipped() {
        // Without padding the chain needs no routine skipped: same alignment,
        // same null model, same E-value as without the mask.
        let (score, skipped, evalue) = evaluate_padded(0, true);
        assert_eq!(skipped, 0);
        assert_eq!((score, evalue), {
            let (s, _, e) = evaluate_padded(0, false);
            (s, e)
        });
    }

    #[test]
    fn without_moves_stretches_and_hit() {
        let symbols: Vec<usize> = (10..20).collect();
        let segments = vec![0..3, 3..9, 9..10];
        let base = without(&symbols, &segments, Some((3, 8)), &[4, 5, 7]);
        assert_eq!(base.symbols, [10, 11, 12, 13, 16, 18, 19]);
        assert_eq!(base.segments, [0..3, 3..6, 6..7]);
        assert_eq!(base.hit, Some((3, 5)));
        // Nothing skipped, nothing moves.
        let same = without(&symbols, &segments, Some((2, 4)), &[]);
        assert_eq!((same.symbols, same.segments), (symbols, segments));
        assert_eq!(same.hit, Some((2, 4)));
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
    fn same_results_with_any_number_of_threads() {
        let alphabet = Alphabet::default_set();
        let code = |c: &str| alphabet.lookup(c).unwrap();
        let mut rng = Rng::new(3);
        let pool = ["CMD", "PSH", "USR", "SID", "TSK", "C2W"];
        let seqs: Vec<HostSeq> = (0..9)
            .map(|h| HostSeq {
                host: format!("pc-{h}"),
                symbols: (0..40)
                    .map(|_| code(pool[rng.below(pool.len() as u64) as usize]))
                    .collect(),
                events: vec![0; 40],
            })
            .collect();
        let segments: Vec<Vec<Range<usize>>> = seqs
            .iter()
            .map(|_| std::iter::once(0..40).collect())
            .collect();
        let query = vec![code("PSH"), code("C2W"), code("USR"), code("SID")];
        let scoring = Scoring::from_background(&alphabet, &vec![5; alphabet.symbols.len()]);
        let mut opts = Options::new("q", "", "e");
        opts.shuffles = 30;
        let none = vec![Vec::new(); seqs.len()];
        let routine: Vec<Vec<bool>> = seqs
            .iter()
            .map(|s| sequence::routine(s, &query, 4, alphabet.symbols.len()))
            .collect();
        for masks in [&none, &routine] {
            let run = |threads| -> Vec<(String, i32, f64)> {
                evaluate_all(&seqs, &segments, masks, &query, &scoring, &opts, threads)
                    .iter()
                    .map(|h| (h.seq.host.clone(), h.score(), h.p))
                    .collect()
            };
            let one = run(1);
            assert_eq!(one, run(4));
            assert_eq!(one, run(16));
        }
    }

    #[test]
    fn strip_puts_the_marker_under_the_score() {
        let null = [5, 6, 6, 7, 7, 7, 8, 9];
        let strip = null_strip(&null, 20, Style::Alert).unwrap();
        let lines: Vec<&str> = strip.lines().collect();
        let last_bar = lines[0]
            .chars()
            .enumerate()
            .filter(|&(_, c)| c == '·' || ('▁'..='█').contains(&c))
            .map(|(i, _)| i)
            .max()
            .unwrap();
        let marker = lines[1].chars().position(|c| c == '▲').unwrap();
        // The marker sits under the last column: score 20 is the top.
        assert_eq!(marker, last_bar);
        // A score inside the shuffles sits under its own column.
        let inside = null_strip(&null, 7, Style::Warn).unwrap();
        let lines: Vec<&str> = inside.lines().collect();
        let marker = lines[1].chars().position(|c| c == '▲').unwrap();
        let first_bar = lines[0]
            .chars()
            .position(|c| ('▁'..='█').contains(&c))
            .unwrap();
        assert_eq!(marker, first_bar + 2);
        assert!(null_strip(&[], 3, Style::Alert).is_none());
    }

    #[test]
    fn histogram_counts_each_score() {
        assert_eq!(histogram(&[3, 1, 3, 2, 3]), vec![(1, 1), (2, 1), (3, 3)]);
        assert!(histogram(&[]).is_empty());
    }
}
