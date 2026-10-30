//! Builds one symbol sequence per host, ordered in time: the "genome" of
//! each machine that queries are aligned against.

use std::collections::BTreeMap;
use std::ops::Range;

use crate::alphabet::Alphabet;
use crate::events::Event;

pub struct HostSeq {
    pub host: String,
    pub symbols: Vec<usize>,
    /// Index into the event list for each symbol, to show the evidence.
    pub events: Vec<usize>,
}

/// (timestamp, event index, symbol) for one encoded event.
type Encoded = (Option<i64>, usize, usize);

pub fn build(events: &[Event], alphabet: &Alphabet) -> Vec<HostSeq> {
    let mut by_host: BTreeMap<&str, Vec<Encoded>> = BTreeMap::new();
    for (i, event) in events.iter().enumerate() {
        if let Some(symbol) = alphabet.encode(event) {
            by_host
                .entry(&event.host)
                .or_default()
                .push((event.ts, i, symbol));
        }
    }
    by_host
        .into_iter()
        .map(|(host, mut items)| {
            // Events without a timestamp keep their file order, before the rest.
            items.sort();
            HostSeq {
                host: host.to_string(),
                symbols: items.iter().map(|item| item.2).collect(),
                events: items.iter().map(|item| item.1).collect(),
            }
        })
        .collect()
}

/// Splits a host's sequence into stretches of activity: a new one starts
/// when more than `max_gap` seconds pass between two symbols. Alignments stay
/// inside one stretch, so a chain cannot borrow a step from the next day.
/// `max_gap <= 0` keeps the whole sequence as one stretch.
pub fn segments(seq: &HostSeq, events: &[Event], max_gap: i64) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut start = 0;
    for i in 1..seq.symbols.len() {
        let gap = match (events[seq.events[i - 1]].ts, events[seq.events[i]].ts) {
            (Some(a), Some(b)) => b - a,
            _ => 0,
        };
        if max_gap > 0 && gap > max_gap {
            out.push(start..i);
            start = i;
        }
    }
    if start < seq.symbols.len() {
        out.push(start..seq.symbols.len());
    }
    out
}

/// How many times each symbol appears across all hosts.
pub fn symbol_counts(seqs: &[HostSeq], alphabet_len: usize) -> Vec<usize> {
    let mut counts = vec![0; alphabet_len];
    for symbol in seqs.iter().flat_map(|s| &s.symbols) {
        counts[*symbol] += 1;
    }
    counts
}

/// What `--mask` hides on a host when searching for `query`, indexed by
/// symbol: everything the query does not use, and the query's own symbols
/// that appear at least `times` times on the host. A step of a chain shows up
/// once; a technique the host repeats is its routine, or padding.
pub fn routine(seq: &HostSeq, query: &[usize], times: usize, alphabet_len: usize) -> Vec<bool> {
    let mut counts = vec![0; alphabet_len];
    for &symbol in &seq.symbols {
        counts[symbol] += 1;
    }
    (0..alphabet_len)
        .map(|symbol| !query.contains(&symbol) || counts[symbol] >= times)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routine_is_what_the_query_does_not_use_or_the_host_repeats() {
        let seq = HostSeq {
            host: "pc".into(),
            symbols: vec![0, 1, 1, 2, 3, 1, 4],
            events: (0..7).collect(),
        };
        // The query uses 1, 2 and 3; the host runs 1 three times.
        let routine = routine(&seq, &[1, 2, 3], 2, 6);
        assert_eq!(routine, [true, true, false, false, true, true]);
        // With a higher bar, 1 stops being routine.
        assert!(!super::routine(&seq, &[1, 2, 3], 4, 6)[1]);
    }
}
