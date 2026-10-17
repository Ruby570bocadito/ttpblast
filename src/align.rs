//! Local alignment (Smith-Waterman with affine gaps, Gotoh's variant) between
//! a query chain and a host's symbol sequence.

use crate::alphabet::Alphabet;

/// Substituting a technique for another one of the same tactic (PowerShell
/// for cmd, a Run key for a scheduled task) still looks like the same chain.
pub const SAME_TACTIC: i32 = 2;
pub const OTHER_TACTIC: i32 = -3;
/// A gap of length k costs GAP_OPEN + (k - 1) * GAP_EXTEND.
pub const GAP_OPEN: i32 = 4;
pub const GAP_EXTEND: i32 = 1;
const MIN_IDENTITY: i32 = 3;
const MAX_IDENTITY: i32 = 10;

pub struct Scoring {
    matrix: Vec<i32>,
    size: usize,
    pub identity: Vec<i32>,
    pub gap_open: i32,
    pub gap_extend: i32,
}

impl Scoring {
    /// Identity scores come from how rare each symbol is in the searched
    /// data, its information content log2(1/q), rounded and clamped to 3..=10:
    /// matching a rare step (LSASS access) weighs more than matching a common
    /// one (PowerShell). Substitutions only look at tactics. A matrix learned
    /// from real attack chains, as BLOSUM is learned from protein blocks,
    /// should replace these hand-set rules.
    pub fn from_background(alphabet: &Alphabet, counts: &[usize]) -> Self {
        let n = alphabet.symbols.len();
        let total = counts.iter().sum::<usize>() as f64;
        let identity = counts
            .iter()
            .map(|&c| {
                let q = (c as f64 + 1.0) / (total + n as f64);
                ((-q.log2()).round() as i32).clamp(MIN_IDENTITY, MAX_IDENTITY)
            })
            .collect();
        let tactics: Vec<&str> = alphabet.symbols.iter().map(|s| s.tactic.as_str()).collect();
        Self::build(&tactics, identity)
    }

    pub fn build(tactics: &[&str], identity: Vec<i32>) -> Self {
        let size = tactics.len();
        let mut matrix = vec![0; size * size];
        for a in 0..size {
            for b in 0..size {
                matrix[a * size + b] = if a == b {
                    identity[a]
                } else if tactics[a] == tactics[b] {
                    SAME_TACTIC
                } else {
                    OTHER_TACTIC
                };
            }
        }
        Scoring {
            matrix,
            size,
            identity,
            gap_open: GAP_OPEN,
            gap_extend: GAP_EXTEND,
        }
    }

    pub fn score(&self, a: usize, b: usize) -> i32 {
        self.matrix[a * self.size + b]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Query step `q` aligned with host symbol `t` (same or substituted).
    Pair { q: usize, t: usize },
    /// Host symbol `t` with no counterpart in the query (an extra step).
    Extra { t: usize },
    /// Query step `q` missing from the host.
    Missing { q: usize },
}

pub struct Alignment {
    pub score: i32,
    pub steps: Vec<Step>,
}

impl Alignment {
    pub fn pairs(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        self.steps.iter().filter_map(|s| match *s {
            Step::Pair { q, t } => Some((q, t)),
            _ => None,
        })
    }

    /// Moves host positions by `offset`, for alignments made on a slice.
    pub fn shifted(mut self, offset: usize) -> Self {
        for step in &mut self.steps {
            match step {
                Step::Pair { t, .. } | Step::Extra { t } => *t += offset,
                Step::Missing { .. } => {}
            }
        }
        self
    }

    /// Host positions covered, first to last.
    pub fn host_span(&self) -> (usize, usize) {
        let positions = || {
            self.steps.iter().filter_map(|s| match *s {
                Step::Pair { t, .. } | Step::Extra { t } => Some(t),
                Step::Missing { .. } => None,
            })
        };
        (
            positions().min().unwrap_or(0),
            positions().max().unwrap_or(0),
        )
    }
}

const NEG: i32 = i32::MIN / 4;

struct Matrices {
    h: Vec<i32>,
    e: Vec<i32>,
    f: Vec<i32>,
    cols: usize,
    best: i32,
    end: (usize, usize),
}

fn fill(query: &[usize], target: &[usize], sc: &Scoring) -> Matrices {
    let cols = target.len() + 1;
    let size = (query.len() + 1) * cols;
    let (mut h, mut e, mut f) = (vec![0; size], vec![NEG; size], vec![NEG; size]);
    let (mut best, mut end) = (0, (0, 0));
    for i in 1..=query.len() {
        for j in 1..=target.len() {
            let k = i * cols + j;
            // e: gap in the query (extra host symbol); f: query step missing.
            e[k] = (h[k - 1] - sc.gap_open).max(e[k - 1] - sc.gap_extend);
            f[k] = (h[k - cols] - sc.gap_open).max(f[k - cols] - sc.gap_extend);
            let diagonal = h[k - cols - 1] + sc.score(query[i - 1], target[j - 1]);
            h[k] = 0.max(diagonal).max(e[k]).max(f[k]);
            if h[k] > best {
                best = h[k];
                end = (i, j);
            }
        }
    }
    Matrices {
        h,
        e,
        f,
        cols,
        best,
        end,
    }
}

/// Best local alignment score only (used for the shuffled null model).
pub fn best_score(query: &[usize], target: &[usize], sc: &Scoring) -> i32 {
    fill(query, target, sc).best
}

/// Best local alignment with its traceback, or `None` if nothing scores > 0.
pub fn align(query: &[usize], target: &[usize], sc: &Scoring) -> Option<Alignment> {
    #[derive(PartialEq)]
    enum State {
        H,
        E,
        F,
    }
    let m = fill(query, target, sc);
    if m.best <= 0 {
        return None;
    }
    let (mut i, mut j) = m.end;
    let mut state = State::H;
    let mut steps = Vec::new();
    loop {
        let k = i * m.cols + j;
        match state {
            State::H => {
                if m.h[k] == 0 {
                    break;
                }
                if m.h[k] == m.h[k - m.cols - 1] + sc.score(query[i - 1], target[j - 1]) {
                    steps.push(Step::Pair { q: i - 1, t: j - 1 });
                    i -= 1;
                    j -= 1;
                } else if m.h[k] == m.e[k] {
                    state = State::E;
                } else {
                    state = State::F;
                }
            }
            State::E => {
                steps.push(Step::Extra { t: j - 1 });
                if m.e[k] == m.h[k - 1] - sc.gap_open {
                    state = State::H;
                }
                j -= 1;
            }
            State::F => {
                steps.push(Step::Missing { q: i - 1 });
                if m.f[k] == m.h[k - m.cols] - sc.gap_open {
                    state = State::H;
                }
                i -= 1;
            }
        }
    }
    steps.reverse();
    Some(Alignment {
        score: m.best,
        steps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Toy alphabet: 0 and 1 share a tactic, 2 and 3 are on their own.
    fn scoring() -> Scoring {
        Scoring::build(&["exec", "exec", "disc", "cred"], vec![5, 5, 5, 8])
    }

    #[test]
    fn exact_match_inside_noise() {
        let sc = scoring();
        let aln = align(&[0, 2, 3], &[2, 2, 0, 2, 3, 1, 1], &sc).unwrap();
        assert_eq!(aln.score, 18);
        assert_eq!(
            aln.steps,
            vec![
                Step::Pair { q: 0, t: 2 },
                Step::Pair { q: 1, t: 3 },
                Step::Pair { q: 2, t: 4 }
            ]
        );
        assert_eq!(aln.host_span(), (2, 4));
    }

    #[test]
    fn substitution_within_tactic() {
        let sc = scoring();
        // Query 0,2,3 against host 1,2,3: 0 -> 1 is a same-tactic substitution.
        let aln = align(&[0, 2, 3], &[1, 2, 3], &sc).unwrap();
        assert_eq!(aln.score, SAME_TACTIC + 5 + 8);
        assert_eq!(aln.pairs().count(), 3);
    }

    #[test]
    fn extra_step_opens_a_gap() {
        let sc = scoring();
        // Host has an extra symbol (1) between the query steps 2 and 3.
        let aln = align(&[0, 2, 3], &[0, 2, 1, 3], &sc).unwrap();
        assert_eq!(aln.score, 5 + 5 - GAP_OPEN + 8);
        assert!(aln.steps.contains(&Step::Extra { t: 2 }));
    }

    #[test]
    fn missing_step_opens_a_gap() {
        let sc = scoring();
        let aln = align(&[0, 2, 3, 0], &[0, 3, 0], &sc).unwrap();
        assert_eq!(aln.score, 5 - GAP_OPEN + 8 + 5);
        assert!(aln.steps.contains(&Step::Missing { q: 1 }));
    }

    #[test]
    fn nothing_in_common() {
        let sc = scoring();
        assert!(align(&[3, 3], &[2, 2, 2], &sc).is_none());
        assert_eq!(best_score(&[3, 3], &[2, 2, 2], &sc), 0);
    }

    #[test]
    fn score_matches_alignment() {
        let sc = scoring();
        let (q, t) = ([0, 2, 3, 1, 2], [3, 1, 0, 2, 2, 3, 1, 0, 2]);
        assert_eq!(best_score(&q, &t, &sc), align(&q, &t, &sc).unwrap().score);
    }
}
