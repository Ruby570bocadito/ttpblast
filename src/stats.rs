//! Significance of an alignment score, from the scores the query gets against
//! shuffled versions of the same host (so each host is judged against its own
//! composition). Two models of those null scores:
//!
//! - `Tail`: an exponential tail, P(S >= s) ∝ e^(-λs), the Karlin-Altschul
//!   form behind BLAST E-values, fitted only to the upper half of the scores.
//! - `Gumbel`: the whole extreme-value distribution, fitted by moments.
//!
//! Null scores here often pile up on a floor (a rare symbol that every
//! shuffle contains scores the same however it is shuffled), which the full
//! Gumbel does not describe; the tail fit ignores the bulk.

use std::f64::consts::EULER_GAMMA;

/// Below this spread the null scores are basically a single value and a
/// Gumbel fit means nothing; fall back to the empirical p-value.
const MIN_SD: f64 = 0.5;
/// Scores needed strictly above the threshold to estimate a tail.
const MIN_TAIL: usize = 10;

#[derive(Debug, Clone, Copy)]
pub struct Tail {
    pub threshold: i32,
    /// Fraction of null scores >= threshold.
    pub p_threshold: f64,
    pub lambda: f64,
    /// Null scores in the tail, to judge the misfit.
    pub count: usize,
}

impl Tail {
    /// Geometric fit (the discrete exponential) to the scores strictly above
    /// the median, which leaves out a floor however big it is. The
    /// maximum-likelihood λ is ln(1 + 1/mean excess).
    pub fn fit(samples: &[i32]) -> Option<Tail> {
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let threshold = sorted.get(sorted.len() / 2)? + 1;
        let tail = &sorted[sorted.partition_point(|&x| x < threshold)..];
        if tail.iter().filter(|&&x| x > threshold).count() < MIN_TAIL {
            return None;
        }
        let excess =
            tail.iter().map(|&x| f64::from(x - threshold)).sum::<f64>() / tail.len() as f64;
        Some(Tail {
            threshold,
            p_threshold: tail.len() as f64 / sorted.len() as f64,
            lambda: (1.0 + 1.0 / excess).ln(),
            count: tail.len(),
        })
    }

    /// P(S >= s) for s above the threshold.
    pub fn sf(&self, s: i32) -> f64 {
        self.p_threshold * (-self.lambda * f64::from(s - self.threshold)).exp()
    }

    /// Largest gap, inside the tail, between the fitted and the observed
    /// P(S >= s | S >= threshold). Large values mean the tail is not
    /// exponential and E-values far beyond the shuffles are unreliable.
    pub fn misfit(&self, samples: &[i32]) -> f64 {
        let tail: Vec<i32> = samples
            .iter()
            .copied()
            .filter(|&x| x >= self.threshold)
            .collect();
        let n = tail.len() as f64;
        let max = tail.iter().copied().max().unwrap_or(self.threshold);
        (self.threshold..=max)
            .map(|s| {
                let observed = tail.iter().filter(|&&x| x >= s).count() as f64 / n;
                let model = (-self.lambda * f64::from(s - self.threshold)).exp();
                (observed - model).abs()
            })
            .fold(0.0, f64::max)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Gumbel {
    pub mu: f64,
    pub lambda: f64,
}

impl Gumbel {
    /// Method of moments: sd = π / (λ√6) and mean = μ + γ/λ.
    pub fn fit(samples: &[i32]) -> Option<Gumbel> {
        if samples.len() < 2 {
            return None;
        }
        let n = samples.len() as f64;
        let mean = samples.iter().map(|&x| f64::from(x)).sum::<f64>() / n;
        let var = samples
            .iter()
            .map(|&x| (f64::from(x) - mean).powi(2))
            .sum::<f64>()
            / (n - 1.0);
        let sd = var.sqrt();
        if sd < MIN_SD {
            return None;
        }
        let lambda = std::f64::consts::PI / (sd * 6f64.sqrt());
        Some(Gumbel {
            mu: mean - EULER_GAMMA / lambda,
            lambda,
        })
    }

    pub fn cdf(&self, x: f64) -> f64 {
        (-(-self.lambda * (x - self.mu)).exp()).exp()
    }

    /// P(S >= s) for an integer score, with a continuity correction. Uses
    /// expm1 so very small tail probabilities keep their precision.
    pub fn sf(&self, s: i32) -> f64 {
        let y = (-self.lambda * (f64::from(s) - 0.5 - self.mu)).exp();
        -(-y).exp_m1()
    }

    /// Kolmogorov-Smirnov distance between the integer samples and the fit,
    /// comparing at each observed value. Large values mean the Gumbel model
    /// does not describe this host well.
    pub fn ks(&self, samples: &[i32]) -> f64 {
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let n = sorted.len() as f64;
        let mut distance: f64 = 0.0;
        let mut i = 0;
        while i < sorted.len() {
            let value = sorted[i];
            let below = i as f64 / n;
            while i < sorted.len() && sorted[i] == value {
                i += 1;
            }
            let up_to = i as f64 / n;
            distance = distance
                .max((up_to - self.cdf(f64::from(value) + 0.5)).abs())
                .max((below - self.cdf(f64::from(value) - 0.5)).abs());
        }
        distance
    }
}

/// Approximate 95 % critical value of the Kolmogorov-Smirnov distance for
/// `n` samples: a misfit above it is unlikely to be sampling noise alone.
pub fn ks_critical(n: usize) -> f64 {
    1.36 / (n.max(1) as f64).sqrt()
}

/// (count of null scores >= s, plus one) / (n + 1): never zero.
pub fn empirical_p(null: &[i32], s: i32) -> f64 {
    let hits = null.iter().filter(|&&x| x >= s).count();
    (hits + 1) as f64 / (null.len() + 1) as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;

    fn gumbel_samples(mu: f64, lambda: f64, n: usize) -> Vec<i32> {
        let mut rng = Rng::new(9);
        (0..n)
            .map(|_| {
                let u = rng.unit().max(1e-12);
                (mu - (-u.ln()).ln() / lambda).round() as i32
            })
            .collect()
    }

    #[test]
    fn recovers_parameters() {
        let samples = gumbel_samples(20.0, 0.4, 20_000);
        let g = Gumbel::fit(&samples).unwrap();
        assert!((g.lambda - 0.4).abs() < 0.03, "lambda {}", g.lambda);
        assert!((g.mu - 20.0).abs() < 0.5, "mu {}", g.mu);
        assert!(g.ks(&samples) < 0.03, "ks {}", g.ks(&samples));
    }

    #[test]
    fn tail_is_monotonic_and_tiny() {
        let g = Gumbel {
            mu: 10.0,
            lambda: 0.5,
        };
        assert!(g.sf(5) > g.sf(10) && g.sf(10) > g.sf(30));
        let far = g.sf(80);
        assert!(far > 0.0 && far < 1e-12, "{far}");
    }

    #[test]
    fn tail_recovers_geometric_rate() {
        // Floor of 7 for 60 % of the samples, geometric tail above it.
        let mut rng = Rng::new(11);
        let lambda: f64 = 0.7;
        let samples: Vec<i32> = (0..20_000)
            .map(|_| {
                if rng.unit() < 0.6 {
                    7
                } else {
                    let u = rng.unit().max(1e-12);
                    8 + (u.ln() / -lambda).floor() as i32
                }
            })
            .collect();
        let fit = Tail::fit(&samples).unwrap();
        assert_eq!(fit.threshold, 8);
        assert!((fit.p_threshold - 0.4).abs() < 0.02, "{}", fit.p_threshold);
        assert!((fit.lambda - lambda).abs() < 0.05, "lambda {}", fit.lambda);
        assert!(
            fit.misfit(&samples) < 0.02,
            "desajuste {}",
            fit.misfit(&samples)
        );
        assert!(fit.sf(30) < fit.sf(20) && fit.sf(20) < fit.sf(10));
    }

    #[test]
    fn tail_needs_spread() {
        assert!(Tail::fit(&[7; 200]).is_none());
        let mostly_flat: Vec<i32> = (0..200).map(|i| if i < 195 { 7 } else { 9 }).collect();
        assert!(Tail::fit(&mostly_flat).is_none());
    }

    #[test]
    fn degenerate_null_has_no_fit() {
        assert!(Gumbel::fit(&[7; 100]).is_none());
        assert!((empirical_p(&[7; 99], 7) - 1.0).abs() < 1e-12);
        assert!((empirical_p(&[7; 99], 8) - 0.01).abs() < 1e-12);
    }
}
