//! Small deterministic PRNG (SplitMix64). Reproducible runs matter more here
//! than statistical perfection, and it avoids an extra dependency. Not for
//! cryptography.

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform integer in `0..n` (the modulo bias is negligible for small n).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    /// Uniform integer in `lo..hi`.
    pub fn range(&mut self, lo: i64, hi: i64) -> i64 {
        lo + self.below((hi - lo) as u64) as i64
    }

    /// Uniform float in `[0, 1)`.
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Poisson-distributed count (Knuth's method, fine for small means).
    pub fn poisson(&mut self, mean: f64) -> u32 {
        let limit = (-mean).exp();
        let mut k = 0;
        let mut p = 1.0;
        loop {
            p *= self.unit();
            if p <= limit {
                return k;
            }
            k += 1;
        }
    }

    /// Fisher-Yates shuffle.
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i as u64 + 1) as usize;
            items.swap(i, j);
        }
    }
}

/// FNV-1a hash, used to derive a stable per-host seed.
pub fn fnv1a(text: &str) -> u64 {
    text.bytes().fold(0xCBF2_9CE4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01B3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_sequence() {
        let (mut a, mut b) = (Rng::new(42), Rng::new(42));
        assert!((0..100).all(|_| a.next_u64() == b.next_u64()));
    }

    #[test]
    fn shuffle_keeps_elements() {
        let mut rng = Rng::new(1);
        let mut v: Vec<u32> = (0..50).collect();
        rng.shuffle(&mut v);
        let mut sorted = v.clone();
        sorted.sort();
        assert_eq!(sorted, (0..50).collect::<Vec<_>>());
        assert_ne!(v, sorted);
    }

    #[test]
    fn poisson_mean_is_close() {
        let mut rng = Rng::new(3);
        let n = 20_000;
        let total: u32 = (0..n).map(|_| rng.poisson(4.0)).sum();
        let mean = f64::from(total) / f64::from(n);
        assert!((mean - 4.0).abs() < 0.1, "media {mean}");
    }
}
