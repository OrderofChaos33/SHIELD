//! Deterministic PRNG (SplitMix64 expansion + xoshiro256** core).
//! Used so every randomized defense is reproducible under a test seed
//! and session-key-derived in production wiring. NOT a CSPRNG by itself:
//! production seeds come from OS entropy / the session secret.

pub struct Rng {
    s: [u64; 4],
}

impl Rng {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut s = [0u64; 4];
        for i in 0..4 {
            let mut z = u64::from_le_bytes(seed[i * 8..i * 8 + 8].try_into().unwrap())
                .wrapping_add(0x9E37_79B9_7F4A_7C15);
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            s[i] = z ^ (z >> 31);
        }
        Self { s }
    }

    pub fn next_u64(&mut self) -> u64 {
        let result = (self.s[1].wrapping_mul(5)).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// Uniform in [0, 1)
    pub fn next_f32(&mut self) -> f32 {
        ((self.next_u64() >> 40) as f32) / ((1u64 << 24) as f32)
    }

    /// Standard normal via Box–Muller.
    pub fn next_normal(&mut self) -> f32 {
        let u1 = self.next_f32().max(1e-9);
        let u2 = self.next_f32();
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f32::consts::PI * u2).cos()
    }

    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream() {
        let mut a = Rng::from_seed(&[7u8; 32]);
        let mut b = Rng::from_seed(&[7u8; 32]);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seed_different_stream() {
        let mut a = Rng::from_seed(&[7u8; 32]);
        let mut b = Rng::from_seed(&[8u8; 32]);
        assert_ne!(a.next_u64(), b.next_u64());
    }
}
