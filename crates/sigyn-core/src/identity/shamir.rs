use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{Result, SigynError};

/// A single Shamir shard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shard {
    /// Shard index (1-based, used as x coordinate)
    pub index: u8,
    /// The shard data (same length as the secret)
    pub data: Vec<u8>,
    /// Total shards created
    pub total: u8,
    /// Threshold needed to reconstruct
    pub threshold: u8,
}

/// Result of splitting a secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryShardSet {
    pub shards: Vec<Shard>,
    pub threshold: u8,
    pub total: u8,
}

/// Split a secret into K-of-N Shamir shards using GF(256).
pub fn split_secret(secret: &[u8], threshold: u8, total: u8) -> Result<RecoveryShardSet> {
    if threshold < 2 {
        return Err(SigynError::ShamirInvalid("threshold must be >= 2".into()));
    }
    if total < threshold {
        return Err(SigynError::ShamirInvalid(
            "total must be >= threshold".into(),
        ));
    }
    if secret.is_empty() {
        return Err(SigynError::ShamirInvalid("secret must not be empty".into()));
    }

    let mut rng = rand::thread_rng();
    let mut shards: Vec<Vec<u8>> = (0..total)
        .map(|_| Vec::with_capacity(secret.len()))
        .collect();

    // For each byte of the secret, create a random polynomial and evaluate at each x
    for &secret_byte in secret {
        // Coefficients: a[0] = secret_byte, a[1..threshold-1] = random
        let mut coeffs = vec![0u8; threshold as usize];
        coeffs[0] = secret_byte;
        rng.fill_bytes(&mut coeffs[1..]);

        for i in 0..total {
            let x = i + 1; // x values are 1-based
            let y = evaluate_polynomial(&coeffs, x);
            shards[i as usize].push(y);
        }
    }

    let shard_set = RecoveryShardSet {
        shards: shards
            .into_iter()
            .enumerate()
            .map(|(i, data)| Shard {
                index: (i + 1) as u8,
                data,
                total,
                threshold,
            })
            .collect(),
        threshold,
        total,
    };

    Ok(shard_set)
}

/// Reconstruct the secret from at least `threshold` shards using Lagrange interpolation in GF(256).
pub fn reconstruct_secret(shards: &[Shard]) -> Result<Vec<u8>> {
    if shards.is_empty() {
        return Err(SigynError::ShamirInvalid("no shards provided".into()));
    }

    let threshold = shards[0].threshold as usize;
    if shards.len() < threshold {
        return Err(SigynError::ShamirInvalid(format!(
            "need {} shards, got {}",
            threshold,
            shards.len()
        )));
    }

    let secret_len = shards[0].data.len();
    if shards.iter().any(|s| s.data.len() != secret_len) {
        return Err(SigynError::ShamirInvalid(
            "shards have different lengths".into(),
        ));
    }

    let shards_to_use = &shards[..threshold];
    let xs: Vec<u8> = shards_to_use.iter().map(|s| s.index).collect();

    let mut secret = Vec::with_capacity(secret_len);

    for byte_idx in 0..secret_len {
        let ys: Vec<u8> = shards_to_use.iter().map(|s| s.data[byte_idx]).collect();
        secret.push(lagrange_interpolate_at_zero(&xs, &ys));
    }

    Ok(secret)
}

// --- GF(256) arithmetic (constant-time via lookup tables) ---

/// GF(256) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
/// Precomputed exp and log tables for constant-time multiplication and inversion.
///
/// Generate both tables at compile time. We use a single function returning
/// a tuple so the two tables stay consistent.
const fn generate_gf256_tables() -> ([u8; 512], [u8; 256]) {
    // EXP_TABLE has 512 entries (doubled to avoid modular reduction at runtime)
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];

    let mut val: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = val as u8;
        exp[i + 255] = val as u8; // duplicate for easy wrap-around
        log[val as usize] = i as u8;
        // Multiply by generator 3 (primitive root for polynomial 0x11B)
        // val * 3 = val * (2 + 1) = (val << 1) ^ val
        let doubled = val << 1;
        let doubled = if doubled & 0x100 != 0 {
            doubled ^ 0x11B
        } else {
            doubled
        };
        val = doubled ^ val;
        i += 1;
    }

    (exp, log)
}

static TABLES: ([u8; 512], [u8; 256]) = generate_gf256_tables();

#[inline]
fn exp_table() -> &'static [u8; 512] {
    &TABLES.0
}

#[inline]
fn log_table() -> &'static [u8; 256] {
    &TABLES.1
}

fn gf256_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    exp_table()[log_table()[a as usize] as usize + log_table()[b as usize] as usize]
}

fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    exp_table()[255 - log_table()[a as usize] as usize]
}

fn evaluate_polynomial(coeffs: &[u8], x: u8) -> u8 {
    // Horner's method
    let mut result = 0u8;
    for &coeff in coeffs.iter().rev() {
        result = gf256_mul(result, x) ^ coeff;
    }
    result
}

fn lagrange_interpolate_at_zero(xs: &[u8], ys: &[u8]) -> u8 {
    let mut secret = 0u8;

    for i in 0..xs.len() {
        let mut num = 1u8;
        let mut den = 1u8;

        for j in 0..xs.len() {
            if i != j {
                num = gf256_mul(num, xs[j]); // (0 - x_j) = x_j in GF(256)
                den = gf256_mul(den, xs[i] ^ xs[j]); // (x_i - x_j)
            }
        }

        let lagrange = gf256_mul(num, gf256_inv(den));
        secret ^= gf256_mul(ys[i], lagrange);
    }

    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_reconstruct() {
        let secret = b"my super secret key material!!!";
        let set = split_secret(secret, 3, 5).unwrap();
        assert_eq!(set.shards.len(), 5);

        // Reconstruct with first 3 shards
        let recovered = reconstruct_secret(&set.shards[..3]).unwrap();
        assert_eq!(recovered, secret);

        // Reconstruct with last 3 shards
        let recovered = reconstruct_secret(&set.shards[2..]).unwrap();
        assert_eq!(recovered, secret);

        // Reconstruct with shards 0, 2, 4
        let subset = vec![
            set.shards[0].clone(),
            set.shards[2].clone(),
            set.shards[4].clone(),
        ];
        let recovered = reconstruct_secret(&subset).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_insufficient_shards_fails() {
        let secret = b"test";
        let set = split_secret(secret, 3, 5).unwrap();
        assert!(reconstruct_secret(&set.shards[..2]).is_err());
    }

    #[test]
    fn test_2_of_3() {
        let secret = b"hello world 1234";
        let set = split_secret(secret, 2, 3).unwrap();

        for i in 0..3 {
            for j in (i + 1)..3 {
                let subset = vec![set.shards[i].clone(), set.shards[j].clone()];
                let recovered = reconstruct_secret(&subset).unwrap();
                assert_eq!(recovered, secret, "Failed with shards {} and {}", i, j);
            }
        }
    }

    #[test]
    fn test_single_byte_secret() {
        let secret = &[42u8];
        let set = split_secret(secret, 2, 3).unwrap();
        let recovered = reconstruct_secret(&set.shards[..2]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_gf256_mul_identity() {
        assert_eq!(gf256_mul(1, 42), 42);
        assert_eq!(gf256_mul(42, 1), 42);
        assert_eq!(gf256_mul(0, 42), 0);
    }

    #[test]
    fn test_gf256_inverse() {
        for a in 1..=255u8 {
            let inv = gf256_inv(a);
            assert_eq!(gf256_mul(a, inv), 1, "inverse failed for {}", a);
        }
    }
}
