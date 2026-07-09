use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{Result, SigynError};

/// Domain-separation context for the shard secret checksum (BLAKE3 `derive_key`).
const SHARD_CHECKSUM_CONTEXT: &str = "sigyn-shamir-shard-checksum-v1";

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
    /// Hex-encoded BLAKE3 checksum of the original secret, domain-separated
    /// via `derive_key`. Used to detect an incorrect reconstruction (corrupted
    /// or mismatched shards). `None` for shards created before this field
    /// existed; verification is skipped in that case.
    ///
    /// The secrets Sigyn shards are uniformly random 32-byte keys, so
    /// publishing this one-way digest alongside the shards does not create a
    /// feasible brute-force oracle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
}

/// One-way, domain-separated digest of the secret, hex-encoded.
fn secret_checksum(secret: &[u8]) -> String {
    let digest = blake3::derive_key(SHARD_CHECKSUM_CONTEXT, secret);
    blake3::Hash::from(digest).to_hex().to_string()
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

    let mut rng = rand::rngs::OsRng;
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

    let checksum = secret_checksum(secret);

    let shard_set = RecoveryShardSet {
        shards: shards
            .into_iter()
            .enumerate()
            .map(|(i, data)| Shard {
                index: (i + 1) as u8,
                data,
                total,
                threshold,
                checksum: Some(checksum.clone()),
            })
            .collect(),
        threshold,
        total,
    };

    Ok(shard_set)
}

/// Reconstruct the secret from at least `threshold` shards using Lagrange interpolation in GF(256).
///
/// Validates shard metadata (distinct non-zero indices, consistent
/// threshold/total across shards) and, when the shards carry a checksum,
/// verifies the reconstructed secret against it. Shards created before the
/// checksum field existed skip that final verification.
pub fn reconstruct_secret(shards: &[Shard]) -> Result<Vec<u8>> {
    if shards.is_empty() {
        return Err(SigynError::ShamirInvalid("no shards provided".into()));
    }

    // All shards must agree on (threshold, total) — a mismatch means they do
    // not come from the same split.
    let threshold_u8 = shards[0].threshold;
    let total = shards[0].total;
    if shards
        .iter()
        .any(|s| s.threshold != threshold_u8 || s.total != total)
    {
        return Err(SigynError::ShamirInvalid(
            "shards have inconsistent threshold/total metadata — they do not come from the same split".into(),
        ));
    }

    // split_secret never produces threshold < 2; anything lower is corrupt
    // metadata (threshold 0 would silently yield an all-zero "secret").
    if threshold_u8 < 2 {
        return Err(SigynError::ShamirInvalid(format!(
            "invalid shard threshold {} (must be at least 2)",
            threshold_u8
        )));
    }

    let threshold = threshold_u8 as usize;
    if shards.len() < threshold {
        return Err(SigynError::ShamirInvalid(format!(
            "need {} shards, got {}",
            threshold,
            shards.len()
        )));
    }

    // Indices must be non-zero (x = 0 is the secret itself and breaks
    // interpolation), within range, and pairwise distinct (a duplicated
    // index yields a zero Lagrange denominator and a wrong secret).
    let mut seen = [false; 256];
    for shard in shards {
        if shard.index == 0 {
            return Err(SigynError::ShamirInvalid(
                "shard index 0 is invalid (indices are 1-based)".into(),
            ));
        }
        if shard.index > total {
            return Err(SigynError::ShamirInvalid(format!(
                "shard index {} exceeds total shard count {}",
                shard.index, total
            )));
        }
        if seen[shard.index as usize] {
            return Err(SigynError::ShamirInvalid(format!(
                "duplicate shard index {} — each shard must be a distinct shard file",
                shard.index
            )));
        }
        seen[shard.index as usize] = true;
    }

    let secret_len = shards[0].data.len();
    if secret_len == 0 {
        return Err(SigynError::ShamirInvalid("shard data is empty".into()));
    }
    if shards.iter().any(|s| s.data.len() != secret_len) {
        return Err(SigynError::ShamirInvalid(
            "shards have different lengths".into(),
        ));
    }

    // All shards that carry a checksum must agree on it.
    let expected_checksum = shards.iter().find_map(|s| s.checksum.as_deref());
    if let Some(expected) = expected_checksum {
        if shards
            .iter()
            .filter_map(|s| s.checksum.as_deref())
            .any(|c| c != expected)
        {
            return Err(SigynError::ShamirInvalid(
                "shards carry different secret checksums — they do not come from the same split"
                    .into(),
            ));
        }
    }

    let shards_to_use = &shards[..threshold];
    let xs: Vec<u8> = shards_to_use.iter().map(|s| s.index).collect();

    let mut secret = Vec::with_capacity(secret_len);

    for byte_idx in 0..secret_len {
        let ys: Vec<u8> = shards_to_use.iter().map(|s| s.data[byte_idx]).collect();
        secret.push(lagrange_interpolate_at_zero(&xs, &ys));
    }

    // Verify the reconstructed secret against the shard checksum, if present.
    if let Some(expected) = expected_checksum {
        let expected_hash = blake3::Hash::from_hex(expected).map_err(|_| {
            SigynError::ShamirInvalid("shard checksum is malformed (expected hex)".into())
        })?;
        let actual = blake3::Hash::from(blake3::derive_key(SHARD_CHECKSUM_CONTEXT, &secret));
        if actual != expected_hash {
            return Err(SigynError::ShamirInvalid(
                "reconstructed secret failed checksum verification — shards are corrupted, mismatched, or fewer than the true threshold".into(),
            ));
        }
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
    fn test_duplicate_shard_indices_rejected() {
        let secret = b"duplicate index test secret!!";
        let set = split_secret(secret, 3, 5).unwrap();

        // Same shard three times — must be an error, not a wrong secret.
        let dupes = vec![
            set.shards[0].clone(),
            set.shards[0].clone(),
            set.shards[0].clone(),
        ];
        let err = reconstruct_secret(&dupes).unwrap_err();
        assert!(err.to_string().contains("duplicate"), "got: {}", err);

        // One duplicate among otherwise valid shards — also an error.
        let dupes = vec![
            set.shards[0].clone(),
            set.shards[1].clone(),
            set.shards[1].clone(),
        ];
        assert!(reconstruct_secret(&dupes).is_err());
    }

    #[test]
    fn test_zero_index_rejected() {
        let secret = b"zero index test";
        let set = split_secret(secret, 2, 3).unwrap();

        let mut shards = vec![set.shards[0].clone(), set.shards[1].clone()];
        shards[0].index = 0;
        let err = reconstruct_secret(&shards).unwrap_err();
        assert!(err.to_string().contains("index 0"), "got: {}", err);
    }

    #[test]
    fn test_zero_threshold_rejected() {
        let secret = b"zero threshold test";
        let set = split_secret(secret, 2, 3).unwrap();

        let mut shards: Vec<Shard> = set.shards.clone();
        for s in &mut shards {
            s.threshold = 0;
        }
        // Must be an error, not an all-zero "secret".
        let err = reconstruct_secret(&shards).unwrap_err();
        assert!(err.to_string().contains("threshold"), "got: {}", err);
    }

    #[test]
    fn test_inconsistent_metadata_rejected() {
        let secret = b"metadata consistency test";
        let set = split_secret(secret, 3, 5).unwrap();

        // Threshold mismatch across shards
        let mut shards: Vec<Shard> = set.shards[..3].to_vec();
        shards[1].threshold = 4;
        let err = reconstruct_secret(&shards).unwrap_err();
        assert!(err.to_string().contains("inconsistent"), "got: {}", err);

        // Total mismatch across shards
        let mut shards: Vec<Shard> = set.shards[..3].to_vec();
        shards[2].total = 7;
        let err = reconstruct_secret(&shards).unwrap_err();
        assert!(err.to_string().contains("inconsistent"), "got: {}", err);
    }

    #[test]
    fn test_index_beyond_total_rejected() {
        let secret = b"index range test";
        let set = split_secret(secret, 2, 3).unwrap();

        let mut shards = vec![set.shards[0].clone(), set.shards[1].clone()];
        shards[1].index = 9;
        assert!(reconstruct_secret(&shards).is_err());
    }

    #[test]
    fn test_checksum_present_and_verified_on_happy_path() {
        let secret = b"checksum happy path secret!!";
        let set = split_secret(secret, 3, 5).unwrap();

        // Every freshly split shard carries the same checksum.
        for shard in &set.shards {
            assert!(shard.checksum.is_some());
            assert_eq!(shard.checksum, set.shards[0].checksum);
        }

        let recovered = reconstruct_secret(&set.shards[..3]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_checksum_detects_corrupted_shard() {
        let secret = b"corruption detection secret!";
        let set = split_secret(secret, 3, 5).unwrap();

        // Flip one byte of shard data: metadata and checksums stay consistent,
        // but reconstruction now yields a wrong secret — the checksum must
        // catch it instead of returning Ok(garbage).
        let mut shards: Vec<Shard> = set.shards[..3].to_vec();
        shards[1].data[0] ^= 0xff;
        let err = reconstruct_secret(&shards).unwrap_err();
        assert!(
            err.to_string().contains("checksum verification"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_mismatched_checksums_across_splits_rejected() {
        // Shards from two different splits (different secrets) carry
        // different checksums and must be rejected up front.
        let set_a = split_secret(b"secret A is thirty-two bytes..!!", 2, 3).unwrap();
        let set_b = split_secret(b"secret B is thirty-two bytes..!!", 2, 3).unwrap();

        let shards = vec![set_a.shards[0].clone(), set_b.shards[1].clone()];
        let err = reconstruct_secret(&shards).unwrap_err();
        assert!(
            err.to_string().contains("different secret checksums"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_legacy_shards_without_checksum_still_work() {
        let secret = b"legacy shard compatibility!!";
        let set = split_secret(secret, 3, 5).unwrap();

        // Simulate shards created before the checksum field existed.
        let mut shards: Vec<Shard> = set.shards[..3].to_vec();
        for s in &mut shards {
            s.checksum = None;
        }
        let recovered = reconstruct_secret(&shards).unwrap();
        assert_eq!(recovered, secret);

        // Mixed: verification uses the checksum from the shards that have one.
        let mut shards: Vec<Shard> = set.shards[..3].to_vec();
        shards[0].checksum = None;
        let recovered = reconstruct_secret(&shards).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_shard_json_without_checksum_deserializes() {
        // Backward compatibility: shard files written before the checksum
        // field existed must still parse (checksum defaults to None).
        let json = r#"{"index":1,"data":[1,2,3],"total":3,"threshold":2}"#;
        let shard: Shard = serde_json::from_str(json).unwrap();
        assert_eq!(shard.index, 1);
        assert!(shard.checksum.is_none());
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
