use anyhow::{Context, Result};
use clap::Args;
use console::style;

const REPO: &str = "tonybenoy/sigyn";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum archive size: 100 MiB. Enforced *while streaming* the download so an
/// oversized (or maliciously endless) body is aborted before it is fully buffered.
const MAX_ARCHIVE_SIZE: usize = 100 * 1024 * 1024;

/// Maximum size for the small text sidecar files (`checksums.sha256` and its
/// `.sig`). These are tiny; cap them tightly to bound memory and abuse.
const MAX_CHECKSUMS_SIZE: usize = 1024 * 1024;

/// Ed25519 public key pinned into the binary. The release process MUST sign the
/// `checksums.sha256` file with the matching private key and publish the detached
/// 64-byte signature as `checksums.sha256.sig` next to the release assets. At
/// self-update time we verify that signature against this key BEFORE trusting any
/// checksum (and therefore before trusting the downloaded binary).
///
/// SECURITY: this is a PLACEHOLDER (all zeros). Until it is replaced with the real
/// release-signing public key, `sigyn update` refuses to self-update (fail closed;
/// see [`signing_key_is_placeholder`]). Do NOT ship a release with this value.
///
/// To configure the release pipeline:
///   1. Generate an Ed25519 keypair; keep the private key offline/secret.
///   2. For each release, sign the raw bytes of `checksums.sha256`, producing a
///      64-byte detached signature, and upload it as `checksums.sha256.sig`.
///   3. Replace the 32 bytes below with the public key bytes.
const UPDATE_SIGNING_PUBKEY: [u8; 32] = [0u8; 32];

#[derive(Args)]
pub struct UpdateArgs {
    /// Only check for updates, don't install
    #[arg(long)]
    check: bool,
}

/// Detect the GitHub release target triple for this platform.
fn detect_target() -> Result<&'static str> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Ok("x86_64-unknown-linux-gnu")
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        Ok("aarch64-unknown-linux-gnu")
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        Ok("x86_64-apple-darwin")
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        Ok("aarch64-apple-darwin")
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        Ok("x86_64-pc-windows-msvc")
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "windows", target_arch = "x86_64"),
    )))]
    {
        anyhow::bail!("unsupported platform for self-update")
    }
}

/// Parse a version string like "v0.2.8" or "0.2.8" into (major, minor, patch).
fn parse_version(v: &str) -> Option<(u32, u32, u32)> {
    let v = v.strip_prefix('v').unwrap_or(v);
    // Strip any pre-release suffix for comparison
    let v = v.split('-').next()?;
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    Some((
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ))
}

/// Returns true if `latest` is newer than `current`.
fn is_newer(current: &str, latest: &str) -> bool {
    match (parse_version(current), parse_version(latest)) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

/// Build a hardened HTTP client with timeouts.
fn build_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_secs(10))
        .user_agent(format!("sigyn/{}", CURRENT_VERSION))
        .build()
        .context("failed to build HTTP client")
}

/// Fetch the latest release tag from GitHub.
async fn fetch_latest_version(client: &reqwest::Client) -> Result<String> {
    let url = format!("https://api.github.com/repos/{}/releases/latest", REPO);
    let resp = client
        .get(&url)
        .header("Accept", "application/vnd.github.v3+json")
        .send()
        .await
        .context("failed to query GitHub releases")?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "GitHub API returned {}: check your network connection",
            resp.status()
        );
    }

    let body: serde_json::Value = resp.json().await?;
    let tag = body["tag_name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no tag_name in release response"))?;

    Ok(tag.to_string())
}

/// Append `chunk` to `buf`, failing if doing so would exceed `max_size`.
///
/// Network-free so the streaming size-cap logic can be unit tested. The check is
/// performed *before* the bytes are appended, so `buf` never grows past the cap.
fn push_capped(buf: &mut Vec<u8>, chunk: &[u8], max_size: usize) -> Result<()> {
    if buf.len().saturating_add(chunk.len()) > max_size {
        anyhow::bail!(
            "download exceeded maximum allowed size of {} bytes",
            max_size
        );
    }
    buf.extend_from_slice(chunk);
    Ok(())
}

/// Download a file, streaming the body and enforcing `max_size` as we go.
///
/// Unlike a plain `resp.bytes().await`, this never buffers more than `max_size`
/// bytes: it aborts as soon as the accumulated body would exceed the cap, so a
/// hostile or misconfigured server cannot exhaust memory.
async fn download_bytes(client: &reqwest::Client, url: &str, max_size: usize) -> Result<Vec<u8>> {
    let mut resp = client.get(url).send().await.context("download failed")?;

    if !resp.status().is_success() {
        anyhow::bail!("download returned HTTP {}", resp.status());
    }

    // Fast-path rejection using the advertised length (advisory; not trusted).
    if let Some(len) = resp.content_length() {
        if len > max_size as u64 {
            anyhow::bail!(
                "download size ({} bytes) exceeds maximum allowed ({} bytes)",
                len,
                max_size
            );
        }
    }

    let mut buf = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .context("download failed while streaming body")?
    {
        push_capped(&mut buf, &chunk, max_size)?;
    }

    Ok(buf)
}

/// Verify a detached Ed25519 `signature` over `message` against `pubkey_bytes`.
///
/// The key parameter is passed explicitly (rather than reading the pinned const
/// directly) so the verification path is unit-testable with an ephemeral keypair.
/// Fails closed: any malformed key, malformed signature, or bad signature is an
/// error. Uses the Ed25519 wrapper re-exported by sigyn-core.
fn verify_detached_signature(
    pubkey_bytes: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    use sigyn_engine::crypto::keys::VerifyingKeyWrapper;

    let key = VerifyingKeyWrapper::from_bytes(pubkey_bytes)
        .map_err(|e| anyhow::anyhow!("invalid pinned update signing key: {e}"))?;
    key.verify(message, signature)
        .map_err(|_| anyhow::anyhow!("checksums signature is not valid for the pinned key"))
}

/// True while [`UPDATE_SIGNING_PUBKEY`] is still the all-zeros placeholder.
///
/// Used to fail closed: we refuse to self-update until a real signing key is
/// pinned, rather than silently skipping signature verification.
fn signing_key_is_placeholder() -> bool {
    UPDATE_SIGNING_PUBKEY == [0u8; 32]
}

/// Verify SHA-256 checksum of archive bytes against the checksums file.
fn verify_checksum(archive_name: &str, archive_bytes: &[u8], checksums: &str) -> Result<()> {
    use sha2::{Digest, Sha256};

    let actual = hex::encode(Sha256::digest(archive_bytes));

    for line in checksums.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[1] == archive_name {
            let expected = parts[0].to_lowercase();
            if actual == expected {
                return Ok(());
            } else {
                anyhow::bail!(
                    "checksum mismatch for {}: expected {}, got {}",
                    archive_name,
                    expected,
                    actual
                );
            }
        }
    }

    anyhow::bail!("no checksum found for {} in checksums file", archive_name);
}

/// Extract the sigyn binary from a tar.gz archive and return its bytes.
fn extract_binary_from_tar_gz(archive_bytes: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;

    let decoder = flate2::read::GzDecoder::new(archive_bytes);
    let mut archive = tar::Archive::new(decoder);

    let binary_name = if cfg!(windows) { "sigyn.exe" } else { "sigyn" };

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;

        // Reject path traversal: entries must not contain ".." components
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            anyhow::bail!("archive contains path traversal entry: {}", path.display());
        }

        if path.file_name().and_then(|n| n.to_str()) == Some(binary_name) {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            return Ok(buf);
        }
    }

    anyhow::bail!("binary '{}' not found in archive", binary_name);
}

/// Replace the current executable with new bytes.
fn replace_current_exe(new_bytes: &[u8]) -> Result<()> {
    let current_exe =
        std::env::current_exe().context("cannot determine current executable path")?;
    let current_exe = current_exe.canonicalize().unwrap_or(current_exe);

    let parent = current_exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cannot determine parent directory of executable"))?;

    // Use a random temp file name to avoid predictable paths
    let random_suffix: u64 = rand::random();
    let new_path = parent.join(format!(".sigyn-update-{:016x}", random_suffix));

    // Write new binary to temp file
    std::fs::write(&new_path, new_bytes).context("failed to write new binary")?;

    // Make executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new_path, std::fs::Permissions::from_mode(0o755))?;
    }

    // Atomic rename (on Unix this replaces the file even while running)
    #[cfg(unix)]
    {
        std::fs::rename(&new_path, &current_exe).context("failed to replace binary")?;
    }

    // On Windows: rename current to .old, rename new to current
    #[cfg(windows)]
    {
        let old_path = parent.join(".sigyn-old.exe");
        let _ = std::fs::remove_file(&old_path); // clean up any previous .old
        std::fs::rename(&current_exe, &old_path).context("failed to move current binary aside")?;
        std::fs::rename(&new_path, &current_exe).context("failed to move new binary in place")?;
        let _ = std::fs::remove_file(&old_path); // best-effort cleanup
    }

    Ok(())
}

pub fn handle(args: UpdateArgs, json: bool) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let client = build_client()?;

        eprintln!("{}", style("Checking for updates...").dim());

        let latest_tag = fetch_latest_version(&client).await?;
        let latest_version = latest_tag.strip_prefix('v').unwrap_or(&latest_tag);

        if json && args.check {
            crate::output::print_json(&serde_json::json!({
                "current_version": CURRENT_VERSION,
                "latest_version": latest_version,
                "update_available": is_newer(CURRENT_VERSION, latest_version),
            }))?;
            return Ok(());
        }

        if !is_newer(CURRENT_VERSION, latest_version) {
            if json {
                crate::output::print_json(&serde_json::json!({
                    "current_version": CURRENT_VERSION,
                    "latest_version": latest_version,
                    "status": "up_to_date",
                }))?;
            } else {
                crate::output::print_success(&format!("Already up to date (v{})", CURRENT_VERSION));
            }
            return Ok(());
        }

        println!(
            "  {} v{} -> v{}",
            style("Update available:").bold(),
            CURRENT_VERSION,
            latest_version,
        );

        if args.check {
            println!(
                "  Run {} to install the update.",
                style("sigyn update").bold()
            );
            return Ok(());
        }

        // Fail closed: refuse to self-update until a real release-signing key is
        // pinned. Skipping signature verification silently would be dishonest
        // about the security posture, so we stop here instead.
        if signing_key_is_placeholder() {
            anyhow::bail!(
                "self-update signature verification is not yet configured; \
                 download releases manually from https://github.com/{}/releases",
                REPO
            );
        }

        let target = detect_target()?;
        let ext = if cfg!(windows) { "zip" } else { "tar.gz" };
        let archive_name = format!("sigyn-{}-{}.{}", latest_tag, target, ext);
        let archive_url = format!(
            "https://github.com/{}/releases/download/{}/{}",
            REPO, latest_tag, archive_name
        );
        let checksums_url = format!(
            "https://github.com/{}/releases/download/{}/checksums.sha256",
            REPO, latest_tag
        );
        // Detached Ed25519 signature over the checksums file.
        let checksums_sig_url = format!("{}.sig", checksums_url);

        // Download archive (size-capped while streaming).
        eprint!("  {} downloading {}...", style("->").cyan(), archive_name);
        let archive_bytes = download_bytes(&client, &archive_url, MAX_ARCHIVE_SIZE).await?;
        eprintln!(" {}", style("done").green());

        // Verify checksum. The checksums file is only trusted once its detached
        // Ed25519 signature is verified against the pinned public key, so the
        // checksum (and therefore the binary) is authenticated, not just
        // transport-trusted. Any failure here fails closed.
        eprint!("  {} verifying signature...", style("->").cyan());
        let checksum_bytes = download_bytes(&client, &checksums_url, MAX_CHECKSUMS_SIZE)
            .await
            .context("failed to download checksums (refusing to install unverified binary)")?;
        let sig_bytes = download_bytes(&client, &checksums_sig_url, MAX_CHECKSUMS_SIZE)
            .await
            .context(
                "failed to download checksums signature \
                 (refusing to install unverified binary)",
            )?;
        verify_detached_signature(&UPDATE_SIGNING_PUBKEY, &checksum_bytes, &sig_bytes)
            .context("checksums signature verification failed (refusing to install)")?;
        let checksums = String::from_utf8_lossy(&checksum_bytes);
        verify_checksum(&archive_name, &archive_bytes, &checksums)?;
        eprintln!(" {}", style("ok").green());

        // Extract binary
        eprint!("  {} extracting binary...", style("->").cyan());
        let binary_bytes = if cfg!(windows) {
            anyhow::bail!("zip extraction not yet supported; use install.ps1 to update on Windows")
        } else {
            extract_binary_from_tar_gz(&archive_bytes)?
        };
        eprintln!(" {}", style("done").green());

        // Replace executable
        eprint!("  {} replacing binary...", style("->").cyan());
        replace_current_exe(&binary_bytes)?;
        eprintln!(" {}", style("done").green());

        if json {
            crate::output::print_json(&serde_json::json!({
                "previous_version": CURRENT_VERSION,
                "new_version": latest_version,
                "status": "updated",
            }))?;
        } else {
            println!();
            crate::output::print_success(&format!(
                "Updated sigyn v{} -> v{}",
                CURRENT_VERSION, latest_version
            ));
        }

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigyn_engine::crypto::keys::SigningKeyPair;

    // --- Streaming size cap (push_capped) ---

    #[test]
    fn push_capped_allows_body_up_to_the_limit() {
        let cap = 16;
        let mut buf = Vec::new();
        assert!(push_capped(&mut buf, b"aaaaaaaa", cap).is_ok());
        assert!(push_capped(&mut buf, b"bbbbbbbb", cap).is_ok()); // exactly at the cap
        assert_eq!(buf.len(), 16);
    }

    #[test]
    fn push_capped_rejects_one_byte_over_the_limit() {
        let cap = 16;
        let mut buf = vec![0u8; 16];
        let err = push_capped(&mut buf, b"c", cap);
        assert!(err.is_err(), "one byte over the cap must be rejected");
        // The buffer must not have grown past the cap.
        assert_eq!(buf.len(), 16);
    }

    #[test]
    fn streaming_cap_aborts_on_oversized_body() {
        // Mirrors the real download loop: feed chunks until the cap is exceeded.
        let cap = 16;
        let chunks: [&[u8]; 3] = [b"aaaaaaaa", b"bbbbbbbb", b"cccccccc"]; // 24 bytes total
        let mut buf = Vec::new();
        let mut errored = false;
        for chunk in chunks {
            if push_capped(&mut buf, chunk, cap).is_err() {
                errored = true;
                break;
            }
        }
        assert!(errored, "cumulative body over the cap must abort");
        assert!(
            buf.len() <= cap,
            "buffer never exceeds the cap, got {}",
            buf.len()
        );
    }

    // --- Detached Ed25519 signature verification ---

    fn keypair(seed: u8) -> (SigningKeyPair, [u8; 32]) {
        let kp = SigningKeyPair::from_bytes(&[seed; 32]);
        let pubkey = kp.verifying_key().to_bytes();
        (kp, pubkey)
    }

    #[test]
    fn signature_verifies_for_matching_key_and_message() {
        let (kp, pubkey) = keypair(7);
        let msg = b"abc123  sigyn-v1.0.0-x86_64-unknown-linux-gnu.tar.gz\n";
        let sig = kp.sign(msg);
        assert!(verify_detached_signature(&pubkey, msg, &sig).is_ok());
    }

    #[test]
    fn signature_rejects_tampered_message() {
        let (kp, pubkey) = keypair(7);
        let sig = kp.sign(b"original checksums");
        assert!(verify_detached_signature(&pubkey, b"tampered checksums", &sig).is_err());
    }

    #[test]
    fn signature_rejects_tampered_signature() {
        let (kp, pubkey) = keypair(7);
        let msg = b"checksums file contents";
        let mut sig = kp.sign(msg);
        sig[0] ^= 0x01;
        assert!(verify_detached_signature(&pubkey, msg, &sig).is_err());
    }

    #[test]
    fn signature_rejects_wrong_key() {
        let (kp_a, _pub_a) = keypair(1);
        let (_kp_b, pub_b) = keypair(2);
        let msg = b"checksums";
        let sig = kp_a.sign(msg);
        assert!(verify_detached_signature(&pub_b, msg, &sig).is_err());
    }

    #[test]
    fn signature_rejects_malformed_signature_length() {
        let (_kp, pubkey) = keypair(3);
        assert!(verify_detached_signature(&pubkey, b"msg", b"too short").is_err());
    }

    // --- Fail-closed placeholder gate ---

    #[test]
    fn placeholder_key_is_detected_so_update_fails_closed() {
        // Until the real release-signing key is pinned, self-update must refuse.
        assert!(signing_key_is_placeholder());
    }
}
