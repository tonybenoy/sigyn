use anyhow::{Context, Result};
use clap::Args;
use console::style;

const REPO: &str = "tonybenoy/sigyn";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum archive size: 100 MiB. Reject anything larger before extraction.
const MAX_ARCHIVE_SIZE: usize = 100 * 1024 * 1024;

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

/// Download a file and return the bytes.
async fn download_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let resp = client.get(url).send().await.context("download failed")?;

    if !resp.status().is_success() {
        anyhow::bail!("download returned HTTP {}", resp.status());
    }

    Ok(resp.bytes().await?.to_vec())
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

        // Download archive
        eprint!("  {} downloading {}...", style("->").cyan(), archive_name);
        let archive_bytes = download_bytes(&client, &archive_url).await?;
        eprintln!(" {}", style("done").green());

        // Enforce archive size limit
        if archive_bytes.len() > MAX_ARCHIVE_SIZE {
            anyhow::bail!(
                "archive size ({} bytes) exceeds maximum allowed ({} bytes)",
                archive_bytes.len(),
                MAX_ARCHIVE_SIZE
            );
        }

        // Verify checksum
        eprint!("  {} verifying checksum...", style("->").cyan());
        match download_bytes(&client, &checksums_url).await {
            Ok(checksum_bytes) => {
                let checksums = String::from_utf8_lossy(&checksum_bytes);
                verify_checksum(&archive_name, &archive_bytes, &checksums)?;
                eprintln!(" {}", style("ok").green());
            }
            Err(e) => {
                anyhow::bail!(
                    "failed to download checksums (refusing to install unverified binary): {}",
                    e
                );
            }
        }

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
