use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;

use anyhow::Result;
use sigyn_core::vault::PlaintextEnv;

/// Serve secrets over a Unix domain socket.
/// Clients connect and send a key name; server responds with the value.
///
/// Protocol:
///   - Client sends a line with a key name.
///   - Server responds with `OK <value>` or `ERR <reason>`.
///   - Special commands:
///     - `LIST`  — returns all key names, one per line, terminated by `.`
///     - `QUIT` / `EXIT` — shuts down the server
pub fn serve_secrets(env: &PlaintextEnv, socket_path: &str) -> Result<()> {
    // Try to bind first; if EADDRINUSE, remove stale socket and retry (H11: avoid TOCTOU)
    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            std::fs::remove_file(socket_path)?;
            UnixListener::bind(socket_path)?
        }
        Err(e) => return Err(e.into()),
    };

    // H10: Restrict socket permissions to owner only
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    }
    println!("Listening on {}", socket_path);

    for stream in listener.incoming() {
        let stream = stream?;
        let reader = BufReader::new(&stream);
        for line in reader.lines() {
            let key = line?;
            let key = key.trim();

            if key == "QUIT" || key == "EXIT" {
                let _ = std::fs::remove_file(socket_path);
                return Ok(());
            }

            if key == "LIST" {
                // Return all key names, one per line, terminated by a dot
                for k in env.entries.keys() {
                    writeln!(&stream, "{}", k)?;
                }
                writeln!(&stream, ".")?;
                continue;
            }

            match env.entries.get(key) {
                Some(entry) => {
                    if let Some(val) = entry.value.as_str() {
                        writeln!(&stream, "OK {}", val)?;
                    } else {
                        writeln!(&stream, "ERR unsupported type")?;
                    }
                }
                None => writeln!(&stream, "ERR not found")?,
            }
        }
    }

    let _ = std::fs::remove_file(socket_path);
    Ok(())
}
