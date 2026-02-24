use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;

use anyhow::Result;
use sigyn_engine::vault::PlaintextEnv;

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

#[cfg(test)]
mod tests {
    use super::*;
    use sigyn_engine::crypto::keys::KeyFingerprint;
    use sigyn_engine::secrets::types::SecretValue;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    fn make_env(pairs: &[(&str, &str)]) -> PlaintextEnv {
        let fp = KeyFingerprint([0u8; 16]);
        let mut env = PlaintextEnv::new();
        for (k, v) in pairs {
            env.set(k.to_string(), SecretValue::String(v.to_string()), &fp);
        }
        env
    }

    #[test]
    fn test_socket_get_and_quit() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let env = make_env(&[("DB_URL", "postgres://localhost"), ("API_KEY", "sk-123")]);

        let sock_path = sock_str.clone();
        let handle = std::thread::spawn(move || {
            serve_secrets(&env, &sock_path).unwrap();
        });

        // Wait for server to start
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        let stream = UnixStream::connect(&sock_str).unwrap();
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);

        // GET existing key
        writeln!(writer, "DB_URL").unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "OK postgres://localhost");

        // GET another key
        line.clear();
        writeln!(writer, "API_KEY").unwrap();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "OK sk-123");

        // GET non-existent key
        line.clear();
        writeln!(writer, "NOPE").unwrap();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "ERR not found");

        // QUIT
        writeln!(writer, "QUIT").unwrap();

        handle.join().unwrap();
    }

    #[test]
    fn test_socket_list_command() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("list-test.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let env = make_env(&[("A", "1"), ("B", "2")]);

        let sock_path = sock_str.clone();
        let handle = std::thread::spawn(move || {
            serve_secrets(&env, &sock_path).unwrap();
        });

        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        let stream = UnixStream::connect(&sock_str).unwrap();
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);

        // LIST command
        writeln!(writer, "LIST").unwrap();
        let mut keys = Vec::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let trimmed = line.trim();
            if trimmed == "." {
                break;
            }
            keys.push(trimmed.to_string());
        }
        assert!(keys.contains(&"A".to_string()));
        assert!(keys.contains(&"B".to_string()));

        // Quit
        writeln!(writer, "QUIT").unwrap();
        handle.join().unwrap();
    }
}
