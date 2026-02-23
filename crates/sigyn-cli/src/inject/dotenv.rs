use sigyn_core::vault::PlaintextEnv;

pub fn format_dotenv(env: &PlaintextEnv) -> String {
    let mut out = String::new();
    for (key, entry) in &env.entries {
        if let Some(val) = entry.value.as_str() {
            let escaped = val.replace('\\', "\\\\").replace('"', "\\\"");
            if val.contains(' ') || val.contains('"') || val.contains('#') || val.contains('\n') {
                out.push_str(&format!("{}=\"{}\"\n", key, escaped));
            } else {
                out.push_str(&format!("{}={}\n", key, val));
            }
        }
    }
    out
}

pub fn format_shell_eval(env: &PlaintextEnv) -> String {
    let mut out = String::new();
    for (key, entry) in &env.entries {
        if let Some(val) = entry.value.as_str() {
            let escaped = val.replace('\'', "'\\''");
            out.push_str(&format!("export {}='{}'\n", key, escaped));
        }
    }
    out
}

pub fn format_docker_env(env: &PlaintextEnv) -> String {
    let mut out = String::new();
    for (key, entry) in &env.entries {
        if let Some(val) = entry.value.as_str() {
            out.push_str(&format!("--env {}={} ", key, shell_escape(val)));
        }
    }
    out.trim_end().to_string()
}

fn shell_escape(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '/')
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}
