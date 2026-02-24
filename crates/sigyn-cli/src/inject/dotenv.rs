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

#[cfg(test)]
mod tests {
    use super::*;
    use sigyn_core::crypto::keys::KeyFingerprint;
    use sigyn_core::secrets::types::SecretValue;
    use sigyn_core::vault::PlaintextEnv;

    fn make_env(pairs: &[(&str, &str)]) -> PlaintextEnv {
        let fp = KeyFingerprint([0u8; 16]);
        let mut env = PlaintextEnv::new();
        for (k, v) in pairs {
            env.set(k.to_string(), SecretValue::String(v.to_string()), &fp);
        }
        env
    }

    #[test]
    fn test_format_dotenv_simple() {
        let env = make_env(&[("KEY", "value")]);
        let out = format_dotenv(&env);
        assert_eq!(out, "KEY=value\n");
    }

    #[test]
    fn test_format_dotenv_with_spaces() {
        let env = make_env(&[("KEY", "hello world")]);
        let out = format_dotenv(&env);
        assert_eq!(out, "KEY=\"hello world\"\n");
    }

    #[test]
    fn test_format_dotenv_with_quotes() {
        let env = make_env(&[("KEY", "say \"hi\"")]);
        let out = format_dotenv(&env);
        assert_eq!(out, "KEY=\"say \\\"hi\\\"\"\n");
    }

    #[test]
    fn test_format_dotenv_with_hash() {
        let env = make_env(&[("KEY", "foo#bar")]);
        let out = format_dotenv(&env);
        assert_eq!(out, "KEY=\"foo#bar\"\n");
    }

    #[test]
    fn test_format_dotenv_with_newline() {
        let env = make_env(&[("KEY", "line1\nline2")]);
        let out = format_dotenv(&env);
        assert!(out.contains('"'));
    }

    #[test]
    fn test_format_dotenv_with_backslash_and_space() {
        // Backslash escaping only happens when value is quoted (contains space/quote/hash/newline)
        let env = make_env(&[("KEY", "path\\to dir")]);
        let out = format_dotenv(&env);
        assert!(out.contains("\\\\"));
        assert!(out.contains('"'));
    }

    #[test]
    fn test_format_dotenv_backslash_unquoted() {
        // Without triggering quoting, backslashes are kept as-is
        let env = make_env(&[("KEY", "path\\to")]);
        let out = format_dotenv(&env);
        assert_eq!(out, "KEY=path\\to\n");
    }

    #[test]
    fn test_format_shell_eval_simple() {
        let env = make_env(&[("DB", "postgres://localhost")]);
        let out = format_shell_eval(&env);
        assert_eq!(out, "export DB='postgres://localhost'\n");
    }

    #[test]
    fn test_format_shell_eval_with_single_quotes() {
        let env = make_env(&[("MSG", "it's a test")]);
        let out = format_shell_eval(&env);
        assert_eq!(out, "export MSG='it'\\''s a test'\n");
    }

    #[test]
    fn test_format_docker_env_simple() {
        let env = make_env(&[("KEY", "value")]);
        let out = format_docker_env(&env);
        assert_eq!(out, "--env KEY=value");
    }

    #[test]
    fn test_format_docker_env_with_special_chars() {
        let env = make_env(&[("KEY", "hello world")]);
        let out = format_docker_env(&env);
        assert!(out.contains("--env KEY="));
        assert!(out.contains("'hello world'"));
    }

    #[test]
    fn test_format_docker_env_multiple() {
        let env = make_env(&[("A", "1"), ("B", "2")]);
        let out = format_docker_env(&env);
        assert!(out.contains("--env A=1"));
        assert!(out.contains("--env B=2"));
    }

    #[test]
    fn test_shell_escape_simple() {
        assert_eq!(shell_escape("hello"), "hello");
        assert_eq!(shell_escape("foo_bar"), "foo_bar");
        assert_eq!(shell_escape("path/to/file"), "path/to/file");
        assert_eq!(shell_escape("v1.2.3"), "v1.2.3");
        assert_eq!(shell_escape("a-b"), "a-b");
    }

    #[test]
    fn test_shell_escape_special() {
        assert_eq!(shell_escape("hello world"), "'hello world'");
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
        assert_eq!(shell_escape("a=b"), "'a=b'");
    }

    #[test]
    fn test_format_dotenv_empty() {
        let env = PlaintextEnv::new();
        assert_eq!(format_dotenv(&env), "");
    }

    #[test]
    fn test_format_shell_eval_empty() {
        let env = PlaintextEnv::new();
        assert_eq!(format_shell_eval(&env), "");
    }

    #[test]
    fn test_format_docker_env_empty() {
        let env = PlaintextEnv::new();
        assert_eq!(format_docker_env(&env), "");
    }
}
