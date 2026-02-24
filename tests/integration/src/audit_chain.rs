use sigyn_engine::audit::chain::AuditLog;
use sigyn_engine::audit::entry::{AuditAction, AuditOutcome};
use sigyn_engine::crypto::keys::{KeyFingerprint, SigningKeyPair};
use tempfile::TempDir;

#[test]
fn test_audit_chain_integrity() {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("audit.jsonl");

    let signing_key = SigningKeyPair::generate();
    let actor = KeyFingerprint([0xAAu8; 16]);

    // 1. Create audit log and append 10 entries with different actions
    {
        let mut log = AuditLog::open(&log_path).unwrap();

        let actions = vec![
            AuditAction::VaultCreated,
            AuditAction::SecretWritten {
                key: "DB_URL".into(),
            },
            AuditAction::SecretRead {
                key: "DB_URL".into(),
            },
            AuditAction::MemberInvited {
                fingerprint: KeyFingerprint([0xBBu8; 16]),
            },
            AuditAction::PolicyChanged,
            AuditAction::SecretWritten {
                key: "API_KEY".into(),
            },
            AuditAction::EnvironmentCreated {
                name: "staging".into(),
            },
            AuditAction::EnvironmentPromoted {
                source: "dev".into(),
                target: "staging".into(),
            },
            AuditAction::SecretDeleted {
                key: "OLD_KEY".into(),
            },
            AuditAction::MasterKeyRotated,
        ];

        for (i, action) in actions.into_iter().enumerate() {
            let env = if i < 3 { Some("dev".into()) } else { None };
            let entry = log
                .append(&actor, action, env, AuditOutcome::Success, &signing_key)
                .unwrap();
            assert_eq!(entry.sequence, i as u64);
        }
    }

    // 2. Verify the chain is intact
    {
        let log = AuditLog::open(&log_path).unwrap();
        let count = log.verify_chain().unwrap();
        assert_eq!(count, 10);
    }

    // 3. Read back entries and verify structure
    {
        let log = AuditLog::open(&log_path).unwrap();
        let tail = log.tail(10).unwrap();
        assert_eq!(tail.len(), 10);

        // First entry should have no prev_hash
        assert!(tail[0].prev_hash.is_none());

        // Each subsequent entry's prev_hash should match the previous entry's entry_hash
        for i in 1..tail.len() {
            assert_eq!(tail[i].prev_hash, Some(tail[i - 1].entry_hash));
        }

        // All entries have non-empty signatures
        for entry in &tail {
            assert!(!entry.signature.is_empty());
        }
    }
}

#[test]
fn test_audit_chain_detects_tampering() {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("audit.jsonl");

    let signing_key = SigningKeyPair::generate();
    let actor = KeyFingerprint([0xCCu8; 16]);

    // Append 5 entries
    {
        let mut log = AuditLog::open(&log_path).unwrap();
        for i in 0..5 {
            log.append(
                &actor,
                AuditAction::SecretWritten {
                    key: format!("KEY_{}", i),
                },
                Some("dev".into()),
                AuditOutcome::Success,
                &signing_key,
            )
            .unwrap();
        }
    }

    // Verify chain is valid before tampering
    {
        let log = AuditLog::open(&log_path).unwrap();
        assert_eq!(log.verify_chain().unwrap(), 5);
    }

    // Tamper with the file: modify the 3rd entry's prev_hash
    {
        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 5);

        // Parse the 3rd entry (index 2), modify its prev_hash, and rewrite
        let mut entry: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
        // Flip a byte in prev_hash to simulate tampering
        if let Some(prev_hash) = entry.get_mut("prev_hash") {
            if let Some(arr) = prev_hash.as_array_mut() {
                if let Some(first) = arr.first_mut() {
                    let val = first.as_u64().unwrap_or(0);
                    *first = serde_json::Value::from(val ^ 0xFF);
                }
            }
        }

        let mut new_lines: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
        new_lines[2] = serde_json::to_string(&entry).unwrap();
        std::fs::write(&log_path, new_lines.join("\n") + "\n").unwrap();
    }

    // Verify chain now detects tampering
    {
        let log = AuditLog::open(&log_path).unwrap();
        let result = log.verify_chain();
        assert!(
            result.is_err(),
            "Chain verification should fail after tampering"
        );
    }
}

#[test]
fn test_audit_log_append_continues_after_reopen() {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("audit.jsonl");

    let signing_key = SigningKeyPair::generate();
    let actor = KeyFingerprint([0xDDu8; 16]);

    // Append 3 entries, then close
    {
        let mut log = AuditLog::open(&log_path).unwrap();
        for _ in 0..3 {
            log.append(
                &actor,
                AuditAction::SecretRead { key: "KEY".into() },
                None,
                AuditOutcome::Success,
                &signing_key,
            )
            .unwrap();
        }
    }

    // Reopen and append 2 more
    {
        let mut log = AuditLog::open(&log_path).unwrap();
        for _ in 0..2 {
            let entry = log
                .append(
                    &actor,
                    AuditAction::PolicyChanged,
                    None,
                    AuditOutcome::Success,
                    &signing_key,
                )
                .unwrap();
            // Sequence should continue from 3
            assert!(entry.sequence >= 3);
        }
    }

    // Verify full chain
    {
        let log = AuditLog::open(&log_path).unwrap();
        let count = log.verify_chain().unwrap();
        assert_eq!(count, 5);
    }
}

#[test]
fn test_audit_log_records_denied_outcomes() {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("audit.jsonl");

    let signing_key = SigningKeyPair::generate();
    let actor = KeyFingerprint([0xEEu8; 16]);

    let mut log = AuditLog::open(&log_path).unwrap();
    log.append(
        &actor,
        AuditAction::SecretRead {
            key: "FORBIDDEN".into(),
        },
        Some("prod".into()),
        AuditOutcome::Denied("insufficient permissions".into()),
        &signing_key,
    )
    .unwrap();

    let tail = log.tail(1).unwrap();
    assert_eq!(tail.len(), 1);
    assert!(matches!(tail[0].outcome, AuditOutcome::Denied(_)));
}
