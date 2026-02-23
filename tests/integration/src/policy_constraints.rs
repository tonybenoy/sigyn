use chrono::{TimeZone, Utc};
use sigyn_core::crypto::keys::KeyFingerprint;
use sigyn_core::policy::constraints::{Constraints, TimeWindow};
use sigyn_core::policy::engine::{AccessAction, AccessRequest, PolicyDecision, PolicyEngine};
use sigyn_core::policy::member::MemberPolicy;
use sigyn_core::policy::roles::Role;
use sigyn_core::policy::storage::VaultPolicy;

fn make_constraints() -> Constraints {
    Constraints {
        time_windows: vec![],
        ip_allowlist: vec![],
        rate_limit: None,
        expires_at: None,
        require_mfa: false,
    }
}

#[test]
fn test_expired_member_denied() {
    let owner_fp = KeyFingerprint([0u8; 16]);
    let member_fp = KeyFingerprint([1u8; 16]);

    let mut policy = VaultPolicy::new();
    let mut member = MemberPolicy::new(member_fp.clone(), Role::Contributor);

    // Set expiry to 1 hour in the past
    let mut constraints = make_constraints();
    constraints.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
    member.constraints = Some(constraints);
    policy.add_member(member);

    let engine = PolicyEngine::new(&policy, &owner_fp);

    let request = AccessRequest {
        actor: member_fp.clone(),
        action: AccessAction::Read,
        env: "dev".into(),
        key: Some("DB_URL".into()),
    };

    let decision = engine.evaluate(&request).unwrap();
    assert!(
        matches!(decision, PolicyDecision::Deny(ref reason) if reason.contains("expired")),
        "Expected Deny with 'expired' reason, got: {:?}",
        decision
    );
}

#[test]
fn test_non_expired_member_allowed() {
    let owner_fp = KeyFingerprint([0u8; 16]);
    let member_fp = KeyFingerprint([1u8; 16]);

    let mut policy = VaultPolicy::new();
    let mut member = MemberPolicy::new(member_fp.clone(), Role::Contributor);

    // Set expiry to 1 hour in the future
    let mut constraints = make_constraints();
    constraints.expires_at = Some(Utc::now() + chrono::Duration::hours(1));
    member.constraints = Some(constraints);
    policy.add_member(member);

    let engine = PolicyEngine::new(&policy, &owner_fp);

    let request = AccessRequest {
        actor: member_fp.clone(),
        action: AccessAction::Read,
        env: "dev".into(),
        key: Some("DB_URL".into()),
    };

    assert_eq!(engine.evaluate(&request).unwrap(), PolicyDecision::Allow);
}

#[test]
fn test_time_window_enforcement() {
    // Test the Constraints::check method directly with fixed times

    // Window: Monday 9-17 UTC
    let mut constraints = make_constraints();
    constraints.time_windows = vec![TimeWindow {
        days: vec![chrono::Weekday::Mon],
        start_hour: 9,
        end_hour: 17,
        timezone: "UTC".into(),
    }];

    // Monday 14:00 UTC -> should be allowed
    let monday_14 = Utc.with_ymd_and_hms(2025, 3, 10, 14, 0, 0).unwrap();
    assert!(constraints.check(monday_14).is_ok());

    // Monday 20:00 UTC -> outside window
    let monday_20 = Utc.with_ymd_and_hms(2025, 3, 10, 20, 0, 0).unwrap();
    assert!(constraints.check(monday_20).is_err());

    // Monday 8:59 UTC -> before window
    let monday_early = Utc.with_ymd_and_hms(2025, 3, 10, 8, 0, 0).unwrap();
    assert!(constraints.check(monday_early).is_err());

    // Tuesday 14:00 UTC -> wrong day
    let tuesday_14 = Utc.with_ymd_and_hms(2025, 3, 11, 14, 0, 0).unwrap();
    assert!(constraints.check(tuesday_14).is_err());
}

#[test]
fn test_time_window_with_policy_engine() {
    let owner_fp = KeyFingerprint([0u8; 16]);
    let member_fp = KeyFingerprint([1u8; 16]);

    let mut policy = VaultPolicy::new();
    let mut member = MemberPolicy::new(member_fp.clone(), Role::Contributor);

    // Create a time window that covers 24h every day of the week (always valid)
    let mut constraints = make_constraints();
    constraints.time_windows = vec![TimeWindow {
        days: vec![
            chrono::Weekday::Mon,
            chrono::Weekday::Tue,
            chrono::Weekday::Wed,
            chrono::Weekday::Thu,
            chrono::Weekday::Fri,
            chrono::Weekday::Sat,
            chrono::Weekday::Sun,
        ],
        start_hour: 0,
        end_hour: 0, // 0-0 means overnight range: always active
        timezone: "UTC".into(),
    }];
    member.constraints = Some(constraints);
    policy.add_member(member);

    let engine = PolicyEngine::new(&policy, &owner_fp);

    let request = AccessRequest {
        actor: member_fp.clone(),
        action: AccessAction::Read,
        env: "dev".into(),
        key: None,
    };

    // Should be allowed since the time window covers all hours
    assert_eq!(engine.evaluate(&request).unwrap(), PolicyDecision::Allow);
}

#[test]
fn test_multiple_time_windows() {
    let mut constraints = make_constraints();

    // Two windows: Mon 9-17 and Fri 9-17
    constraints.time_windows = vec![
        TimeWindow {
            days: vec![chrono::Weekday::Mon],
            start_hour: 9,
            end_hour: 17,
            timezone: "UTC".into(),
        },
        TimeWindow {
            days: vec![chrono::Weekday::Fri],
            start_hour: 9,
            end_hour: 17,
            timezone: "UTC".into(),
        },
    ];

    // Monday 10:00 -> allowed (matches first window)
    let mon = Utc.with_ymd_and_hms(2025, 3, 10, 10, 0, 0).unwrap();
    assert!(constraints.check(mon).is_ok());

    // Friday 10:00 -> allowed (matches second window)
    let fri = Utc.with_ymd_and_hms(2025, 3, 14, 10, 0, 0).unwrap();
    assert!(constraints.check(fri).is_ok());

    // Wednesday 10:00 -> denied (neither window matches)
    let wed = Utc.with_ymd_and_hms(2025, 3, 12, 10, 0, 0).unwrap();
    assert!(constraints.check(wed).is_err());
}

#[test]
fn test_no_constraints_allows_access() {
    let owner_fp = KeyFingerprint([0u8; 16]);
    let member_fp = KeyFingerprint([1u8; 16]);

    let mut policy = VaultPolicy::new();
    let member = MemberPolicy::new(member_fp.clone(), Role::Contributor);
    // No constraints set (None)
    policy.add_member(member);

    let engine = PolicyEngine::new(&policy, &owner_fp);

    let request = AccessRequest {
        actor: member_fp.clone(),
        action: AccessAction::Write,
        env: "dev".into(),
        key: Some("ANY_KEY".into()),
    };

    assert_eq!(engine.evaluate(&request).unwrap(), PolicyDecision::Allow);
}

#[test]
fn test_ip_allowlist_constraint() {
    let mut constraints = make_constraints();
    constraints.ip_allowlist = vec!["10.0.0.0/24".into(), "192.168.1.5".into()];

    // Allowed IPs
    assert!(constraints.check_ip("10.0.0.1").is_ok());
    assert!(constraints.check_ip("10.0.0.255").is_ok());
    assert!(constraints.check_ip("192.168.1.5").is_ok());

    // Denied IPs
    assert!(constraints.check_ip("10.0.1.1").is_err());
    assert!(constraints.check_ip("192.168.1.6").is_err());
    assert!(constraints.check_ip("8.8.8.8").is_err());
}

#[test]
fn test_combined_expiry_and_time_window() {
    let mut constraints = make_constraints();

    // Set a future expiry
    constraints.expires_at = Some(Utc::now() + chrono::Duration::days(30));

    // Set a Monday-only window
    constraints.time_windows = vec![TimeWindow {
        days: vec![chrono::Weekday::Mon],
        start_hour: 9,
        end_hour: 17,
        timezone: "UTC".into(),
    }];

    // Monday 10:00, not expired -> allowed
    let mon_10 = Utc.with_ymd_and_hms(2025, 3, 10, 10, 0, 0).unwrap();
    assert!(constraints.check(mon_10).is_ok());

    // Tuesday 10:00, not expired but wrong day -> denied
    let tue_10 = Utc.with_ymd_and_hms(2025, 3, 11, 10, 0, 0).unwrap();
    assert!(constraints.check(tue_10).is_err());
}
