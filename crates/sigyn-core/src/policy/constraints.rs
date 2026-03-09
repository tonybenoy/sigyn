use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Vault-level audit push mode. Controls whether audit log entries must be
/// pushed to the remote after operations. Only configurable by owner/admin
/// via the signed policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuditMode {
    /// Audit entries are appended locally; push when convenient (current default).
    #[default]
    Offline,
    /// Audit entries must be pushed to the remote after each operation.
    /// Operations fail if push fails (only enforced when a git remote is configured).
    Online,
    /// Try to push audit entries; warn on failure but don't block the operation.
    BestEffort,
}

impl fmt::Display for AuditMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditMode::Offline => write!(f, "offline"),
            AuditMode::Online => write!(f, "online"),
            AuditMode::BestEffort => write!(f, "best-effort"),
        }
    }
}

impl FromStr for AuditMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "offline" => Ok(AuditMode::Offline),
            "online" => Ok(AuditMode::Online),
            "best-effort" | "besteffort" => Ok(AuditMode::BestEffort),
            other => Err(format!(
                "unknown audit mode '{}'. Valid: offline, online, best-effort",
                other
            )),
        }
    }
}

/// Per-action MFA requirements. Each field controls whether MFA is needed for
/// that specific action. All default to `false`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MfaActions {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
    #[serde(default)]
    pub delete: bool,
    #[serde(default)]
    pub manage_members: bool,
    #[serde(default)]
    pub manage_policy: bool,
    #[serde(default)]
    pub create_env: bool,
    #[serde(default)]
    pub promote: bool,
}

impl MfaActions {
    /// All actions require MFA.
    pub fn all() -> Self {
        Self {
            read: true,
            write: true,
            delete: true,
            manage_members: true,
            manage_policy: true,
            create_env: true,
            promote: true,
        }
    }

    /// No actions require MFA.
    pub fn none() -> Self {
        Self::default()
    }

    /// Returns true if any action requires MFA.
    pub fn any_enabled(&self) -> bool {
        self.read
            || self.write
            || self.delete
            || self.manage_members
            || self.manage_policy
            || self.create_env
            || self.promote
    }

    /// Returns true if all actions require MFA.
    pub fn all_enabled(&self) -> bool {
        self.read
            && self.write
            && self.delete
            && self.manage_members
            && self.manage_policy
            && self.create_env
            && self.promote
    }

    /// Merge another MfaActions into this one (OR logic).
    pub fn merge(&mut self, other: &MfaActions) {
        self.read |= other.read;
        self.write |= other.write;
        self.delete |= other.delete;
        self.manage_members |= other.manage_members;
        self.manage_policy |= other.manage_policy;
        self.create_env |= other.create_env;
        self.promote |= other.promote;
    }

    /// Parse a comma-separated list of action names. Accepts "all" and "none".
    pub fn from_csv(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("all") {
            return Ok(Self::all());
        }
        if s.eq_ignore_ascii_case("none") {
            return Ok(Self::none());
        }
        let mut actions = Self::none();
        for part in s.split(',') {
            match part.trim().to_lowercase().as_str() {
                "read" => actions.read = true,
                "write" => actions.write = true,
                "delete" => actions.delete = true,
                "manage-members" | "manage_members" => actions.manage_members = true,
                "manage-policy" | "manage_policy" => actions.manage_policy = true,
                "create-env" | "create_env" => actions.create_env = true,
                "promote" => actions.promote = true,
                other => {
                    return Err(format!(
                        "unknown MFA action '{}'. Valid: read, write, delete, manage-members, manage-policy, create-env, promote, all, none",
                        other
                    ))
                }
            }
        }
        Ok(actions)
    }

    /// Return a comma-separated string of enabled actions.
    pub fn to_csv(&self) -> String {
        if self.all_enabled() {
            return "all".into();
        }
        let mut parts = Vec::new();
        if self.read {
            parts.push("read");
        }
        if self.write {
            parts.push("write");
        }
        if self.delete {
            parts.push("delete");
        }
        if self.manage_members {
            parts.push("manage-members");
        }
        if self.manage_policy {
            parts.push("manage-policy");
        }
        if self.create_env {
            parts.push("create-env");
        }
        if self.promote {
            parts.push("promote");
        }
        if parts.is_empty() {
            "none".into()
        } else {
            parts.join(",")
        }
    }
}

/// Custom deserializer: accept either the new `MfaActions` object or the legacy
/// `require_mfa: true/false` boolean (which maps to all/none).
fn deserialize_mfa<'de, D>(deserializer: D) -> Result<MfaActions, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum MfaField {
        Actions(MfaActions),
        Legacy(bool),
    }
    match MfaField::deserialize(deserializer)? {
        MfaField::Actions(a) => Ok(a),
        MfaField::Legacy(true) => Ok(MfaActions::all()),
        MfaField::Legacy(false) => Ok(MfaActions::none()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints {
    pub time_windows: Vec<TimeWindow>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Per-action MFA requirements. Backward-compatible: accepts `true`/`false`
    /// (legacy all-or-nothing) or the new `MfaActions` object.
    #[serde(default, alias = "require_mfa", deserialize_with = "deserialize_mfa")]
    pub mfa_actions: MfaActions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub days: Vec<chrono::Weekday>,
    pub start_hour: u8,
    pub end_hour: u8,
}

impl Constraints {
    /// Check all constraints.
    /// Returns Ok(()) if all constraints pass, or Err with a reason string.
    pub fn check(&self, now: chrono::DateTime<chrono::Utc>) -> Result<(), String> {
        // Expiry check
        if let Some(expires_at) = self.expires_at {
            if now > expires_at {
                return Err("access expired".into());
            }
        }

        // Time window check (if any windows are defined, at least one must match)
        if !self.time_windows.is_empty() {
            let in_window = self.time_windows.iter().any(|w| w.is_active(now));
            if !in_window {
                return Err("outside allowed time window".into());
            }
        }

        Ok(())
    }
}

impl TimeWindow {
    /// Validate that the time window values are sane.
    pub fn validate(&self) -> Result<(), String> {
        if self.start_hour > 23 {
            return Err(format!(
                "start_hour {} is out of range (0-23)",
                self.start_hour
            ));
        }
        if self.end_hour > 23 {
            return Err(format!("end_hour {} is out of range (0-23)", self.end_hour));
        }
        if self.days.is_empty() {
            return Err("time window must specify at least one day".into());
        }
        Ok(())
    }

    /// Check if the given UTC time falls within this window.
    pub fn is_active(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        use chrono::Datelike;
        let weekday = now.weekday();
        if !self.days.contains(&weekday) {
            return false;
        }
        let hour = now.hour_utc();
        if self.start_hour == self.end_hour {
            // Same start and end means all day
            true
        } else if self.start_hour < self.end_hour {
            // Normal range: e.g. 9..17
            hour >= self.start_hour && hour < self.end_hour
        } else {
            // Overnight range: e.g. 22..6 means 22-23 or 0-5
            hour >= self.start_hour || hour < self.end_hour
        }
    }
}

trait HourUtc {
    fn hour_utc(&self) -> u8;
}

impl HourUtc for chrono::DateTime<chrono::Utc> {
    fn hour_utc(&self) -> u8 {
        use chrono::Timelike;
        self.hour() as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn make_constraints() -> Constraints {
        Constraints {
            time_windows: vec![],
            expires_at: None,
            mfa_actions: MfaActions::none(),
        }
    }

    #[test]
    fn test_expiry_check() {
        let mut c = make_constraints();
        let now = Utc::now();
        c.expires_at = Some(now - chrono::Duration::hours(1));
        assert!(c.check(now).is_err());

        c.expires_at = Some(now + chrono::Duration::hours(1));
        assert!(c.check(now).is_ok());
    }

    #[test]
    fn test_time_window_check() {
        let now = Utc.with_ymd_and_hms(2025, 3, 10, 14, 0, 0).unwrap(); // Monday 14:00 UTC
        let mut c = make_constraints();
        c.time_windows = vec![TimeWindow {
            days: vec![chrono::Weekday::Mon],
            start_hour: 9,
            end_hour: 17,
        }];
        assert!(c.check(now).is_ok());

        // Outside hours
        let late = Utc.with_ymd_and_hms(2025, 3, 10, 20, 0, 0).unwrap();
        assert!(c.check(late).is_err());

        // Wrong day
        let tuesday = Utc.with_ymd_and_hms(2025, 3, 11, 14, 0, 0).unwrap();
        assert!(c.check(tuesday).is_err());
    }

    #[test]
    fn test_overnight_time_window() {
        let window = TimeWindow {
            days: vec![chrono::Weekday::Fri],
            start_hour: 22,
            end_hour: 6,
        };
        let late_friday = Utc.with_ymd_and_hms(2025, 3, 14, 23, 0, 0).unwrap();
        assert!(window.is_active(late_friday));

        let mid_friday = Utc.with_ymd_and_hms(2025, 3, 14, 15, 0, 0).unwrap();
        assert!(!window.is_active(mid_friday));
    }

    #[test]
    fn test_mfa_actions_csv_roundtrip() {
        let actions = MfaActions::from_csv("read,write,manage-members").unwrap();
        assert!(actions.read);
        assert!(actions.write);
        assert!(actions.manage_members);
        assert!(!actions.delete);
        assert!(!actions.manage_policy);
        assert!(!actions.create_env);
        assert!(!actions.promote);

        let csv = actions.to_csv();
        let parsed = MfaActions::from_csv(&csv).unwrap();
        assert_eq!(actions, parsed);
    }

    #[test]
    fn test_mfa_actions_all_none() {
        let all = MfaActions::from_csv("all").unwrap();
        assert!(all.all_enabled());
        assert_eq!(all.to_csv(), "all");

        let none = MfaActions::from_csv("none").unwrap();
        assert!(!none.any_enabled());
        assert_eq!(none.to_csv(), "none");
    }

    #[test]
    fn test_mfa_actions_merge() {
        let mut a = MfaActions::from_csv("read").unwrap();
        let b = MfaActions::from_csv("write,delete").unwrap();
        a.merge(&b);
        assert!(a.read);
        assert!(a.write);
        assert!(a.delete);
        assert!(!a.manage_members);
    }

    #[test]
    fn test_mfa_actions_invalid_action() {
        assert!(MfaActions::from_csv("read,bogus").is_err());
    }

    #[test]
    fn test_legacy_require_mfa_deserialization() {
        // Legacy format: require_mfa: true -> all actions
        let json = r#"{"time_windows":[],"expires_at":null,"require_mfa":true}"#;
        let c: Constraints = serde_json::from_str(json).unwrap();
        assert!(c.mfa_actions.all_enabled());

        // Legacy format: require_mfa: false -> no actions
        let json = r#"{"time_windows":[],"expires_at":null,"require_mfa":false}"#;
        let c: Constraints = serde_json::from_str(json).unwrap();
        assert!(!c.mfa_actions.any_enabled());
    }

    #[test]
    fn test_new_mfa_actions_deserialization() {
        let json = r#"{"time_windows":[],"expires_at":null,"mfa_actions":{"read":true,"write":false,"delete":false,"manage_members":true,"manage_policy":false,"create_env":false,"promote":false}}"#;
        let c: Constraints = serde_json::from_str(json).unwrap();
        assert!(c.mfa_actions.read);
        assert!(c.mfa_actions.manage_members);
        assert!(!c.mfa_actions.write);
    }

    #[test]
    fn test_audit_mode_default() {
        assert_eq!(AuditMode::default(), AuditMode::Offline);
    }

    #[test]
    fn test_audit_mode_display_fromstr_roundtrip() {
        for mode in [AuditMode::Offline, AuditMode::Online, AuditMode::BestEffort] {
            let s = mode.to_string();
            let parsed: AuditMode = s.parse().unwrap();
            assert_eq!(mode, parsed);
        }
    }

    #[test]
    fn test_audit_mode_fromstr_variants() {
        assert_eq!("offline".parse::<AuditMode>().unwrap(), AuditMode::Offline);
        assert_eq!("ONLINE".parse::<AuditMode>().unwrap(), AuditMode::Online);
        assert_eq!(
            "best-effort".parse::<AuditMode>().unwrap(),
            AuditMode::BestEffort
        );
        assert_eq!(
            "best_effort".parse::<AuditMode>().unwrap(),
            AuditMode::BestEffort
        );
        assert_eq!(
            "besteffort".parse::<AuditMode>().unwrap(),
            AuditMode::BestEffort
        );
        assert!("invalid".parse::<AuditMode>().is_err());
    }

    #[test]
    fn test_audit_mode_serde_roundtrip() {
        for mode in [AuditMode::Offline, AuditMode::Online, AuditMode::BestEffort] {
            let json = serde_json::to_string(&mode).unwrap();
            let parsed: AuditMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, parsed);
        }
    }
}
