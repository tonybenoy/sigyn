use serde::{Deserialize, Serialize};

use crate::error::{Result, SigynError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationSchedule {
    pub key_pattern: String,
    pub cron_expression: String,
    pub grace_period_hours: u32,
    pub auto_rotate: bool,
    pub hooks: Vec<String>,
    pub last_rotated: Option<chrono::DateTime<chrono::Utc>>,
    pub next_rotation: Option<chrono::DateTime<chrono::Utc>>,
}

impl RotationSchedule {
    /// Create a new rotation schedule with the given cron expression and grace period.
    ///
    /// Returns an error if the cron expression is invalid, so a bad schedule
    /// can never be saved and silently never fire. The `cron` crate expects
    /// 6 or 7 fields (`sec min hour day-of-month month day-of-week [year]`),
    /// not the traditional 5-field crontab format.
    pub fn new(cron_expression: &str, grace_period_hours: u32) -> Result<Self> {
        use std::str::FromStr;
        cron::Schedule::from_str(cron_expression).map_err(|e| {
            SigynError::ValidationFailed(format!(
                "invalid cron expression '{}': {} (expected 6 or 7 fields: \
                 sec min hour day-of-month month day-of-week [year], \
                 e.g. '0 0 3 * * *' for daily at 03:00)",
                cron_expression, e
            ))
        })?;
        Ok(Self {
            key_pattern: String::from("*"),
            cron_expression: cron_expression.to_string(),
            grace_period_hours,
            auto_rotate: false,
            hooks: Vec::new(),
            last_rotated: None,
            next_rotation: None,
        })
    }

    /// Replace the rotation hooks, validating each command first (rejects
    /// shell metacharacters, path traversal, and over-long commands).
    pub fn set_hooks(&mut self, hooks: Vec<String>) -> Result<()> {
        for hook in &hooks {
            super::hooks::validate_hook(hook)?;
        }
        self.hooks = hooks;
        Ok(())
    }

    /// Parse the cron expression into a cron::Schedule.
    fn parse_schedule(&self) -> Option<cron::Schedule> {
        use std::str::FromStr;
        cron::Schedule::from_str(&self.cron_expression).ok()
    }

    /// Check if a secret is due for rotation based on its last update time.
    ///
    /// Returns true if there is at least one scheduled rotation time between
    /// `last_updated` and `now - grace_period`, meaning the secret should have
    /// been rotated already (accounting for the grace period).
    pub fn is_due(&self, last_updated: chrono::DateTime<chrono::Utc>) -> bool {
        let schedule = match self.parse_schedule() {
            Some(s) => s,
            None => return false,
        };

        let now = chrono::Utc::now();
        let grace = chrono::Duration::hours(self.grace_period_hours as i64);
        let deadline = now - grace;

        // Find the next scheduled time after last_updated. If it falls before
        // the current time minus the grace period, the rotation is overdue.
        if let Some(next) = schedule.after(&last_updated).next() {
            return next <= deadline;
        }

        false
    }

    /// Get the next rotation time after a given timestamp.
    pub fn next_after(
        &self,
        after: chrono::DateTime<chrono::Utc>,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        let schedule = self.parse_schedule()?;
        schedule.after(&after).next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    /// Build a schedule bypassing constructor validation, mimicking data
    /// deserialized from disk (which may carry an invalid cron expression).
    fn raw_schedule(cron_expression: &str, grace_period_hours: u32) -> RotationSchedule {
        RotationSchedule {
            key_pattern: String::from("*"),
            cron_expression: cron_expression.to_string(),
            grace_period_hours,
            auto_rotate: false,
            hooks: Vec::new(),
            last_rotated: None,
            next_rotation: None,
        }
    }

    #[test]
    fn test_new_creates_schedule() {
        let sched = RotationSchedule::new("0 0 * * * *", 24).unwrap();
        assert_eq!(sched.cron_expression, "0 0 * * * *");
        assert_eq!(sched.grace_period_hours, 24);
        assert_eq!(sched.key_pattern, "*");
        assert!(!sched.auto_rotate);
    }

    #[test]
    fn test_new_rejects_invalid_cron() {
        assert!(RotationSchedule::new("not a cron", 0).is_err());
        assert!(RotationSchedule::new("", 0).is_err());
        // Traditional 5-field crontab format is not supported by the cron
        // crate (it requires a seconds field); must error, not silently
        // never fire.
        assert!(RotationSchedule::new("0 3 * * *", 0).is_err());
    }

    #[test]
    fn test_new_accepts_six_and_seven_field_cron() {
        assert!(RotationSchedule::new("0 0 3 * * *", 0).is_ok());
        assert!(RotationSchedule::new("0 0 3 * * * 2027", 0).is_ok());
    }

    #[test]
    fn test_set_hooks_validates() {
        let mut sched = RotationSchedule::new("0 0 * * * *", 0).unwrap();
        assert!(sched
            .set_hooks(vec!["notify-service --env prod".into()])
            .is_ok());
        assert_eq!(sched.hooks.len(), 1);

        // Shell metacharacters are rejected and hooks stay unchanged
        assert!(sched.set_hooks(vec!["evil; rm -rf /".into()]).is_err());
        assert_eq!(sched.hooks, vec!["notify-service --env prod".to_string()]);

        // Path traversal is rejected
        assert!(sched.set_hooks(vec!["../../evil".into()]).is_err());
    }

    #[test]
    fn test_recently_updated_secret_is_not_due() {
        // Daily schedule at 03:00, 0 hours grace
        let sched = RotationSchedule::new("0 0 3 * * *", 0).unwrap();
        // Last updated 1 minute ago -- no daily boundary can have passed
        let last_updated = Utc::now() - Duration::minutes(1);
        assert!(!sched.is_due(last_updated));
    }

    #[test]
    fn test_old_secret_is_due() {
        // Every hour schedule, 0 hours grace
        let sched = RotationSchedule::new("0 0 * * * *", 0).unwrap();
        // Last updated 2 hours ago -- at least one hourly boundary has passed
        let last_updated = Utc::now() - Duration::hours(2);
        assert!(sched.is_due(last_updated));
    }

    #[test]
    fn test_grace_period_delays_due() {
        // Every hour schedule, 3 hours grace
        let sched = RotationSchedule::new("0 0 * * * *", 3).unwrap();
        // Last updated 2 hours ago -- hourly boundary passed but within grace
        let last_updated = Utc::now() - Duration::hours(2);
        assert!(!sched.is_due(last_updated));
    }

    #[test]
    fn test_next_after_returns_future_time() {
        let sched = RotationSchedule::new("0 0 * * * *", 0).unwrap();
        let now = Utc::now();
        let next = sched.next_after(now);
        assert!(next.is_some());
        assert!(next.unwrap() > now);
    }

    #[test]
    fn test_invalid_cron_returns_not_due() {
        // Invalid cron loaded from stored data (bypassing the constructor)
        // must not panic; is_due degrades to "never due".
        let sched = raw_schedule("not a cron", 0);
        let last_updated = Utc::now() - Duration::hours(100);
        assert!(!sched.is_due(last_updated));
    }

    #[test]
    fn test_invalid_cron_next_after_returns_none() {
        let sched = raw_schedule("not a cron", 0);
        assert!(sched.next_after(Utc::now()).is_none());
    }
}
