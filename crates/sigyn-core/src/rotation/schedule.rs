use serde::{Deserialize, Serialize};

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
    pub fn new(cron_expression: &str, grace_period_hours: u32) -> Self {
        Self {
            key_pattern: String::from("*"),
            cron_expression: cron_expression.to_string(),
            grace_period_hours,
            auto_rotate: false,
            hooks: Vec::new(),
            last_rotated: None,
            next_rotation: None,
        }
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

    #[test]
    fn test_new_creates_schedule() {
        let sched = RotationSchedule::new("0 0 * * * *", 24);
        assert_eq!(sched.cron_expression, "0 0 * * * *");
        assert_eq!(sched.grace_period_hours, 24);
        assert_eq!(sched.key_pattern, "*");
        assert!(!sched.auto_rotate);
    }

    #[test]
    fn test_recently_updated_secret_is_not_due() {
        // Daily schedule at 03:00, 0 hours grace
        let sched = RotationSchedule::new("0 0 3 * * *", 0);
        // Last updated 1 minute ago -- no daily boundary can have passed
        let last_updated = Utc::now() - Duration::minutes(1);
        assert!(!sched.is_due(last_updated));
    }

    #[test]
    fn test_old_secret_is_due() {
        // Every hour schedule, 0 hours grace
        let sched = RotationSchedule::new("0 0 * * * *", 0);
        // Last updated 2 hours ago -- at least one hourly boundary has passed
        let last_updated = Utc::now() - Duration::hours(2);
        assert!(sched.is_due(last_updated));
    }

    #[test]
    fn test_grace_period_delays_due() {
        // Every hour schedule, 3 hours grace
        let sched = RotationSchedule::new("0 0 * * * *", 3);
        // Last updated 2 hours ago -- hourly boundary passed but within grace
        let last_updated = Utc::now() - Duration::hours(2);
        assert!(!sched.is_due(last_updated));
    }

    #[test]
    fn test_next_after_returns_future_time() {
        let sched = RotationSchedule::new("0 0 * * * *", 0);
        let now = Utc::now();
        let next = sched.next_after(now);
        assert!(next.is_some());
        assert!(next.unwrap() > now);
    }

    #[test]
    fn test_invalid_cron_returns_not_due() {
        let sched = RotationSchedule::new("not a cron", 0);
        let last_updated = Utc::now() - Duration::hours(100);
        assert!(!sched.is_due(last_updated));
    }

    #[test]
    fn test_invalid_cron_next_after_returns_none() {
        let sched = RotationSchedule::new("not a cron", 0);
        assert!(sched.next_after(Utc::now()).is_none());
    }
}
