use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints {
    pub time_windows: Vec<TimeWindow>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub require_mfa: bool,
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
            require_mfa: false,
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
}
