use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints {
    pub time_windows: Vec<TimeWindow>,
    pub ip_allowlist: Vec<String>,
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

    /// Check if a given IP address is allowed. Empty allowlist means all IPs allowed.
    pub fn check_ip(&self, ip: &str) -> Result<(), String> {
        if self.ip_allowlist.is_empty() {
            return Ok(());
        }
        // Support exact match and CIDR prefix match
        for allowed in &self.ip_allowlist {
            if allowed == ip {
                return Ok(());
            }
            // Simple CIDR prefix: "10.0.0." matches "10.0.0.5"
            if allowed.ends_with('.') && ip.starts_with(allowed.as_str()) {
                return Ok(());
            }
            // CIDR notation support: "192.168.1.0/24" style
            if let Some((network, prefix_str)) = allowed.split_once('/') {
                if let Ok(prefix_len) = prefix_str.parse::<u8>() {
                    if cidr_match(network, ip, prefix_len) {
                        return Ok(());
                    }
                }
            }
        }
        Err(format!("IP {} not in allowlist", ip))
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

/// Simple IPv4 CIDR matching.
fn cidr_match(network: &str, ip: &str, prefix_len: u8) -> bool {
    let parse_ipv4 = |s: &str| -> Option<u32> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        let mut result = 0u32;
        for part in parts {
            result = result << 8 | part.parse::<u32>().ok()?;
        }
        Some(result)
    };

    let Some(net) = parse_ipv4(network) else {
        return false;
    };
    let Some(addr) = parse_ipv4(ip) else {
        return false;
    };
    if prefix_len > 32 {
        return false;
    }
    if prefix_len == 0 {
        return true;
    }
    let mask = !((1u32 << (32 - prefix_len)) - 1);
    (net & mask) == (addr & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn make_constraints() -> Constraints {
        Constraints {
            time_windows: vec![],
            ip_allowlist: vec![],
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

    #[test]
    fn test_ip_allowlist_exact() {
        let mut c = make_constraints();
        c.ip_allowlist = vec!["10.0.0.1".into(), "192.168.1.5".into()];
        assert!(c.check_ip("10.0.0.1").is_ok());
        assert!(c.check_ip("192.168.1.5").is_ok());
        assert!(c.check_ip("10.0.0.2").is_err());
    }

    #[test]
    fn test_ip_allowlist_cidr() {
        let mut c = make_constraints();
        c.ip_allowlist = vec!["192.168.1.0/24".into()];
        assert!(c.check_ip("192.168.1.1").is_ok());
        assert!(c.check_ip("192.168.1.255").is_ok());
        assert!(c.check_ip("192.168.2.1").is_err());
    }

    #[test]
    fn test_empty_allowlist_allows_all() {
        let c = make_constraints();
        assert!(c.check_ip("anything").is_ok());
    }

    #[test]
    fn test_cidr_match() {
        assert!(cidr_match("10.0.0.0", "10.0.0.5", 24));
        assert!(cidr_match("10.0.0.0", "10.0.1.5", 16));
        assert!(!cidr_match("10.0.0.0", "10.0.1.5", 24));
        assert!(cidr_match("0.0.0.0", "1.2.3.4", 0));
    }
}
