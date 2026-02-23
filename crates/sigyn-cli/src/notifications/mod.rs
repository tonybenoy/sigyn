use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    pub events: Vec<String>,
    pub secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub webhooks: Vec<WebhookConfig>,
    pub poll_interval_secs: u64,
    pub desktop_notifications: bool,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            webhooks: Vec::new(),
            poll_interval_secs: 300,
            desktop_notifications: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NotificationEvent {
    pub event_type: String,
    pub vault: String,
    pub env: Option<String>,
    pub key: Option<String>,
    pub actor: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub message: String,
}

/// JSON payload sent to webhook endpoints.
#[derive(Debug, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub event: String,
    pub timestamp: String,
    pub details: WebhookPayloadDetails,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebhookPayloadDetails {
    pub vault: String,
    pub env: Option<String>,
    pub key: Option<String>,
    pub actor: String,
    pub message: String,
}

impl WebhookPayload {
    pub fn from_event(event: &NotificationEvent) -> Self {
        Self {
            event: event.event_type.clone(),
            timestamp: event.timestamp.to_rfc3339(),
            details: WebhookPayloadDetails {
                vault: event.vault.clone(),
                env: event.env.clone(),
                key: event.key.clone(),
                actor: event.actor.clone(),
                message: event.message.clone(),
            },
        }
    }
}

/// Send a webhook notification via HTTP POST.
///
/// Builds a JSON payload from the event, POSTs it to the configured URL
/// with a 10-second timeout, and returns an error if the request fails
/// or the server returns a non-success status code.
pub fn send_webhook(config: &WebhookConfig, event: &NotificationEvent) -> Result<()> {
    if config.url.is_empty() {
        anyhow::bail!("webhook URL is empty");
    }

    let payload = WebhookPayload::from_event(event);

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let mut request = client
        .post(&config.url)
        .header("Content-Type", "application/json")
        .json(&payload);

    // If a shared secret is configured, include it as a header for verification
    if let Some(secret) = &config.secret {
        request = request.header("X-Sigyn-Secret", secret.as_str());
    }

    let response = request.send()?;

    if !response.status().is_success() {
        anyhow::bail!(
            "webhook POST to {} returned status {}",
            config.url,
            response.status()
        );
    }

    Ok(())
}

pub fn notify_all(config: &NotificationConfig, event: &NotificationEvent) -> Result<Vec<String>> {
    let mut sent = Vec::new();

    for webhook in &config.webhooks {
        if webhook.events.is_empty()
            || webhook
                .events
                .iter()
                .any(|e| e == &event.event_type || e == "*")
        {
            send_webhook(webhook, event)?;
            sent.push(webhook.url.clone());
        }
    }

    Ok(sent)
}

/// Convenience function: load notification config from SIGYN_HOME and
/// send the event to all matching webhooks.
pub fn notify_event(sigyn_home: &std::path::Path, event: &NotificationEvent) -> Result<Vec<String>> {
    let config = load_notification_config(sigyn_home);
    notify_all(&config, event)
}

pub fn load_notification_config(sigyn_home: &std::path::Path) -> NotificationConfig {
    let path = sigyn_home.join("notifications.toml");
    if path.exists() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(config) = toml::from_str(&content) {
                return config;
            }
        }
    }
    NotificationConfig::default()
}

pub fn save_notification_config(
    sigyn_home: &std::path::Path,
    config: &NotificationConfig,
) -> Result<()> {
    let path = sigyn_home.join("notifications.toml");
    let content = toml::to_string_pretty(config)?;
    std::fs::write(path, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event() -> NotificationEvent {
        NotificationEvent {
            event_type: "secret.created".into(),
            vault: "test-vault".into(),
            env: Some("dev".into()),
            key: Some("DB_URL".into()),
            actor: "abc123".into(),
            timestamp: chrono::DateTime::parse_from_rfc3339("2026-01-15T10:30:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            message: "Secret created".into(),
        }
    }

    #[test]
    fn test_default_config() {
        let config = NotificationConfig::default();
        assert!(config.webhooks.is_empty());
        assert_eq!(config.poll_interval_secs, 300);
    }

    #[test]
    fn test_notify_all_empty() {
        let config = NotificationConfig::default();
        let event = make_event();
        let sent = notify_all(&config, &event).unwrap();
        assert!(sent.is_empty());
    }

    #[test]
    fn test_webhook_payload_serialization() {
        let event = make_event();
        let payload = WebhookPayload::from_event(&event);

        let json = serde_json::to_value(&payload).unwrap();

        assert_eq!(json["event"], "secret.created");
        assert_eq!(json["timestamp"], "2026-01-15T10:30:00+00:00");
        assert_eq!(json["details"]["vault"], "test-vault");
        assert_eq!(json["details"]["env"], "dev");
        assert_eq!(json["details"]["key"], "DB_URL");
        assert_eq!(json["details"]["actor"], "abc123");
        assert_eq!(json["details"]["message"], "Secret created");
    }

    #[test]
    fn test_webhook_payload_roundtrip() {
        let event = make_event();
        let payload = WebhookPayload::from_event(&event);

        let serialized = serde_json::to_string(&payload).unwrap();
        let deserialized: WebhookPayload = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.event, "secret.created");
        assert_eq!(deserialized.details.vault, "test-vault");
        assert_eq!(deserialized.details.env, Some("dev".into()));
    }

    #[test]
    fn test_send_webhook_rejects_empty_url() {
        let config = WebhookConfig {
            url: String::new(),
            events: vec!["*".into()],
            secret: None,
        };
        let event = make_event();
        let result = send_webhook(&config, &event);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }
}
