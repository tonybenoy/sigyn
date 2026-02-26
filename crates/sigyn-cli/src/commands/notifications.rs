use anyhow::Result;
use clap::Subcommand;
use console::style;

use crate::config::sigyn_home;
use crate::notifications::{
    load_notification_config, save_notification_config, NotificationEvent, WebhookConfig,
};

#[derive(Subcommand)]
pub enum NotificationCommands {
    /// Configure webhook notifications interactively
    Configure,
    /// Send a test notification to configured webhooks
    Test,
    /// List configured webhooks
    List,
}

pub fn handle(cmd: NotificationCommands, json: bool) -> Result<()> {
    let home = sigyn_home();

    match cmd {
        NotificationCommands::Configure => {
            let mut config = load_notification_config(&home);

            if !crate::config::is_interactive() {
                anyhow::bail!(
                    "notification configure requires an interactive terminal.\n\
                     Edit ~/.sigyn/notifications.toml directly."
                );
            }

            // Prompt for webhook URL
            let url: String = dialoguer::Input::new()
                .with_prompt("Webhook URL")
                .interact_text()?;

            if url.is_empty() {
                anyhow::bail!("webhook URL cannot be empty");
            }

            // Validate URL scheme
            if !url.starts_with("https://")
                && !url.starts_with("http://localhost")
                && !url.starts_with("http://127.0.0.1")
                && !url.starts_with("http://[::1]")
            {
                anyhow::bail!(
                    "webhook URL must use HTTPS (HTTP only allowed for localhost): {}",
                    url
                );
            }

            // Select events
            let event_options = &[
                "* (all events)",
                "secret.created",
                "secret.updated",
                "secret.deleted",
                "secret.rotated",
                "secret.generated",
                "member.revoked",
                "breach_mode",
            ];
            let defaults = vec![true, false, false, false, false, false, false, false];
            let selections = dialoguer::MultiSelect::new()
                .with_prompt("Select events to receive")
                .items(event_options)
                .defaults(&defaults)
                .interact()?;

            let events: Vec<String> = selections
                .iter()
                .map(|&i| {
                    if i == 0 {
                        "*".into()
                    } else {
                        event_options[i].into()
                    }
                })
                .collect();

            // Optional shared secret
            let secret: String = dialoguer::Input::new()
                .with_prompt("Shared secret (optional, press Enter to skip)")
                .allow_empty(true)
                .interact_text()?;

            let webhook = WebhookConfig {
                url: url.clone(),
                events: events.clone(),
                secret: if secret.is_empty() {
                    None
                } else {
                    Some(secret)
                },
            };

            config.webhooks.push(webhook);
            save_notification_config(&home, &config)?;

            if json {
                crate::output::print_json(&serde_json::json!({
                    "action": "webhook_added",
                    "url": url,
                    "events": events,
                }))?;
            } else {
                crate::output::print_success("Webhook configured");
                println!("  URL:    {}", url);
                println!("  Events: {}", events.join(", "));
                println!("  Config: {}", home.join("notifications.toml").display());
            }
        }
        NotificationCommands::Test => {
            let config = load_notification_config(&home);

            if config.webhooks.is_empty() {
                anyhow::bail!("no webhooks configured.\n  Run: sigyn notification configure");
            }

            let event = NotificationEvent {
                event_type: "test".into(),
                vault: "test-vault".into(),
                env: Some("test".into()),
                key: Some("TEST_KEY".into()),
                actor: "sigyn-cli".into(),
                timestamp: chrono::Utc::now(),
                message: "This is a test notification from sigyn".into(),
            };

            let mut successes = 0u32;
            let mut failures = Vec::new();

            for webhook in &config.webhooks {
                match crate::notifications::send_webhook(webhook, &event) {
                    Ok(()) => {
                        successes += 1;
                        if !json {
                            println!("  {} {}", style("✓").green(), webhook.url);
                        }
                    }
                    Err(e) => {
                        failures.push((webhook.url.clone(), e.to_string()));
                        if !json {
                            println!("  {} {} — {}", style("✗").red(), webhook.url, e);
                        }
                    }
                }
            }

            if json {
                crate::output::print_json(&serde_json::json!({
                    "successes": successes,
                    "failures": failures.iter().map(|(u, e)| serde_json::json!({"url": u, "error": e})).collect::<Vec<_>>(),
                }))?;
            } else if failures.is_empty() {
                crate::output::print_success(&format!("Test sent to {} webhook(s)", successes));
            } else {
                eprintln!(
                    "\n{} {} succeeded, {} failed",
                    style("Result:").bold(),
                    successes,
                    failures.len()
                );
            }
        }
        NotificationCommands::List => {
            let config = load_notification_config(&home);

            if json {
                crate::output::print_json(&serde_json::json!({
                    "webhooks": config.webhooks.iter().map(|w| serde_json::json!({
                        "url": w.url,
                        "events": w.events,
                        "has_secret": w.secret.is_some(),
                    })).collect::<Vec<_>>(),
                }))?;
            } else {
                println!("{}", style("Configured Webhooks").bold());
                println!("{}", style("─".repeat(60)).dim());

                if config.webhooks.is_empty() {
                    println!("  (none configured)");
                    println!();
                    println!("  Run: sigyn notification configure");
                } else {
                    for (i, webhook) in config.webhooks.iter().enumerate() {
                        println!(
                            "  {}. {} {}",
                            i + 1,
                            style(&webhook.url).cyan(),
                            if webhook.secret.is_some() {
                                style("(secret set)").dim().to_string()
                            } else {
                                String::new()
                            }
                        );
                        println!("     Events: {}", webhook.events.join(", "));
                    }
                }
            }
        }
    }
    Ok(())
}
