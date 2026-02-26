use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{prelude::*, widgets::*};
use sigyn_engine::policy::engine::AccessAction;
#[allow(unused_imports)]
use sigyn_engine::policy::storage::VaultPolicyExt;
use std::io::stdout;

#[derive(Debug, Clone, PartialEq)]
enum TuiTab {
    Secrets,
    Members,
    Audit,
    Status,
}

struct TuiState {
    active_tab: TuiTab,
    secrets: Vec<(String, String, String)>, // key, type, masked_value
    selected_index: usize,
    vault_name: String,
    env_name: String,
    should_quit: bool,
    // Real vault data fields
    secret_keys: Vec<String>,
    member_list: Vec<String>,
    audit_entries: Vec<String>,
    vault_info: String,
}

impl TuiState {
    fn new(vault_name: String, env_name: String) -> Self {
        Self {
            active_tab: TuiTab::Secrets,
            secrets: Vec::new(),
            selected_index: 0,
            vault_name,
            env_name,
            should_quit: false,
            secret_keys: Vec::new(),
            member_list: Vec::new(),
            audit_entries: Vec::new(),
            vault_info: String::new(),
        }
    }

    fn next_tab(&mut self) {
        self.active_tab = match self.active_tab {
            TuiTab::Secrets => TuiTab::Members,
            TuiTab::Members => TuiTab::Audit,
            TuiTab::Audit => TuiTab::Status,
            TuiTab::Status => TuiTab::Secrets,
        };
    }

    fn prev_tab(&mut self) {
        self.active_tab = match self.active_tab {
            TuiTab::Secrets => TuiTab::Status,
            TuiTab::Members => TuiTab::Secrets,
            TuiTab::Audit => TuiTab::Members,
            TuiTab::Status => TuiTab::Audit,
        };
    }

    fn select_next(&mut self) {
        let len = match self.active_tab {
            TuiTab::Secrets => self.secrets.len(),
            TuiTab::Members => self.member_list.len(),
            TuiTab::Audit => self.audit_entries.len(),
            _ => 0,
        };
        if len > 0 {
            self.selected_index = (self.selected_index + 1) % len;
        }
    }

    fn select_prev(&mut self) {
        let len = match self.active_tab {
            TuiTab::Secrets => self.secrets.len(),
            TuiTab::Members => self.member_list.len(),
            TuiTab::Audit => self.audit_entries.len(),
            _ => 0,
        };
        if len > 0 {
            self.selected_index = self.selected_index.checked_sub(1).unwrap_or(len - 1);
        }
    }
}

/// Attempt to load real vault data and populate the TUI state.
///
/// If any step fails (vault not found, wrong passphrase, etc.) the state
/// falls back to placeholder content so the TUI can still be launched for
/// demonstration purposes.
fn load_vault_data(state: &mut TuiState) {
    match try_load_vault_data(state) {
        Ok(()) => {}
        Err(_) => {
            // Fall back to placeholder content
            if state.secrets.is_empty() {
                state.secrets = vec![
                    ("DB_URL".into(), "string".into(), "--------".into()),
                    ("API_KEY".into(), "string".into(), "--------".into()),
                    ("JWT_SECRET".into(), "generated".into(), "--------".into()),
                ];
                state.secret_keys = state.secrets.iter().map(|(k, _, _)| k.clone()).collect();
            }
            if state.member_list.is_empty() {
                state.member_list = vec!["(placeholder) no vault loaded".into()];
            }
            if state.audit_entries.is_empty() {
                state.audit_entries = vec!["(placeholder) no audit data".into()];
            }
            if state.vault_info.is_empty() {
                state.vault_info = "Vault not loaded — using placeholder data".into();
            }
        }
    }
}

fn try_load_vault_data(state: &mut TuiState) -> Result<()> {
    use sigyn_engine::audit::AuditLog;
    use sigyn_engine::vault::{env_file, VaultPaths};

    let home = crate::config::sigyn_home();
    let paths = VaultPaths::new(home);

    // Load manifest to verify the vault exists
    let manifest_path = paths.manifest_path(&state.vault_name);
    let manifest_content = std::fs::read_to_string(&manifest_path)?;
    let manifest = sigyn_engine::vault::VaultManifest::from_toml(&manifest_content)?;

    // Try to unlock the vault using the default identity
    let store = sigyn_engine::identity::keygen::IdentityStore::new(crate::config::sigyn_home());
    let loaded = crate::commands::identity::load_identity(&store, None)?;
    let fingerprint = loaded.identity.fingerprint.clone();

    let header_bytes = std::fs::read(paths.members_path(&state.vault_name))?;
    let header: sigyn_engine::crypto::EnvelopeHeader =
        ciborium::from_reader(header_bytes.as_slice())
            .map_err(|e| anyhow::anyhow!("failed to decode header: {}", e))?;

    let master_key = sigyn_engine::crypto::envelope::unseal_master_key(
        &header,
        loaded.encryption_key(),
        manifest.vault_id,
    )?;
    let cipher = sigyn_engine::crypto::vault_cipher::VaultCipher::new(master_key);

    // --- Access control check: verify the user has Read access before showing secrets ---
    let policy = sigyn_engine::policy::storage::VaultPolicy::load_encrypted(
        &paths.policy_path(&state.vault_name),
        &cipher,
    )
    .unwrap_or_default();

    {
        let engine = sigyn_engine::policy::engine::PolicyEngine::new(&policy, &manifest.owner);
        let request = sigyn_engine::policy::engine::AccessRequest {
            actor: fingerprint.clone(),
            action: AccessAction::Read,
            env: state.env_name.clone(),
            key: None,
            mfa_verified: false,
        };
        let decision = engine.evaluate(&request)?;
        match decision {
            sigyn_engine::policy::engine::PolicyDecision::Deny(reason) => {
                anyhow::bail!("access denied: {}", reason);
            }
            sigyn_engine::policy::engine::PolicyDecision::RequiresMfa => {
                anyhow::bail!("MFA verification required");
            }
            _ => {}
        }
    }

    // --- Secrets tab: key names and types (no values) ---
    let env_path = paths.env_path(&state.vault_name, &state.env_name);
    if env_path.exists() {
        let encrypted = env_file::read_encrypted_env(&env_path)?;
        let plaintext = env_file::decrypt_env(&encrypted, &cipher)?;

        state.secrets = plaintext
            .entries
            .iter()
            .map(|(key, entry)| {
                (
                    key.clone(),
                    entry.value.type_name().to_string(),
                    "--------".to_string(), // Never show values in TUI
                )
            })
            .collect();
        state.secret_keys = state.secrets.iter().map(|(k, _, _)| k.clone()).collect();
    }

    // --- Members tab: fingerprints and roles ---
    // (policy already loaded above for access check)

    state.member_list = Vec::new();
    // Always show the owner first
    state
        .member_list
        .push(format!("{} [owner]", manifest.owner.to_hex()));
    for (_fp_hex, member) in &policy.members {
        let line = format!("{} [{}]", member.fingerprint.to_hex(), member.role);
        // Avoid duplicating the owner if they also appear in the policy
        if !state.member_list.contains(&line) {
            state.member_list.push(line);
        }
    }

    // --- Audit tab: last 20 entries ---
    let audit_path = paths.audit_path(&state.vault_name);
    if audit_path.exists() {
        if let Ok(log) = AuditLog::open(&audit_path) {
            if let Ok(entries) = log.tail(20) {
                state.audit_entries = entries
                    .iter()
                    .map(|e| {
                        format!(
                            "[{}] {} {:?} ({})",
                            e.timestamp.format("%Y-%m-%d %H:%M:%S"),
                            e.actor.to_hex(),
                            e.action,
                            match &e.outcome {
                                sigyn_engine::audit::entry::AuditOutcome::Success =>
                                    "ok".to_string(),
                                sigyn_engine::audit::entry::AuditOutcome::Denied(r) =>
                                    format!("denied: {}", r),
                                sigyn_engine::audit::entry::AuditOutcome::Error(r) =>
                                    format!("error: {}", r),
                            }
                        )
                    })
                    .collect();
            }
        }
    }
    if state.audit_entries.is_empty() {
        state.audit_entries = vec!["No audit entries recorded yet".into()];
    }

    // --- Status tab ---
    let _ = fingerprint; // used above for unlock
    let env_count = if paths.env_dir(&state.vault_name).exists() {
        std::fs::read_dir(paths.env_dir(&state.vault_name))
            .map(|rd| rd.filter_map(|e| e.ok()).count())
            .unwrap_or(0)
    } else {
        0
    };

    state.vault_info = format!(
        "Vault: {}\nEnvironments: {}\nMembers: {}\nSecrets in '{}': {}",
        state.vault_name,
        env_count,
        state.member_list.len(),
        state.env_name,
        state.secrets.len(),
    );

    Ok(())
}

pub fn run_tui(vault_name: &str, env_name: &str) -> Result<()> {
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;

    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    let mut state = TuiState::new(vault_name.to_string(), env_name.to_string());

    // Try to load real data; fall back to placeholders on failure
    load_vault_data(&mut state);

    loop {
        terminal.draw(|frame| draw_ui(frame, &state))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => state.should_quit = true,
                        KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                            state.selected_index = 0;
                            state.next_tab();
                        }
                        KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                            state.selected_index = 0;
                            state.prev_tab();
                        }
                        KeyCode::Down | KeyCode::Char('j') => state.select_next(),
                        KeyCode::Up | KeyCode::Char('k') => state.select_prev(),
                        _ => {}
                    }
                }
            }
        }

        if state.should_quit {
            break;
        }
    }

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

fn draw_ui(frame: &mut Frame, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(frame.area());

    // Header with tabs
    let tabs = Tabs::new(vec!["Secrets", "Members", "Audit", "Status"])
        .block(Block::default().borders(Borders::ALL).title(format!(
            " Sigyn -- {} / {} ",
            state.vault_name, state.env_name
        )))
        .select(match state.active_tab {
            TuiTab::Secrets => 0,
            TuiTab::Members => 1,
            TuiTab::Audit => 2,
            TuiTab::Status => 3,
        })
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, chunks[0]);

    // Main content
    match state.active_tab {
        TuiTab::Secrets => draw_secrets_tab(frame, state, chunks[1]),
        TuiTab::Members => draw_members_tab(frame, state, chunks[1]),
        TuiTab::Audit => draw_audit_tab(frame, state, chunks[1]),
        TuiTab::Status => draw_status_tab(frame, state, chunks[1]),
    }

    // Footer
    let footer = Paragraph::new(" q: Quit | Tab: Switch tab | j/k: Navigate | Enter: Details")
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, chunks[2]);
}

fn draw_secrets_tab(frame: &mut Frame, state: &TuiState, area: Rect) {
    let rows: Vec<Row> = state
        .secrets
        .iter()
        .enumerate()
        .map(|(i, (key, typ, val))| {
            let style = if i == state.selected_index {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(key.as_str()),
                Cell::from(typ.as_str()),
                Cell::from(val.as_str()),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(30),
            Constraint::Percentage(20),
            Constraint::Percentage(50),
        ],
    )
    .header(
        Row::new(vec!["Key", "Type", "Value"])
            .style(Style::default().add_modifier(Modifier::BOLD))
            .bottom_margin(1),
    )
    .block(Block::default().borders(Borders::ALL).title(" Secrets "));

    frame.render_widget(table, area);
}

fn draw_members_tab(frame: &mut Frame, state: &TuiState, area: Rect) {
    let items: Vec<ListItem> = state
        .member_list
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let style = if i == state.selected_index {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(m.as_str()).style(style)
        })
        .collect();

    let list = List::new(items).block(Block::default().borders(Borders::ALL).title(" Members "));

    frame.render_widget(list, area);
}

fn draw_audit_tab(frame: &mut Frame, state: &TuiState, area: Rect) {
    let items: Vec<ListItem> = state
        .audit_entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let style = if i == state.selected_index {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(entry.as_str()).style(style)
        })
        .collect();

    let list = List::new(items).block(Block::default().borders(Borders::ALL).title(" Audit Log "));

    frame.render_widget(list, area);
}

fn draw_status_tab(frame: &mut Frame, state: &TuiState, area: Rect) {
    let info_text = if state.vault_info.is_empty() {
        format!(
            "Vault: {}\nEnvironment: {}\nSecrets: {}",
            state.vault_name,
            state.env_name,
            state.secrets.len(),
        )
    } else {
        state.vault_info.clone()
    };

    let mut lines: Vec<Line> = Vec::new();
    for raw in info_text.lines() {
        if let Some((label, value)) = raw.split_once(": ") {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{}: ", label),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(value),
            ]));
        } else {
            lines.push(Line::from(raw));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Sync: ",
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from("  Status: not configured"));

    let block = Block::default().borders(Borders::ALL).title(" Status ");
    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}
