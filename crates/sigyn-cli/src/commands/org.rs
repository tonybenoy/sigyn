use anyhow::{Context, Result};
use clap::Subcommand;
use console::style;
use sigyn_engine::crypto::envelope;
use sigyn_engine::crypto::vault_cipher::VaultCipher;
use sigyn_engine::hierarchy::manifest::{ChildRef, GitRemoteConfig, NodeManifest};
use sigyn_engine::hierarchy::path::{HierarchyPaths, OrgPath};
use sigyn_engine::identity::keygen::IdentityStore;
use sigyn_engine::policy::storage::VaultPolicy;
use sigyn_engine::policy::storage::VaultPolicyExt;

use crate::commands::identity::load_identity;
use crate::config::sigyn_home;

#[derive(Subcommand)]
pub enum OrgCommands {
    /// Create a root organization
    Create {
        /// Organization name
        name: String,
    },
    /// Manage hierarchy nodes
    #[command(subcommand)]
    Node(NodeCommands),
    /// Display the org hierarchy tree
    Tree {
        /// Root org name (optional if only one org exists)
        #[arg(long)]
        org: Option<String>,
    },
    /// Show node info
    Info {
        /// Org path (e.g. "acme/platform/web")
        path: String,
    },
    /// Manage policies at a hierarchy level
    #[command(subcommand)]
    Policy(OrgPolicyCommands),
    /// Configure git sync for a hierarchy level
    #[command(subcommand)]
    Sync(OrgSyncCommands),
}

#[derive(Subcommand)]
pub enum NodeCommands {
    /// Create a child node
    Create {
        /// Node name
        name: String,
        /// Parent org path (e.g. "acme" or "acme/platform")
        #[arg(long)]
        parent: String,
        /// Node type (default: "team")
        #[arg(long, default_value = "team")]
        r#type: String,
    },
    /// Remove an empty node
    Remove {
        /// Org path to the node to remove
        path: String,
    },
}

#[derive(Subcommand)]
pub enum OrgPolicyCommands {
    /// Show RBAC at a hierarchy level
    Show {
        /// Org path
        #[arg(long)]
        path: String,
    },
    /// Add a member at a hierarchy level (cascades slot addition)
    MemberAdd {
        /// Member fingerprint (hex)
        fingerprint: String,
        /// Role to assign
        #[arg(long)]
        role: String,
        /// Org path
        #[arg(long)]
        path: String,
    },
    /// Remove a member from a hierarchy level (cascades slot removal)
    MemberRemove {
        /// Member fingerprint (hex)
        fingerprint: String,
        /// Org path
        #[arg(long)]
        path: String,
    },
    /// Show merged effective permissions for a member
    Effective {
        /// Member fingerprint (hex)
        fingerprint: String,
        /// Org path
        #[arg(long)]
        path: String,
    },
}

#[derive(Subcommand)]
pub enum OrgSyncCommands {
    /// Set git remote at a hierarchy level
    Configure {
        /// Org path
        #[arg(long)]
        path: String,
        /// Remote URL
        #[arg(long)]
        remote_url: String,
        /// Branch name (default: main)
        #[arg(long, default_value = "main")]
        branch: String,
    },
}

/// Load an org node manifest from its sealed file (public for cross-module use).
pub fn load_org_manifest_path(
    manifest_path: &std::path::Path,
) -> Result<sigyn_engine::hierarchy::manifest::NodeManifest> {
    load_org_manifest(manifest_path)
}

/// Load an org node manifest from its sealed file.
fn load_org_manifest(
    manifest_path: &std::path::Path,
) -> Result<sigyn_engine::hierarchy::manifest::NodeManifest> {
    let data = std::fs::read(manifest_path)?;
    if !sigyn_engine::crypto::sealed::is_sealed(&data) {
        anyhow::bail!("org manifest is not in sealed format — file may be tampered or corrupted");
    }
    let home = crate::config::sigyn_home();
    let device_key = sigyn_engine::device::load_or_create_device_key(&home)?;
    let cipher =
        sigyn_engine::crypto::sealed::derive_file_cipher(&device_key, b"sigyn-org-manifest-v1")?;
    let plaintext = sigyn_engine::crypto::sealed::sealed_decrypt(&cipher, &data, b"org-manifest")
        .map_err(|e| anyhow::anyhow!("failed to decrypt org manifest: {}", e))?;
    let content = std::str::from_utf8(&plaintext)?;
    NodeManifest::from_toml(content)
        .map_err(|e| anyhow::anyhow!("failed to parse org manifest: {}", e))
}

/// Save an org node manifest in sealed format.
fn save_org_manifest(
    manifest_path: &std::path::Path,
    manifest: &sigyn_engine::hierarchy::manifest::NodeManifest,
) -> Result<()> {
    let home = crate::config::sigyn_home();
    let device_key = sigyn_engine::device::load_or_create_device_key(&home)?;
    let cipher =
        sigyn_engine::crypto::sealed::derive_file_cipher(&device_key, b"sigyn-org-manifest-v1")?;
    let sealed = sigyn_engine::crypto::sealed::sealed_encrypt(
        &cipher,
        manifest.to_toml()?.as_bytes(),
        b"org-manifest",
    )?;
    crate::config::secure_write(manifest_path, &sealed)?;
    Ok(())
}

/// Look up the verifying key for a node's owner. Tries local identity store first,
/// then falls back to the loaded identity if it is the owner.
fn resolve_owner_verifying_key(
    manifest: &NodeManifest,
    loaded: &sigyn_engine::identity::LoadedIdentity,
    store: &IdentityStore,
) -> sigyn_engine::crypto::keys::VerifyingKeyWrapper {
    if loaded.identity.fingerprint == manifest.owner {
        return loaded.identity.signing_pubkey.clone();
    }
    if let Ok(identities) = store.list() {
        if let Some(owner_id) = identities
            .iter()
            .find(|id| id.fingerprint == manifest.owner)
        {
            return owner_id.signing_pubkey.clone();
        }
    }
    // Fall back — this may fail verification, but we warn
    eprintln!(
        "{} owner identity {} not found locally; policy verification may fail",
        console::style("warning:").yellow().bold(),
        manifest.owner.to_hex()
    );
    loaded.identity.signing_pubkey.clone()
}

pub fn handle(cmd: OrgCommands, identity: Option<&str>, json: bool) -> Result<()> {
    let home = sigyn_home();
    let store = IdentityStore::new(home.clone());
    let hierarchy_paths = HierarchyPaths::new(home.clone());

    match cmd {
        OrgCommands::Create { name } => {
            let loaded = load_identity(&store, identity)?;
            let fingerprint = loaded.identity.fingerprint.clone();

            // Validate name as a valid single-segment org path
            let org_path = OrgPath::parse(&name).context("invalid org name")?;
            if org_path.depth() != 1 {
                anyhow::bail!("org name must be a single segment (no slashes)");
            }

            let node_dir = hierarchy_paths.node_dir(&org_path);
            if node_dir.exists() {
                anyhow::bail!("organization '{}' already exists", name);
            }

            let manifest = NodeManifest::new(name.clone(), "org".into(), fingerprint.clone());
            let node_id = manifest.node_id;

            // Create envelope with owner as sole recipient
            let master_cipher = VaultCipher::generate();
            let header = envelope::seal_v2(
                master_cipher.key_bytes(),
                &std::collections::BTreeMap::new(),
                std::slice::from_ref(&loaded.identity.encryption_pubkey),
                &std::collections::BTreeMap::new(),
                node_id,
            )?;

            std::fs::create_dir_all(hierarchy_paths.children_dir(&org_path))?;

            // Write manifest (encrypted with device key)
            {
                let device_key = sigyn_engine::device::load_or_create_device_key(&home)?;
                let cipher = sigyn_engine::crypto::sealed::derive_file_cipher(
                    &device_key,
                    b"sigyn-org-manifest-v1",
                )?;
                let sealed = sigyn_engine::crypto::sealed::sealed_encrypt(
                    &cipher,
                    manifest.to_toml()?.as_bytes(),
                    b"org-manifest",
                )?;
                crate::config::secure_write(&hierarchy_paths.manifest_path(&org_path), &sealed)?;
            }

            // Write signed envelope header
            let signed_header = envelope::sign_header(&header, loaded.signing_key(), node_id)
                .map_err(|e| anyhow::anyhow!("failed to sign header: {}", e))?;
            crate::config::secure_write(&hierarchy_paths.members_path(&org_path), &signed_header)?;

            // Write empty signed policy
            let policy = VaultPolicy::new();
            policy.save_signed(
                &hierarchy_paths.policy_path(&org_path),
                &master_cipher,
                loaded.signing_key(),
                &node_id,
            )?;

            if json {
                crate::output::print_json(&serde_json::json!({
                    "name": name,
                    "node_id": node_id.to_string(),
                    "owner": fingerprint.to_hex(),
                }))?;
            } else {
                crate::output::print_success(&format!("Organization '{}' created", name));
                println!("  ID:    {}", node_id);
                println!("  Owner: {}", style(fingerprint.to_hex()).cyan());
            }
        }

        OrgCommands::Node(node_cmd) => match node_cmd {
            NodeCommands::Create {
                name,
                parent,
                r#type,
            } => {
                let loaded = load_identity(&store, identity)?;
                let fingerprint = loaded.identity.fingerprint.clone();

                let parent_path = OrgPath::parse(&parent).context("invalid parent path")?;
                let parent_manifest_path = hierarchy_paths.manifest_path(&parent_path);
                if !parent_manifest_path.exists() {
                    anyhow::bail!("parent node '{}' not found", parent);
                }

                let child_path = parent_path.child(&name).context("invalid node name")?;
                let child_dir = hierarchy_paths.node_dir(&child_path);
                if child_dir.exists() {
                    anyhow::bail!("node '{}' already exists under '{}'", name, parent);
                }

                // Read parent manifest to set parent_id
                let mut parent_manifest = load_org_manifest(&parent_manifest_path)?;

                let mut manifest =
                    NodeManifest::new(name.clone(), r#type.clone(), fingerprint.clone());
                manifest.parent_id = Some(parent_manifest.node_id);
                let node_id = manifest.node_id;

                // Create envelope with owner as sole recipient
                let master_cipher = VaultCipher::generate();
                let header = envelope::seal_v2(
                    master_cipher.key_bytes(),
                    &std::collections::BTreeMap::new(),
                    std::slice::from_ref(&loaded.identity.encryption_pubkey),
                    &std::collections::BTreeMap::new(),
                    node_id,
                )?;

                std::fs::create_dir_all(hierarchy_paths.children_dir(&child_path))?;

                save_org_manifest(&hierarchy_paths.manifest_path(&child_path), &manifest)?;

                let signed_header = envelope::sign_header(&header, loaded.signing_key(), node_id)
                    .map_err(|e| anyhow::anyhow!("failed to sign header: {}", e))?;
                crate::config::secure_write(
                    &hierarchy_paths.members_path(&child_path),
                    &signed_header,
                )?;

                let policy = VaultPolicy::new();
                policy.save_signed(
                    &hierarchy_paths.policy_path(&child_path),
                    &master_cipher,
                    loaded.signing_key(),
                    &node_id,
                )?;

                // Update parent's children list
                parent_manifest.children.push(ChildRef {
                    node_id,
                    name: name.clone(),
                    node_type: r#type.clone(),
                });
                save_org_manifest(&parent_manifest_path, &parent_manifest)?;

                if json {
                    crate::output::print_json(&serde_json::json!({
                        "name": name,
                        "node_id": node_id.to_string(),
                        "parent": parent,
                        "type": r#type,
                    }))?;
                } else {
                    crate::output::print_success(&format!(
                        "Node '{}' created under '{}'",
                        name, parent
                    ));
                    println!("  ID:   {}", node_id);
                    println!("  Type: {}", r#type);
                    println!("  Path: {}", child_path);
                }
            }

            NodeCommands::Remove { path } => {
                let org_path = OrgPath::parse(&path).context("invalid org path")?;

                let manifest_path = hierarchy_paths.manifest_path(&org_path);
                if !manifest_path.exists() {
                    anyhow::bail!("node '{}' not found", path);
                }

                // Check no children
                let children = hierarchy_paths.list_children(&org_path)?;
                if !children.is_empty() {
                    anyhow::bail!(
                        "cannot remove '{}': has {} child node(s). Remove children first.",
                        path,
                        children.len()
                    );
                }

                // Check no linked vaults
                let vault_paths = sigyn_engine::vault::VaultPaths::new(home.clone());
                let linked = vault_paths.list_vaults_for_org(&path, None)?;
                if !linked.is_empty() {
                    anyhow::bail!(
                        "cannot remove '{}': {} vault(s) are linked. Detach them first.",
                        path,
                        linked.len()
                    );
                }

                // If not root, update parent's children list
                if let Some(parent_path) = org_path.parent() {
                    let parent_manifest_path = hierarchy_paths.manifest_path(&parent_path);
                    if parent_manifest_path.exists() {
                        let parent_content = std::fs::read_to_string(&parent_manifest_path)?;
                        let mut parent_manifest = NodeManifest::from_toml(&parent_content)?;
                        let node_name = org_path.segments().last().unwrap();
                        parent_manifest.children.retain(|c| c.name != *node_name);
                        crate::config::secure_write(
                            &parent_manifest_path,
                            parent_manifest.to_toml()?.as_bytes(),
                        )?;
                    }
                }

                // Remove the node directory
                std::fs::remove_dir_all(hierarchy_paths.node_dir(&org_path))?;

                if json {
                    crate::output::print_json(&serde_json::json!({
                        "removed": path,
                    }))?;
                } else {
                    crate::output::print_success(&format!("Node '{}' removed", path));
                }
            }
        },

        OrgCommands::Tree { org } => {
            let org_name = match org {
                Some(name) => name,
                None => {
                    let orgs = hierarchy_paths.list_orgs()?;
                    match orgs.len() {
                        0 => anyhow::bail!(
                            "no organizations found. Create one with: sigyn org create <name>"
                        ),
                        1 => orgs.into_iter().next().unwrap(),
                        _ => anyhow::bail!(
                            "multiple orgs found, specify one with --org: {}",
                            orgs.join(", ")
                        ),
                    }
                }
            };

            let root_path = OrgPath::parse(&org_name)?;
            if !hierarchy_paths.manifest_path(&root_path).exists() {
                anyhow::bail!("organization '{}' not found", org_name);
            }

            if json {
                let tree = build_tree_json(&hierarchy_paths, &root_path)?;
                crate::output::print_json(&tree)?;
            } else {
                println!("{}", style("Organization Hierarchy").bold());
                println!("{}", style("─".repeat(40)).dim());
                print_tree(&hierarchy_paths, &root_path, "", true)?;
            }
        }

        OrgCommands::Info { path } => {
            let org_path = OrgPath::parse(&path)?;
            let manifest_path = hierarchy_paths.manifest_path(&org_path);
            if !manifest_path.exists() {
                anyhow::bail!("node '{}' not found", path);
            }

            let manifest = load_org_manifest(&manifest_path)?;

            if json {
                crate::output::print_json(&serde_json::json!({
                    "name": manifest.name,
                    "node_id": manifest.node_id.to_string(),
                    "node_type": manifest.node_type,
                    "parent_id": manifest.parent_id.map(|id| id.to_string()),
                    "owner": manifest.owner.to_hex(),
                    "children": manifest.children.len(),
                    "created_at": manifest.created_at.to_rfc3339(),
                    "description": manifest.description,
                    "git_remote": manifest.git_remote.as_ref().map(|r| &r.url),
                }))?;
            } else {
                println!("{}", style("Node Info").bold());
                println!("  Name:     {}", manifest.name);
                println!("  ID:       {}", manifest.node_id);
                println!("  Type:     {}", manifest.node_type);
                println!("  Path:     {}", path);
                println!("  Owner:    {}", style(manifest.owner.to_hex()).cyan());
                println!("  Children: {}", manifest.children.len());
                println!(
                    "  Created:  {}",
                    manifest.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
                if let Some(desc) = &manifest.description {
                    println!("  Desc:     {}", desc);
                }
                if let Some(remote) = &manifest.git_remote {
                    println!("  Remote:   {} ({})", remote.url, remote.branch);
                }
            }
        }

        OrgCommands::Policy(policy_cmd) => match policy_cmd {
            OrgPolicyCommands::Show { path } => {
                let org_path = OrgPath::parse(&path)?;
                let manifest_path = hierarchy_paths.manifest_path(&org_path);
                if !manifest_path.exists() {
                    anyhow::bail!("node '{}' not found", path);
                }

                let loaded = load_identity(&store, identity)?;
                let manifest = load_org_manifest(&manifest_path)?;
                let owner_vk = resolve_owner_verifying_key(&manifest, &loaded, &store);

                // Unseal to read policy (verify header signature with owner's key)
                let header_bytes = std::fs::read(hierarchy_paths.members_path(&org_path))?;
                let header =
                    envelope::verify_and_load_header(&header_bytes, manifest.node_id, &owner_vk)
                        .map_err(|e| anyhow::anyhow!("failed to verify header: {}", e))?;
                let master_key =
                    envelope::unseal_vault_key(&header, loaded.encryption_key(), manifest.node_id)?;
                let cipher = VaultCipher::new(master_key);
                let policy = VaultPolicy::load_signed(
                    &hierarchy_paths.policy_path(&org_path),
                    &cipher,
                    &owner_vk,
                    &manifest.node_id,
                )?;

                if json {
                    let members: Vec<_> = policy
                        .members()
                        .map(|m| {
                            serde_json::json!({
                                "fingerprint": m.fingerprint.to_hex(),
                                "role": m.role.to_string(),
                                "allowed_envs": m.allowed_envs,
                                "secret_patterns": m.secret_patterns,
                            })
                        })
                        .collect();
                    crate::output::print_json(&serde_json::json!({
                        "path": path,
                        "owner": manifest.owner.to_hex(),
                        "members": members,
                    }))?;
                } else {
                    println!("{} ({})", style("Policy").bold(), style(&path).cyan());
                    println!("{}", style("─".repeat(40)).dim());
                    println!("  Owner: {}", style(manifest.owner.to_hex()).cyan());
                    let members: Vec<_> = policy.members().collect();
                    if members.is_empty() {
                        println!("  No additional members");
                    } else {
                        for m in members {
                            println!(
                                "  {} [{}] envs={} patterns={}",
                                style(m.fingerprint.to_hex()).bold(),
                                m.role,
                                m.allowed_envs.join(","),
                                m.secret_patterns.join(","),
                            );
                        }
                    }
                }
            }

            OrgPolicyCommands::MemberAdd {
                fingerprint,
                role,
                path,
            } => {
                let org_path = OrgPath::parse(&path)?;
                let manifest_path = hierarchy_paths.manifest_path(&org_path);
                if !manifest_path.exists() {
                    anyhow::bail!("node '{}' not found", path);
                }

                let loaded = load_identity(&store, identity)?;
                let manifest = load_org_manifest(&manifest_path)?;
                let owner_vk = resolve_owner_verifying_key(&manifest, &loaded, &store);

                let role = sigyn_engine::policy::Role::from_str_name(&role)
                    .ok_or_else(|| anyhow::anyhow!("unknown role: use readonly, auditor, operator, contributor, manager, admin, owner"))?;

                let fp = sigyn_engine::crypto::KeyFingerprint::from_hex(&fingerprint)?;

                // Unseal to modify policy (verify header signature with owner's key)
                let header_bytes = std::fs::read(hierarchy_paths.members_path(&org_path))?;
                let header =
                    envelope::verify_and_load_header(&header_bytes, manifest.node_id, &owner_vk)
                        .map_err(|e| anyhow::anyhow!("failed to verify header: {}", e))?;
                let master_key =
                    envelope::unseal_vault_key(&header, loaded.encryption_key(), manifest.node_id)?;
                let cipher = VaultCipher::new(master_key);
                let mut policy = VaultPolicy::load_signed(
                    &hierarchy_paths.policy_path(&org_path),
                    &cipher,
                    &owner_vk,
                    &manifest.node_id,
                )?;

                let member = sigyn_engine::policy::MemberPolicy::new(fp.clone(), role);
                policy.add_member(member);
                policy.save_signed(
                    &hierarchy_paths.policy_path(&org_path),
                    &cipher,
                    loaded.signing_key(),
                    &manifest.node_id,
                )?;

                if json {
                    crate::output::print_json(&serde_json::json!({
                        "added": fingerprint,
                        "role": role.to_string(),
                        "path": path,
                    }))?;
                } else {
                    crate::output::print_success(&format!(
                        "Added {} as {} at '{}'",
                        style(&fingerprint).cyan(),
                        role,
                        path
                    ));
                }
            }

            OrgPolicyCommands::MemberRemove { fingerprint, path } => {
                let org_path = OrgPath::parse(&path)?;
                let manifest_path = hierarchy_paths.manifest_path(&org_path);
                if !manifest_path.exists() {
                    anyhow::bail!("node '{}' not found", path);
                }

                let loaded = load_identity(&store, identity)?;
                let manifest = load_org_manifest(&manifest_path)?;
                let owner_vk = resolve_owner_verifying_key(&manifest, &loaded, &store);

                let fp = sigyn_engine::crypto::KeyFingerprint::from_hex(&fingerprint)?;

                let header_bytes = std::fs::read(hierarchy_paths.members_path(&org_path))?;
                let header =
                    envelope::verify_and_load_header(&header_bytes, manifest.node_id, &owner_vk)
                        .map_err(|e| anyhow::anyhow!("failed to verify header: {}", e))?;
                let master_key =
                    envelope::unseal_vault_key(&header, loaded.encryption_key(), manifest.node_id)?;
                let cipher = VaultCipher::new(master_key);
                let mut policy = VaultPolicy::load_signed(
                    &hierarchy_paths.policy_path(&org_path),
                    &cipher,
                    &owner_vk,
                    &manifest.node_id,
                )?;

                if policy.remove_member(&fp).is_none() {
                    anyhow::bail!("member {} not found at '{}'", fingerprint, path);
                }
                policy.save_signed(
                    &hierarchy_paths.policy_path(&org_path),
                    &cipher,
                    loaded.signing_key(),
                    &manifest.node_id,
                )?;

                if json {
                    crate::output::print_json(&serde_json::json!({
                        "removed": fingerprint,
                        "path": path,
                    }))?;
                } else {
                    crate::output::print_success(&format!(
                        "Removed {} from '{}'",
                        style(&fingerprint).cyan(),
                        path
                    ));
                }
            }

            OrgPolicyCommands::Effective { fingerprint, path } => {
                let org_path = OrgPath::parse(&path)?;
                let loaded = load_identity(&store, identity)?;

                let fp = sigyn_engine::crypto::KeyFingerprint::from_hex(&fingerprint)?;

                // Build the policy chain from the target path to root
                let mut chain_paths = vec![org_path.clone()];
                chain_paths.extend(org_path.ancestors().into_iter().rev());
                // chain_paths: [leaf, ..., root] — but we want vault→root order
                // For effective permissions starting from a node, chain is: [node, parent, ..., root]
                // ancestors() returns [root, ..., parent], rev() gives [parent, ..., root]
                // So chain_paths = [node, parent, ..., root] — correct

                let mut levels = Vec::new();
                for cp in &chain_paths {
                    let mp = hierarchy_paths.manifest_path(cp);
                    if !mp.exists() {
                        continue;
                    }
                    let manifest = load_org_manifest(&mp)?;
                    let owner_vk = resolve_owner_verifying_key(&manifest, &loaded, &store);

                    let header_bytes = std::fs::read(hierarchy_paths.members_path(cp))?;
                    let header = envelope::verify_and_load_header(
                        &header_bytes,
                        manifest.node_id,
                        &owner_vk,
                    )
                    .map_err(|e| anyhow::anyhow!("failed to verify header: {}", e))?;
                    let master_key = envelope::unseal_vault_key(
                        &header,
                        loaded.encryption_key(),
                        manifest.node_id,
                    )?;
                    let cipher = VaultCipher::new(master_key);
                    let policy = VaultPolicy::load_signed(
                        &hierarchy_paths.policy_path(cp),
                        &cipher,
                        &owner_vk,
                        &manifest.node_id,
                    )?;

                    levels.push((cp.as_str(), manifest.owner.clone(), policy));
                }

                // Collect effective permissions
                let mut is_owner = false;
                let mut roles: Vec<(String, sigyn_engine::policy::Role)> = Vec::new();
                let mut all_envs: Vec<String> = Vec::new();
                let mut all_patterns: Vec<String> = Vec::new();
                let mut has_wildcard_env = false;
                let mut has_wildcard_pattern = false;

                for (level_path, owner, policy) in &levels {
                    if fp == *owner {
                        is_owner = true;
                    }
                    if let Some(m) = policy.get_member(&fp) {
                        roles.push((level_path.to_string(), m.role));
                        for env in &m.allowed_envs {
                            if env == "*" {
                                has_wildcard_env = true;
                            } else if !all_envs.contains(env) {
                                all_envs.push(env.clone());
                            }
                        }
                        for pat in &m.secret_patterns {
                            if pat == "*" {
                                has_wildcard_pattern = true;
                            } else if !all_patterns.contains(pat) {
                                all_patterns.push(pat.clone());
                            }
                        }
                    }
                }

                let effective_envs = if has_wildcard_env {
                    vec!["*".into()]
                } else {
                    all_envs
                };
                let effective_patterns = if has_wildcard_pattern {
                    vec!["*".into()]
                } else {
                    all_patterns
                };
                let highest_role = roles.iter().map(|(_, r)| *r).max_by_key(|r| r.level());

                if json {
                    crate::output::print_json(&serde_json::json!({
                        "fingerprint": fingerprint,
                        "path": path,
                        "is_owner": is_owner,
                        "highest_role": highest_role.map(|r| r.to_string()),
                        "roles_by_level": roles.iter().map(|(p, r)| serde_json::json!({"level": p, "role": r.to_string()})).collect::<Vec<_>>(),
                        "effective_envs": effective_envs,
                        "effective_patterns": effective_patterns,
                    }))?;
                } else {
                    println!(
                        "{} for {} at '{}'",
                        style("Effective Permissions").bold(),
                        style(&fingerprint).cyan(),
                        path
                    );
                    println!("{}", style("─".repeat(50)).dim());
                    if is_owner {
                        println!("  Owner: {} (full access)", style("yes").green());
                    }
                    if let Some(role) = highest_role {
                        println!("  Highest role: {}", style(role.to_string()).bold());
                    } else if !is_owner {
                        println!("  {} Not a member at any level", style("!").red());
                    }
                    for (level, role) in &roles {
                        println!("    {} -> {}", style(level).dim(), role);
                    }
                    println!("  Environments: {}", effective_envs.join(", "));
                    println!("  Patterns:     {}", effective_patterns.join(", "));
                }
            }
        },

        OrgCommands::Sync(sync_cmd) => match sync_cmd {
            OrgSyncCommands::Configure {
                path,
                remote_url,
                branch,
            } => {
                let org_path = OrgPath::parse(&path)?;
                let manifest_path = hierarchy_paths.manifest_path(&org_path);
                if !manifest_path.exists() {
                    anyhow::bail!("node '{}' not found", path);
                }

                let mut manifest = load_org_manifest(&manifest_path)?;
                manifest.git_remote = Some(GitRemoteConfig {
                    url: remote_url.clone(),
                    branch: branch.clone(),
                });
                save_org_manifest(&manifest_path, &manifest)?;

                if json {
                    crate::output::print_json(&serde_json::json!({
                        "path": path,
                        "remote_url": remote_url,
                        "branch": branch,
                    }))?;
                } else {
                    crate::output::print_success(&format!("Git remote configured for '{}'", path));
                    println!("  URL:    {}", remote_url);
                    println!("  Branch: {}", branch);
                }
            }
        },
    }

    Ok(())
}

fn print_tree(
    paths: &HierarchyPaths,
    org_path: &OrgPath,
    prefix: &str,
    is_last: bool,
) -> Result<()> {
    let manifest_path = paths.manifest_path(org_path);
    let manifest = load_org_manifest(&manifest_path)?;

    let connector = if prefix.is_empty() {
        ""
    } else if is_last {
        "└── "
    } else {
        "├── "
    };

    let type_tag = style(format!("[{}]", manifest.node_type)).dim();
    println!(
        "{}{}{} {}",
        prefix,
        connector,
        style(&manifest.name).bold(),
        type_tag
    );

    let children = paths.list_children(org_path)?;
    let child_prefix = if prefix.is_empty() {
        "".to_string()
    } else if is_last {
        format!("{}    ", prefix)
    } else {
        format!("{}│   ", prefix)
    };

    // Also show linked vaults (requires unlock, so just list vault dirs)
    let home = sigyn_home();
    let vault_paths = sigyn_engine::vault::VaultPaths::new(home);
    let org_str = org_path.as_str();
    // Note: vault manifests are encrypted, so we can't filter by org_path without unlocking.
    // Show all vaults under this org dir as potential matches.
    if let Ok(vaults) = vault_paths.list_vaults_for_org(&org_str, None) {
        let direct_vaults: Vec<_> = vaults;

        let total_items = children.len() + direct_vaults.len();
        for (i, vault_name) in direct_vaults.iter().enumerate() {
            let is_last_item = i + children.len() >= total_items.saturating_sub(1);
            let vc = if is_last_item && children.is_empty() {
                "└── "
            } else {
                "├── "
            };
            println!(
                "{}{}{}",
                child_prefix,
                vc,
                style(format!("{} [vault]", vault_name)).dim()
            );
        }
    }

    for (i, child_name) in children.iter().enumerate() {
        let child_path = org_path.child(child_name)?;
        print_tree(paths, &child_path, &child_prefix, i == children.len() - 1)?;
    }

    Ok(())
}

fn build_tree_json(paths: &HierarchyPaths, org_path: &OrgPath) -> Result<serde_json::Value> {
    let manifest_path = paths.manifest_path(org_path);
    let manifest = load_org_manifest(&manifest_path)?;

    let children_names = paths.list_children(org_path)?;
    let mut children_json = Vec::new();
    for child_name in children_names {
        let child_path = org_path.child(&child_name)?;
        children_json.push(build_tree_json(paths, &child_path)?);
    }

    // List directly linked vaults
    let home = sigyn_home();
    let vault_paths = sigyn_engine::vault::VaultPaths::new(home);
    let org_str = org_path.as_str();
    let direct_vaults: Vec<String> = vault_paths
        .list_vaults_for_org(&org_str, None)
        .unwrap_or_default();

    Ok(serde_json::json!({
        "name": manifest.name,
        "node_id": manifest.node_id.to_string(),
        "node_type": manifest.node_type,
        "children": children_json,
        "vaults": direct_vaults,
    }))
}
