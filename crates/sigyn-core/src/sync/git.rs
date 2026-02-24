use std::path::PathBuf;

use super::state::{SyncState, SyncStatus};
use crate::error::{Result, SigynError};

fn make_callbacks() -> git2::RemoteCallbacks<'static> {
    let mut cb = git2::RemoteCallbacks::new();
    cb.credentials(|_url, username, allowed| {
        if allowed.contains(git2::CredentialType::SSH_KEY) {
            git2::Cred::ssh_key_from_agent(username.unwrap_or("git"))
        } else if allowed.contains(git2::CredentialType::USER_PASS_PLAINTEXT) {
            let config = git2::Config::open_default()?;
            git2::Cred::credential_helper(&config, _url, username)
        } else {
            Err(git2::Error::from_str("no suitable credential type"))
        }
    });
    cb
}

pub struct GitSyncEngine {
    vault_path: PathBuf,
}

impl GitSyncEngine {
    pub fn new(vault_path: PathBuf) -> Self {
        Self { vault_path }
    }

    pub fn init(&self) -> Result<()> {
        git2::Repository::init(&self.vault_path)
            .map_err(|e| SigynError::GitError(e.to_string()))?;
        Ok(())
    }

    pub fn is_repo(&self) -> bool {
        git2::Repository::open(&self.vault_path).is_ok()
    }

    pub fn add_remote(&self, name: &str, url: &str) -> Result<()> {
        let repo = self.open_repo()?;
        repo.remote(name, url)
            .map_err(|e| SigynError::GitError(e.to_string()))?;
        Ok(())
    }

    pub fn status(&self) -> Result<SyncState> {
        let repo = match git2::Repository::open(&self.vault_path) {
            Ok(r) => r,
            Err(_) => {
                return Ok(SyncState {
                    status: SyncStatus::NeverSynced,
                    last_push: None,
                    last_pull: None,
                    remote_url: None,
                });
            }
        };

        let remote_url = repo
            .find_remote("origin")
            .ok()
            .and_then(|r| r.url().map(String::from));

        let status = if remote_url.is_none() {
            SyncStatus::NeverSynced
        } else {
            self.compute_sync_status(&repo)
                .unwrap_or(SyncStatus::NeverSynced)
        };

        Ok(SyncState {
            status,
            last_push: None,
            last_pull: None,
            remote_url,
        })
    }

    pub fn stage_all(&self) -> Result<()> {
        let repo = self.open_repo()?;
        let mut index = repo
            .index()
            .map_err(|e| SigynError::GitError(e.to_string()))?;
        index
            .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
            .map_err(|e| SigynError::GitError(e.to_string()))?;
        index
            .write()
            .map_err(|e| SigynError::GitError(e.to_string()))?;
        Ok(())
    }

    pub fn commit(&self, message: &str) -> Result<git2::Oid> {
        let repo = self.open_repo()?;
        let mut index = repo
            .index()
            .map_err(|e| SigynError::GitError(e.to_string()))?;
        let tree_oid = index
            .write_tree()
            .map_err(|e| SigynError::GitError(e.to_string()))?;
        let tree = repo
            .find_tree(tree_oid)
            .map_err(|e| SigynError::GitError(e.to_string()))?;

        let sig = repo
            .signature()
            .or_else(|_| git2::Signature::now("sigyn-automated", "noreply@sigyn.local"))
            .map_err(|e| SigynError::GitError(e.to_string()))?;

        let parent = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
        let parents: Vec<&git2::Commit> = parent.iter().collect();

        let oid = repo
            .commit(Some("HEAD"), &sig, &sig, message, &tree, &parents)
            .map_err(|e| SigynError::GitError(e.to_string()))?;

        Ok(oid)
    }

    pub fn push(&self, remote_name: &str, branch: &str) -> Result<()> {
        let repo = self.open_repo()?;
        let mut remote = repo
            .find_remote(remote_name)
            .map_err(|e| SigynError::GitError(e.to_string()))?;

        let refspec = format!("refs/heads/{}:refs/heads/{}", branch, branch);
        let mut push_opts = git2::PushOptions::new();
        push_opts.remote_callbacks(make_callbacks());
        remote
            .push(&[&refspec], Some(&mut push_opts))
            .map_err(|e| SigynError::GitError(e.to_string()))?;
        Ok(())
    }

    pub fn pull(&self, remote_name: &str, branch: &str) -> Result<PullResult> {
        let repo = self.open_repo()?;
        let mut remote = repo
            .find_remote(remote_name)
            .map_err(|e| SigynError::GitError(e.to_string()))?;

        let mut fetch_opts = git2::FetchOptions::new();
        fetch_opts.remote_callbacks(make_callbacks());
        remote
            .fetch(&[branch], Some(&mut fetch_opts), None)
            .map_err(|e| SigynError::GitError(e.to_string()))?;

        let fetch_head = repo
            .find_reference("FETCH_HEAD")
            .map_err(|e| SigynError::GitError(e.to_string()))?;
        let fetch_commit = repo
            .reference_to_annotated_commit(&fetch_head)
            .map_err(|e| SigynError::GitError(e.to_string()))?;

        let (analysis, _) = repo
            .merge_analysis(&[&fetch_commit])
            .map_err(|e| SigynError::GitError(e.to_string()))?;

        if analysis.is_up_to_date() {
            return Ok(PullResult::UpToDate);
        }

        if analysis.is_fast_forward() {
            let refname = format!("refs/heads/{}", branch);
            if let Ok(mut reference) = repo.find_reference(&refname) {
                reference
                    .set_target(fetch_commit.id(), "sigyn pull fast-forward")
                    .map_err(|e| SigynError::GitError(e.to_string()))?;
            } else {
                repo.reference(&refname, fetch_commit.id(), true, "sigyn pull")
                    .map_err(|e| SigynError::GitError(e.to_string()))?;
            }
            repo.set_head(&refname)
                .map_err(|e| SigynError::GitError(e.to_string()))?;
            repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))
                .map_err(|e| SigynError::GitError(e.to_string()))?;
            return Ok(PullResult::FastForward);
        }

        Ok(PullResult::Conflict)
    }

    pub fn has_changes(&self) -> Result<bool> {
        let repo = self.open_repo()?;
        let statuses = repo
            .statuses(None)
            .map_err(|e| SigynError::GitError(e.to_string()))?;
        Ok(!statuses.is_empty())
    }

    pub fn sync(&self, remote_name: &str, branch: &str, message: &str) -> Result<SyncResult> {
        // Pull first
        let pull_result = self.pull(remote_name, branch)?;
        if matches!(pull_result, PullResult::Conflict) {
            return Ok(SyncResult::Conflict);
        }

        // Stage and commit local changes
        if self.has_changes()? {
            self.stage_all()?;
            self.commit(message)?;
        }

        // Push
        self.push(remote_name, branch)?;

        Ok(match pull_result {
            PullResult::UpToDate => SyncResult::Pushed,
            PullResult::FastForward => SyncResult::Merged,
            PullResult::Conflict => SyncResult::Conflict,
        })
    }

    fn open_repo(&self) -> Result<git2::Repository> {
        git2::Repository::open(&self.vault_path).map_err(|e| SigynError::GitError(e.to_string()))
    }

    fn compute_sync_status(&self, repo: &git2::Repository) -> Result<SyncStatus> {
        let head = match repo.head() {
            Ok(h) => h,
            Err(_) => return Ok(SyncStatus::NeverSynced),
        };

        let local_oid = head
            .target()
            .ok_or_else(|| SigynError::GitError("HEAD has no target".into()))?;

        let upstream = match repo.find_reference("refs/remotes/origin/main") {
            Ok(r) => r,
            Err(_) => return Ok(SyncStatus::NeverSynced),
        };

        let remote_oid = upstream
            .target()
            .ok_or_else(|| SigynError::GitError("upstream has no target".into()))?;

        if local_oid == remote_oid {
            return Ok(SyncStatus::UpToDate);
        }

        let (ahead, behind) = repo
            .graph_ahead_behind(local_oid, remote_oid)
            .map_err(|e| SigynError::GitError(e.to_string()))?;

        Ok(match (ahead, behind) {
            (0, 0) => SyncStatus::UpToDate,
            (a, 0) => SyncStatus::LocalAhead(a as u64),
            (0, b) => SyncStatus::RemoteAhead(b as u64),
            _ => SyncStatus::Diverged,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PullResult {
    UpToDate,
    FastForward,
    Conflict,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SyncResult {
    Pushed,
    Merged,
    Conflict,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_and_commit() {
        let dir = tempfile::tempdir().unwrap();
        let engine = GitSyncEngine::new(dir.path().to_path_buf());
        engine.init().unwrap();
        assert!(engine.is_repo());

        // Write a file and commit
        std::fs::write(dir.path().join("test.txt"), "hello").unwrap();
        engine.stage_all().unwrap();
        let oid = engine.commit("initial commit").unwrap();
        assert!(!oid.is_zero());
    }

    #[test]
    fn test_has_changes() {
        let dir = tempfile::tempdir().unwrap();
        let engine = GitSyncEngine::new(dir.path().to_path_buf());
        engine.init().unwrap();

        std::fs::write(dir.path().join("file.txt"), "data").unwrap();
        assert!(engine.has_changes().unwrap());

        engine.stage_all().unwrap();
        engine.commit("commit").unwrap();

        // After commit, working tree is clean
        assert!(!engine.has_changes().unwrap());
    }
}
