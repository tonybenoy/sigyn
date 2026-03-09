# Sigyn End-to-End Test Plan

**Version:** 0.11.0
**Date:** 2026-03-09
**Objective:** Validate every major Sigyn flow across realistic multi-repo, multi-user, multi-role scenarios.

---

## Test Infrastructure

### Repositories

| Repo | Purpose | URL |
|------|---------|-----|
| `sigyn-test-python` | Python Flask app consuming secrets via `sigyn run` | https://github.com/tonybenoy/sigyn-test-python |
| `sigyn-test-vault` | Dedicated vault repo synced via `sigyn sync` (shared infrastructure secrets) | https://github.com/tonybenoy/sigyn-test-vault |
| `sigyn-test-npm` | Node.js Express app consuming secrets via `sigyn run` | https://github.com/tonybenoy/sigyn-test-npm |

### Team Personas

| Persona | Role | Description |
|---------|------|-------------|
| **Alice** | Owner | CTO — creates vaults, sets policy, owns everything |
| **Bob** | Admin | VP Engineering — manages policy, delegates to others |
| **Carol** | Manager | Team Lead — manages members, can't change policy |
| **Dave** | Contributor | Backend Dev — reads/writes secrets |
| **Eve** | ReadOnly | QA Engineer — can only read secrets |
| **Frank** | Operator | CI/CD Bot — can write secrets but NOT read them |
| **Grace** | Auditor | Compliance Officer — reads secrets + audit logs |

---

## Phase 1: Identity & Bootstrap

### T1.1 — Identity Creation
- [ ] Alice creates identity: `sigyn identity create --name alice --email alice@acme.io`
- [ ] Bob creates identity: `sigyn identity create --name bob --email bob@acme.io`
- [ ] Carol creates identity: `sigyn identity create --name carol --email carol@acme.io`
- [ ] Dave creates identity: `sigyn identity create --name dave --email dave@acme.io`
- [ ] Eve creates identity: `sigyn identity create --name eve --email eve@acme.io`
- [ ] Frank creates identity: `sigyn identity create --name frank --email frank@acme.io`
- [ ] Grace creates identity: `sigyn identity create --name grace --email grace@acme.io`

### T1.2 — Identity Operations
- [ ] `sigyn identity list` — shows all 7 identities
- [ ] `sigyn identity show --name alice` — displays fingerprint, email, creation date
- [ ] `sigyn identity change-passphrase --name dave` — change Dave's passphrase
- [ ] Verify old passphrase no longer works, new passphrase works

### T1.3 — Default Identity Config
- [ ] `sigyn init` — set Alice as default identity
- [ ] Verify `~/.sigyn/config.toml` has `default_identity = "alice"`

---

## Phase 2: Vault Creation & Environments

### T2.1 — Create Vaults (Alice as Owner)

**Python project vault:**
- [ ] `sigyn vault create python-app -i alice`
- [ ] Verify creates `dev`, `staging`, `prod` environments by default

**Shared infrastructure vault (synced to dedicated repo):**
- [ ] `sigyn vault create shared-infra -i alice`
- [ ] `sigyn sync configure -v shared-infra --remote git@github.com:tonybenoy/sigyn-test-vault.git`

**NPM project vault:**
- [ ] `sigyn vault create npm-app -i alice`

### T2.2 — Vault Info & Listing
- [ ] `sigyn vault list` — shows all 3 vaults
- [ ] `sigyn vault info -v python-app` — shows UUID, owner fingerprint, environments
- [ ] `sigyn vault info -v shared-infra` — verify owner is Alice
- [ ] `sigyn vault info -v npm-app` — verify 3 default environments

### T2.3 — Custom Environment Creation
- [ ] `sigyn env create -v python-app --name ci` — add CI environment
- [ ] `sigyn env create -v npm-app --name preview` — add preview environment
- [ ] `sigyn env list -v python-app` — shows: dev, staging, prod, ci
- [ ] `sigyn env list -v npm-app` — shows: dev, staging, prod, preview

---

## Phase 3: Team Delegation & RBAC

### T3.1 — Alice (Owner) Invites Bob (Admin)
- [ ] `sigyn delegation invite create -v python-app -i alice --role admin --fingerprint <bob-fp> -o bob-python.invite`
- [ ] `sigyn delegation invite accept -i bob --file bob-python.invite`
- [ ] Repeat for `shared-infra` and `npm-app`
- [ ] `sigyn policy show -v python-app` — Bob listed as Admin

### T3.2 — Bob (Admin) Invites Carol (Manager)
- [ ] `sigyn delegation invite create -v python-app -i bob --role manager --fingerprint <carol-fp> -o carol.invite`
- [ ] `sigyn delegation invite accept -i carol --file carol.invite`
- [ ] Verify delegation tree: Alice → Bob → Carol

### T3.3 — Carol (Manager) Invites Dave (Contributor)
- [ ] `sigyn delegation invite create -v python-app -i carol --role contributor --fingerprint <dave-fp> -o dave.invite`
- [ ] `sigyn delegation invite accept -i dave --file dave.invite`

### T3.4 — Alice Invites Remaining Members
- [ ] Invite Eve as ReadOnly to `python-app` (envs: dev, staging only)
- [ ] Invite Frank as Operator to `python-app` (envs: ci, prod)
- [ ] Invite Grace as Auditor to `shared-infra`

### T3.5 — Bulk Invite
- [ ] Create `bulk.json` with Dave + Eve for `npm-app`
- [ ] `sigyn delegation bulk-invite -v npm-app -i alice --file bulk.json`
- [ ] Verify both members added

### T3.6 — Delegation Tree
- [ ] `sigyn delegation tree -v python-app`
- [ ] Verify hierarchy: Alice(Owner) → Bob(Admin) → Carol(Manager) → Dave(Contributor)
- [ ] Verify Alice → Eve(ReadOnly), Alice → Frank(Operator), Alice → Grace(Auditor)

### T3.7 — Environment-Scoped Access
- [ ] `sigyn delegation grant-env -v python-app -i alice --fingerprint <dave-fp> --env prod`
- [ ] `sigyn policy check -v python-app --fingerprint <dave-fp> --action read --env prod` → allowed
- [ ] `sigyn policy check -v python-app --fingerprint <eve-fp> --action read --env prod` → denied (Eve only has dev, staging)
- [ ] `sigyn policy check -v python-app --fingerprint <eve-fp> --action write --env dev` → denied (ReadOnly)

---

## Phase 4: Secret Management

### T4.1 — Set Secrets (Python Vault)
```
sigyn set -v python-app -e dev DATABASE_URL=postgres://localhost:5432/devdb -i alice
sigyn set -v python-app -e dev API_KEY=dev-key-12345 -i alice
sigyn set -v python-app -e dev SECRET_TOKEN=dev-token-abc -i alice
sigyn set -v python-app -e dev REDIS_URL=redis://localhost:6379 -i alice

sigyn set -v python-app -e staging DATABASE_URL=postgres://staging-db:5432/app -i alice
sigyn set -v python-app -e staging API_KEY=staging-key-67890 -i alice

sigyn set -v python-app -e prod DATABASE_URL=postgres://prod-db:5432/app -i alice
sigyn set -v python-app -e prod API_KEY=prod-key-REAL -i alice
sigyn set -v python-app -e prod SECRET_TOKEN=prod-token-xyz -i alice
sigyn set -v python-app -e prod REDIS_URL=redis://prod-redis:6379 -i alice
```

### T4.2 — Set Secrets (NPM Vault)
```
sigyn set -v npm-app -e dev DATABASE_URL=postgres://localhost:5432/npmdev -i alice
sigyn set -v npm-app -e dev API_KEY=npm-dev-key -i alice
sigyn set -v npm-app -e dev STRIPE_SECRET=sk_test_fake123 -i alice
sigyn set -v npm-app -e dev JWT_SECRET=dev-jwt-secret -i alice
```

### T4.3 — Set Secrets (Shared Infra Vault)
```
sigyn set -v shared-infra -e prod POSTGRES_MASTER=postgres://master:5432/main -i alice
sigyn set -v shared-infra -e prod REDIS_CLUSTER=redis://cluster:6379 -i alice
sigyn set -v shared-infra -e prod DATADOG_API_KEY=dd-key-prod -i alice
```

### T4.4 — Get & List Secrets
- [ ] `sigyn get -v python-app -e dev DATABASE_URL -i alice` → returns `postgres://localhost:5432/devdb`
- [ ] `sigyn ls -v python-app -e dev -i alice` → lists 4 secrets (masked)
- [ ] `sigyn ls -v python-app -e dev -i alice --reveal` → shows actual values
- [ ] `sigyn get -v python-app -e dev DATABASE_URL -i dave` → works (Contributor)
- [ ] `sigyn get -v python-app -e dev DATABASE_URL -i eve` → works (ReadOnly can read)
- [ ] `sigyn get -v python-app -e dev DATABASE_URL -i frank` → **DENIED** (Operator cannot read)

### T4.5 — Write Permissions
- [ ] `sigyn set -v python-app -e dev NEW_KEY=value -i dave` → works (Contributor)
- [ ] `sigyn set -v python-app -e dev NEW_KEY2=value -i eve` → **DENIED** (ReadOnly)
- [ ] `sigyn set -v python-app -e ci CI_TOKEN=tok -i frank` → works (Operator can write)
- [ ] `sigyn get -v python-app -e ci CI_TOKEN -i frank` → **DENIED** (Operator can't read back)

### T4.6 — Delete Secrets
- [ ] `sigyn secret remove -v python-app -e dev NEW_KEY -i dave` → works
- [ ] `sigyn secret remove -v python-app -e dev API_KEY -i eve` → **DENIED**

### T4.7 — Secret Generation
- [ ] `sigyn secret generate -v python-app -e dev SESSION_SECRET --type password --length 32 -i alice`
- [ ] `sigyn secret generate -v python-app -e dev REQUEST_ID --type uuid -i alice`
- [ ] `sigyn secret generate -v npm-app -e dev ENCRYPTION_KEY --type hex --length 64 -i alice`
- [ ] Verify generated values match expected format

### T4.8 — Secret Search
- [ ] `sigyn secret search -v python-app "DB*" -i alice` → finds DATABASE_URL across envs
- [ ] `sigyn secret search -v python-app "*KEY*" -i alice` → finds API_KEY across envs

### T4.9 — Import from .env
- [ ] Create `.env` file with 5 secrets
- [ ] `sigyn secret import -v npm-app -e dev --file .env -i alice`
- [ ] Verify all 5 imported

### T4.10 — Batch Edit
- [ ] `sigyn secret edit -v python-app -e dev -i alice` — opens editor, modify 2 values
- [ ] Verify changes persisted

---

## Phase 5: Environment Operations

### T5.1 — Environment Diff
- [ ] `sigyn env diff -v python-app dev staging -i alice` → shows keys present in dev but not staging
- [ ] `sigyn env diff -v python-app dev staging -i alice --reveal` → shows actual value differences

### T5.2 — Environment Clone
- [ ] `sigyn env clone -v python-app dev local -i alice`
- [ ] `sigyn ls -v python-app -e local -i alice` → same secrets as dev

### T5.3 — Environment Promote
- [ ] `sigyn env promote -v python-app staging prod -i alice`
- [ ] Verify prod now has staging values for overlapping keys

### T5.4 — Secret Copy Between Vaults
- [ ] `sigyn secret copy -v python-app -e dev --to-vault npm-app --to-env dev --pattern "DATABASE_*" -i alice`
- [ ] Verify DATABASE_URL copied to npm-app dev

### T5.5 — Environment Delete
- [ ] `sigyn env delete -v python-app -e local -i alice`
- [ ] Verify environment no longer listed

---

## Phase 6: Sync & Git Integration

### T6.1 — Configure Sync
- [ ] `sigyn sync configure -v python-app --remote git@github.com:tonybenoy/sigyn-test-python.git -i alice`
- [ ] `sigyn sync configure -v npm-app --remote git@github.com:tonybenoy/sigyn-test-npm.git -i alice`
- [ ] `sigyn sync configure -v shared-infra --remote git@github.com:tonybenoy/sigyn-test-vault.git -i alice`

### T6.2 — Push
- [ ] `sigyn sync push -v python-app -i alice`
- [ ] `sigyn sync push -v npm-app -i alice`
- [ ] `sigyn sync push -v shared-infra -i alice`
- [ ] Verify encrypted data appears in each GitHub repo (no plaintext secrets)

### T6.3 — Pull (Simulate Second Device)
- [ ] On a separate `$SIGYN_HOME`, `sigyn sync pull -v shared-infra -i bob`
- [ ] Verify Bob (Admin) can read secrets after pull
- [ ] Verify encrypted vault files are present locally

### T6.4 — Sync Status
- [ ] `sigyn sync status -v python-app -i alice` → shows clean/up-to-date

### T6.5 — Conflict Resolution
- [ ] Simulate concurrent edits (Alice and Bob modify same secret)
- [ ] `sigyn sync pull` triggers conflict
- [ ] `sigyn sync resolve -v shared-infra --strategy latest -i alice`
- [ ] Verify conflict resolved

---

## Phase 7: Run & Secret Injection

### T7.1 — Python Project
- [ ] `cd /tmp/sigyn-e2e-test/sigyn-test-python`
- [ ] `sigyn run -v python-app -e dev -i alice -- python -c "import os; print(os.environ.get('DATABASE_URL'))"`
- [ ] Verify output: `postgres://localhost:5432/devdb`

### T7.2 — NPM Project
- [ ] `cd /tmp/sigyn-e2e-test/sigyn-test-npm`
- [ ] `sigyn run -v npm-app -e dev -i alice -- node -e "console.log(process.env.STRIPE_SECRET)"`
- [ ] Verify output: `sk_test_fake123`

### T7.3 — Clean Environment
- [ ] `sigyn run -v python-app -e dev -i alice --clean -- env | wc -l`
- [ ] Verify only Sigyn-injected vars present (minimal env)

### T7.4 — Export Formats
- [ ] `sigyn run export -v python-app -e dev -i alice --format dotenv` → valid .env output
- [ ] `sigyn run export -v python-app -e dev -i alice --format json` → valid JSON
- [ ] `sigyn run export -v python-app -e dev -i alice --format shell` → `export KEY=VALUE` lines
- [ ] `sigyn run export -v python-app -e dev -i alice --format docker` → Docker env format
- [ ] `sigyn run export -v python-app -e dev -i alice --format k8s` → Kubernetes secret YAML

### T7.5 — Inline Secret Refs
- [ ] `sigyn run -v python-app -e dev -i alice --allow-inline-secrets -- echo "DB is {{DATABASE_URL}}"`
- [ ] Verify `{{DATABASE_URL}}` replaced with actual value

### T7.6 — Prod/Staging Shortcuts
- [ ] `sigyn run -v python-app --prod -i alice -- env | grep DATABASE_URL`
- [ ] Verify prod value used

---

## Phase 8: Audit & Compliance

### T8.1 — Audit Tail
- [ ] `sigyn audit tail -v python-app -i alice` → shows recent events
- [ ] Verify SecretCreated, MemberAdded events present

### T8.2 — Audit Query
- [ ] `sigyn audit query -v python-app -i grace --actor <alice-fp>` → Alice's actions only
- [ ] `sigyn audit query -v python-app -i grace --env prod` → prod-only events

### T8.3 — Audit Verify
- [ ] `sigyn audit verify -v python-app -i alice` → chain integrity OK
- [ ] Verify BLAKE3 hash chain is valid

### T8.4 — Audit Export
- [ ] `sigyn audit export -v python-app -i grace --format json > audit.json`
- [ ] `sigyn audit export -v python-app -i grace --format csv > audit.csv`
- [ ] Verify both files valid and contain same events

### T8.5 — Witness Signing
- [ ] `sigyn audit witness -v python-app -i bob` → Bob co-signs audit
- [ ] Verify witness signature in audit tail

### T8.6 — Audit Anchor
- [ ] `sigyn audit anchor -v python-app -i alice`
- [ ] Verify git commit created with audit hash

### T8.7 — Auditor Role Verification
- [ ] `sigyn audit tail -v shared-infra -i grace` → works (Auditor can read audit)
- [ ] `sigyn get -v shared-infra -e prod POSTGRES_MASTER -i grace` → works (Auditor can read)
- [ ] `sigyn set -v shared-infra -e prod NEW=val -i grace` → **DENIED** (Auditor can't write)

---

## Phase 9: Secret Rotation

### T9.1 — Manual Rotation
- [ ] `sigyn rotate key -v python-app -e prod API_KEY -i alice`
- [ ] Verify old value replaced, audit logged

### T9.2 — Rotation Schedule
- [ ] `sigyn rotate schedule set -v python-app -e prod API_KEY --cron "0 0 1 * *" -i alice` (monthly)
- [ ] `sigyn rotate schedule list -v python-app -i alice` → shows schedule
- [ ] `sigyn rotate due -v python-app -i alice --max-age 30d` → shows secrets not rotated in 30 days

### T9.3 — Breach Mode
- [ ] `sigyn rotate breach-mode -v python-app -i alice`
- [ ] Verify ALL secrets rotated
- [ ] Verify delegated access revoked
- [ ] Verify audit logs breach-mode event

### T9.4 — Dead Secret Check
- [ ] `sigyn rotate dead-check -v python-app -i alice`
- [ ] Shows any secrets that haven't been accessed

---

## Phase 10: Delegation Advanced Flows

### T10.1 — Cascade Revocation
- [ ] `sigyn delegation revoke -v python-app -i alice --fingerprint <bob-fp> --cascade`
- [ ] Verify Bob removed
- [ ] Verify Carol (invited by Bob) also removed
- [ ] Verify Dave (invited by Carol) also removed
- [ ] `sigyn delegation tree -v python-app` → only Alice, Eve, Frank, Grace remain

### T10.2 — Non-Cascade Revocation
- [ ] Re-invite Bob, Carol, Dave
- [ ] `sigyn delegation revoke -v python-app -i alice --fingerprint <carol-fp>` (no cascade)
- [ ] Verify Carol removed
- [ ] Verify Dave's delegation parent updated or Dave also removed (orphan handling)

### T10.3 — Environment Access Revocation
- [ ] `sigyn delegation revoke-env -v python-app -i alice --fingerprint <dave-fp> --env prod`
- [ ] `sigyn get -v python-app -e prod API_KEY -i dave` → **DENIED**
- [ ] `sigyn get -v python-app -e dev API_KEY -i dave` → still works

### T10.4 — Role Hierarchy Enforcement
- [ ] Carol (Manager) tries to invite someone as Admin → **DENIED** (can't delegate above own role)
- [ ] Dave (Contributor) tries to invite anyone → **DENIED** (below Manager)

---

## Phase 11: Vault Ownership & Transfer

### T11.1 — Ownership Transfer
- [ ] `sigyn vault transfer -v python-app -i alice --to <bob-fp>`
- [ ] `sigyn vault accept-transfer -v python-app -i bob`
- [ ] `sigyn vault info -v python-app` → owner is now Bob
- [ ] Verify Alice retains access (as what role?)

### T11.2 — Vault Export
- [ ] `sigyn vault export -v python-app -i bob -o python-app-backup.tar.gz`
- [ ] Verify file created, encrypted, contains all environments

### T11.3 — TOFU Pinning
- [ ] `sigyn vault pins` → shows pinned vault owners
- [ ] Simulate owner change from unexpected source
- [ ] Verify TOFU warning triggered
- [ ] `sigyn vault trust -v python-app -i alice` → accept new owner

---

## Phase 12: Organization Hierarchy

### T12.1 — Create Org
- [ ] `sigyn org create acme -i alice`
- [ ] `sigyn org node create acme/platform -i alice`
- [ ] `sigyn org node create acme/platform/web -i alice`
- [ ] `sigyn org node create acme/platform/api -i alice`
- [ ] `sigyn org node create acme/data -i alice`

### T12.2 — Org Tree
- [ ] `sigyn org tree acme -i alice`
- [ ] Verify tree: acme → platform → {web, api}, acme → data

### T12.3 — Vault Attachment
- [ ] `sigyn vault attach -v python-app --org-path acme/platform/api -i alice`
- [ ] `sigyn vault attach -v npm-app --org-path acme/platform/web -i alice`
- [ ] `sigyn vault attach -v shared-infra --org-path acme -i alice`
- [ ] `sigyn vault info -v python-app` → shows org path

### T12.4 — Org-Level Policy
- [ ] `sigyn org policy member-add acme -i alice --fingerprint <bob-fp> --role admin`
- [ ] Verify Bob has access inherited at org level

---

## Phase 13: CI/CD Integration

### T13.1 — CI Bundle Creation
- [ ] `sigyn ci setup -v python-app -i frank` → generates base64 bundle
- [ ] Verify bundle contains: fingerprint, identity file, device key

### T13.2 — GitHub Action (Python Repo)
Add workflow to `sigyn-test-python`:
```yaml
name: Sigyn Secrets
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tonybenoy/sigyn@main
        with:
          sigyn-bundle: ${{ secrets.SIGYN_BUNDLE }}
          vault: python-app
          env: ci
          vault-repo: git@github.com:tonybenoy/sigyn-test-python.git
          vault-repo-ssh-key: ${{ secrets.VAULT_SSH_KEY }}
          mode: env
      - run: echo "DB is set = $([[ -n $DATABASE_URL ]] && echo yes || echo no)"
```
- [ ] Push workflow
- [ ] Verify GitHub Action runs and secrets injected

### T13.3 — GitHub Action (NPM Repo)
- [ ] Similar workflow for `sigyn-test-npm`
- [ ] Verify secrets available in CI

### T13.4 — Export Modes in CI
- [ ] Test `mode: dotenv` → creates .env file
- [ ] Test `mode: json` → creates JSON file
- [ ] Test `mode: mask-only` → masks secrets in logs without exporting

---

## Phase 14: MFA Flows

### T14.1 — MFA Setup
- [ ] `sigyn mfa setup -i alice` → generates TOTP QR/secret
- [ ] `sigyn mfa status -i alice` → enrolled

### T14.2 — MFA Policy
- [ ] `sigyn policy require-mfa -v python-app -i alice --action write`
- [ ] Verify write operations now require TOTP

### T14.3 — Per-Member MFA
- [ ] `sigyn policy member-require-mfa -v python-app -i alice --fingerprint <bob-fp> --action manage-members`
- [ ] Verify Bob needs TOTP for member management

### T14.4 — MFA Backup Codes
- [ ] `sigyn mfa backup -i alice` → generates backup codes
- [ ] Verify backup code works as TOTP alternative

### T14.5 — MFA Disable
- [ ] `sigyn mfa disable -i alice` → requires TOTP to disable

---

## Phase 15: Fork Management

### T15.1 — Leashed Fork
- [ ] `sigyn fork create -v python-app --name python-app-fork --mode leashed -i dave`
- [ ] `sigyn fork list -v python-app -i alice` → shows fork
- [ ] `sigyn fork status -v python-app --name python-app-fork -i dave` → leashed, active

### T15.2 — Fork Sync
- [ ] Modify secret in parent vault
- [ ] `sigyn fork sync -v python-app --name python-app-fork -i dave`
- [ ] Verify change propagated

### T15.3 — Fork with Expiry
- [ ] `sigyn fork create -v npm-app --name npm-temp --mode unleashed --expiry 24h -i alice`
- [ ] Verify fork expires after 24h

---

## Phase 16: Context & Project Config

### T16.1 — Context Management
- [ ] `sigyn context set -v python-app -e dev`
- [ ] `sigyn context show` → shows python-app / dev
- [ ] `sigyn ls` → lists secrets without `-v` and `-e` flags
- [ ] `sigyn context clear`

### T16.2 — Project Config (.sigyn.toml)
- [ ] `cd /tmp/sigyn-e2e-test/sigyn-test-python`
- [ ] `sigyn ls -i alice` → automatically uses vault=python-app, env=dev from .sigyn.toml
- [ ] Override: `sigyn ls -v python-app -e prod -i alice` → uses CLI flag over config

### T16.3 — Config Priority
- [ ] Set conflicting values in CLI flag, context, .sigyn.toml, and global config
- [ ] Verify priority: CLI > context > .sigyn.toml > global

---

## Phase 17: Notifications

### T17.1 — Webhook Configuration
- [ ] `sigyn notification configure -v python-app -i alice --url https://httpbin.org/post --events secret.created,secret.deleted`
- [ ] `sigyn notification list -v python-app -i alice` → shows webhook

### T17.2 — Webhook Test
- [ ] `sigyn notification test -v python-app -i alice` → sends test payload
- [ ] Verify 200 response

### T17.3 — Event Trigger
- [ ] Create a secret → verify webhook fires with `secret.created` event

---

## Phase 18: Edge Cases & Security

### T18.1 — Access After Revocation
- [ ] Revoke Dave from python-app
- [ ] Verify Dave cannot read, write, or list secrets
- [ ] Verify Dave's cached data is inaccessible (envelope re-keyed)

### T18.2 — Invalid Operations
- [ ] Set secret with empty key → error
- [ ] Set secret with invalid key name (spaces, special chars) → error
- [ ] Create vault with name > 64 chars → error
- [ ] Create identity with duplicate name → error or override prompt

### T18.3 — Concurrent Operations
- [ ] Two users set same secret simultaneously
- [ ] Verify CRDT conflict resolution handles gracefully

### T18.4 — Large Secrets
- [ ] Set a secret with 100KB value → verify works
- [ ] Set 500 secrets in one vault → verify list/search performance

### T18.5 — Key Rotation (Identity)
- [ ] `sigyn identity rotate-keys -i alice`
- [ ] Verify new fingerprint
- [ ] Verify all vaults re-sealed with new key
- [ ] Verify old fingerprint no longer works

### T18.6 — Vault Delete Protection
- [ ] `sigyn vault delete -v python-app -i dave` → **DENIED** (not owner)
- [ ] `sigyn vault delete -v python-app -i alice` → prompts confirmation

---

## Phase 19: Doctor & Maintenance

### T19.1 — Health Check
- [ ] `sigyn doctor` → runs all checks
- [ ] Verify checks: identity exists, vaults valid, audit chain OK, sync status

### T19.2 — Shell Completions
- [ ] `sigyn completions bash > /tmp/sigyn.bash`
- [ ] `sigyn completions zsh > /tmp/sigyn.zsh`
- [ ] Verify files generated

---

## Phase 20: Cleanup

### T20.1 — Delete Test Vaults
- [ ] `sigyn vault delete -v python-app -i alice`
- [ ] `sigyn vault delete -v npm-app -i alice`
- [ ] `sigyn vault delete -v shared-infra -i alice`

### T20.2 — Delete Test Identities
- [ ] Delete all 7 test identities

### T20.3 — Archive Test Repos
- [ ] `gh repo delete tonybenoy/sigyn-test-python --yes`
- [ ] `gh repo delete tonybenoy/sigyn-test-vault --yes`
- [ ] `gh repo delete tonybenoy/sigyn-test-npm --yes`

---

## Test Matrix Summary

| Flow | Roles Tested | Vaults Used | Expected Failures |
|------|-------------|-------------|-------------------|
| Identity CRUD | All 7 | — | — |
| Vault creation | Owner | All 3 | — |
| RBAC delegation | Owner, Admin, Manager | python-app | Manager→Admin (denied) |
| Secret CRUD | Owner, Contributor, ReadOnly, Operator | python-app, npm-app | ReadOnly write, Operator read |
| Env operations | Owner, Admin | python-app | — |
| Git sync | Owner, Admin | All 3 | — |
| Run injection | Owner | python-app, npm-app | — |
| Audit | Owner, Auditor | python-app, shared-infra | Auditor write (denied) |
| Rotation | Owner | python-app | — |
| Cascade revoke | Owner | python-app | — |
| Ownership transfer | Owner, Admin | python-app | — |
| Org hierarchy | Owner, Admin | All 3 | — |
| CI/CD | Operator | python-app, npm-app | Operator read (denied) |
| MFA | Owner, Admin | python-app | — |
| Forks | Owner, Contributor | python-app, npm-app | — |
| Notifications | Owner | python-app | — |
| Edge cases | Various | python-app | Multiple denied ops |

---

## Success Criteria

1. **All RBAC boundaries enforced** — no role can exceed its permissions
2. **No plaintext secrets in git** — only encrypted data in remote repos
3. **Audit chain integrity** — `sigyn audit verify` passes for all vaults
4. **Cascade revocation complete** — no orphaned access after cascade revoke
5. **CI/CD injection works** — GitHub Actions successfully receive secrets
6. **Cross-vault operations** — secret copy, org hierarchy linking work
7. **Conflict resolution** — CRDT merge produces correct results
8. **Key rotation safe** — identity key rotation doesn't break existing access
9. **Export formats valid** — all 6 export formats parse correctly
10. **MFA enforcement** — protected actions require TOTP when policy set

---

*Generated for Sigyn v0.11.0 — the serverless, encrypted, peer-to-peer secret manager.*
