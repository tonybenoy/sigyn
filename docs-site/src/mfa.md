# Multi-Factor Authentication (MFA)

Sigyn supports optional TOTP-based multi-factor authentication to add a second layer
of security beyond the identity passphrase.

## How It Works

1. **Enrollment** -- `sigyn mfa setup` generates a TOTP secret, displays an
   `otpauth://` URI for your authenticator app, and produces 8 single-use backup
   codes.
2. **Policy enforcement** -- when `require_mfa: true` is set on global or per-member
   constraints, the policy engine requires MFA verification before granting access.
3. **Session grace period** -- after successful verification, a session is created
   that lasts 1 hour by default, so you aren't re-prompted on every operation.
4. **Backup codes** -- if you lose access to your authenticator, any of the 8 backup
   codes can be used once in place of a TOTP code.

## Enrollment

```bash
sigyn mfa setup -i alice
```

This will:

- Generate a TOTP secret and display a **QR code** in the terminal for scanning.
- The base32 secret is also printed for manual entry if needed.
- Ask you to enter a code from your authenticator app to verify setup.
- Print 8 backup codes. **Save these in a secure location.**

## Checking Status

```bash
sigyn mfa status -i alice
```

Shows whether MFA is enrolled, when it was enabled, how many backup codes remain,
and whether a session is currently active.

## Generating New Backup Codes

```bash
sigyn mfa backup -i alice
```

Requires a valid TOTP code. Generates a fresh set of 8 backup codes and invalidates
all previous ones.

## Disabling MFA

```bash
sigyn mfa disable -i alice
```

Requires a valid TOTP code or backup code to confirm. Removes the `.mfa` file and
clears any active session.

## Enforcing MFA via Policy

### Global Enforcement

Set `require_mfa: true` in the vault's `global_constraints` to require MFA for all
non-owner members:

```json
{
  "global_constraints": {
    "require_mfa": true,
    "time_windows": [],
    "ip_allowlist": [],
    "expires_at": null
  }
}
```

### Per-Member Enforcement

Set `require_mfa: true` on an individual member's constraints to require MFA only
for that member:

```json
{
  "constraints": {
    "require_mfa": true,
    "time_windows": [],
    "ip_allowlist": [],
    "expires_at": null
  }
}
```

## Cryptographic Details

- **MFA state encryption**: the `.mfa` file is encrypted with ChaCha20-Poly1305
  using a key derived via HKDF-SHA256 from the identity's X25519 private key with
  info context `b"mfa-state"`. No additional passphrase is needed -- unlocking the
  identity is sufficient.
- **Backup code storage**: codes are hashed with blake3 before being stored. Each
  code is consumed (removed) on use.
- **Session tamper detection**: session files contain a blake3 keyed hash (using the
  identity fingerprint as key material) over the verification timestamp. Tampered
  sessions are rejected.

## Related Documentation

- [Security Model](security.md) -- full cryptographic details and threat model
- [CLI Reference](cli-reference.md) -- complete command reference
- [Getting Started](getting-started.md) -- initial setup including MFA enrollment
