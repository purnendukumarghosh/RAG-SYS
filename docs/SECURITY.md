# Security model

## What NimbusVPN protects against

| Threat | Mitigation |
|---|---|
| Eavesdropping or tampering on untrusted networks (public Wi-Fi, ISP) | WireGuard: Curve25519 key exchange, ChaCha20-Poly1305 AEAD, BLAKE2s; perfect forward secrecy with key rotation every 2 minutes |
| "Harvest now, decrypt later" by a future quantum attacker | A random 256-bit **preshared key per device** is mixed into the handshake (Noise `psk2`) |
| Traffic or DNS leaking outside the tunnel | Full-tunnel `AllowedIPs = 0.0.0.0/0, ::/0` covers both IP families; DNS servers pushed in the profile. For a kill-switch, use the client's option (WireGuard for Windows blocks untunneled traffic for full-tunnel profiles; Android/iOS offer "always-on VPN") |
| Lateral movement between VPN users | Client isolation: `wg0 → wg0` forwarding dropped |
| SSRF / credential theft via the cloud metadata service | `169.254.0.0/16` blocked for tunnel traffic; IMDSv2 required with hop limit 1 (Terraform) |
| Stolen or lost device | Disable, delete or rotate a device; the change reaches the kernel immediately via `wg syncconf` |
| Forgotten temporary access | Device expiry; expired peers leave the config within one reconcile interval |
| Password guessing | Argon2id hashes; account lockout after 5 failures; per-IP rate limit; unknown usernames get the same responses and lockout, so accounts cannot be enumerated |
| Phished or reused password | TOTP two-factor auth (RFC 6238), ±1 step drift, codes cannot be replayed |
| Stolen session token | 60-minute expiry; logout, password change, role change or disable revokes all tokens (`token_version`) |
| XSS / clickjacking in the dashboard | CSP `script-src 'self'` with no inline scripts; all user data inserted with `textContent`; `frame-ancestors 'none'`; `X-Frame-Options: DENY` |
| Config-file injection via device names | Names restricted to a safe character set at the API boundary; the renderer strips non-printables too |
| Insecure direct object references | Device lookups check ownership and return `404` for other users' devices |
| Theft of the database or disk backup | Private keys of clients are **never stored**; preshared keys, the server key and TOTP seeds are encrypted with AES-256-GCM under a key derived from `NIMBUS_SECRET_KEY` (not on disk); each ciphertext is bound to its record; the plaintext `wg0.conf` lives on tmpfs |
| Container breakout impact | Only `NET_ADMIN` and `NET_RAW` capabilities, `no-new-privileges`, API port not published |
| Silent misuse | Audit log for sign-ins, failures, device and user changes, with actor and source IP |

## Key handling

```
NIMBUS_SECRET_KEY (environment only)
   ├─ HKDF("jwt-signing")         → HS256 key for access tokens
   └─ HKDF("at-rest-encryption")  → AES-256-GCM key
         ├─ server private key    (context "server-private-key")  → /data/server_key.enc
         ├─ device preshared keys (context "psk:<device public key>") → database
         └─ TOTP seeds            (context "totp:<user id>")        → database
```

- **Server-generated device keys:** generated in memory, returned once in the creation
  response (config + QR code), then discarded. The dashboard clears them from the page when
  the dialog closes.
- **Bring your own key:** the device runs `wg genkey | wg pubkey` and registers only the
  public key. The private key never leaves the device.

## What it does *not* protect against

- **A compromised server.** Whoever controls the VM can see decrypted traffic as it leaves
  the tunnel, as with any VPN. Choose a provider and region you trust, and keep the host
  patched (`install.sh --harden` enables unattended security upgrades).
- **Loss of `NIMBUS_SECRET_KEY`.** Without it the encrypted preshared keys and server key
  cannot be decrypted. Back it up separately from the data volume. Rotating it currently
  means re-issuing device profiles.
- **Anonymity.** A VPN moves trust from your network to the VPN server. It does not make you
  anonymous to the sites you visit.
- **Bootstrap credentials.** With Terraform, the initial admin password is in the instance's
  user data. Change it right after first sign-in and enable 2FA. `install.sh` deletes it from
  `.env` once the admin account exists.
- **Multi-instance rate limiting.** The per-IP limiter is in-memory, so it applies to one
  process. Account lockout is stored in the database and applies everywhere.

## Hardening checklist

- [ ] Change the initial admin password; enable TOTP for every admin.
- [ ] Use a real domain (not sslip.io) so certificates and bookmarks stay stable.
- [ ] Restrict SSH to your IP (`ssh_allowed_cidrs`) or close it entirely.
- [ ] Back up `NIMBUS_SECRET_KEY` and the `nimbus-data` volume (separately).
- [ ] Set device expiry for guests and contractors.
- [ ] Review the audit log regularly (`/api/admin/audit?action=login.failed`).
