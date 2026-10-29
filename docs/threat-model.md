# Threat model

Assets: user accounts, the session tokens that stand in for them, and the secrets that sign or protect those tokens and codes.

Attacker types considered:
- **Remote attacker** who can call the login API as often as they like.
- **Attacker with a leaked database or backup**, who has the SQLite file but not the environment secrets.
- **Attacker with a stolen token**, e.g. from a compromised browser or a log file.
- **Shoulder surfer** who sees one OTP or TOTP code.

| Threat | Control | Where | Tested by |
|---|---|---|---|
| Online password guessing | 5 failures lock the account for 5 minutes; counter updated atomically | `passwords.py` | `online_guessing`, `test_lockout_after_max_attempts` |
| Offline cracking of leaked password hashes | bcrypt cost 12, unique salt per user | `passwords.py` | `test_password_is_stored_as_bcrypt`, `test_same_password_gets_different_salts` |
| Weak or reused passwords | 12-72 characters, common-password list, can't contain the username | `passwords.py` | `test_policy_rejects` |
| Username enumeration from error text | One message for unknown user, wrong password, over-long password and locked account | `passwords.py` | `enumeration_by_message`, `test_same_error_for_every_failure` |
| Username enumeration from response time | Unknown users and locked accounts still run bcrypt against a dummy hash | `passwords.py` | `enumeration_by_timing`, `test_unknown_user_still_runs_bcrypt` |
| Guessing the OTP | 3 attempts, then the code and the login challenge are destroyed; 45 s lifetime | `otp.py`, `service.py` | `otp_guessing`, `test_three_wrong_codes_kill_the_challenge` |
| Replaying a used OTP | Deleted on first successful use | `otp.py` | `otp_replay`, `test_code_works_once` |
| Leaked OTP table | Stored as HMAC with a key that isn't in the database (plain SHA-256 cracks in ~1 s) | `otp.py` | `offline_otp_crack`, `test_code_is_stored_as_hmac_not_sha256` |
| Timing attack on code comparison | `hmac.compare_digest` | `otp.py`, `totp.py` | - |
| Skipping the password step | Second factor only accepted against a live challenge created by a correct password | `service.py` | `skip_password_step`, `test_second_factor_needs_a_password_challenge` |
| Replaying a seen TOTP code | Last accepted step stored; only newer steps accepted | `totp.py` | `totp_replay`, `test_totp_code_cannot_be_replayed` |
| Forged token (`alg: none`, algorithm confusion) | Algorithm list pinned to HS256 | `tokens.py` | `jwt_alg_none` |
| Forged token (guessed or leaked secret) | Secret from env, 32+ bytes required, never in source | `config.py` | `jwt_weak_key`, `test_settings_require_secrets` |
| Modified token payload | HMAC signature over header and payload | `tokens.py` | `jwt_tamper` |
| Token meant for another service | `iss` and `aud` required and checked | `tokens.py` | `jwt_wrong_audience` |
| Stolen token used after logout | `jti` checked against the server-side store on every request | `tokens.py` | `revoked_token` |
| Many stolen sessions after a compromise | `revoke_all(username)` | `tokens.py` | `stolen_tokens_after_reset` |
| Old token reused | 5 minute lifetime, `exp`/`nbf`/`iat` checked against the service clock | `tokens.py` | `expired_token`, `test_expired_rejected` |
| Secrets in logs | Codes, passwords and tokens are never logged; tokens by `jti` only | `audit.py` | `test_nothing_secret_in_logs` |

## Known gaps

- **Lockout as denial of service.** Anyone who knows a username can keep that account locked. Fix: per-IP and per-account rate limiting with backoff, not a hard lock.
- **TOTP secrets unencrypted at rest.** They need the same treatment as the OTP key: encrypt with a key from a secrets manager.
- **No breached-password check.** The common-password list is tiny. A real system should check new passwords against Have I Been Pwned's k-anonymity range API.
- **Code delivery is simulated.** Email or SMS delivery brings its own risks (SIM swap, mailbox compromise). TOTP or passkeys avoid them.
- **Single-node store.** Revocation works because every request hits the same SQLite file. With several API servers, the revocation list needs to be shared, for example in Redis.
