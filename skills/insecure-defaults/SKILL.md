---
name: insecure-defaults
description: "James integration of Trail of Bits' insecure defaults detection. Identifies dangerous default configuration values and unsafe initialization patterns."
---

# Insecure Defaults Detection

You are scanning a codebase or configuration for insecure default values and unsafe initialization patterns.

## Workflow

### 1. Configuration File Audit
Scan all config files (`.env`, `.yaml`, `.toml`, `.json`, `.ini`, `*.conf`):

**Weak / Default Credentials**
- Default passwords: `password`, `admin`, `changeme`, `secret`, `1234`, `test`.
- Default API keys or tokens with obvious placeholder values.
- Empty password fields.

**Missing Security Headers (web apps)**
- `Content-Security-Policy` absent.
- `X-Frame-Options` absent.
- `Strict-Transport-Security` absent.
- `X-Content-Type-Options` absent.

**Weak Cryptographic Defaults**
- TLS version set to 1.0 or 1.1 (require 1.2 minimum, prefer 1.3).
- Cipher suites including RC4, DES, 3DES, NULL, EXPORT.
- Certificate validation disabled (`insecureSkipVerify`, `verify=false`, `ssl_verify=false`).

**Dangerous Feature Defaults**
- Debug mode enabled in production config (`DEBUG=true`, `debug: true`).
- Verbose error messages with stack traces exposed to clients.
- Directory listing enabled.
- Unnecessary services enabled by default.

### 2. Code Initialization Audit
Scan source code for unsafe initialization:

**Zeroed / Uninitialized Secrets**
- Cryptographic keys initialized to all-zeros.
- IVs / nonces hardcoded or reused.
- Entropy sources: use of `rand::thread_rng()` vs `OsRng`; `Math.random()` for security purposes.

**Default-Open Network Bindings**
- Servers binding to `0.0.0.0` where `127.0.0.1` is sufficient.
- Wildcard CORS (`Access-Control-Allow-Origin: *`) on sensitive APIs.

**Missing Timeouts**
- HTTP clients with no timeout configured.
- Database connection pools with no idle timeout.
- Session tokens with no expiry.

### 3. Output Format
```
[SEVERITY: High/Medium/Low]
Location: <file:line or config key>
Issue: <type of insecure default>
Current value: <what it is>
Recommended value: <what it should be>
```

### 4. Remediation Checklist
- [ ] No default/placeholder credentials in any config.
- [ ] All security headers present and configured.
- [ ] TLS 1.2+ enforced, weak ciphers disabled.
- [ ] Debug mode disabled in production configs.
- [ ] All network services bind to minimum required interface.
- [ ] All secrets use cryptographically secure random sources.
