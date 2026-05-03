# Security policy

argos-edge is a security-adjacent project (reverse proxy +
WAF + AppSec + SSO). Vulnerability reports are taken
seriously; this document spells out what to report, where
to send it, and what to expect back.

## Supported versions

argos-edge is solo-maintained. Security fixes ship against:

| Version | Status |
|---|---|
| Latest tagged release on `main` | ✅ Supported |
| Previous minor (latest of `1.3.x` if current is `1.3.y`) | ✅ Supported on best-effort basis |
| Older releases | ❌ Not supported — upgrade to latest |

The latest release is always at
[github.com/cmos486/argos-edge/releases](https://github.com/cmos486/argos-edge/releases).
Tooling-only patches (e.g. `1.3.36.X` capture automation)
inherit the security posture of the panel binary they
target.

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.**
Public reports give attackers a head start on un-patched
deployments.

**Preferred**: GitHub Security Advisories private vulnerability
reporting at
[github.com/cmos486/argos-edge/security/advisories/new](https://github.com/cmos486/argos-edge/security/advisories/new).
This routes the report directly to the maintainer in a
private channel and tracks coordination metadata
(severity, affected versions, patch ETA) in one place.

**Alternative**: open a GitHub issue with the title
"Security report — coordination needed" and **no technical
detail**. The maintainer will respond with a private
channel.

In your report please include:

- Affected version(s) — output of `argos version` if
  available, or the docker image tag
- Panel mode in use (`lan` / `behind_caddy`) — relevant
  for surface-area scoping
- Steps to reproduce, ideally against a fresh
  `docker compose up -d` install
- Impact assessment — what an attacker can do, and
  whether authentication or operator-mediated input is
  required
- Suggested fix or mitigation if you have one (optional)

## Response

This is a maintainer-time-permitting project. I aim to
acknowledge reports within a reasonable timeframe and
triage based on severity, but cannot commit to specific
response SLAs. Active exploitation in the wild will be
prioritized.

For coordinated disclosure, the industry-standard 90-day
window applies as a default ceiling, with adjustments
based on severity and exploitation status. If the
vulnerability is being actively exploited against
argos-edge deployments, I may ship a fix and disclose
sooner to protect users.

If you do not hear back after a couple of weeks, please
assume the report did not reach me and re-send via a
different channel (e.g. a GitHub issue with the
no-technical-detail title from the previous section).

## Scope

**In scope** (argos-edge codebase):

- Panel binary (Go backend + embedded React SPA)
- Docker compose stack as published in this repo
- CLI subcommands (`argos backup`, `argos restore`,
  `argos reset-password`, etc.)
- HTTP API (`/api/...`) authentication and authorization
- Caddyfile bootstrap, CrowdSec acquisition + profiles
  config, AppSec rules — as committed in this repo
- Credential / secret handling
  (`ARGOS_MASTER_KEY` / AES-GCM-encrypted DB columns)
- TOTP enrollment + session lifecycle
- ForwardAuth path, OIDC sign-in flow
- WAF / AppSec rule bypass via panel-side input
  validation gaps
- Drift detection / reconciler false negatives that
  could mask a real bypass

**Out of scope**:

- Upstream Caddy 2 vulnerabilities — report to the
  [Caddy project](https://github.com/caddyserver/caddy/security)
- Upstream CrowdSec vulnerabilities (LAPI, AppSec
  component, bouncer plugin) — report to the
  [CrowdSec project](https://github.com/crowdsecurity/crowdsec/security)
- Upstream Coraza / OWASP CRS rule-set issues — report
  to [Coraza](https://github.com/corazawaf/coraza/security)
  / [OWASP CRS](https://github.com/coreruleset/coreruleset/security)
- Self-signed cert warnings during `lan` mode HTTP-only
  panel access (intentional; documented in
  `docs/getting-started/installation.md`)
- DoS by the operator against their own homelab stack
- Issues only reproducible on heavily-modified forks
- Theoretical attacks requiring privileged container
  access (if you already have root in the panel
  container, you have already won)
- Social-engineering attacks against the maintainer

If your report falls in the out-of-scope list above, the
appropriate upstream project is the right destination —
argos-edge cannot fix issues in code it does not own.
The maintainer is happy to confirm whether a report is in
scope before you spend effort writing it up; ping via the
no-detail GitHub issue first if unsure.

## Hall of fame

_See [Security advisories](https://github.com/cmos486/argos-edge/security/advisories) for the public record._
