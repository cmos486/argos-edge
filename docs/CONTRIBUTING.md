# Contributing

argos-edge is a solo-maintained homelab project. This document is
small on purpose: it captures only the rules that have already been
broken and resulted in real fixes, not a wishlist of conventions.

## Operator data sanitization

The repo is public. Smoke tests, walkthroughs, screenshots, code
examples, and release notes are committed verbatim from the
maintainer's own deployment, which means it is easy to accidentally
publish:

- internal LAN IP addresses
- private homelab subdomain names (which reveal what services run
  inside the maintainer's network)
- personal email addresses or GitHub-attributable handles in places
  other than commit authorship

The v1.3.15 release rolled back a session's worth of leaks; this
section codifies the prevention.

### Use these placeholders

| What | Placeholder | RFC |
|---|---|---|
| Public domain | `example.com`, `*.example.com` | [RFC 2606](https://datatracker.ietf.org/doc/html/rfc2606) |
| LAN / private IP | `192.0.2.X`, `198.51.100.X`, `203.0.113.X` | [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) |
| Email | `ops@example.com`, `admin@example.com`, `user@example.com` | RFC 2606 |

### Suggested service-name pattern for examples

When walking through a multi-service deployment, reach for generic
nouns + `example.com`:

```
home.example.com         (Home Assistant)
media.example.com        (Jellyfin / Plex)
photos.example.com       (Immich / Photoprism)
storage.example.com      (Nextcloud)
network-controller.example.com   (UniFi)
notes.example.com        (Joplin / hedgedoc)
```

The exact mapping is whatever makes the example readable. Avoid
real-sounding subdomains that match a fingerprint of the maintainer's
actual setup.

### What stays in tact (intentionally)

- The Go module path `github.com/cmos486/argos-edge` -- this is the
  actual public repo URL; it appears in every Go import and in
  README badges by design.
- `cmos486.github.io` -- the published docs portal URL.
- `mkdocs.yml site_url`, `repo_url`, `repo_name`, `site_author` --
  the literal published-site config.
- Maintainer GitHub handle in shield badges and "edit this page"
  links.
- Commit author lines (history is immutable; rewriting tags would
  break already-published GitHub releases).

These references are equivalent to writing "the maintainer of this
repo is the GitHub user `cmos486`" -- public information by virtue
of how anyone reaches the repo.

### Enforcement

The `scripts/check-no-personal-data.sh` guardrail scans for the
three regression patterns and exits non-zero if any are found:

```sh
./scripts/check-no-personal-data.sh
```

Run it locally before opening a PR. CI runs the same script on every
push.

If a hit is a false positive (it shouldn't be -- the patterns are
deliberately narrow) update the script with a documented exception
alongside the new entry, not a `# noqa`-style ignore comment in the
source line.
