# Phase 1 test DNS

Phase 1 (hosts + Let's Encrypt via Cloudflare DNS-01) needs a real DNS name
that resolves to the LXC running argos. The record is managed manually;
argos-edge itself does not touch zone contents (only ACME challenge TXTs
via Caddy's cloudflare-dns provider).

Record provisioned for testing:

    app.example.com  A  192.0.2.167  (proxied=false, ttl=auto)

Created with the Cloudflare v4 API using `CLOUDFLARE_API_TOKEN` (token must
have Zone:DNS:Edit on `example.com`). Propagation verified via
`dig +short app.example.com @1.1.1.1`.

No code change: this file only records the manual operation for future
reference. If a new test host is needed, repeat the same API call with a
different subdomain.
