# Phase 1 test DNS

Phase 1 (hosts + Let's Encrypt via Cloudflare DNS-01) needs a real DNS name
that resolves to the LXC running argos. The record is managed manually;
argos-edge itself does not touch zone contents (only ACME challenge TXTs
via Caddy's cloudflare-dns provider).

Record provisioned for testing:

    argos-test.cmos486.es  A  192.168.3.167  (proxied=false, ttl=auto)

Created with the Cloudflare v4 API using `CLOUDFLARE_API_TOKEN` (token must
have Zone:DNS:Edit on `cmos486.es`). Propagation verified via
`dig +short argos-test.cmos486.es @1.1.1.1`.

No code change: this file only records the manual operation for future
reference. If a new test host is needed, repeat the same API call with a
different subdomain.
