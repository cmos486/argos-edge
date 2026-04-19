-- ForwardAuth per-host toggle. auth_required=1 means Caddy must
-- round-trip every request through /api/auth/forward before the
-- reverse_proxy to the upstream fires (Phase D wires the Caddy side).
--
-- Default 0 keeps every existing host publicly reachable (same
-- behavior as pre-019). Flipping the flag on one host does NOT
-- affect any other host -- scope is strictly per-row.

ALTER TABLE hosts ADD COLUMN auth_required INTEGER NOT NULL DEFAULT 0;
