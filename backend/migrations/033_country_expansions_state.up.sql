-- v1.3.33: country_ban_expansions gains a state column for the
-- new reconciler health check.
--
-- States:
--   active   -- panel cidr_count matches LAPI within tolerance.
--              Default for existing rows + new INSERTs.
--   drifted  -- last reconciler tick observed > 1% divergence
--              between panel cidr_count and the current LAPI
--              decision count for argos-country-<CC> origin.
--              Surfaces in the UI like the v1.3.27 drift detector
--              for scenarios; operator decides whether to re-emit.
--
-- Why this column exists: v1.3.31 dogfood revealed silent
-- divergence when CrowdSec's flush.max_items: 5000 cap forced
-- a cascade flush of older argos-country-* alerts (and their
-- cascade-deleted decisions). v1.3.33's AddRangeDecisions
-- shape restructure prevents the cause; the state column +
-- reconciler are the defensive layer that catches any residual
-- drift (LAPI restart with stale snapshot, manual cscli
-- decisions delete, future shape changes).
--
-- Idempotent: pre-v1.3.33 rows default to 'active'.

ALTER TABLE country_ban_expansions
    ADD COLUMN state TEXT NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'drifted'));

CREATE INDEX idx_country_ban_expansions_state
    ON country_ban_expansions(state);
