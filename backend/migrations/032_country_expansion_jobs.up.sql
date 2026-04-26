-- v1.3.31: country_expansion_jobs is the progress-shadow table
-- for the async background worker that wraps Expander.Ban.
--
-- One row per expansion attempt. The existing
-- country_ban_expansions row is still the source of truth for
-- "is country X currently banned" -- a job row is the transient
-- progress + error tracker, written on submit and updated as
-- the worker proceeds chunk-by-chunk.
--
-- States:
--   pending   -- submitted, not picked up by the worker yet
--                (only relevant when the worker is busy or the
--                panel just booted and the global mutex is held)
--   running   -- worker is mid-expansion; chunks_done updates
--                live as each chunk POSTs to LAPI
--   completed -- all chunks processed; cidr_committed reflects
--                the LAPI-accepted total (failed chunks count
--                in chunks_total but not cidr_committed)
--   failed    -- panel-restarted recovery (boot-time reconcile)
--                or expander returned an error before any chunk
--                committed
--
-- Boot-time recovery (v1.3.31): pending + running rows are
-- transitioned to failed with error_message='panel restarted'.
-- The goroutine that owned them is gone; the operator can re-
-- submit the expansion.

CREATE TABLE country_expansion_jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    country_code    TEXT NOT NULL,
    state           TEXT NOT NULL CHECK (state IN
                       ('pending', 'running', 'completed', 'failed')),
    chunks_total    INTEGER NOT NULL DEFAULT 0,
    chunks_done     INTEGER NOT NULL DEFAULT 0,
    chunks_failed   INTEGER NOT NULL DEFAULT 0,
    cidr_committed  INTEGER NOT NULL DEFAULT 0,
    requested_count INTEGER NOT NULL DEFAULT 0,
    duration        TEXT NOT NULL DEFAULT '',
    reason          TEXT NOT NULL DEFAULT '',
    error_message   TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at      TIMESTAMP,
    completed_at    TIMESTAMP,
    created_by      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_country_expansion_jobs_country
    ON country_expansion_jobs(country_code, created_at DESC);

CREATE INDEX idx_country_expansion_jobs_state
    ON country_expansion_jobs(state);
