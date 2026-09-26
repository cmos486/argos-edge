-- v1.3.42.0: hourly rollup of log_entries for the long ranges.
--
-- log_hourly holds, per closed UTC hour, source, host and status
-- class, the request count, bytes out, duration sum / max, exact
-- per-group percentiles, an 8-bucket duration histogram and the
-- 403 / 429 / level=error counters the security cards read.
-- log_hourly_paths holds the 50 busiest paths per host per hour.
--
-- host_id is NOT NULL DEFAULT 0 (0 = no host) because a NULL inside
-- a PRIMARY KEY never equals itself in SQLite and INSERT OR REPLACE
-- would append duplicates instead of replacing.
--
-- The fill job (internal/logs/rollup.go) writes closed hours only,
-- idempotently; the hour in progress is read live from log_entries.
-- Nothing on log_entries changes: the four load-bearing indexes
-- referenced with INDEXED BY are untouched.

CREATE TABLE log_hourly (
  hour          TIMESTAMP NOT NULL,
  source        TEXT      NOT NULL,
  host_id       INTEGER   NOT NULL DEFAULT 0,
  status_class  INTEGER   NOT NULL DEFAULT 0,
  requests      INTEGER   NOT NULL,
  bytes_out     INTEGER   NOT NULL DEFAULT 0,
  dur_sum_ms    INTEGER   NOT NULL DEFAULT 0,
  dur_max_ms    INTEGER   NOT NULL DEFAULT 0,
  dur_p50_ms    INTEGER,
  dur_p95_ms    INTEGER,
  dur_p99_ms    INTEGER,
  dur_h0        INTEGER   NOT NULL DEFAULT 0,
  dur_h1        INTEGER   NOT NULL DEFAULT 0,
  dur_h2        INTEGER   NOT NULL DEFAULT 0,
  dur_h3        INTEGER   NOT NULL DEFAULT 0,
  dur_h4        INTEGER   NOT NULL DEFAULT 0,
  dur_h5        INTEGER   NOT NULL DEFAULT 0,
  dur_h6        INTEGER   NOT NULL DEFAULT 0,
  dur_h7        INTEGER   NOT NULL DEFAULT 0,
  forbidden     INTEGER   NOT NULL DEFAULT 0,
  rate_limited  INTEGER   NOT NULL DEFAULT 0,
  errors        INTEGER   NOT NULL DEFAULT 0,
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (hour, source, host_id, status_class)
);

CREATE TABLE log_hourly_paths (
  hour          TIMESTAMP NOT NULL,
  host_id       INTEGER   NOT NULL DEFAULT 0,
  path          TEXT      NOT NULL,
  requests      INTEGER   NOT NULL,
  bytes_out     INTEGER   NOT NULL DEFAULT 0,
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (hour, host_id, path)
);

CREATE INDEX idx_log_hourly_source_hour ON log_hourly (source, hour);
CREATE INDEX idx_log_hourly_paths_hour  ON log_hourly_paths (hour);
