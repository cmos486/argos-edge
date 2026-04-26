# Drift detection

Argos's CrowdSec configuration has two surfaces the operator
controls from the panel: the **disabled-scenarios** set and the
**AppSec anomaly thresholds**. Both write a sentinel file the
operator-mediated `setup-appsec.sh` consumes on its next run.
Drift detection (v1.3.27) is the panel-side check that confirms
the running CrowdSec state actually matches what the panel
believes is set.

This page covers what drift means, how the detector works, and
what to do when the UI surfaces an amber banner.

## What drift means in argos

Two ways the panel and the runtime can disagree:

- The panel's `appsec.disabled_scenarios` setting lists scenarios
  X, Y, Z but `cscli scenarios list` still shows them installed.
  Setup-appsec.sh hasn't run yet, or it ran but errored before
  removing them.
- The panel's `appsec.inbound_threshold` is 22 but
  `/etc/crowdsec/appsec-rules/argos-tuning.yaml` still has
  `setvar:tx.inbound_anomaly_score_threshold=15`. Same root
  cause: the regeneration step in setup-appsec.sh didn't run.

Pre-v1.3.27 the panel had a manual "Mark as applied" button that
required the operator to assert "yes I ran the script". That was
operator-trust only — the panel never actually verified the
running state. v1.3.27 replaced it with a real check.

## How the detector works

A goroutine started at panel boot runs every 60 seconds (the
`drift.DefaultInterval`):

1. Reads `appsec.disabled_scenarios` + thresholds from the
   `settings` k/v table.
2. Reads the actual installed scenarios from
   `/crowdsec-state/scenarios/` (the read-only mount of
   `crowdsec_config` introduced in v1.3.25).
3. Reads the actual thresholds from
   `/crowdsec-state/appsec-rules/argos-tuning.yaml` via regex on
   the SecAction lines (`tx.inbound_anomaly_score_threshold=NN`).
4. Compares panel intent vs runtime state.
5. Persists the snapshot to two settings rows:
   `appsec.scenarios.drift_state` and `appsec.tuning.drift_state`,
   each a JSON blob with `drift_detected`, the expected vs actual
   state, and `last_check_at`.

The first tick runs synchronously inside the goroutine so the
snapshot is fresh within seconds of boot, not 60s after.

## Reading the result

```bash
GET /api/security/drift
```

Response shape:

```json
{
  "scenarios": {
    "drift_detected": false,
    "expected_disabled": ["crowdsecurity/foo", "crowdsecurity/bar"],
    "actually_enabled": [],
    "last_check_at": "2026-04-26T18:46:12Z"
  },
  "appsec_tuning": {
    "drift_detected": false,
    "expected_inbound": 15,
    "actual_inbound": 15,
    "expected_outbound": 4,
    "actual_outbound": 4,
    "last_check_at": "2026-04-26T18:46:12Z"
  },
  "last_check_at": "2026-04-26T18:46:12Z"
}
```

The frontend polls this endpoint every 10 seconds while the
`/security` page is open. The 10s polling cadence is tighter
than the 60s server-side tick on purpose — when the operator
runs `setup-appsec.sh` and clears the drift, the UI sees it
within 10s of the next detector tick (so worst-case ~70s after
the script completes).

## When the UI surfaces drift

A top-of-page amber banner appears on `/security` when either
surface has `drift_detected: true`:

> Configuration drift detected. CrowdSec runtime state does
> not match the panel intent. Run
> `docker compose exec crowdsec /setup-appsec.sh`; this banner
> clears automatically once the next drift check observes the
> match (within ~60s of the script finishing).

Per-tab amber dots also appear next to the **Scenarios** and
**AppSec** tab labels when their respective surface is drifted,
so the operator knows which tab to act on.

When `drift_detected: false`, there is no banner and no dot —
no visual noise.

## What to do when drift is detected

```bash
docker compose exec crowdsec /setup-appsec.sh
```

The script:

1. Reads the panel-managed sentinels under `/shared/`.
2. Removes panel-disabled scenarios via `cscli scenarios remove
   --force`.
3. Regenerates `argos-tuning.yaml` with the operator-set
   thresholds.
4. Reloads CrowdSec via `SIGHUP` (or `kill -TERM 1` for the
   full-restart paths added in v1.3.29 / v1.3.33).

Within 60s of the script finishing, the next drift detector
tick observes the synced state and clears the banner. No
operator click required to dismiss it.

## What this replaces

The v1.3.25 "Mark as applied" buttons + the
`appsec.scenarios.last_applied_at` /
`appsec.tuning.last_applied_at` settings rows were removed in
v1.3.27. The mark-applied API endpoints
(`POST /api/security/scenarios/mark-applied` +
`/appsec-tuning/mark-applied`) are gone. Migration 031 deletes
the deprecated settings rows.

## Limitations

- The detector's source of truth is the read-only
  `/crowdsec-state` mount. If that mount is missing (dev panel
  running outside docker), the detector returns
  `drift_detected: false` for both surfaces — it has no way to
  verify either direction.
- The threshold regex matches `tx.inbound_anomaly_score_threshold=NN`
  in the regenerated argos-tuning.yaml. If a future
  setup-appsec.sh refactor changes that line shape, the detector
  silently always-detects-drift. Smoke
  (`scripts/smoke/drift-detection.sh`) is the regression gate.
- The detector reports drift but does not auto-remediate.
  Auto-running setup-appsec.sh from the panel would couple the
  panel to docker-exec privileges; the operator-mediated
  reload is the documented contract.

## Related

- [Scenarios management](crowdsec.md#scenarios-management) — the
  surface that produces the `appsec.disabled_scenarios` setting.
- [AppSec](appsec.md) — the WAF-inline surface; v1.3.25's
  threshold tuning UI produces the threshold settings the
  detector compares.
- [Reconciler health checks](../architecture/components.md#reconcilers-verify-what) —
  drift detection is one of three reconciler surfaces in the
  panel container.
- `scripts/smoke/drift-detection.sh` — 12-phase EFFECT smoke for
  the full lifecycle.
