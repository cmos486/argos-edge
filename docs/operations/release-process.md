# Release process

argos-edge ships from `main`. Tagging `v<x>.<y>.<z>` on `main`
triggers the `release.yml` workflow which auto-publishes a
GitHub release sourced from `docs/release-notes/<tag>.md`. This
page documents the human steps before the tag push and the
automation that takes over after.

## The tag-to-release pipeline

```
local: edit code, write release notes, commit, push to main
       |
       v
local: git tag v1.x.y && git push origin v1.x.y
       |
       v
GitHub Actions: release.yml workflow fires
                |
                v
        - resolve docs/release-notes/v1.x.y.md
        - softprops/action-gh-release publishes
                |
                v
GitHub: release object visible at /releases/tag/v1.x.y
        with rendered Markdown body
```

`release.yml` lives at `.github/workflows/release.yml`. It
triggers on tag pushes matching `v[0-9]+.*` and uses
`softprops/action-gh-release@v2` with the workflow's
`GITHUB_TOKEN` and `permissions: contents: write`.

## Pre-tag checklist

Before pushing a release tag, every release author runs through:

1. Working tree is clean on `main`.
2. `docs/release-notes/v<version>.md` exists with the
   release narrative. Pre-release variants live under
   `docs/release-notes/prereleases/v<version>-<label>.md`.
3. `CHANGELOG.md` has the new version block.
4. `mkdocs.yml` nav lists the new release-notes page (so the
   docs portal renders it -- mkdocs --strict catches missing
   entries).
5. `backend/cmd/argos/main.go` `argosVersion` and
   `frontend/package.json` `version` are bumped (or
   intentionally not bumped for tooling-only patches like the
   v1.3.27.1 release-publishing automation -- document the
   intent in the release notes).
6. `./scripts/check-no-personal-data.sh` clean.
7. `mkdocs build --strict` clean.
8. The release's smoke gate (live-stack `scripts/smoke/*.sh`)
   PASSES against the operator's prod stack -- working
   agreement v1.3.20+ requires this for any release that
   touches CrowdSec / Caddy / runtime behaviour.
9. Commit and push to `main`.

## Tagging

```bash
git tag -a v1.3.X -m "v1.3.X -- short title

Multi-line body summarising the scope. The auto-published
release uses docs/release-notes/v1.3.X.md as the body, so
this annotated-tag message can stay short."

git push origin v1.3.X
```

The workflow fires within ~30s of the tag push appearing on
GitHub. Watch progress at
`https://github.com/<owner>/<repo>/actions`. On success the
release appears at `/releases/tag/v1.3.X`.

## Pre-release tags

Tags containing a `-` (e.g. `v1.4.0-alpha`, `v1.5.0-rc1`) are
flagged `prerelease=true` automatically. The workflow looks for
the body at `docs/release-notes/prereleases/<tag>.md` rather
than the top-level dir. This matches the existing mkdocs nav
split (`Pre-releases:` subgroup).

## What the workflow won't do

- **Retroactively publish missing releases.** The trigger is
  push-only on the tag ref. If `v1.3.27` was tagged before the
  workflow shipped and never got a release, the workflow will
  not pick it up on the next unrelated push. Backfill manually
  with `gh release create` -- see the next section.
- **Build or upload artefacts.** argos ships as docker images
  built locally + source on GitHub. No binaries are attached.
  The workflow's `fail_on_unmatched_files: false` makes this
  explicit.
- **Trigger downstream deploys.** The operator pulls + runs
  `make deploy-prod` manually after a tag (per
  `docs/operations/deployment.md`). No automated deploy hook.

## Backfilling a pre-existing tag

If the workflow was added after `v1.3.X` was already tagged,
publish the missing release manually with the GitHub CLI:

```bash
gh release create v1.3.X \
    --title "v1.3.X" \
    --notes-file docs/release-notes/v1.3.X.md \
    --verify-tag
```

Add `--prerelease` for tags with a `-` suffix.
`--verify-tag` makes the command fail if the tag does not
already exist remotely (defends against accidental tag
creation via the release command).

This path requires the operator to have `gh` CLI installed +
authenticated locally (`gh auth login`).

## Troubleshooting

### The workflow ran but the release body is empty

The release-notes file at the tag commit was missing or
unreadable. The workflow's `Resolve release notes path` step
fails with `::error::` and the action stops before publish, so
this state should be a hard fail rather than a silent
empty-body. If you see an empty release body, check that the
file existed at the tag commit (not just on `main` -- the
workflow checks out the tag, not `HEAD`).

### "Resource not accessible by integration" when publishing

The workflow's `permissions: contents: write` block was
missing or got dropped. Compare against the existing
`docs.yml` workflow which has the same block for `gh-pages`
deploy.

### softprops/action-gh-release version pinning

The workflow uses `@v2` (major-version float). To pin to a
SHA for stricter supply-chain hygiene, swap `@v2` for the
exact commit SHA from
[the action's tags](https://github.com/softprops/action-gh-release/tags).
Major-version pinning is the homelab default.
