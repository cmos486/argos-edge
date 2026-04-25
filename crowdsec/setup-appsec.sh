#!/bin/sh
# setup-appsec.sh -- idempotent installer for argos' AppSec (WAF inline)
# layer. Performs three steps in order:
#
#   1. install crowdsecurity/{appsec-virtual-patching,appsec-generic-rules,
#      appsec-crs} collections. Re-running is a no-op (--force is idempotent
#      on already-installed hub items).
#   2. copy the AppSec acquis snippet from the mounted source
#      /setup/acquis.d/appsec.yaml into the durable config volume at
#      /etc/crowdsec/acquis.d/appsec.yaml. This decouples the file from
#      the compose mount so a fresh crowdsec boot does NOT try to load
#      appsec before the collections are present -- which would crash-
#      loop the container ("no appsec-config found for ...").
#   3. SIGHUP the crowdsec process so the new acquis is picked up
#      without restarting the container. LAPI stays up, the bouncer
#      keeps working, a ~1s window sees no AppSec listener.
#
# Usage (inside the crowdsec container):
#   docker compose exec crowdsec /setup-appsec.sh
#
# Exit codes: 0 on success, non-zero on a genuine failure (missing
# binary, install error, copy failure).

set -eu

log() { printf '[setup-appsec] %s\n' "$*"; }

# Two acquis files, two listeners, two appsec-configs:
#   7422  crowdsecurity/appsec-default  (vendor, ban)         -> block mode
#   7423  argos/appsec-detect           (local, allow)        -> detect mode
# Caddy picks the URL at runtime via /load; crowdsec just serves both.
SRC_ACQUIS_BLOCK=/setup/acquis.d/appsec.yaml
DST_ACQUIS_BLOCK=/etc/crowdsec/acquis.d/appsec.yaml
SRC_ACQUIS_DETECT=/setup/acquis.d/appsec-detect.yaml
DST_ACQUIS_DETECT=/etc/crowdsec/acquis.d/appsec-detect.yaml

# v1.3.10 introduced argos-appsec-detect.yaml (detect mode local
# config). v1.3.12 introduces argos-appsec-block.yaml so block
# mode uses a local config too -- the vendor crowdsecurity/appsec-default
# omits CRS, so block mode pre-v1.3.12 never matched generic OWASP
# attack classes. Both files live in the same shared volume; the
# acquis files reference them by `name:` (argos/appsec-detect and
# argos/appsec-block).
SRC_CONFIG_DETECT=/setup/appsec-configs/argos-appsec-detect.yaml
DST_CONFIG_DETECT=/etc/crowdsec/appsec-configs/argos-appsec-detect.yaml
SRC_CONFIG_BLOCK=/setup/appsec-configs/argos-appsec-block.yaml
DST_CONFIG_BLOCK=/etc/crowdsec/appsec-configs/argos-appsec-block.yaml

require_cscli() {
    command -v cscli >/dev/null 2>&1 || {
        echo "cscli not found; are you running this inside the crowdsec container?" >&2
        exit 1
    }
}

install_collection() {
    name="$1"
    # --force is a no-op when the collection is already up-to-date, and
    # re-installs (same content) when it isn't. Safe for repeats.
    log "installing/refreshing collection: ${name}"
    cscli collections install "${name}" --force
}

fix_lapi_credentials() {
    # Crowdsec auto-generates /etc/crowdsec/local_api_credentials.yaml
    # from config.yaml.local on first boot. Because argos ships
    # listen_uri: 0.0.0.0:8081 (so the bouncer in the argos_net bridge
    # can reach LAPI), that URL gets copied into the credentials file.
    # AppSec's bouncer-key validator reads the same credentials to
    # dial back into LAPI -- and dialing 0.0.0.0 from inside the
    # container fails. Rewriting to 127.0.0.1 makes the in-process
    # client loop back cleanly without affecting external callers.
    f=/etc/crowdsec/local_api_credentials.yaml
    if [ ! -f "${f}" ]; then
        return 0
    fi
    if grep -q '0.0.0.0' "${f}"; then
        log "rewriting ${f} to use 127.0.0.1 (was 0.0.0.0)"
        sed -i 's|0\.0\.0\.0|127.0.0.1|g' "${f}"
    fi
}

copy_file() {
    src="$1"
    dst="$2"
    if [ ! -f "${src}" ]; then
        echo "source file missing: ${src}" >&2
        exit 1
    fi
    mkdir -p "$(dirname "${dst}")"
    if [ -f "${dst}" ] && cmp -s "${src}" "${dst}"; then
        log "already in place: ${dst}"
        return 0
    fi
    cp "${src}" "${dst}"
    log "copied: ${src} -> ${dst}"
}

reload_crowdsec() {
    # cscli has no "reload acquisition" today; SIGHUP to the main
    # daemon re-reads /etc/crowdsec/acquis.d/*.yaml in-place. The
    # container runs crowdsec as PID 1 (argv[0] is "crowdsec", no
    # absolute path) so pidof + a cmdline match both work; prefer
    # pidof because it is a single-purpose tool and cheaper than ps.
    pid=$(pidof crowdsec 2>/dev/null | tr ' ' '\n' | head -n1 || true)
    if [ -z "${pid}" ]; then
        log "crowdsec PID not found; skipping reload (daemon may not be running)"
        return 0
    fi
    log "sending SIGHUP to crowdsec (pid=${pid}) to reload acquis"
    kill -HUP "${pid}"
}

main() {
    require_cscli
    log "updating hub catalogue"
    cscli hub update

    install_collection crowdsecurity/appsec-virtual-patching
    install_collection crowdsecurity/appsec-generic-rules
    install_collection crowdsecurity/appsec-crs

    # Block mode acquis + detect mode acquis + both argos local
    # appsec-configs (block + detect each have their own).
    copy_file "${SRC_ACQUIS_BLOCK}"  "${DST_ACQUIS_BLOCK}"
    copy_file "${SRC_ACQUIS_DETECT}" "${DST_ACQUIS_DETECT}"
    copy_file "${SRC_CONFIG_DETECT}" "${DST_CONFIG_DETECT}"
    copy_file "${SRC_CONFIG_BLOCK}"  "${DST_CONFIG_BLOCK}"

    fix_lapi_credentials
    reload_crowdsec

    log "done. Verify with:"
    log "  cscli collections list"
    log "  cscli appsec-configs list"
    log "  cscli appsec-rules list"
}

main "$@"
