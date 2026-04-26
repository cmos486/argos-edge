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

# v1.3.19: argos local rule pack carrying the homelab-friendly CRS
# threshold override (5 -> 15). Loaded inband by both block and
# detect appsec-configs.
SRC_RULE_TUNING=/setup/appsec-rules/argos-tuning.yaml
DST_RULE_TUNING=/etc/crowdsec/appsec-rules/argos-tuning.yaml

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

apply_panel_sentinels() {
    # v1.3.19: read panel-managed sentinels from /shared (the volume
    # the panel writes to as /data/shared) and translate them into
    # the actual CrowdSec config files.
    #
    #  /shared/argos-whitelist-entries.txt
    #     -> /etc/crowdsec/parsers/s02-enrich/argos-whitelist.yaml
    #
    # v1.3.25 added two more sentinels:
    #
    #  /shared/argos-disabled-scenarios.txt
    #     -> cscli scenarios remove --force per line
    #
    #  /shared/argos-appsec-tuning.txt
    #     -> regenerate /etc/crowdsec/appsec-rules/argos-tuning.yaml
    #        with the operator-set inbound/outbound thresholds
    #        BEFORE the v1.3.19 hardcoded scenario removes run.
    #
    # All sentinels carry a "# argos-managed" header; operators are
    # told not to edit them. The panel rewrites whenever the
    # corresponding setting changes.

    DST_WHITELIST=/etc/crowdsec/parsers/s02-enrich/argos-whitelist.yaml
    SRC_WHITELIST=/shared/argos-whitelist-entries.txt
    DST_TUNING=/etc/crowdsec/appsec-rules/argos-tuning.yaml
    SRC_TUNING=/shared/argos-appsec-tuning.txt
    SRC_DISABLED=/shared/argos-disabled-scenarios.txt

    # --- argos-tuning.yaml regeneration ---
    #
    # Order matters: argos-tuning.yaml was just copy_file'd from
    # /setup/appsec-rules/ to /etc/crowdsec/appsec-rules/ with the
    # v1.3.19 default thresholds (15/4). If the panel sentinel
    # exists, OVERWRITE that file with operator-set values. Empty
    # / missing sentinel -> v1.3.19 defaults stand.
    #
    # The sentinel format is key=value, one per line:
    #   inbound_threshold=20
    #   outbound_threshold=4
    inbound=15
    outbound=4
    if [ -f "${SRC_TUNING}" ]; then
        v=$(grep -E '^inbound_threshold=' "${SRC_TUNING}" 2>/dev/null \
            | head -n 1 | cut -d= -f2 | tr -d '[:space:]')
        if [ -n "${v}" ]; then inbound="${v}"; fi
        v=$(grep -E '^outbound_threshold=' "${SRC_TUNING}" 2>/dev/null \
            | head -n 1 | cut -d= -f2 | tr -d '[:space:]')
        if [ -n "${v}" ]; then outbound="${v}"; fi
    fi
    mkdir -p "$(dirname "${DST_TUNING}")"
    {
        echo "# Managed by argos panel -- do not edit manually."
        echo "# Edits will be overwritten on the next setup-appsec.sh run."
        echo "# Inbound default 15 (v1.3.19 homelab tune); outbound default 4."
        echo "# Operator overrides via panel /security AppSec tab."
        echo "name: argos/tuning"
        echo "seclang_rules:"
        echo "  - SecAction \"id:900110,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=${inbound}\""
        echo "  - SecAction \"id:900111,phase:1,pass,nolog,setvar:tx.outbound_anomaly_score_threshold=${outbound}\""
    } > "${DST_TUNING}.tmp"
    mv "${DST_TUNING}.tmp" "${DST_TUNING}"
    log "rewrote ${DST_TUNING} (inbound=${inbound} outbound=${outbound})"

    # --- panel-disabled scenarios ---
    #
    # Read /shared/argos-disabled-scenarios.txt and remove each.
    # Tolerates blank lines + #-comments. Each remove is `--force`
    # so re-running the script is idempotent. The v1.3.19
    # hardcoded set (appsec-native, appsec-generic-test) is
    # handled separately in main() below; this loop is for the
    # operator-managed additions only.
    if [ -f "${SRC_DISABLED}" ]; then
        while IFS= read -r line; do
            name=$(printf '%s' "${line}" | sed 's/[[:space:]]*$//')
            case "${name}" in
                ''|\#*) continue ;;
            esac
            log "panel-disabled scenario: ${name}"
            cscli scenarios remove "${name}" --force 2>/dev/null || true
        done < "${SRC_DISABLED}"
    fi

    # --- argos-whitelist.yaml ---
    #
    # CrowdSec's whitelist parser separates `ip:` (single addresses)
    # from `cidr:` (ranges with /N notation). Operator entries from
    # the panel arrive as "<scope> <value>" lines where scope is
    # "ip" or "range"; we partition them into the right list.
    mkdir -p "$(dirname "${DST_WHITELIST}")"
    operator_ips=""
    operator_cidrs=""
    if [ -f "${SRC_WHITELIST}" ]; then
        operator_ips=$(grep -v '^#' "${SRC_WHITELIST}" | grep -v '^[[:space:]]*$' \
            | awk '$1=="ip" && $2!="" {print "    - " $2}')
        operator_cidrs=$(grep -v '^#' "${SRC_WHITELIST}" | grep -v '^[[:space:]]*$' \
            | awk '$1=="range" && $2!="" {print "    - " $2}')
    fi
    {
        echo "# Managed by argos panel -- do not edit manually."
        echo "# Edits will be overwritten on the next setup-appsec.sh run."
        echo "# System ranges (RFC 1918 / loopback / ULA) are emitted"
        echo "# unconditionally; manual entries come from the panel's"
        echo "# security_whitelist DB table via /shared/argos-whitelist-entries.txt."
        echo "name: argos/whitelist"
        echo "description: \"argos-managed whitelist (system ranges + operator entries)\""
        echo "whitelist:"
        echo "  reason: \"argos-managed allow\""
        echo "  cidr:"
        echo "    - 127.0.0.0/8"
        echo "    - 10.0.0.0/8"
        echo "    - 172.16.0.0/12"
        echo "    - 192.168.0.0/16"
        echo "    - fc00::/7"
        echo "    - ::1/128"
        if [ -n "${operator_cidrs}" ]; then
            echo "${operator_cidrs}"
        fi
        if [ -n "${operator_ips}" ]; then
            echo "  ip:"
            echo "${operator_ips}"
        fi
    } > "${DST_WHITELIST}.tmp"
    mv "${DST_WHITELIST}.tmp" "${DST_WHITELIST}"
    log "rewrote ${DST_WHITELIST}"
}

main() {
    require_cscli
    log "updating hub catalogue"
    cscli hub update

    install_collection crowdsecurity/appsec-virtual-patching
    install_collection crowdsecurity/appsec-generic-rules
    install_collection crowdsecurity/appsec-crs

    # Block mode acquis + detect mode acquis + both argos local
    # appsec-configs (block + detect each have their own) + the
    # argos/tuning local rule pack referenced from both configs.
    copy_file "${SRC_ACQUIS_BLOCK}"  "${DST_ACQUIS_BLOCK}"
    copy_file "${SRC_ACQUIS_DETECT}" "${DST_ACQUIS_DETECT}"
    copy_file "${SRC_CONFIG_DETECT}" "${DST_CONFIG_DETECT}"
    copy_file "${SRC_CONFIG_BLOCK}"  "${DST_CONFIG_BLOCK}"
    copy_file "${SRC_RULE_TUNING}"   "${DST_RULE_TUNING}"

    # v1.3.19: disable the two scenarios that turn AppSec alerts
    # into auto-bans. argos's intent for "detect mode" is "log,
    # don't block" -- but the vendor scenario set converts every
    # WAF alert into a LAPI decision regardless of the appsec-
    # config remediation, which silently autobans operators on
    # legitimate traffic from socket.io / monitoring tools.
    #
    #   crowdsecurity/appsec-native     bans on raw rule_name
    #                                   match -- triggers on every
    #                                   inband WAF alert.
    #   crowdsecurity/appsec-generic-test  test scenario, fires on
    #                                   /crowdsec-test-... probes.
    #
    # appsec-vpatch (CVE-specific) and crowdsec-appsec-outofband
    # (5+-hit threshold) STAY enabled -- those represent
    # high-signal threats. Operators who want the vendor-default
    # aggressive posture can re-install both with
    #   cscli scenarios install crowdsecurity/appsec-native
    #   cscli scenarios install crowdsecurity/appsec-generic-test
    # and re-run setup-appsec.sh has no effect on already-
    # installed scenarios -- a re-install survives this script.
    log "disabling default-aggressive scenarios (appsec-native, appsec-generic-test)"
    cscli scenarios remove crowdsecurity/appsec-native --force 2>/dev/null || true
    cscli scenarios remove crowdsecurity/appsec-generic-test --force 2>/dev/null || true

    # v1.3.19: translate panel-managed sentinels into CrowdSec
    # config (profiles.yaml argos-managed block + whitelist file).
    apply_panel_sentinels

    fix_lapi_credentials
    reload_crowdsec

    log "done. Verify with:"
    log "  cscli collections list"
    log "  cscli appsec-configs list"
    log "  cscli appsec-rules list"
}

main "$@"
