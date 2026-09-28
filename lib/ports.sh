#!/bin/bash
# ============================================================
# RECON Framework — lib/ports.sh
# Phase 04 — Port Scanning + Service Detection
# Rebuilt to follow reconFTW's portscan() methodology:
#   naabu (fast top-ports) -> nmap (targeted, only ports naabu found)
#   with CDN exclusion, optional origin-IP bypass, optional
#   passive lookups (Shodan InternetDB / smap) and optional
#   service fingerprinting (nerva).
# ============================================================

port_scan() {
  local IN="$WORKDIR/03_live_hosts/live.txt"
  local OUT="$WORKDIR/04_ports"
  local ERR_LOG="$OUT/ports_errors.log"

  : > "$ERR_LOG"

  if [ ! -s "$IN" ]; then
    log warn "No live hosts found. Skipping port scan."
    return 0
  fi

  log info "Phase 04: Port scanning starting"

  # ── Extract clean hostnames from live hosts list ──────────
  local tmp_hosts="/tmp/recon_port_hosts_$$.txt"
  awk '{print $1}' "$IN" 2>>"$ERR_LOG" \
    | sed -E 's#^https?://##; s#/.*$##; s#:[0-9]+$##' \
    | grep -v '^$' \
    | sort -u > "$tmp_hosts"

  if [ ! -s "$tmp_hosts" ]; then
    rm -f "$tmp_hosts"
    log error "No valid hosts extracted from live host list. Port scan cannot continue."
    return 1
  fi

  # ── Resolve hosts to IPs (needed for CDN filtering) ───────
  local ips_all="$OUT/ips.txt"
  : > "$ips_all"
  if require_tool dnsx; then
    log info "Resolving hosts to IPs..."
    command dnsx -l "$tmp_hosts" -a -resp-only -silent 2>>"$ERR_LOG" \
      | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
      | grep -aEiv "^(127|10|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\." \
      | sort -u > "$ips_all" || true
  else
    log warn "dnsx not found; falling back to naabu resolving hostnames directly (no CDN filtering)."
  fi

  # ── CDN provider check (skip scanning CDN-fronted IPs) ────
  local ips_nocdn="$OUT/ips_nocdn.txt"
  cp "$ips_all" "$ips_nocdn" 2>/dev/null || : > "$ips_nocdn"

  if [ -s "$ips_all" ] && require_tool cdncheck; then
    log info "Checking for CDN/WAF providers..."
    command cdncheck -silent -resp -cdn -waf -nc < "$ips_all" 2>>"$ERR_LOG" \
      | sort -u > "$OUT/cdn_providers.txt" || true
    check_output "$OUT/cdn_providers.txt" "cdncheck" || true

    if [ -s "$OUT/cdn_providers.txt" ]; then
      comm -23 <(sort -u "$ips_all") \
        <(cut -d'[' -f1 "$OUT/cdn_providers.txt" | sed 's/[[:space:]]*$//' | sort -u) \
        | grep -aEiv "^(127|10|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\." \
        | sort -u > "$ips_nocdn"
    fi
  fi

  local nocdn_count
  nocdn_count=$(wc -l < "$ips_nocdn" 2>/dev/null | tr -d ' ')
  log info "Resolved IPs (no CDN): ${nocdn_count:-0}"

  # ── Optional CDN bypass: try to recover real origin IPs ───
  # NOTE: hakoriginfinder requires a full IP range (e.g. via `prips`)
  # plus a single -h <url> target — it does NOT accept a list of
  # hostnames via stdin (confirmed against the tool's own usage/docs).
  # We don't have a reliable IP range to feed it in this pipeline, so
  # this step is disabled by default. Set CDN_BYPASS=true only if you
  # provide your own IP-range logic here.
  if [ "${CDN_BYPASS:-false}" = "true" ] && require_tool hakoriginfinder; then
    log warn "CDN_BYPASS is enabled but hakoriginfinder needs an IP range (prips) + -h <url>, not a hostname list. Skipping — see comment in ports.sh."
  fi

  # Fall back to raw hostnames if we have no resolved IPs at all
  # (e.g. dnsx missing) so naabu still has something to scan.
  local naabu_input="$ips_nocdn"
  if [ ! -s "$naabu_input" ]; then
    naabu_input="$tmp_hosts"
  fi

  # ── naabu fast port scan (top-ports, like reconFTW default) ──
  if ! require_tool naabu; then
    rm -f "$tmp_hosts"
    log error "naabu is required for port scanning"
    return 1
  fi

  log info "Running naabu fast port scan..."
  # shellcheck disable=SC2086  # NAABU_PORTS is meant to expand as flags
  command naabu -l "$naabu_input" \
    ${NAABU_PORTS:---top-ports 1000} \
    -rate "${NAABU_RATE:-1000}" \
    -silent \
    -o "$OUT/naabu_ports.txt" 2>>"$ERR_LOG" || log warn "naabu exited with a non-zero status; continuing with whatever output it produced."

  if ! check_output "$OUT/naabu_ports.txt" "naabu"; then
    rm -f "$tmp_hosts"
    log error "naabu produced no output for live hosts. See $ERR_LOG"
    return 1
  fi

  # ── nmap targeted scan: only the ports naabu actually found ──
  if require_tool nmap && [ -s "$OUT/naabu_ports.txt" ]; then
    local naabu_ports_csv
    naabu_ports_csv=$(cut -d':' -f2 "$OUT/naabu_ports.txt" | sed '/^$/d' | sort -un | paste -sd, -)

    local tmp_ips="/tmp/recon_ips_$$.txt"
    cut -d':' -f1 "$OUT/naabu_ports.txt" | sort -u > "$tmp_ips"

    if [ -n "$naabu_ports_csv" ]; then
      log info "Running nmap service detection on discovered ports ($naabu_ports_csv)..."
      # `command` bypasses any shell function/alias named nmap (this
      # environment wraps it via a grc colouriser function that can
      # misbehave under `set -euo pipefail` in a non-interactive script).
      command nmap -p "$naabu_ports_csv" \
        -T4 -Pn -sV \
        -iL "$tmp_ips" \
        -oA "$OUT/nmap_active" 2>>"$ERR_LOG" || log warn "nmap exited with a non-zero status; continuing with whatever output it produced."
    else
      log warn "Could not build port list from naabu output; falling back to default nmap top ports."
      command nmap -T4 -Pn -sV \
        -iL "$tmp_ips" \
        -oA "$OUT/nmap_active" 2>>"$ERR_LOG" || log warn "nmap exited with a non-zero status; continuing with whatever output it produced."
    fi
    rm -f "$tmp_ips"
    check_output "$OUT/nmap_active.xml" "nmap" || true
  fi

  # ── Convert nmap XML findings into ready-to-use URLs ──────
  if require_tool nmapurls && [ -s "$OUT/nmap_active.xml" ]; then
    log info "Extracting web URLs from nmap results..."
    command nmapurls < "$OUT/nmap_active.xml" 2>>"$ERR_LOG" | sort -u > "$OUT/webs_from_ports.txt" || true
    check_output "$OUT/webs_from_ports.txt" "nmapurls" || true
  fi

  # ── Optional passive lookups (no packets sent) ────────────
  if [ "${PORTSCAN_PASSIVE:-false}" = "true" ] && [ -s "$ips_nocdn" ]; then
    if require_tool curl; then
      log info "Querying Shodan InternetDB (passive)..."
      : > "$OUT/portscan_passive_shodan.json"
      while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        curl -s "https://internetdb.shodan.io/${ip}" 2>>"$ERR_LOG" >> "$OUT/portscan_passive_shodan.json" || true
      done < "$ips_nocdn"
      check_output "$OUT/portscan_passive_shodan.json" "shodan_internetdb" || true
    fi

    if require_tool smap; then
      log info "Running smap (passive port lookup)..."
      command smap -iL "$ips_nocdn" > "$OUT/portscan_passive_smap.txt" 2>>"$ERR_LOG" || true
      check_output "$OUT/portscan_passive_smap.txt" "smap" || true
    fi
  fi

  # ── Optional service fingerprinting (nerva) ───────────────
  if [ "${SERVICE_FINGERPRINT:-false}" = "true" ] && require_tool nerva && [ -s "$OUT/naabu_ports.txt" ]; then
    log info "Running service fingerprinting (nerva)..."
    command nerva --json -l "$OUT/naabu_ports.txt" -w "${SERVICE_FINGERPRINT_TIMEOUT_MS:-2000}" \
      -o "$OUT/service_fingerprints.jsonl" 2>>"$ERR_LOG" || true
    check_output "$OUT/service_fingerprints.jsonl" "nerva" || true
  fi

  rm -f "$tmp_hosts"

  log success "Port scanning phase complete"
}
