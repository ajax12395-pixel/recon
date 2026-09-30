#!/bin/bash
# ============================================================
# RECON Framework — lib/js.sh
# Phase 07 — JavaScript Analysis + Secret Extraction
#
# Rebuilt to match reconFTW's jschecks() methodology exactly,
# minus the wordlist/getjswords step (explicitly excluded).
# Pipeline: subjs -> httpx (live filter) -> sourcemapper
#           (recover unminified source) -> xnLinkFinder
#           (endpoints incl. relative paths) + jsluice ->
#           mantra + trufflehog (two independent secret-
#           detection passes, one on live JS, one on the
#           recovered source-map code).
# Every external tool is optional: if it's missing, that step
# is skipped (require_tool) and the rest of the phase still runs.
# ============================================================

js_analysis() {
  local JS_URLS="$WORKDIR/05_urls/categorized/js_urls.txt"
  local OUT="$WORKDIR/07_js"
  local ERR_LOG="$OUT/js_errors.log"

  : > "$ERR_LOG"

  log info "Phase 07: JavaScript analysis starting"

  touch "$JS_URLS"

  # ── 1. subjs — discover JS files from live hosts ──────────
  if require_tool subjs && [ -s "$WORKDIR/03_live_hosts/live.txt" ]; then
    log info "Running subjs..."
    command subjs < "$WORKDIR/03_live_hosts/live.txt" > "$OUT/subjs_output.txt" 2>>"$ERR_LOG" || true
    if [ -s "$OUT/subjs_output.txt" ]; then
      cat "$OUT/subjs_output.txt" >> "$JS_URLS"
    fi
    check_output "$OUT/subjs_output.txt" "subjs" || true
  fi

  # Dedup (urless if available, like reconFTW; plain sort -u otherwise)
  if [ -s "$JS_URLS" ]; then
    if require_tool urless; then
      command urless < "$JS_URLS" 2>>"$ERR_LOG" | sort -u > "$OUT/js_urls.txt" || cp "$JS_URLS" "$OUT/js_urls.txt"
    else
      sort -u "$JS_URLS" -o "$JS_URLS"
      cp "$JS_URLS" "$OUT/js_urls.txt"
    fi
  fi

  if [ ! -s "$OUT/js_urls.txt" ]; then
    log warn "No JS URLs found. Skipping JS content analysis."
    touch "$OUT/js_urls.txt" "$OUT/js_livelinks.txt" "$OUT/js_endpoints.txt" "$OUT/js_secrets.txt"
    return 0
  fi

  # ── 2. httpx — keep only live JS files (200 + javascript) ──
  local JS_LIVE="$OUT/js_livelinks.txt"
  : > "$JS_LIVE"
  if require_tool httpx; then
    log info "Resolving JS URLs with httpx..."
    command httpx -follow-redirects -random-agent -silent \
      -timeout "${HTTPX_TIMEOUT:-10}" -threads "${HTTPX_THREADS:-50}" \
      -status-code -content-type -retries 2 -no-color \
      < "$OUT/js_urls.txt" 2>>"$ERR_LOG" \
      | awk '/\[200\]/ && /javascript/ {print $1}' \
      | sort -u > "$JS_LIVE" || true
    check_output "$JS_LIVE" "httpx (js filter)" || true
  fi
  if [ ! -s "$JS_LIVE" ]; then
    log warn "httpx filtering produced nothing (or httpx missing); falling back to unfiltered JS list."
    cp "$OUT/js_urls.txt" "$JS_LIVE"
  fi

  # ── 3. sourcemapper — recover unminified source ────────────
  local SOURCEMAPPER_DIR="$OUT/sourcemapper"
  if require_tool sourcemapper && [ -s "$JS_LIVE" ]; then
    log info "Running sourcemapper on live JS files..."
    mkdir -p "$SOURCEMAPPER_DIR"
    local sm_count=0
    while IFS= read -r js_url; do
      [ -z "$js_url" ] && continue
      local sm_hash
      sm_hash=$(printf '%s' "$js_url" | sha256sum | cut -d' ' -f1)
      command sourcemapper -jsurl "$js_url" -output "$SOURCEMAPPER_DIR/$sm_hash" \
        2>>"$ERR_LOG" >/dev/null || true
      sm_count=$((sm_count + 1))
    done < "$JS_LIVE"
    log info "sourcemapper processed: $sm_count JS files"
  fi

  # ── 4. Endpoint extraction: jsluice (from recovered source) ─
  #      + xnLinkFinder (from live JS, catches relative paths) ─
  : > "$OUT/js_endpoints.txt"
  if require_tool jsluice && [ -d "$SOURCEMAPPER_DIR" ] && [ -n "$(ls -A "$SOURCEMAPPER_DIR" 2>/dev/null)" ]; then
    log info "Running jsluice on recovered source..."
    find "$SOURCEMAPPER_DIR" \( -name "*.js" -o -name "*.ts" \) -type f 2>/dev/null \
      | command jsluice urls 2>>"$ERR_LOG" | jq -r '.url' 2>/dev/null \
      | sort -u >> "$OUT/js_endpoints.txt" || true
  fi
  if require_tool xnLinkFinder && [ -s "$JS_LIVE" ]; then
    log info "Running xnLinkFinder..."
    local xnlf_args=(-i "$JS_LIVE" -o "$OUT/xnlinkfinder_out.txt")
    if [ -s "$WORKDIR/01_subdomains/all_subdomains.txt" ]; then
      xnlf_args+=(-sf "$WORKDIR/01_subdomains/all_subdomains.txt")
    fi
    command xnLinkFinder "${xnlf_args[@]}" 2>>"$ERR_LOG" >/dev/null || true
    if [ -s "$OUT/xnlinkfinder_out.txt" ]; then
      grep -a '^/' "$OUT/xnlinkfinder_out.txt" >> "$OUT/js_endpoints.txt" || true
    fi
  fi
  sort -u "$OUT/js_endpoints.txt" -o "$OUT/js_endpoints.txt" 2>>"$ERR_LOG"

  # ── 5. Secrets: mantra (live JS) + trufflehog (recovered source) ─
  : > "$OUT/js_secrets.txt"
  if require_tool mantra && [ -s "$JS_LIVE" ]; then
    log info "Running mantra..."
    command mantra < "$JS_LIVE" > "$OUT/js_secrets.txt" 2>>"$ERR_LOG" || true
    check_output "$OUT/js_secrets.txt" "mantra" || true
  fi

  : > "$OUT/js_secrets_jsmap.txt"
  if require_tool trufflehog && [ -d "$SOURCEMAPPER_DIR" ] && [ -n "$(ls -A "$SOURCEMAPPER_DIR" 2>/dev/null)" ]; then
    log info "Running trufflehog on recovered source-map code..."
    command trufflehog filesystem "$SOURCEMAPPER_DIR" -j 2>>"$ERR_LOG" \
      | jq -c . 2>/dev/null > "$OUT/js_secrets_jsmap.txt" || true
    check_output "$OUT/js_secrets_jsmap.txt" "trufflehog (sourcemap)" || true
  fi

  log info "JS files (live): $(wc -l < "$JS_LIVE" 2>>"$ERR_LOG" | tr -d ' ')"
  log info "Endpoints extracted: $(wc -l < "$OUT/js_endpoints.txt" 2>>"$ERR_LOG" | tr -d ' ')"
  log info "Secrets (mantra): $(wc -l < "$OUT/js_secrets.txt" 2>>"$ERR_LOG" | tr -d ' ')"
  log info "Secrets (source-map/trufflehog): $(wc -l < "$OUT/js_secrets_jsmap.txt" 2>>"$ERR_LOG" | tr -d ' ')"
}
