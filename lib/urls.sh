#!/bin/bash
# ============================================================
# RECON Framework — lib/urls.sh
# Phase 05 — URL + Endpoint Collection & Categorization
# ============================================================

collect_urls() {
  local IN="$WORKDIR/03_live_hosts/live.txt"
  local OUT="$WORKDIR/05_urls"
  local ERR_LOG="$OUT/raw/urls_errors.log"

  : > "$ERR_LOG"

  if [ ! -s "$IN" ]; then
    log warn "No live hosts found. Skipping URL collection."
    return 0
  fi

  log info "Phase 05: URL collection starting"

  # urlfinder (ProjectDiscovery passive URL discovery)
  if require_tool urlfinder; then
    log info "Running urlfinder..."
    urlfinder -d "$TARGET" -all \
      -o "$OUT/raw/urlfinder.txt" 2>>"$ERR_LOG"
    check_output "$OUT/raw/urlfinder.txt" "urlfinder"
  fi

  # waymore
  if require_tool waymore; then
    log info "Running waymore (root-domain first)..."
    waymore -i "$TARGET" -mode U \
      -oU "$OUT/raw/waymore.txt" 2>>"$ERR_LOG" || true

    if [ ! -s "$OUT/raw/waymore.txt" ] && [ "$TARGET_MODE" = "wildcard" ]; then
      log warn "waymore root-domain run returned no data; trying selective wildcard fallback"
      local tmp_waymore="/tmp/recon_waymore_$$.txt"
      local fallback_count=0
      local max_fallback_hosts="${WAYMORE_FALLBACK_MAX_HOSTS:-20}"
      : > "$OUT/raw/waymore.txt"

      while IFS= read -r live_url; do
        [ -z "$live_url" ] && continue
        fallback_count=$((fallback_count + 1))
        if [ "$max_fallback_hosts" -gt 0 ] && [ "$fallback_count" -gt "$max_fallback_hosts" ]; then
          break
        fi

        waymore -i "$live_url" -mode U \
          -oU "$tmp_waymore" 2>>"$ERR_LOG" || true

        [ -s "$tmp_waymore" ] && cat "$tmp_waymore" >> "$OUT/raw/waymore.txt"
      done < "$IN"

      rm -f "$tmp_waymore"
      if [ "$max_fallback_hosts" -gt 0 ]; then
        log info "waymore fallback processed up to $max_fallback_hosts live hosts"
      fi
      [ -s "$OUT/raw/waymore.txt" ] && sort -u "$OUT/raw/waymore.txt" -o "$OUT/raw/waymore.txt"
    fi

    check_output "$OUT/raw/waymore.txt" "waymore"
  fi

  # katana (JavaScript-aware crawler)
  if require_tool katana; then
    log info "Running katana..."
    katana -silent -list "$IN" \
      -jc -kf all \
      -c "$KATANA_CONCURRENCY" \
      -d "$KATANA_DEPTH" \
      -fs rdn \
      > "$OUT/raw/katana.txt" 2>>"$ERR_LOG"
    check_output "$OUT/raw/katana.txt" "katana"
  fi

  # github-endpoints (discover endpoints leaked in public GitHub repos)
  local GITHUB_TOKENS="${GITHUB_TOKENS:-$HOME/tools/.github_tokens}"
  if require_tool github-endpoints; then
    if [ -s "$GITHUB_TOKENS" ]; then
      log info "Running github-endpoints..."
      github-endpoints -q -k -d "$TARGET" -t "$GITHUB_TOKENS" \
        -o "$OUT/raw/github-endpoints.txt" 2>>"$ERR_LOG"
      check_output "$OUT/raw/github-endpoints.txt" "github-endpoints"
    else
      log warn "github-endpoints skipped: no GitHub tokens file found at $GITHUB_TOKENS"
    fi
  fi

  # ── MERGE ALL URLs ────────────────────────────────────────
  log info "Merging all URLs..."
  cat "$OUT/raw/"*.txt 2>>"$ERR_LOG" \
    | grep -oE "https?://[^ '\"]+" \
    | grep -v "^$" \
    | sort -u > "$OUT/all_urls.txt"

  # Use anew if available for dedup
  if command -v anew &>/dev/null; then
    local tmp_urls="/tmp/recon_urls_merge_$$.txt"
    mv "$OUT/all_urls.txt" "$tmp_urls"
    cat "$tmp_urls" | anew "$OUT/all_urls.txt" >/dev/null 2>>"$ERR_LOG"
    rm -f "$tmp_urls"
  fi

  local total
  total=$(wc -l < "$OUT/all_urls.txt" 2>>"$ERR_LOG" | tr -d ' ')

  if [ -z "$total" ] || [ "$total" -eq 0 ]; then
    log error "URL collection produced zero URLs from non-empty live hosts. See $ERR_LOG"
    return 1
  fi

  log info "Total URLs collected: ${total:-0}"

  # ── CATEGORIZE URLs ───────────────────────────────────────
  log info "Categorizing URLs..."
  local ALLURLS="$OUT/all_urls.txt"
  local CAT="$OUT/categorized"

  grep -iE '\.js(\?|$)' "$ALLURLS" 2>>"$ERR_LOG" | sort -u > "$CAT/js_urls.txt" || true
  grep -iE '\.php(\?|$)' "$ALLURLS" 2>>"$ERR_LOG" | sort -u > "$CAT/php_urls.txt" || true
  grep -iE '\.(asp|aspx)(\?|$)' "$ALLURLS" 2>>"$ERR_LOG" | sort -u > "$CAT/asp_urls.txt" || true
  grep -iE '\.(jsp|jspx)(\?|$)' "$ALLURLS" 2>>"$ERR_LOG" | sort -u > "$CAT/jsp_urls.txt" || true
  grep -iE '\.(json|xml|graphql|gql)(\?|$)' "$ALLURLS" 2>>"$ERR_LOG" | sort -u > "$CAT/api_endpoints.txt" || true
  grep -iE 'login|signin|auth|oauth|reset|password' "$ALLURLS" 2>>"$ERR_LOG" | sort -u > "$CAT/login_flows.txt" || true
  grep -iE 'upload|file|download|image|media' "$ALLURLS" 2>>"$ERR_LOG" | sort -u > "$CAT/upload_endpoints.txt" || true
  grep -iE 'admin|dashboard|internal|manage' "$ALLURLS" 2>>"$ERR_LOG" | sort -u > "$CAT/admin_panels.txt" || true
  grep -iE '\.(env|bak|config|sql|log)(\?|$)' "$ALLURLS" 2>>"$ERR_LOG" | sort -u > "$CAT/sensitive_files.txt" || true
  grep -iE '\.(php|asp|aspx|jsp|cfm|cgi)(\?|$)' "$ALLURLS" 2>>"$ERR_LOG" | sort -u > "$CAT/backend_files.txt" || true
  grep -E '=[0-9]{2,}' "$ALLURLS" 2>>"$ERR_LOG" | sort -u > "$CAT/idor_candidates.txt" || true
  grep -iE 'admin|login|signup|redirect|callback|auth|dev|test|beta|debug|staging|url=|r=|u=|goto=|return=|dest=' "$ALLURLS" 2>>"$ERR_LOG" | sort -u > "$CAT/interesting_endpoints.txt" || true
  grep -iE 'aws|s3|bucket|gcp|azure|vault|token|apikey|secret' "$ALLURLS" 2>>"$ERR_LOG" | sort -u > "$CAT/cloud_leaks.txt" || true
  grep '=' "$ALLURLS" 2>>"$ERR_LOG" | sort -u > "$CAT/param_urls.txt" || true

  # Wayback sensitive file enumerator (full regex from methodology)
  grep -E \
    "\.xls|\.xlsx|\.csv|\.sql|\.db|\.bak|\.backup|\.old|\.tar\.gz|\.tgz|\.zip|\.7z|\.rar|\.pdf|\.doc|\.docx|\.pptx|\.txt|\.log|\.ini|\.conf|\.config|\.env|\.json|\.xml|\.yml|\.yaml|\.pem|\.key|\.crt|\.ssh|\.git|\.htaccess|\.htpasswd|\.php|\.swp|\.swo|\.dump|\.dmp" \
    "$ALLURLS" 2>>"$ERR_LOG" | sort -u >> "$CAT/sensitive_files.txt" || true
  sort -u "$CAT/sensitive_files.txt" -o "$CAT/sensitive_files.txt" 2>>"$ERR_LOG"

  # Parameter extraction (qsreplace method from methodology)
  if command -v qsreplace &>/dev/null; then
    grep '=' "$ALLURLS" 2>>"$ERR_LOG" | qsreplace "FUZZ" >> "$WORKDIR/08_params/all_params.txt" 2>>"$ERR_LOG" || true
  fi

  # Filter live URLs
  if require_tool httpx; then
    log info "Filtering live URLs..."
    httpx -l "$OUT/all_urls.txt" -status-code -content-length -silent \
      -threads 200 \
      > "$OUT/live_urls.txt" 2>>"$ERR_LOG"
  fi

  log success "URL collection and categorization complete"
}
