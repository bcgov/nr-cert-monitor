#!/usr/bin/env bash
set -euo pipefail

# Keep in step with bcgov/actions-openshift cert-keeper/check.sh:
# cert-keeper renews at 1/3 of lifetime left; alert 3 days later.
LIFETIME_DIVISOR=3
MARGIN_DAYS=3

# Fail-fast tool checks
for cmd in openssl jq date timeout; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "::error::Required command '$cmd' is not installed or not in PATH." >&2
    exit 1
  fi
done

# Verify argument exists
if [ "$#" -lt 1 ] || [ -z "${1:-}" ]; then
  echo "::error::Missing configuration file argument. Usage: $0 <config_file>" >&2
  exit 1
fi

CONFIG_FILE="$1"

# Verify config file exists
if [ ! -f "$CONFIG_FILE" ]; then
  echo "::error::Configuration file '$CONFIG_FILE' not found." >&2
  exit 1
fi

# Convert YAML to JSON for schema validation
if command -v yq >/dev/null 2>&1; then
  CONFIG_JSON=$(yq -o=json eval '.' "$CONFIG_FILE" 2>/dev/null || true)
elif command -v python3 >/dev/null 2>&1 && python3 -c "import yaml" >/dev/null 2>&1; then
  CONFIG_JSON=$(python3 -c 'import sys, yaml, json; json.dump(yaml.safe_load(sys.stdin), sys.stdout)' < "$CONFIG_FILE" 2>/dev/null || true)
else
  echo "::error::No YAML parser found. Please install 'yq' or 'python3-yaml'." >&2
  exit 1
fi

if [ -z "$CONFIG_JSON" ] || [ "$CONFIG_JSON" = "null" ]; then
  echo "::error::Configuration file '$CONFIG_FILE' is empty or null." >&2
  exit 1
fi

# Strict declarative validation: reject removed warning_days and require all active keys.
if echo "$CONFIG_JSON" | jq -e '(.technical | has("warning_days")) or (.monitoring.domains | any(has("warning_days")))' >/dev/null 2>&1; then
  echo "::error::warning_days is no longer supported; alerts trigger at 1/${LIFETIME_DIVISOR} of certificate lifetime minus ${MARGIN_DAYS} days" >&2
  exit 1
fi

if ! echo "$CONFIG_JSON" | jq -e '.technical.timeout_seconds | type == "number" and . > 0' >/dev/null 2>&1; then
  echo "::error::Missing or invalid required key: .technical.timeout_seconds (must be a positive number)" >&2
  exit 1
fi

if ! echo "$CONFIG_JSON" | jq -e '.technical.port | type == "number" and . > 0' >/dev/null 2>&1; then
  echo "::error::Missing or invalid required key: .technical.port (must be a positive number)" >&2
  exit 1
fi

if ! echo "$CONFIG_JSON" | jq -e '.issue.title_prefix | type == "string" and length > 0' >/dev/null 2>&1; then
  echo "::error::Missing or invalid required key: .issue.title_prefix (must be a non-empty string)" >&2
  exit 1
fi

if ! echo "$CONFIG_JSON" | jq -e '.monitoring.domains | type == "array" and length > 0' >/dev/null 2>&1; then
  echo "::error::Missing or invalid required key: .monitoring.domains (must be a non-empty array)" >&2
  exit 1
fi

if ! echo "$CONFIG_JSON" | jq -e '.monitoring.domains | all((.host | type == "string" and length > 0) and (.description | type == "string" and length > 0))' >/dev/null 2>&1; then
  echo "::error::Invalid domain entry in .monitoring.domains: each item must contain non-empty string 'host' and 'description'" >&2
  exit 1
fi

if ! echo "$CONFIG_JSON" | jq -e '.monitoring.domains | all((.assignees | type == "array" and length > 0 and all(type == "string" and length > 0)))' >/dev/null 2>&1; then
  echo "::error::Missing or invalid required key 'assignees' in .monitoring.domains: each domain must specify a non-empty array of GitHub assignee usernames" >&2
  exit 1
fi

# Extract technical defaults and issue settings
TECH_TIMEOUT_SEC=$(echo "$CONFIG_JSON" | jq -r '.technical.timeout_seconds')
TECH_PORT=$(echo "$CONFIG_JSON" | jq -r '.technical.port')
TITLE_PREFIX=$(echo "$CONFIG_JSON" | jq -r '.issue.title_prefix')
LABELS_CSV=$(echo "$CONFIG_JSON" | jq -r '(.issue.labels // []) | join(",")')

has_breach="false"
breach_count=0
summary_rows=""
breach_rows=""
breaches_array=()
healthy_array=()

record_breach() {
  local host="$1" desc="$2" port="$3" display_host="$4" state="$5" status="$6" expiry_date="$7" days_left="$8" lifetime_days="$9" threshold_days="${10}" assignees="${11}"
  local days_display="${days_left}d"
  local lifetime_display="${lifetime_days}d"
  [ "$days_left" = "N/A" ] && days_display="N/A"
  [ "$lifetime_days" = "N/A" ] && lifetime_display="N/A"

  has_breach="true"
  breach_count=$((breach_count + 1))
  breach_rows+=$'\n'"| $status | $display_host | $desc | $expiry_date | $days_display | $lifetime_display |"
  summary_rows+=$'\n'"| $status | $display_host | $desc | $expiry_date | $days_display | $lifetime_display |"
  breaches_array+=("$(jq -cn \
    --arg host "$host" \
    --arg desc "$desc" \
    --argjson port "$port" \
    --arg state "$state" \
    --arg status "$status" \
    --arg expiry_date "$expiry_date" \
    --arg days_left "$days_left" \
    --arg lifetime_days "$lifetime_days" \
    --arg threshold "$threshold_days" \
    --arg assignees "$assignees" \
    '{host: $host, description: $desc, port: $port, state: $state, status: $status, expiry_date: $expiry_date, days_left: $days_left, lifetime_days: $lifetime_days, threshold: $threshold, assignees: $assignees}')")
}

echo "[AUDIT] Starting SSL/TLS certificate inspection with config: $CONFIG_FILE"

# Iterate over each monitored domain
while IFS= read -r domain_json; do
  [ -z "$domain_json" ] && continue

  host=$(echo "$domain_json" | jq -r '.host')
  desc=$(echo "$domain_json" | jq -r '.description')
  port=$(echo "$domain_json" | jq -r --argjson default_port "$TECH_PORT" '.port // $default_port')
  domain_assignees=$(echo "$domain_json" | jq -r '.assignees | join(",")')

  display_host="$host"
  [ "$port" != "443" ] && display_host="${host}:${port}"

  # Read leaf certificate (public) with timeout and SNI (-servername)
  cert=$(timeout "$TECH_TIMEOUT_SEC" openssl s_client -servername "$host" -connect "${host}:${port}" </dev/null 2>/dev/null \
    | openssl x509 2>/dev/null || true)

  if [ -z "$cert" ]; then
    echo "[AUDIT] BREACH (Unreachable): $host:$port ($desc) - Connection or TLS handshake failed"
    record_breach "$host" "$desc" "$port" "$display_host" "unreachable" "❌ Unreachable" "N/A" "N/A" "N/A" "N/A" "$domain_assignees"
    continue
  fi

  not_before=$(openssl x509 -noout -startdate <<< "$cert" 2>/dev/null | cut -d= -f2- || true)
  not_after=$(openssl x509 -noout -enddate <<< "$cert" 2>/dev/null | cut -d= -f2- || true)
  start_epoch=$(date -u -d "$not_before" +%s 2>/dev/null || true)
  end_epoch=$(date -u -d "$not_after" +%s 2>/dev/null || true)

  if [ -z "$start_epoch" ] || [ -z "$end_epoch" ]; then
    echo "[AUDIT] BREACH (Unreachable): $host:$port ($desc) - Invalid certificate validity dates"
    record_breach "$host" "$desc" "$port" "$display_host" "unreachable" "❌ Unreachable" "N/A" "N/A" "N/A" "N/A" "$domain_assignees"
    continue
  fi

  now_epoch=$(date -u +%s)
  days_left=$(( (end_epoch - now_epoch) / 86400 ))
  lifetime_days=$(( (end_epoch - start_epoch) / 86400 ))
  formatted_date=$(date -u -d "@${end_epoch}" "+%Y-%m-%d")

  # Alert when 1/LIFETIME_DIVISOR of lifetime is left, minus MARGIN_DAYS
  limit_sec=$(( (end_epoch - start_epoch) / LIFETIME_DIVISOR - MARGIN_DAYS * 86400 ))
  (( limit_sec >= 0 )) || limit_sec=0
  threshold_days=$(( limit_sec / 86400 ))

  covers=$(openssl x509 -noout -checkhost "$host" <<< "$cert" 2>/dev/null || true)

  if [[ "$covers" != *"does match"* ]]; then
    echo "[AUDIT] BREACH (Uncovered): $host:$port ($desc) - Served certificate does not cover $host (expires $formatted_date, ${days_left}d left)"
    record_breach "$host" "$desc" "$port" "$display_host" "uncovered" "🚫 Uncovered" "$formatted_date" "$days_left" "$lifetime_days" "$threshold_days" "$domain_assignees"
  elif (( end_epoch <= now_epoch )); then
    echo "[AUDIT] BREACH (Expired): $host:$port ($desc) - Expired $(( -1 * days_left )) day(s) ago ($formatted_date)"
    record_breach "$host" "$desc" "$port" "$display_host" "expired" "🚨 Expired" "$formatted_date" "$days_left" "$lifetime_days" "$threshold_days" "$domain_assignees"
  elif (( end_epoch - now_epoch <= limit_sec )); then
    echo "[AUDIT] BREACH (Expiring): $host:$port ($desc) - Expires in $days_left day(s) of ${lifetime_days}d lifetime (threshold: ${threshold_days}d, expiry: $formatted_date)"
    record_breach "$host" "$desc" "$port" "$display_host" "expiring" "⚠️ Expiring" "$formatted_date" "$days_left" "$lifetime_days" "$threshold_days" "$domain_assignees"
  else
    status="✅ Healthy"
    echo "[AUDIT] OK: $host:$port ($desc) - Expires in $days_left day(s) of ${lifetime_days}d lifetime (threshold: ${threshold_days}d, $formatted_date)"
    summary_rows+=$'\n'"| $status | $display_host | $desc | $formatted_date | ${days_left}d | ${lifetime_days}d |"
    healthy_array+=("$(jq -cn \
      --arg host "$host" \
      --arg desc "$desc" \
      --argjson port "$port" \
      --arg status "$status" \
      --arg expiry_date "$formatted_date" \
      --arg days_left "$days_left" \
      --arg lifetime_days "$lifetime_days" \
      '{host: $host, description: $desc, port: $port, status: $status, expiry_date: $expiry_date, days_left: $days_left, lifetime_days: $lifetime_days}')")
  fi
done < <(echo "$CONFIG_JSON" | jq -c '.monitoring.domains[]')

echo "[AUDIT] Inspection completed. Domains inspected. Breaches found: $breach_count"

# Save structured breaches and healthy files
mkdir -p ./.tmp
if [ "$has_breach" = "true" ] && [ "${#breaches_array[@]}" -gt 0 ]; then
  printf "%s\n" "${breaches_array[@]}" | jq -s '.' > ./.tmp/breaches.json
else
  echo "[]" > ./.tmp/breaches.json
fi

if [ "${#healthy_array[@]}" -gt 0 ]; then
  printf "%s\n" "${healthy_array[@]}" | jq -s '.' > ./.tmp/healthy.json
else
  echo "[]" > ./.tmp/healthy.json
fi

# Construct alert body and issue title if breaches occurred
if [ "$has_breach" = "true" ]; then
  issue_title="${TITLE_PREFIX}${breach_count} domain(s) require SSL/TLS attention"
  alert_body=$(cat <<EOF
### ⚠️ SSL/TLS Certificate Expiry Alert

The following domain(s) require immediate attention due to upcoming SSL/TLS certificate expiration, hostname mismatch, or connection failures:

| Status | Host | Description | Expiry Date | Days Left | Lifetime |
| :--- | :--- | :--- | :--- | :--- | :--- |$breach_rows
EOF
)
else
  issue_title=""
  alert_body=""
fi

# Write GitHub Step Summary
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat <<EOF >> "$GITHUB_STEP_SUMMARY"
### SSL/TLS Certificate Expiry Audit Summary

Reporting certificates at 1/${LIFETIME_DIVISOR} of lifetime minus ${MARGIN_DAYS} days, or when the served certificate does not cover the host.

| Status | Host | Description | Expiry Date | Days Left | Lifetime |
| :--- | :--- | :--- | :--- | :--- | :--- |$summary_rows
EOF
fi

# Write GitHub Action Outputs
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "has_breach=$has_breach"
    echo "breach_count=$breach_count"
    echo "title_prefix=$TITLE_PREFIX"
    echo "breaches_file=./.tmp/breaches.json"
    echo "healthy_file=./.tmp/healthy.json"
    echo "issue_title=$issue_title"
    echo "labels=$LABELS_CSV"
    echo "alert_body<<EOF"
    echo "$alert_body"
    echo "EOF"
  } >> "$GITHUB_OUTPUT"
fi
