#!/usr/bin/env bash
set -euo pipefail

# Fail-fast tool checks
for cmd in openssl jq date; do
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

# Strict declarative validation: Every required key must be present and non-empty.
if ! echo "$CONFIG_JSON" | jq -e '.technical.warning_days | type == "number" and . > 0' >/dev/null 2>&1; then
  echo "::error::Missing or invalid required key: .technical.warning_days (must be a positive number)" >&2
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
TECH_WARN_DAYS=$(echo "$CONFIG_JSON" | jq -r '.technical.warning_days')
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

echo "[AUDIT] Starting SSL/TLS certificate inspection with config: $CONFIG_FILE"

# Iterate over each monitored domain
while IFS= read -r domain_json; do
  [ -z "$domain_json" ] && continue

  host=$(echo "$domain_json" | jq -r '.host')
  desc=$(echo "$domain_json" | jq -r '.description')
  port=$(echo "$domain_json" | jq -r --argjson default_port "$TECH_PORT" '.port // $default_port')
  warn_days=$(echo "$domain_json" | jq -r --argjson default_warn "$TECH_WARN_DAYS" '.warning_days // $default_warn')
  domain_assignees=$(echo "$domain_json" | jq -r '.assignees | join(",")')

  display_host="$host"
  [ "$port" != "443" ] && display_host="${host}:${port}"

  # Run openssl s_client with timeout and SNI (-servername)
  cert_raw=$(timeout "$TECH_TIMEOUT_SEC" openssl s_client -servername "$host" -connect "${host}:${port}" </dev/null 2>/dev/null || true)
  enddate_line=$(echo "$cert_raw" | openssl x509 -noout -enddate 2>/dev/null || true)

  if [[ "$enddate_line" =~ notAfter=(.*) ]]; then
    expiry_str="${BASH_REMATCH[1]}"
    if expiry_epoch=$(date -u -d "$expiry_str" +%s 2>/dev/null); then
      now_epoch=$(date -u +%s)
      days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
      formatted_date=$(date -u -d "$expiry_str" "+%Y-%m-%d")

      if [ "$days_left" -lt "$warn_days" ]; then
        has_breach="true"
        breach_count=$((breach_count + 1))
        if [ "$days_left" -lt 0 ]; then
          status="🚨 Expired"
          echo "[AUDIT] BREACH (Expired): $host:$port ($desc) - Expired $(( -1 * days_left )) day(s) ago ($formatted_date)"
        else
          status="⚠️ Expiring"
          echo "[AUDIT] BREACH (Expiring): $host:$port ($desc) - Expires in $days_left day(s) (threshold: ${warn_days}d, expiry: $formatted_date)"
        fi
        breach_rows+=$'\n'"| $status | $display_host | $desc | $formatted_date | ${days_left}d |"
        breach_obj=$(jq -n \
          --arg host "$host" \
          --arg desc "$desc" \
          --argjson port "$port" \
          --arg status "$status" \
          --arg expiry_date "$formatted_date" \
          --arg days_left "$days_left" \
          --arg threshold "$warn_days" \
          --arg assignees "$domain_assignees" \
          '{host: $host, description: $desc, port: $port, status: $status, expiry_date: $expiry_date, days_left: $days_left, threshold: $threshold, assignees: $assignees}')
        breaches_array+=("$breach_obj")
      else
        status="✅ Healthy"
        echo "[AUDIT] OK: $host:$port ($desc) - Expires in $days_left day(s) ($formatted_date)"
        healthy_obj=$(jq -n \
          --arg host "$host" \
          --arg desc "$desc" \
          --argjson port "$port" \
          --arg status "$status" \
          --arg expiry_date "$formatted_date" \
          --arg days_left "$days_left" \
          '{host: $host, description: $desc, port: $port, status: $status, expiry_date: $expiry_date, days_left: $days_left}')
        healthy_array+=("$healthy_obj")
      fi
      summary_rows+=$'\n'"| $status | $display_host | $desc | $formatted_date | ${days_left}d |"
    else
      has_breach="true"
      breach_count=$((breach_count + 1))
      status="❌ Unreachable"
      echo "[AUDIT] BREACH (Unreachable): $host:$port ($desc) - Invalid certificate date format: $expiry_str"
      breach_rows+=$'\n'"| $status | $display_host | $desc | N/A | N/A |"
      summary_rows+=$'\n'"| $status | $display_host | $desc | N/A | N/A |"
      breach_obj=$(jq -n \
        --arg host "$host" \
        --arg desc "$desc" \
        --argjson port "$port" \
        --arg status "$status" \
        --arg expiry_date "N/A" \
        --arg days_left "N/A" \
        --arg threshold "$warn_days" \
        --arg assignees "$domain_assignees" \
        '{host: $host, description: $desc, port: $port, status: $status, expiry_date: $expiry_date, days_left: $days_left, threshold: $threshold, assignees: $assignees}')
      breaches_array+=("$breach_obj")
    fi
  else
    has_breach="true"
    breach_count=$((breach_count + 1))
    status="❌ Unreachable"
    echo "[AUDIT] BREACH (Unreachable): $host:$port ($desc) - Connection or TLS handshake failed"
    breach_rows+=$'\n'"| $status | $display_host | $desc | N/A | N/A |"
    summary_rows+=$'\n'"| $status | $display_host | $desc | N/A | N/A |"
    breach_obj=$(jq -n \
      --arg host "$host" \
      --arg desc "$desc" \
      --argjson port "$port" \
      --arg status "$status" \
      --arg expiry_date "N/A" \
      --arg days_left "N/A" \
      --arg threshold "$warn_days" \
      --arg assignees "$domain_assignees" \
      '{host: $host, description: $desc, port: $port, status: $status, expiry_date: $expiry_date, days_left: $days_left, threshold: $threshold, assignees: $assignees}')
    breaches_array+=("$breach_obj")
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

The following domain(s) require immediate attention due to upcoming SSL/TLS certificate expiration or connection failures:

| Status | Host | Description | Expiry Date | Days Left |
| :--- | :--- | :--- | :--- | :--- |$breach_rows
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

| Status | Host | Description | Expiry Date | Days Left |
| :--- | :--- | :--- | :--- | :--- |$summary_rows
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
