#!/usr/bin/env bash
set -euo pipefail

echo "=== 1. Validating rules.yml syntax and schema with Python ==="
python3 -c "
import yaml, sys
data = yaml.safe_load(open('rules.yml'))
domains = data.get('monitoring', {}).get('domains', [])
if not domains:
    sys.exit('FAIL: No domains found in rules.yml')
for d in domains:
    host = d.get('host')
    assignees = d.get('assignees')
    if not host or not isinstance(host, str):
        sys.exit(f'FAIL: Domain missing valid host: {d}')
    if not assignees or not isinstance(assignees, list) or len(assignees) == 0:
        sys.exit(f'FAIL: Domain {host} must specify a non-empty assignees list')
    for a in assignees:
        if not isinstance(a, str) or not a.strip():
            sys.exit(f'FAIL: Domain {host} has invalid assignee: {a}')
"
echo "OK: rules.yml syntax and domain assignees are valid."

echo "=== 2. Running audit against current rules.yml ==="
bash scripts/check-certs.sh rules.yml
test -f ./.tmp/breaches.json
test -f ./.tmp/healthy.json
echo "OK: check-certs.sh completed and generated ./.tmp/breaches.json and ./.tmp/healthy.json."

echo "=== 3. Testing fail-fast validation against invalid configs ==="
TEST_TMP=$(mktemp -d)
trap 'rm -rf "$TEST_TMP"' EXIT

# Missing configuration file argument
if bash scripts/check-certs.sh >/dev/null 2>&1; then
  echo "FAIL: Expected failure on missing argument" >&2
  exit 1
fi

# Non-existent file
if bash scripts/check-certs.sh "$TEST_TMP/nonexistent.yml" >/dev/null 2>&1; then
  echo "FAIL: Expected failure on non-existent config file" >&2
  exit 1
fi

# Empty file
touch "$TEST_TMP/empty.yml"
if bash scripts/check-certs.sh "$TEST_TMP/empty.yml" >/dev/null 2>&1; then
  echo "FAIL: Expected failure on empty config" >&2
  exit 1
fi

# Missing required technical.warning_days
cat <<EOF > "$TEST_TMP/missing_warn.yml"
technical:
  timeout_seconds: 10
  port: 443
issue:
  title_prefix: "Test: "
monitoring:
  domains:
    - host: "example.com"
      description: "Example"
      assignees:
        - DerekRoberts
EOF
if bash scripts/check-certs.sh "$TEST_TMP/missing_warn.yml" >/dev/null 2>&1; then
  echo "FAIL: Expected failure on missing technical.warning_days" >&2
  exit 1
fi

# Missing domain assignees
cat <<EOF > "$TEST_TMP/missing_domain_assignees.yml"
technical:
  warning_days: 30
  timeout_seconds: 10
  port: 443
issue:
  title_prefix: "Test: "
monitoring:
  domains:
    - host: "example.com"
      description: "Example"
EOF
if bash scripts/check-certs.sh "$TEST_TMP/missing_domain_assignees.yml" >/dev/null 2>&1; then
  echo "FAIL: Expected failure on missing domain assignees" >&2
  exit 1
fi

# Empty domain assignees array
cat <<EOF > "$TEST_TMP/empty_domain_assignees.yml"
technical:
  warning_days: 30
  timeout_seconds: 10
  port: 443
issue:
  title_prefix: "Test: "
monitoring:
  domains:
    - host: "example.com"
      description: "Example"
      assignees: []
EOF
if bash scripts/check-certs.sh "$TEST_TMP/empty_domain_assignees.yml" >/dev/null 2>&1; then
  echo "FAIL: Expected failure on empty domain assignees" >&2
  exit 1
fi

# Invalid assignees format (must be array)
cat <<EOF > "$TEST_TMP/bad_assignees.yml"
technical:
  warning_days: 30
  timeout_seconds: 10
  port: 443
issue:
  title_prefix: "Test: "
monitoring:
  domains:
    - host: "example.com"
      description: "Example"
      assignees: "single-string-invalid"
EOF
if bash scripts/check-certs.sh "$TEST_TMP/bad_assignees.yml" >/dev/null 2>&1; then
  echo "FAIL: Expected failure on invalid domain assignees type" >&2
  exit 1
fi

echo "All config and engine verification tests passed!"
