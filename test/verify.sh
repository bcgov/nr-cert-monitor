#!/usr/bin/env bash
set -euo pipefail

echo "=== 1. Validating rules.yml syntax with Python ==="
python3 -c "import yaml; yaml.safe_load(open('rules.yml'))"
echo "OK: rules.yml is valid YAML."

echo "=== 2. Running audit against current rules.yml ==="
bash scripts/check-certs.sh rules.yml
test -f ./.tmp/breaches.json
echo "OK: check-certs.sh completed and generated ./.tmp/breaches.json."

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
  assignees:
    - DerekRoberts
monitoring:
  domains:
    - host: "example.com"
      description: "Example"
EOF
if bash scripts/check-certs.sh "$TEST_TMP/missing_warn.yml" >/dev/null 2>&1; then
  echo "FAIL: Expected failure on missing technical.warning_days" >&2
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
  assignees:
    - DerekRoberts
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
