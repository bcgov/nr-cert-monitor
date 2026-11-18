#!/usr/bin/env bash
set -euo pipefail

echo "=== 1. Validating rules.yml syntax and schema with Python ==="
python3 -c "
import yaml, sys
data = yaml.safe_load(open('rules.yml'))
if 'warning_days' in data.get('technical', {}):
    sys.exit('FAIL: technical.warning_days must not be set in rules.yml')
domains = data.get('monitoring', {}).get('domains', [])
if not domains:
    sys.exit('FAIL: No domains found in rules.yml')
for d in domains:
    host = d.get('host')
    if 'warning_days' in d:
        sys.exit(f'FAIL: Domain {host} must not set warning_days')
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
PIDS_FILE="${TEST_TMP}/pids"
cleanup() {
  if [ -f "$PIDS_FILE" ]; then
    xargs -r kill < "$PIDS_FILE" 2>/dev/null || true
  fi
  rm -rf "$TEST_TMP"
}
trap cleanup EXIT

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

# Removed technical.warning_days must fail fast
cat <<EOF > "$TEST_TMP/legacy_warn.yml"
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
      assignees:
        - DerekRoberts
EOF
if bash scripts/check-certs.sh "$TEST_TMP/legacy_warn.yml" >/dev/null 2>&1; then
  echo "FAIL: Expected failure when technical.warning_days is present" >&2
  exit 1
fi

# Removed domain-level warning_days must fail fast
cat <<EOF > "$TEST_TMP/domain_warn.yml"
technical:
  timeout_seconds: 10
  port: 443
issue:
  title_prefix: "Test: "
monitoring:
  domains:
    - host: "example.com"
      description: "Example"
      warning_days: 15
      assignees:
        - DerekRoberts
EOF
if bash scripts/check-certs.sh "$TEST_TMP/domain_warn.yml" >/dev/null 2>&1; then
  echo "FAIL: Expected failure when domain warning_days is present" >&2
  exit 1
fi

# Missing domain assignees
cat <<EOF > "$TEST_TMP/missing_domain_assignees.yml"
technical:
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
echo "OK: Fail-fast validation passed."

echo "=== 4. Testing 1/3 lifetime minus 3d, hostname coverage, expiry, and unreachable ==="
openssl req -x509 -newkey rsa:2048 -keyout "${TEST_TMP}/key.pem" -out "${TEST_TMP}/ok.pem" \
  -not_before "$(date -u -d '61 days ago' +%Y%m%d%H%M%SZ)" \
  -not_after "$(date -u -d '29 days' +%Y%m%d%H%M%SZ)" \
  -nodes -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null
openssl req -x509 -key "${TEST_TMP}/key.pem" -out "${TEST_TMP}/soon.pem" \
  -not_before "$(date -u -d '70 days ago' +%Y%m%d%H%M%SZ)" \
  -not_after "$(date -u -d '20 days' +%Y%m%d%H%M%SZ)" \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null
openssl req -x509 -key "${TEST_TMP}/key.pem" -out "${TEST_TMP}/other.pem" \
  -days 365 -subj "/CN=example.invalid" -addext "subjectAltName=DNS:example.invalid" 2>/dev/null
openssl req -x509 -key "${TEST_TMP}/key.pem" -out "${TEST_TMP}/old.pem" \
  -not_before 20200101000000Z -not_after 20210101000000Z \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null

read -r OK_PORT SOON_PORT OTHER_PORT OLD_PORT CLOSED_PORT < <(python3 -c '
import socket
s = [socket.socket() for _ in range(5)]
for x in s: x.bind(("127.0.0.1", 0))
print(*[x.getsockname()[1] for x in s])
for x in s: x.close()
')

for pair in "ok:${OK_PORT}" "soon:${SOON_PORT}" "other:${OTHER_PORT}" "old:${OLD_PORT}"; do
  openssl s_server -quiet -accept "127.0.0.1:${pair#*:}" -cert "${TEST_TMP}/${pair%%:*}.pem" -key "${TEST_TMP}/key.pem" -www </dev/null >/dev/null 2>&1 &
  echo "$!" >> "$PIDS_FILE"
done

for port in "$OK_PORT" "$SOON_PORT" "$OTHER_PORT" "$OLD_PORT"; do
  for _ in $(seq 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
      exec 3>&-
      break
    fi
    sleep 0.1
  done
done

cat <<EOF > "${TEST_TMP}/local_rules.yml"
technical:
  timeout_seconds: 2
  port: 443
issue:
  title_prefix: "Test: "
monitoring:
  domains:
    - host: "localhost"
      description: "Healthy 90d cert with 29d left (margin check)"
      port: ${OK_PORT}
      assignees:
        - DerekRoberts
    - host: "localhost"
      description: "Expiring 90d cert with 20d left"
      port: ${SOON_PORT}
      assignees:
        - DerekRoberts
    - host: "localhost"
      description: "Uncovered cert for another host"
      port: ${OTHER_PORT}
      assignees:
        - DerekRoberts
    - host: "localhost"
      description: "Expired cert"
      port: ${OLD_PORT}
      assignees:
        - DerekRoberts
    - host: "localhost"
      description: "Unreachable port"
      port: ${CLOSED_PORT}
      assignees:
        - DerekRoberts
EOF

bash scripts/check-certs.sh "${TEST_TMP}/local_rules.yml"

jq -e --argjson p "$OK_PORT" 'length == 1 and .[0].port == $p and .[0].lifetime_days == "90"' ./.tmp/healthy.json >/dev/null
jq -e --argjson p "$SOON_PORT" 'any(.[]; .port == $p and .state == "expiring" and .lifetime_days == "90" and .threshold == "27")' ./.tmp/breaches.json >/dev/null
jq -e --argjson p "$OTHER_PORT" 'any(.[]; .port == $p and .state == "uncovered")' ./.tmp/breaches.json >/dev/null
jq -e --argjson p "$OLD_PORT" 'any(.[]; .port == $p and .state == "expired")' ./.tmp/breaches.json >/dev/null
jq -e --argjson p "$CLOSED_PORT" 'any(.[]; .port == $p and .state == "unreachable")' ./.tmp/breaches.json >/dev/null
jq -e 'length == 4' ./.tmp/breaches.json >/dev/null

echo "All config and engine verification tests passed!"
