#!/usr/bin/env bash
set -euo pipefail

BASE="http://localhost:8000"
EMAIL="smoke@example.com"
PASS="Password123"
ADMIN_EMAIL="admin@example.com"
ADMIN_PASS="AdminPass123"

echo "=== Smoke test start ==="

cleanup() {
  redis-cli -n 0 DEL "failed:${EMAIL}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Helper to print step result
step() {
  local name=$1
  shift
  echo -n "[$name] "
  if "$@"; then
    echo "PASS"
  else
    echo "FAIL"
    exit 1
  fi
}

# 1. Register a normal user (if endpoint exists) else assume exists
# We'll just attempt login; if fails, we cannot continue.
login_user() {
  resp=$(curl -s -w "\n%{http_code}" -X POST "$BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}")
  http_code=$(echo "$resp" | tail -n1)
  body=$(echo "$resp" | sed '$d')
  if [[ $http_code == 200 ]]; then
    ACCESS_TOKEN=$(echo "$body" | jq -r .access_token)
    MFA_REQUIRED=$(echo "$body" | jq -r .mfa_required)
    echo "$ACCESS_TOKEN" > /tmp/user_token.txt
    echo "$MFA_REQUIRED" > /tmp/user_mfa_required.txt
    return 0
  else
    return 1
  fi
}
step "User login" login_user

# 2. /auth/me
me() {
  token=$(cat /tmp/user_token.txt)
  resp=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer $token" "$BASE/auth/me")
  http_code=$(echo "$resp" | tail -n1)
  [[ $http_code == 200 ]]
}
step "GET /auth/me" me

# 3. MFA setup (if not enrolled)
mfa_setup() {
  token=$(cat /tmp/user_token.txt)
  resp=$(curl -s -w "\n%{http_code}" -X POST "$BASE/auth/mfa/setup" \
    -H "Authorization: Bearer $token" -H "Content-Type: application/json")
  http_code=$(echo "$resp" | tail -n1)
  body=$(echo "$resp" | sed '$d')
  if [[ $http_code == 200 ]]; then
    SECRET=$(echo "$body" | jq -r .secret)
    echo "$SECRET" > /tmp/mfa_secret.txt
    return 0
  else
    return 1
  fi
}
if [[ $(cat /tmp/user_mfa_required.txt) == "true" || $(cat /tmp/user_mfa_required.txt) == "false" ]]; then
  # check enrolled via login response mfa_enrolled
  enrolled=$(curl -s -X POST "$BASE/auth/login" -H "Content-Type: application/json" -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" | jq -r .mfa_enrolled)
  if [[ $enrolled == "false" ]]; then
    step "MFA setup" mfa_setup
  fi
fi

# 4. MFA verify with a generated code (using oathtool if available)
mfa_verify() {
  token=$(cat /tmp/user_token.txt)
  secret=$(cat /tmp/mfa_secret.txt)
  if command -v oathtool >/dev/null; then
    code=$(oathtool --base32 --totp "$secret")
  else
    echo "oathtool not installed, skipping verify"
    return 1
  fi
  resp=$(curl -s -w "\n%{http_code}" -X POST "$BASE/auth/mfa/verify" \
    -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
    -d "{\"code\":\"$code\"}")
  http_code=$(echo "$resp" | tail -n1)
  [[ $http_code == 200 ]]
}
step "MFA verify" mfa_verify

# 5. Admin login (assume admin exists)
login_admin() {
  resp=$(curl -s -w "\n%{http_code}" -X POST "$BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASS\"}")
  http_code=$(echo "$resp" | tail -n1)
  body=$(echo "$resp" | sed '$d')
  if [[ $http_code == 200 ]]; then
    ADMIN_TOKEN=$(echo "$body" | jq -r .access_token)
    echo "$ADMIN_TOKEN" > /tmp/admin_token.txt
    return 0
  else
    return 1
  fi
}
step "Admin login" login_admin

admin_token() { cat /tmp/admin_token.txt; }

# 6. Admin endpoints
admin_get() {
  local path=$1
  resp=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer $(admin_token)" "$BASE$path")
  http_code=$(echo "$resp" | tail -n1)
  [[ $http_code == 200 ]]
}
step "GET /admin/sessions" admin_get "/admin/sessions"
step "GET /admin/users" admin_get "/admin/users"
step "GET /admin/audit-log" admin_get "/admin/audit-log"
step "GET /admin/threshold" admin_get "/admin/threshold"
step "GET /admin/alerts" admin_get "/admin/alerts"
step "GET /admin/risk-events" admin_get "/admin/risk-events"
step "GET /admin/model-versions" admin_get "/admin/model-versions"
step "GET /admin/stats" admin_get "/admin/stats"

# 7. Risky login path: three wrong logins then correct, expecting mfa_required:true
risky_login() {
  # reset failed counter
  redis-cli -n 0 DEL "failed:risky@example.com" >/dev/null 2>&1 || true
  for i in {1..3}; do
    resp=$(curl -s -w "\n%{http_code}" -X POST "$BASE/auth/login" \
      -H "Content-Type: application.json" -d "{\"email\":\"risky@example.com\",\"password\":\"WrongPass123\"}")
    http_code=$(echo "$resp" | tail -n1)
    # expect 401
    if [[ $http_code != 401 ]]; then return 1; fi
  done
  # correct password (assume user exists with password Password123)
  resp=$(curl -s -w "\n%{http_code}" -X POST "$BASE/auth/login" \
    -H "Content-Type: application/json" -d "{\"email\":\"risky@example.com\",\"password\":\"Password123\"}")
  http_code=$(echo "$resp" | tail -n1)
  body=$(echo "$resp" | sed '$d')
  if [[ $http_code == 200 ]]; then
    mfa_req=$(echo "$body" | jq -r .mfa_required)
    [[ $mfa_req == "true" ]]
  else
    return 1
  fi
}
step "Risky login triggers MFA" risky_login

echo "=== All smoke tests passed ==="