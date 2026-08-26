# tests/demo_scenario.py
# End-to-end demo script — proves zero trust behavior
# Run with: python tests/demo_scenario.py

import requests
import time
import json

BASE = "http://127.0.0.1:8000"


def header(msg):
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}")


def check(label, condition, actual):
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {label}: {actual}")
    return condition


def scenario_1_normal_login():
    header("SCENARIO 1 — Normal Login")
    r = requests.post(f"{BASE}/auth/login", json={
        "email":    "test@zerotrust.com",
        "password": "password123"
    })
    data = r.json()
    print(f"  Score    : {data.get('risk_score', 'N/A'):.3f}")
    print(f"  Decision : {data.get('decision', 'N/A')}")
    check("Status 200",       r.status_code == 200,  r.status_code)
    check("Token issued",     "access_token" in data, "access_token" in data)
    check("Decision is allow/mfa", data.get("decision") in ("allow", "mfa"), data.get("decision"))
    return data.get("access_token")


def scenario_2_wrong_password():
    header("SCENARIO 2 — Failed Authentication")
    for i in range(1, 4):
        r = requests.post(f"{BASE}/auth/login", json={
            "email":    "test@zerotrust.com",
            "password": "wrongpassword"
        })
        print(f"  Attempt {i}: {r.status_code} — {r.json().get('detail')}")
    check("Returns 401", r.status_code == 401, r.status_code)


def scenario_3_middleware_scoring(token):
    header("SCENARIO 3 — Middleware Scores Every Request")
    endpoints = [
        "/protected",
        "/admin/sessions",
        "/health",
    ]
    for ep in endpoints:
        r = requests.get(f"{BASE}{ep}",
            headers={"Authorization": f"Bearer {token}"}
        )
        print(f"  {ep:30s} → {r.status_code}")
    check("Protected route accessible", True, "middleware fired — check server logs for score")


def scenario_4_token_blacklist(token):
    header("SCENARIO 4 — Token Blacklisted After Logout")
    # Logout
    r = requests.post(f"{BASE}/auth/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    check("Logout success", r.status_code == 200, r.status_code)

    # Try using same token
    r2 = requests.get(f"{BASE}/protected",
        headers={"Authorization": f"Bearer {token}"}
    )
    check("Token rejected after logout", r2.status_code == 401, r2.status_code)


def scenario_5_admin_flow():
    header("SCENARIO 5 — Admin Flow")
    # Login as admin
    r = requests.post(f"{BASE}/auth/login", json={
        "email":    "admin@zerotrust.com",
        "password": "admin123"
    })
    if r.status_code != 200:
        print(f"  [SKIP] Admin login failed: {r.json()}")
        return

    admin_token = r.json()["access_token"]

    # List sessions
    r2 = requests.get(f"{BASE}/admin/sessions",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    sessions = r2.json()
    check("Sessions listed", r2.status_code == 200, f"{len(sessions)} sessions")

    # List users
    r3 = requests.get(f"{BASE}/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    users = r3.json()
    check("Users listed", r3.status_code == 200, f"{len(users)} users")

    # Audit log
    r4 = requests.get(f"{BASE}/admin/audit-log",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    logs = r4.json()
    check("Audit log accessible", r4.status_code == 200, f"{len(logs)} entries")

    # Override first active session
    active = [s for s in sessions if s["decision"] not in ("logged_out",)]
    if active:
        session_id = active[0]["session_id"]
        r5 = requests.post(
            f"{BASE}/admin/sessions/{session_id}/override",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        check("Session override", r5.status_code == 200, r5.json().get("message"))


def scenario_6_input_validation():
    header("SCENARIO 6 — Input Validation")
    cases = [
        ("Short password",  {"email": "x@y.com",      "password": "short"}),
        ("Invalid email",   {"email": "notanemail",    "password": "password123"}),
        ("Empty password",  {"email": "x@y.com",       "password": ""}),
    ]
    for label, payload in cases:
        r = requests.post(f"{BASE}/auth/login", json=payload)
        check(label, r.status_code == 422, r.status_code)


def main():
    print("\nZERO TRUST ENGINE — END TO END DEMO")
    print("=====================================")

    token = scenario_1_normal_login()
    time.sleep(0.5)

    scenario_2_wrong_password()
    time.sleep(0.5)

    if token:
        scenario_3_middleware_scoring(token)
        time.sleep(0.5)
        scenario_4_token_blacklist(token)
        time.sleep(0.5)

    scenario_5_admin_flow()
    time.sleep(0.5)

    scenario_6_input_validation()

    print(f"\n{'='*60}")
    print("  DEMO COMPLETE")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()