#!/usr/bin/env python3
"""
Master Production Security & System Test Runner for Stationary Hub.
Executes all unit, security, integration, and boundary test suites
with structured metrics, timing, and pass/fail reporting.
"""

import sys
import time
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
PYTHON_EXE = ROOT_DIR / ".venv" / "bin" / "python"
if not PYTHON_EXE.exists():
    PYTHON_EXE = Path(sys.executable)

TEST_CATEGORIES = [
    ("Unit Tests - Password Hashing", "test/unit/test_password_hashing.py"),
    ("Unit Tests - JWT Token Lifecycle", "test/unit/test_jwt_tokens.py"),
    ("Unit Tests - Input & Password Complexity", "test/unit/test_input_validation.py"),
    ("Unit Tests - Password Reset Tokens", "test/unit/test_password_reset.py"),
    ("Unit Tests - OAuth Providers & State", "test/unit/test_oauth_providers.py"),
    ("Security Tests - SQL Injection Vectors", "test/security/test_sql_injection.py"),
    ("Security Tests - JWT Vulnerabilities & Replay", "test/security/test_jwt_vulnerabilities.py"),
    ("Security Tests - Rate Limiting & Brute Force", "test/security/test_rate_limiting.py"),
    ("Security Tests - Security Headers & CORS", "test/security/test_security_headers.py"),
    ("Security Tests - Password Reset Replay & Enumeration", "test/security/test_password_reset_security.py"),
    ("Security Tests - OAuth CSRF & State Replay", "test/security/test_oauth_security.py"),
    ("Security Tests - IDOR & Authorization Controls", "test/security/test_idor_authorization.py"),
    ("Integration Tests - Auth Lifecycle Workflow", "test/integration/test_auth_workflow.py"),
    ("Integration Tests - Token Rotation Chain", "test/integration/test_token_rotation.py"),
    ("Integration Tests - Orders & Dialogflow Webhook", "test/integration/test_order_security.py"),
    ("Integration Tests - Forgot Password Recovery Flow", "test/integration/test_forgot_password_flow.py"),
    ("Integration Tests - Social OAuth Authentication", "test/integration/test_social_oauth_flow.py"),
    ("Integration Tests - User Profile & Password Updates", "test/integration/test_user_profile_flow.py"),
    ("Integration Tests - Customer Order History & Reorder", "test/integration/test_order_history_flow.py"),
    ("Boundary Tests - Payload Limits & Unicode", "test/boundary/test_payload_boundaries.py"),
    ("Boundary Tests - Concurrency & Race Conditions", "test/boundary/test_concurrency.py"),
    ("Boundary Tests - Error Handling & Edge Cases", "test/boundary/test_error_handling.py"),
    ("Boundary Tests - Order Catalog & Quantities", "test/boundary/test_order_boundaries.py"),
    ("Boundary Tests - Reset Rate Limits & Weak Passwords", "test/boundary/test_reset_boundaries.py"),
]


def run_suite():
    print("=" * 75)
    print(" 🛡️  STATIONERY HUB: PRODUCTION SECURITY & BOUNDARY TEST SUITE")
    print("=" * 75)
    print(f" Python Interpreter: {PYTHON_EXE}")
    print(f" Test Root Directory: {ROOT_DIR / 'test'}\n")

    overall_start = time.time()
    results = []
    total_passed = 0
    total_failed = 0

    for title, test_path in TEST_CATEGORIES:
        full_path = ROOT_DIR / test_path
        print(f"Running: {title:<50} ... ", end="", flush=True)

        cmd = [
            str(PYTHON_EXE), "-m", "pytest",
            str(full_path),
            "-q", "--tb=short"
        ]

        t0 = time.time()
        res = subprocess.run(cmd, cwd=str(ROOT_DIR), capture_output=True, text=True)
        elapsed = time.time() - t0

        if res.returncode == 0:
            print(f"✅ PASSED ({elapsed:.2f}s)")
            results.append((title, "PASSED", elapsed, ""))
        else:
            print(f"❌ FAILED ({elapsed:.2f}s)")
            results.append((title, "FAILED", elapsed, res.stdout + "\n" + res.stderr))
            total_failed += 1

    overall_time = time.time() - overall_start

    print("\n" + "=" * 75)
    print(f" 📊 TEST EXECUTION SUMMARY (Elapsed: {overall_time:.2f}s)")
    print("=" * 75)
    print(f"{'Test Category':<52} | {'Status':<8} | {'Duration':<8}")
    print("-" * 75)
    for title, status_str, duration, _ in results:
        status_colored = "✅ PASS" if status_str == "PASSED" else "❌ FAIL"
        print(f"{title:<52} | {status_colored:<8} | {duration:.2f}s")
    print("-" * 75)

    if total_failed == 0:
        print(f"\n🎉 ALL {len(TEST_CATEGORIES)} TEST CATEGORIES PASSED WITH 100% SUCCESS!")
        print("   All security layers, boundary conditions, and production requirements verified.")
        return 0
    else:
        print(f"\n⚠️ {total_failed} TEST SUITES FAILED!")
        for title, status_str, _, output in results:
            if status_str == "FAILED":
                print(f"\n--- Output for {title} ---")
                print(output)
        return 1


if __name__ == "__main__":
    sys.exit(run_suite())
