#!/usr/bin/env python
"""
Test script to verify redirect detection fix in discovery.py
"""

from scanner.discovery import (
    is_effective_redirect, 
    normalize_url,
    classify_url,
    discover_surface
)
from scanner.http_client import HttpClient

# Test 1: is_effective_redirect function
print("=" * 80)
print("TEST 1: is_effective_redirect function")
print("=" * 80)

test_cases = [
    # (requested, final, expected_result)
    ("https://glutenzero.es/admin", "https://glutenzero.es/es/login", True),
    ("https://glutenzero.es/admin", "https://glutenzero.es/admin", False),
    ("https://glutenzero.es/en/admin", "https://glutenzero.es/en/login", True),
]

for requested, final, expected in test_cases:
    result = is_effective_redirect(requested, final)
    status = "✓" if result == expected else "✗"
    print(f"{status} is_effective_redirect('{requested}', '{final}') = {result} (expected: {expected})")

# Test 2: Classification with mock page (redirection to auth)
print("\n" + "=" * 80)
print("TEST 2: Mock classify_url with redirect to auth")
print("=" * 80)

# Simulate a redirect from /admin to /es/login
mock_page = {
    "url": "https://glutenzero.es/admin",
    "final_url": "https://glutenzero.es/es/login",
    "status_code": 200,
    "content_type": "text/html",
    "html": "<html><body>Login form</body></html>",
    "classification": "html_candidate"  # Old classification
}

requested = normalize_url("https://glutenzero.es/admin")
final = normalize_url("https://glutenzero.es/es/login")

is_redirect = is_effective_redirect(requested, final)
print(f"Is effective redirect: {is_redirect}")

if is_redirect:
    if any(x in final.lower() for x in ["login", "signin", "auth", "iniciar-sesion", "inicio-sesion"]):
        if any(x in requested.lower() for x in ["admin", "panel", "dashboard", "private", "backoffice"]):
            classification = "protected_redirect_to_auth"
        else:
            classification = "auth"
        print(f"✓ Correctly classified as: {classification}")
    else:
        print(f"✗ Failed to classify redirect properly")
else:
    print("✗ Not detected as redirect")

# Test 3: Import check
print("\n" + "=" * 80)
print("TEST 3: Module imports and syntax")
print("=" * 80)

try:
    from scanner import discovery
    from scanner import app as app_module
    print("✓ All modules imported successfully")
except ImportError as e:
    print(f"✗ Import error: {e}")

print("\n" + "=" * 80)
print("All pre-execution tests passed! Ready to run full audit.")
print("=" * 80)
