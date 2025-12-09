import sys
import os
import logging
import asyncio
from fastapi import FastAPI, Depends

# Add the package to sys.path to verify without installing
sys.path.append(os.path.join(os.getcwd(), "agentic-security", "src"))

try:
    from agentic_security import AgentSecurity
    from agentic_security.exceptions import AgenticSecurityError
    print("✅ Package imported successfully.")
except ImportError as e:
    print(f"❌ Failed to import package: {e}")
    sys.exit(1)

# Mocking Keycloak interaction for structure verification
# We don't want to actually hit the network in this basic structure test
# unless we really want to test integration.
# Let's do a basic instantiation test.

def test_instantiation():
    print("Testing instantiation...")
    try:
        # We purposely don't provide an IAT so it doesn't try to register
        # and we don't have creds, so it should log a warning but not crash.
        security = AgentSecurity(
            realm_url="http://localhost:8080",
            service_name="test-agent",
            creds_file="non_existent_creds.json"
        )
        print("✅ Instantiation successful (mock mode).")
        return security
    except Exception as e:
        print(f"❌ Instantiation failed: {e}")
        return None

def test_dependency_structure(security):
    print("Testing dependency structure...")
    if hasattr(security, "verify_token"):
        print("✅ verify_token property exists.")
    else:
        print("❌ verify_token property missing.")

if __name__ == "__main__":
    security = test_instantiation()
    if security:
        test_dependency_structure(security)
    print("Verification script finished.")
