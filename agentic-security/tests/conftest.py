import pytest
import os
import sys

# Add src to python path so we can import agentic_security
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

@pytest.fixture
def mock_keycloak(mocker):
    """
    Mock the KeycloakOpenID class
    """
    return mocker.patch("agentic_security.registration.KeycloakOpenID")

@pytest.fixture
def mock_env_setup(monkeypatch):
    """
    Setup environment variables if needed
    """
    monkeypatch.setenv("KEYCLOAK_SERVER_URL", "http://localhost:8080")
    monkeypatch.setenv("KEYCLOAK_REALM", "test-realm")
