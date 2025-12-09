import pytest
import os
import json
from unittest.mock import MagicMock
from agentic_security.registration import register_client, RegistrationError

def test_register_client_success(mock_keycloak, tmp_path):
    # Mock return values
    mock_instance = MagicMock()
    mock_keycloak.return_value = mock_instance
    
    mock_instance.register_client.return_value = {
        "clientId": "test-client-id",
        "secret": "test-client-secret"
    }
    
    # Temporary creds file
    creds_file = tmp_path / "credentials.json"
    
    # Call function
    creds = register_client(
        server_url="http://localhost:8080",
        realm_name="test-realm",
        initial_access_token="iat-token",
        client_id="my-client",
        creds_file=str(creds_file)
    )
    
    # Assertions
    assert creds["client_id"] == "test-client-id"
    assert creds["client_secret"] == "test-client-secret"
    assert creds["realm_name"] == "test-realm"
    
    # Check file was written
    assert creds_file.exists()
    with open(creds_file, "r") as f:
        saved_creds = json.load(f)
        assert saved_creds["client_id"] == "test-client-id"

    # Verify Mock calls
    mock_keycloak.assert_called_with(
        server_url="http://localhost:8080",
        client_id="temp-reg",
        realm_name="test-realm"
    )
    
    mock_instance.register_client.assert_called_once()
    call_args = mock_instance.register_client.call_args
    assert call_args.kwargs["token"] == "iat-token"
    assert call_args.kwargs["payload"]["clientId"] == "my-client"
    assert call_args.kwargs["payload"]["serviceAccountsEnabled"] is True


def test_register_client_failure(mock_keycloak):
    mock_instance = MagicMock()
    mock_keycloak.return_value = mock_instance
    
    mock_instance.register_client.side_effect = Exception("Keycloak error")
    
    with pytest.raises(RegistrationError) as excinfo:
        register_client(
            server_url="http://localhost:8080",
            realm_name="test-realm",
            initial_access_token="iat-token",
            client_id="my-client"
        )
    
    assert "Failed to register client my-client" in str(excinfo.value)
