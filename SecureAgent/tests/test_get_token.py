"""Tests for get_token() method and token caching."""
import pytest
from unittest.mock import MagicMock, patch
from SecureAgent.core import AgentSecurity
from SecureAgent.exceptions import AgenticSecurityError, KeycloakConnectionError


@pytest.fixture
def mock_keycloak_openid(mocker):
    """Mock the KeycloakOpenID class."""
    mock = mocker.patch("SecureAgent.core.KeycloakOpenID")
    instance = MagicMock()
    mock.return_value = instance
    return instance


@pytest.fixture
def security_with_creds(mock_keycloak_openid, tmp_path):
    """Create AgentSecurity with mocked credentials file."""
    import json
    creds_file = tmp_path / "credentials.json"
    creds_file.write_text(json.dumps({
        "client_id": "test-client",
        "client_secret": "test-secret",
        "server_url": "http://localhost:8080",
        "realm_name": "test-realm"
    }))
    
    return AgentSecurity(
        realm_url="http://localhost:8080",
        service_name="test-client",
        realm_name="test-realm",
        creds_file=str(creds_file)
    )


class TestGetToken:
    """Tests for get_token() method."""
    
    def test_get_token_success(self, security_with_creds, mock_keycloak_openid):
        """Test successful token retrieval."""
        mock_keycloak_openid.token.return_value = {
            "access_token": "test-access-token",
            "expires_in": 300,
            "token_type": "Bearer"
        }
        
        token = security_with_creds.get_token()
        
        assert token == "test-access-token"
        mock_keycloak_openid.token.assert_called_once_with(grant_type="client_credentials")
    
    def test_get_token_cached(self, security_with_creds, mock_keycloak_openid):
        """Test that tokens are cached."""
        mock_keycloak_openid.token.return_value = {
            "access_token": "test-access-token",
            "expires_in": 300,
            "token_type": "Bearer"
        }
        
        # First call should hit Keycloak
        token1 = security_with_creds.get_token()
        # Second call should use cache
        token2 = security_with_creds.get_token()
        
        assert token1 == token2 == "test-access-token"
        # Should only call Keycloak once due to caching
        mock_keycloak_openid.token.assert_called_once()
    
    def test_get_token_no_cache(self, mock_keycloak_openid, tmp_path):
        """Test token retrieval with caching disabled."""
        import json
        creds_file = tmp_path / "credentials.json"
        creds_file.write_text(json.dumps({
            "client_id": "test-client",
            "client_secret": "test-secret"
        }))
        
        security = AgentSecurity(
            realm_url="http://localhost:8080",
            service_name="test-client",
            creds_file=str(creds_file),
            cache_tokens=False
        )
        
        mock_keycloak_openid.token.return_value = {
            "access_token": "test-access-token",
            "expires_in": 300
        }
        
        security.get_token()
        security.get_token()
        
        # Should call Keycloak twice without caching
        assert mock_keycloak_openid.token.call_count == 2


class TestFailOpen:
    """Tests for fail_open mode."""
    
    def test_fail_open_returns_none_on_error(self, mock_keycloak_openid, tmp_path):
        """Test that fail_open=True returns None instead of raising."""
        import json
        from keycloak.exceptions import KeycloakConnectionError as KCConnectionError
        
        creds_file = tmp_path / "credentials.json"
        creds_file.write_text(json.dumps({
            "client_id": "test-client",
            "client_secret": "test-secret"
        }))
        
        security = AgentSecurity(
            realm_url="http://localhost:8080",
            service_name="test-client",
            creds_file=str(creds_file),
            fail_open=True
        )
        
        mock_keycloak_openid.token.side_effect = KCConnectionError("Connection refused")
        
        result = security.get_token()
        
        assert result is None
    
    def test_fail_open_false_raises_error(self, mock_keycloak_openid, tmp_path):
        """Test that fail_open=False raises exceptions."""
        import json
        from keycloak.exceptions import KeycloakConnectionError as KCConnectionError
        
        creds_file = tmp_path / "credentials.json"
        creds_file.write_text(json.dumps({
            "client_id": "test-client",
            "client_secret": "test-secret"
        }))
        
        security = AgentSecurity(
            realm_url="http://localhost:8080",
            service_name="test-client",
            creds_file=str(creds_file),
            fail_open=False
        )
        
        mock_keycloak_openid.token.side_effect = KCConnectionError("Connection refused")
        
        with pytest.raises(KeycloakConnectionError):
            security.get_token()
