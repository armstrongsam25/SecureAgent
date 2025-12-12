"""Tests for async token operations."""
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
import json


@pytest.fixture
def security_with_creds(mocker, tmp_path):
    """Create AgentSecurity with mocked credentials file."""
    mocker.patch("SecureAgent.core.KeycloakOpenID")
    
    creds_file = tmp_path / "credentials.json"
    creds_file.write_text(json.dumps({
        "client_id": "test-client",
        "client_secret": "test-secret",
        "server_url": "http://localhost:8080",
        "realm_name": "test-realm"
    }))
    
    from SecureAgent.core import AgentSecurity
    return AgentSecurity(
        realm_url="http://localhost:8080",
        service_name="test-client",
        realm_name="test-realm",
        creds_file=str(creds_file)
    )


class TestAsyncGetToken:
    """Tests for get_token_async() method."""
    
    @pytest.mark.asyncio
    async def test_get_token_async_success(self, security_with_creds, mocker):
        """Test successful async token retrieval."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "async-test-token",
            "expires_in": 300,
            "token_type": "Bearer"
        }
        mock_response.raise_for_status = MagicMock()
        
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.post.return_value = mock_response
        
        mocker.patch("httpx.AsyncClient", return_value=mock_client)
        
        # Clear cache first
        security_with_creds.clear_cache()
        
        token = await security_with_creds.get_token_async()
        
        assert token == "async-test-token"
    
    @pytest.mark.asyncio
    async def test_get_token_async_cached(self, security_with_creds, mocker):
        """Test that async tokens are cached."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "async-test-token",
            "expires_in": 300
        }
        mock_response.raise_for_status = MagicMock()
        
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.post.return_value = mock_response
        
        mock_async_client = mocker.patch("httpx.AsyncClient", return_value=mock_client)
        
        # Clear cache first
        security_with_creds.clear_cache()
        
        # First call
        token1 = await security_with_creds.get_token_async()
        # Second call should use cache
        token2 = await security_with_creds.get_token_async()
        
        assert token1 == token2 == "async-test-token"
        # Should only create client once due to caching
        assert mock_async_client.call_count == 1


class TestAsyncExchangeToken:
    """Tests for exchange_token_async() method."""
    
    @pytest.mark.asyncio
    async def test_exchange_token_async_success(self, security_with_creds, mocker):
        """Test successful async token exchange."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "exchanged-token",
            "expires_in": 300
        }
        mock_response.raise_for_status = MagicMock()
        
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value.post.return_value = mock_response
        
        mocker.patch("httpx.AsyncClient", return_value=mock_client)
        
        # Clear cache first
        security_with_creds.clear_cache()
        
        token = await security_with_creds.exchange_token_async(
            user_token="user-token",
            target_client="target-service"
        )
        
        assert token == "exchanged-token"
