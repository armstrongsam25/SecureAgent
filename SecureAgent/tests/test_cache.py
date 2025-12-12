"""Tests for TokenCache."""
import pytest
import asyncio
from datetime import datetime, timedelta
from SecureAgent.cache import TokenCache, CachedToken


class TestTokenCache:
    """Tests for TokenCache class."""
    
    def test_set_and_get_token(self):
        """Test basic set and get operations."""
        cache = TokenCache()
        
        cache.set("test-key", "test-token", expires_in=300)
        result = cache.get("test-key")
        
        assert result == "test-token"
    
    def test_get_returns_none_for_missing_key(self):
        """Test that get returns None for missing keys."""
        cache = TokenCache()
        
        result = cache.get("nonexistent")
        
        assert result is None
    
    def test_expired_token_returns_none(self):
        """Test that expired tokens return None."""
        cache = TokenCache(refresh_buffer_seconds=0)
        
        # Set a token with minimal expiry
        cache.set("test-key", "test-token", expires_in=0)
        
        # Should return None since it's expired
        result = cache.get("test-key")
        
        assert result is None
    
    def test_refresh_buffer(self):
        """Test that tokens are refreshed before actual expiry."""
        cache = TokenCache(refresh_buffer_seconds=60)
        
        # Set a token expiring in 30 seconds
        # With 60 second buffer, it should be considered expired
        cache.set("test-key", "test-token", expires_in=30)
        
        result = cache.get("test-key")
        
        assert result is None  # Should be None due to buffer
    
    def test_clear_specific_key(self):
        """Test clearing a specific cache key."""
        cache = TokenCache()
        
        cache.set("key1", "token1", expires_in=300)
        cache.set("key2", "token2", expires_in=300)
        
        cache.clear("key1")
        
        assert cache.get("key1") is None
        assert cache.get("key2") == "token2"
    
    def test_clear_all(self):
        """Test clearing all cache entries."""
        cache = TokenCache()
        
        cache.set("key1", "token1", expires_in=300)
        cache.set("key2", "token2", expires_in=300)
        
        cache.clear()
        
        assert cache.get("key1") is None
        assert cache.get("key2") is None


class TestTokenCacheAsync:
    """Tests for async TokenCache operations."""
    
    @pytest.mark.asyncio
    async def test_async_set_and_get(self):
        """Test async set and get operations."""
        cache = TokenCache()
        
        await cache.aset("async-key", "async-token", expires_in=300)
        result = await cache.aget("async-key")
        
        assert result == "async-token"
    
    @pytest.mark.asyncio
    async def test_async_expired_token(self):
        """Test that expired tokens return None in async."""
        cache = TokenCache(refresh_buffer_seconds=0)
        
        await cache.aset("test-key", "test-token", expires_in=0)
        result = await cache.aget("test-key")
        
        assert result is None
