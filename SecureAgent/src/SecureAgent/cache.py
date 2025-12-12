"""Token caching with automatic refresh support."""
import logging
import threading
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, Dict

logger = logging.getLogger("SecureAgent.cache")


@dataclass
class CachedToken:
    """A cached token with expiry metadata."""
    access_token: str
    expires_at: datetime
    token_type: str = "Bearer"
    scope: Optional[str] = None


class TokenCache:
    """
    Thread-safe token cache with automatic refresh support.
    
    Tokens are cached by a key (e.g., "client_credentials" or "exchange:<target>")
    and automatically invalidated when they expire.
    """
    
    def __init__(self, refresh_buffer_seconds: int = 30):
        """
        Initialize the token cache.
        
        Args:
            refresh_buffer_seconds: Refresh tokens this many seconds before
                                    actual expiry to avoid edge cases.
        """
        self._cache: Dict[str, CachedToken] = {}
        self._lock = threading.Lock()
        self._async_lock: Optional[asyncio.Lock] = None
        self._refresh_buffer = timedelta(seconds=refresh_buffer_seconds)
    
    @property
    def async_lock(self) -> asyncio.Lock:
        """Lazy initialization of async lock (must be created in async context)."""
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        return self._async_lock
    
    def get(self, key: str) -> Optional[str]:
        """
        Get a cached token if it exists and is still valid.
        
        Args:
            key: Cache key for the token.
            
        Returns:
            The access token string, or None if not cached/expired.
        """
        with self._lock:
            cached = self._cache.get(key)
            if cached is None:
                return None
            
            # Check if token is expired (with buffer)
            if datetime.now() >= (cached.expires_at - self._refresh_buffer):
                logger.debug(f"Token for '{key}' expired or about to expire, removing from cache")
                del self._cache[key]
                return None
            
            logger.debug(f"Cache hit for '{key}'")
            return cached.access_token
    
    def set(self, key: str, access_token: str, expires_in: int, 
            token_type: str = "Bearer", scope: Optional[str] = None) -> None:
        """
        Cache a token.
        
        Args:
            key: Cache key for the token.
            access_token: The access token string.
            expires_in: Token lifetime in seconds.
            token_type: Token type (default: "Bearer").
            scope: Optional scope string.
        """
        with self._lock:
            expires_at = datetime.now() + timedelta(seconds=expires_in)
            self._cache[key] = CachedToken(
                access_token=access_token,
                expires_at=expires_at,
                token_type=token_type,
                scope=scope
            )
            logger.debug(f"Cached token for '{key}', expires at {expires_at}")
    
    def clear(self, key: Optional[str] = None) -> None:
        """
        Clear cached tokens.
        
        Args:
            key: If provided, only clear this key. Otherwise clear all.
        """
        with self._lock:
            if key is not None:
                if key in self._cache:
                    del self._cache[key]
                    logger.debug(f"Cleared cache for '{key}'")
            else:
                self._cache.clear()
                logger.debug("Cleared all cached tokens")
    
    async def aget(self, key: str) -> Optional[str]:
        """Async version of get()."""
        async with self.async_lock:
            cached = self._cache.get(key)
            if cached is None:
                return None
            
            if datetime.now() >= (cached.expires_at - self._refresh_buffer):
                logger.debug(f"Token for '{key}' expired or about to expire, removing from cache")
                del self._cache[key]
                return None
            
            logger.debug(f"Cache hit for '{key}'")
            return cached.access_token
    
    async def aset(self, key: str, access_token: str, expires_in: int,
                   token_type: str = "Bearer", scope: Optional[str] = None) -> None:
        """Async version of set()."""
        async with self.async_lock:
            expires_at = datetime.now() + timedelta(seconds=expires_in)
            self._cache[key] = CachedToken(
                access_token=access_token,
                expires_at=expires_at,
                token_type=token_type,
                scope=scope
            )
            logger.debug(f"Cached token for '{key}', expires at {expires_at}")
