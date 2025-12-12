import logging
import json
import os
from typing import Optional
import httpx
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakConnectionError as KCConnectionError

from .registration import register_client
from .exchange import exchange_token
from .cache import TokenCache
from .exceptions import (
    AgenticSecurityError,
    KeycloakConnectionError,
    InitialAccessTokenError,
    TokenExchangeError
)

logger = logging.getLogger("SecureAgent.core")


class AgentSecurity:
    def __init__(
        self,
        realm_url: str,
        service_name: str,
        initial_access_token: str = None,
        realm_name: str = "agent-mesh",
        creds_file: str = "credentials.json",
        require_auth: bool = True,
        fail_open: bool = False,
        cache_tokens: bool = True,
        cache_refresh_buffer: int = 30
    ):
        """
        Initializes the AgentSecurity framework.
        
        Args:
            realm_url: Base URL of the Keycloak server (e.g. http://localhost:8080)
            service_name: Name of this service/agent (used for client_id if registering)
            initial_access_token: Token used for dynamic registration if credentials don't exist.
            realm_name: Name of the Keycloak realm.
            creds_file: Path to store/read client credentials.
            require_auth: If True, verify_token will raise 401 on failure.
            fail_open: If True, return None instead of raising exceptions when 
                       Keycloak is unreachable (useful for development).
            cache_tokens: If True, cache tokens to reduce API calls.
            cache_refresh_buffer: Seconds before expiry to refresh cached tokens.
        """
        self.server_url = realm_url
        self.realm_name = realm_name
        self.service_name = service_name
        self.creds_file = creds_file
        self.keycloak_openid = None
        self.fail_open = fail_open
        self.cache_tokens = cache_tokens
        
        # Token cache for reducing API calls
        self._token_cache = TokenCache(refresh_buffer_seconds=cache_refresh_buffer) if cache_tokens else None
        
        # Store credentials for async operations
        self._client_id: Optional[str] = None
        self._client_secret: Optional[str] = None
        
        self._initialize(initial_access_token)
        
        # FastAPI Security Scheme
        # This points the Swagger UI to the right place
        self.oauth2_scheme = OAuth2PasswordBearer(
            tokenUrl=f"{self.server_url}/realms/{self.realm_name}/protocol/openid-connect/token"
        )

    def _initialize(self, initial_access_token):
        """Loads credentials or registers if missing."""
        client_id = None
        client_secret = None
        
        if os.path.exists(self.creds_file):
            logger.info(f"Loading existing credentials from {self.creds_file}...")
            try:
                with open(self.creds_file, "r") as f:
                    creds = json.load(f)
                    client_id = creds.get("client_id")
                    client_secret = creds.get("client_secret")
            except Exception as e:
                logger.warning(f"Failed to load credentials: {e}")
        
        if not client_id or not client_secret:
            if not initial_access_token:
                raise InitialAccessTokenError()
            
            logger.info("No credentials found. Initiating Auto-Registration...")
            creds = register_client(
                server_url=self.server_url,
                realm_name=self.realm_name,
                initial_access_token=initial_access_token,
                client_id=self.service_name,
                creds_file=self.creds_file
            )
            client_id = creds["client_id"]
            client_secret = creds["client_secret"]
        
        # Store for async operations
        self._client_id = client_id
        self._client_secret = client_secret
            
        # Initialize the Keycloak Client
        self.keycloak_openid = KeycloakOpenID(
            server_url=self.server_url,
            client_id=client_id,
            realm_name=self.realm_name,
            client_secret_key=client_secret
        )
        logger.info(f"AgentSecurity initialized for client: {client_id}")
    
    def get_token(self) -> Optional[str]:
        """
        Get an access token for this agent using client credentials flow.
        
        Returns:
            Access token string, or None if fail_open=True and Keycloak is unreachable.
            
        Raises:
            AgenticSecurityError: If not initialized or token retrieval fails 
                                  (unless fail_open=True).
        """
        if not self.keycloak_openid:
            if self.fail_open:
                logger.warning("AgentSecurity not initialized, returning None (fail_open=True)")
                return None
            raise AgenticSecurityError(
                "AgentSecurity not initialized with client credentials. Cannot get token."
            )
        
        cache_key = "client_credentials"
        
        # Check cache first
        if self._token_cache:
            cached = self._token_cache.get(cache_key)
            if cached:
                return cached
        
        try:
            # Get token using client credentials grant
            response = self.keycloak_openid.token(grant_type="client_credentials")
            access_token = response.get("access_token")
            
            if not access_token:
                raise AgenticSecurityError("No access token in response")
            
            # Cache the token
            if self._token_cache and "expires_in" in response:
                self._token_cache.set(
                    cache_key,
                    access_token,
                    expires_in=response["expires_in"],
                    scope=response.get("scope")
                )
            
            return access_token
            
        except KCConnectionError as e:
            if self.fail_open:
                logger.warning(f"Keycloak unreachable, returning None (fail_open=True): {e}")
                return None
            raise KeycloakConnectionError(f"Failed to connect to Keycloak: {e}")
        except Exception as e:
            if self.fail_open:
                logger.warning(f"Token retrieval failed, returning None (fail_open=True): {e}")
                return None
            raise AgenticSecurityError(f"Failed to get token: {e}")

    async def get_token_async(self) -> Optional[str]:
        """
        Async version of get_token(). Get an access token using client credentials flow.
        
        Returns:
            Access token string, or None if fail_open=True and Keycloak is unreachable.
        """
        if not self._client_id or not self._client_secret:
            if self.fail_open:
                logger.warning("AgentSecurity not initialized, returning None (fail_open=True)")
                return None
            raise AgenticSecurityError(
                "AgentSecurity not initialized with client credentials. Cannot get token."
            )
        
        cache_key = "client_credentials"
        
        # Check cache first
        if self._token_cache:
            cached = await self._token_cache.aget(cache_key)
            if cached:
                return cached
        
        token_url = f"{self.server_url}/realms/{self.realm_name}/protocol/openid-connect/token"
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    token_url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self._client_id,
                        "client_secret": self._client_secret
                    }
                )
                response.raise_for_status()
                data = response.json()
                
                access_token = data.get("access_token")
                if not access_token:
                    raise AgenticSecurityError("No access token in response")
                
                # Cache the token
                if self._token_cache and "expires_in" in data:
                    await self._token_cache.aset(
                        cache_key,
                        access_token,
                        expires_in=data["expires_in"],
                        scope=data.get("scope")
                    )
                
                return access_token
                
        except httpx.ConnectError as e:
            if self.fail_open:
                logger.warning(f"Keycloak unreachable, returning None (fail_open=True): {e}")
                return None
            raise KeycloakConnectionError(f"Failed to connect to Keycloak: {e}")
        except httpx.HTTPStatusError as e:
            if self.fail_open:
                logger.warning(f"Token retrieval failed, returning None (fail_open=True): {e}")
                return None
            raise AgenticSecurityError(f"Token request failed: {e}")
        except Exception as e:
            if self.fail_open:
                logger.warning(f"Token retrieval failed, returning None (fail_open=True): {e}")
                return None
            raise AgenticSecurityError(f"Failed to get token: {e}")

    def exchange_token(self, user_token: str, target_client: str) -> Optional[str]:
        """
        Exchanges the current user_token for a token valid for the target_client.
        
        Args:
            user_token: The token to exchange.
            target_client: The target client/audience for the new token.
            
        Returns:
            Exchanged access token, or None if fail_open=True and operation fails.
        """
        if not self.keycloak_openid:
            if self.fail_open:
                logger.warning("AgentSecurity not initialized, returning None (fail_open=True)")
                return None
            raise AgenticSecurityError(
                "AgentSecurity not initialized with client credentials. Cannot exchange tokens."
            )
        
        cache_key = f"exchange:{target_client}"
        
        # Check cache first
        if self._token_cache:
            cached = self._token_cache.get(cache_key)
            if cached:
                return cached
        
        try:
            access_token = exchange_token(self.keycloak_openid, user_token, target_client)
            
            # Cache for a shorter time since we don't know exact expiry
            if self._token_cache:
                self._token_cache.set(cache_key, access_token, expires_in=300)  # 5 min default
            
            return access_token
            
        except KCConnectionError as e:
            if self.fail_open:
                logger.warning(f"Keycloak unreachable, returning None (fail_open=True): {e}")
                return None
            raise KeycloakConnectionError(f"Failed to connect to Keycloak: {e}")
        except TokenExchangeError:
            raise  # Re-raise exchange-specific errors (like PolicyDenied)
        except Exception as e:
            if self.fail_open:
                logger.warning(f"Token exchange failed, returning None (fail_open=True): {e}")
                return None
            raise

    async def exchange_token_async(self, user_token: str, target_client: str) -> Optional[str]:
        """
        Async version of exchange_token().
        
        Args:
            user_token: The token to exchange.
            target_client: The target client/audience for the new token.
            
        Returns:
            Exchanged access token, or None if fail_open=True and operation fails.
        """
        if not self._client_id or not self._client_secret:
            if self.fail_open:
                logger.warning("AgentSecurity not initialized, returning None (fail_open=True)")
                return None
            raise AgenticSecurityError(
                "AgentSecurity not initialized with client credentials. Cannot exchange tokens."
            )
        
        cache_key = f"exchange:{target_client}"
        
        # Check cache first
        if self._token_cache:
            cached = await self._token_cache.aget(cache_key)
            if cached:
                return cached
        
        token_url = f"{self.server_url}/realms/{self.realm_name}/protocol/openid-connect/token"
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    token_url,
                    data={
                        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                        "subject_token": user_token,
                        "audience": target_client,
                        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token"
                    }
                )
                response.raise_for_status()
                data = response.json()
                
                access_token = data.get("access_token")
                if not access_token:
                    raise AgenticSecurityError("No access token in exchange response")
                
                # Cache the token
                if self._token_cache and "expires_in" in data:
                    await self._token_cache.aset(
                        cache_key,
                        access_token,
                        expires_in=data["expires_in"]
                    )
                
                return access_token
                
        except httpx.ConnectError as e:
            if self.fail_open:
                logger.warning(f"Keycloak unreachable, returning None (fail_open=True): {e}")
                return None
            raise KeycloakConnectionError(f"Failed to connect to Keycloak: {e}")
        except httpx.HTTPStatusError as e:
            if self.fail_open:
                logger.warning(f"Token exchange failed, returning None (fail_open=True): {e}")
                return None
            raise AgenticSecurityError(f"Token exchange failed: {e}")
        except Exception as e:
            if self.fail_open:
                logger.warning(f"Token exchange failed, returning None (fail_open=True): {e}")
                return None
            raise AgenticSecurityError(f"Failed to exchange token: {e}")

    def clear_cache(self, key: Optional[str] = None) -> None:
        """
        Clear cached tokens.
        
        Args:
            key: Optional specific cache key to clear. If None, clears all.
        """
        if self._token_cache:
            self._token_cache.clear(key)
        
    def get_verify_token_dependency(self):
        """
        Returns a FastAPI dependency for token verification.
        Usage: @app.get("/", dependencies=[Depends(security.verify_token)])
        OR
        def endpoint(token_payload = Depends(security.verify_token))
        """
        async def verify(token: str = Depends(self.oauth2_scheme)):
            try:
                # Local decoding (verify signature/exp) or Introspection
                # For high security/revocation check, we use introspection if we have a client.
                # If we don't have a client (public only), we decode.
                
                # We prefer introspection if we are an authenticated client (Resource Server)
                if self.keycloak_openid:
                    token_info = self.keycloak_openid.introspect(token)
                    if not token_info.get("active"):
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED, 
                            detail="Token invalid or expired (introspection)"
                        )
                    return token_info
                else:
                    # Fallback to local decoding if we have no client credentials?
                    # Or maybe we just configure a public client?
                    # For now, let's stick to introspection as per POC.
                    raise HTTPException(status_code=500, detail="Server not configured for introspection")
                    
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Token verification failed: {e}")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

        return verify

    # To make the instance itself callable or have a property that is the dependency:
    @property
    def verify_token(self):
         return self.get_verify_token_dependency()
