import logging
import json
import os
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from keycloak import KeycloakOpenID

from .registration import register_client
from .exchange import exchange_token
from .exceptions import AgenticSecurityError

logger = logging.getLogger("agentic-security.core")

class AgentSecurity:
    def __init__(
        self,
        realm_url: str,
        service_name: str,
        initial_access_token: str = None,
        realm_name: str = "agent-mesh",
        creds_file: str = "credentials.json",
        require_auth: bool = True
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
        """
        self.server_url = realm_url
        self.realm_name = realm_name
        self.service_name = service_name
        self.creds_file = creds_file
        self.keycloak_openid = None
        
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
                logger.warning("No credentials found and no Initial Access Token provided. Client not authenticated.")
                # We might be in a mode where we only want to verify tokens (public key), 
                # but for full functionality (exchange), we need a client.
                # Proceeding, but exchange_token will fail if called.
                return
            
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
            
        # Initialize the Keycloak Client
        self.keycloak_openid = KeycloakOpenID(
            server_url=self.server_url,
            client_id=client_id,
            realm_name=self.realm_name,
            client_secret_key=client_secret
        )
        logger.info(f"AgentSecurity initialized for client: {client_id}")

    def exchange_token(self, user_token: str, target_client: str) -> str:
        """
        Exchanges the current user_token for a token valid for the target_client.
        """
        if not self.keycloak_openid:
            raise AgenticSecurityError("AgentSecurity not initialized with client credentials. Cannot exchange tokens.")
            
        return exchange_token(self.keycloak_openid, user_token, target_client)

    def verify_token(self, token: str = Depends(lambda: None)): 
        # Note: In FastAPI, we need to wire this up carefully. 
        # The 'token' arg needs to get the value from the request.
        # usually: token: str = Depends(oauth2_scheme)
        # But oauth2_scheme is an instance member.
        pass
        
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
