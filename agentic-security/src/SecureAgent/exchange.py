import logging
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakPostError
from .exceptions import TokenExchangeError, PolicyDenied

logger = logging.getLogger("agentic-security.exchange")

def exchange_token(
    keycloak_client: KeycloakOpenID,
    user_token: str,
    target_client_id: str
) -> str:
    """
    Exchanges a user token for a token that can access the target client (audience).
    """
    logger.info(f"Attempting Token Exchange for audience: {target_client_id}...")
    
    try:
        # keycloak_client must be initialized with the requesting client's credentials
        # (the "Orchestrator" in the pattern)
        
        response = keycloak_client.exchange_token(
            token=user_token,
            audience=target_client_id,
            requested_token_type="urn:ietf:params:oauth:token-type:access_token"
        )
        
        access_token = response.get("access_token")
        if not access_token:
            raise TokenExchangeError("No access token returned in exchange response")
            
        logger.info("Token Exchange Successful!")
        return access_token
        
    except KeycloakPostError as e:
        logger.error(f"Token Exchange denied: {e}")
        if e.response_code == 403:
             raise PolicyDenied("Token Exchange Forbidden by Policy")
        else:
             raise TokenExchangeError(f"Token Exchange Error: {e}")
    except Exception as e:
        logger.error(f"Token Exchange failed: {e}")
        raise TokenExchangeError(f"Token Exchange failed: {e}")
