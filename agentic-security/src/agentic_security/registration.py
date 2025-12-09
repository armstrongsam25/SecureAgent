import logging
import json
import os
from keycloak import KeycloakOpenID
from .exceptions import RegistrationError

logger = logging.getLogger("agentic-security.registration")

def register_client(
    server_url: str,
    realm_name: str,
    initial_access_token: str,
    client_id: str,
    client_name: str = None,
    description: str = None,
    creds_file: str = "credentials.json"
) -> dict:
    """
    Registers a new client with Keycloak using an Initial Access Token.
    Returns a dict containing client_id and client_secret.
    """
    if not client_name:
        client_name = client_id
    
    logger.info(f"Initiating dynamic registration for {client_id}...")
    
    # We use a temporary instance just for the register_client call
    kc_reg = KeycloakOpenID(
        server_url=server_url,
        client_id="temp-reg", 
        realm_name=realm_name
    )
    
    payload = {
        "clientId": client_id,
        "name": client_name,
        "description": description or f"Agentic Security Client: {client_id}",
        "serviceAccountsEnabled": True,
        "standardFlowEnabled": False, # Machine-to-machine
        "directAccessGrantsEnabled": True, 
        "authorizationServicesEnabled": True, # Resource Server
        "clientAuthenticatorType": "client-secret",
        # Default scopes can be adjusted if needed, but these are good defaults for agents
        "defaultClientScopes": ["web-origins", "acr", "roles", "profile", "email"] 
    }
    
    try:
        client_rep = kc_reg.register_client(token=initial_access_token, payload=payload)
        registered_client_id = client_rep["clientId"]
        secret = client_rep["secret"]
        
        logger.info(f"Registration successful. Client ID: {registered_client_id}")
        
        creds = {
            "client_id": registered_client_id,
            "client_secret": secret,
            "server_url": server_url,
            "realm_name": realm_name
        }
        
        # Save credentials locally
        with open(creds_file, "w") as f:
            json.dump(creds, f, indent=2)
            
        return creds
        
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        raise RegistrationError(f"Failed to register client {client_id}: {e}")
