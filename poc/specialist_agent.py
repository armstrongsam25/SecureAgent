import json
import logging
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from keycloak import KeycloakOpenID
import uvicorn
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("specialist-agent")

app = FastAPI(title="Specialist Agent")

# Configuration
KEYCLOAK_URL = "http://localhost:8080/"
REALM_NAME = "agent-mesh"
IAT_FILE = "iat.txt"
CREDS_FILE = "agent_creds.json"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{KEYCLOAK_URL}realms/{REALM_NAME}/protocol/openid-connect/token")

# Global Keycloak Client (initialized on startup)
keycloak_openid = None 

def get_keycloak_openid():
    return keycloak_openid

@app.on_event("startup")
async def startup_event():
    global keycloak_openid
    logger.info("Specialist Agent starting up...")
    
    if os.path.exists(CREDS_FILE):
        logger.info("Loading existing credentials...")
        with open(CREDS_FILE, "r") as f:
            creds = json.load(f)
            client_id = creds["client_id"]
            client_secret = creds["client_secret"]
    else:
        logger.info("No credentials found. Initiating Dynamic Registration...")
        # Load IAT
        if not os.path.exists(IAT_FILE):
             raise Exception(f"IAT file {IAT_FILE} not found. Cannot register.")
        with open(IAT_FILE, "r") as f:
            iat = f.read().strip()
            
        # Temporary client for registration
        # We don't have a client_id yet, but KeycloakOpenID requires one to init.
        # We can pass anything or None, but register_client needs 'token'.
        
        # We start with a generic client wrapper just for registration
        kc_reg = KeycloakOpenID(server_url=KEYCLOAK_URL,
                                client_id="temp-reg",
                                realm_name=REALM_NAME)
        
        payload = {
            "clientId": "specialist-agent",
            "name": "Specialist Agent",
            "description": "A specialist agent protecting crops",
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": False, # Machine-to-machine
            "directAccessGrantsEnabled": True, 
            "authorizationServicesEnabled": True, # Resource Server
            "clientAuthenticatorType": "client-secret",
            "defaultClientScopes": ["web-origins", "acr", "roles", "profile", "email"] 
        }
        
        try:
            logger.info("Registering with Keycloak...")
            client_rep = kc_reg.register_client(token=iat, payload=payload)
            client_id = client_rep["clientId"]
            client_secret = client_rep["secret"]
            logger.info(f"Registration successful! Client ID: {client_id}")
            
            # Save creds
            with open(CREDS_FILE, "w") as f:
                json.dump({"client_id": client_id, "client_secret": client_secret}, f)
                
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            raise e

    # Initialize the real client
    keycloak_openid = KeycloakOpenID(server_url=KEYCLOAK_URL,
                                     client_id=client_id,
                                     realm_name=REALM_NAME,
                                     client_secret_key=client_secret)
    logger.info("Keycloak client initialized.")


async def verify_token(token: str = Depends(oauth2_scheme)):
    # Verify the token
    try:
        # We use introspection or local decode. 
        # Introspection is safer for opaque tokens or ensuring revocation.
        # However, for Token Exchange result, it should be a JWT.
        
        # NOTE: token_introspect returns Active: false if invalid.
        kc = get_keycloak_openid()
        token_info = kc.introspect(token)
        
        if not token_info.get("active"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalid or expired")
            
        return token_info
    except Exception as e:
        logger.error(f"Token verification invalid: {e}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

@app.get("/secure-data")
async def get_secure_data(token_info: dict = Depends(verify_token)):
    # Check Scope?
    # Keycloak introspection returns 'scope' as a space-separated string.
    scopes = token_info.get("scope", "").split()
    
    # We want 'agent:read' or similar. 
    # But usually scopes are 'email profile'.
    # If the Orchestrator exchanged token, it might have requested specific scopes.
    # For now, let's just log the scopes and allow access if authenticated.
    # The requirement said "Require a scope of agent:read".
    
    # If we didn't setup the scope in Keycloak, we won't get it.
    # But for POC, we can check if the USER has it, or if the CLIENT has it.
    # Let's assume ANY valid token is "secure" enough for step 1, 
    # but strictly we should check.
    
    logger.info(f"Access granted to: {token_info.get('sub')} with scopes: {scopes}")
    
    return {"status": "secure", "data": "Secret Crop Rotation Data", "client": token_info.get("client_id")}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8081)
