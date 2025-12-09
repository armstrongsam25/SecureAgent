import json
import logging
from fastapi import FastAPI, Depends, HTTPException, status, Header
import httpx
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakPostError, KeycloakAuthenticationError
import uvicorn
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("orchestrator")

app = FastAPI(title="Orchestrator Agent")

# Configuration
KEYCLOAK_URL = "http://localhost:8080/"
REALM_NAME = "agent-mesh"
IAT_FILE = "iat.txt"
CREDS_FILE = "orchestrator_creds.json"
SPECIALIST_URL = "http://127.0.0.1:8081/secure-data"
SPECIALIST_CLIENT_ID = "specialist-agent"

# Global Keycloak Client
keycloak_openid = None 

@app.on_event("startup")
async def startup_event():
    global keycloak_openid
    logger.info("Orchestrator Agent starting up...")
    
    if os.path.exists(CREDS_FILE):
        logger.info("Loading existing credentials...")
        with open(CREDS_FILE, "r") as f:
            creds = json.load(f)
            client_id = creds["client_id"]
            client_secret = creds["client_secret"]
    else:
        logger.info("No credentials found. Initiating Dynamic Registration...")
        if not os.path.exists(IAT_FILE):
             raise Exception(f"IAT file {IAT_FILE} not found. Cannot register.")
        with open(IAT_FILE, "r") as f:
            iat = f.read().strip()
            
        kc_reg = KeycloakOpenID(server_url=KEYCLOAK_URL,
                                client_id="temp-reg-orch",
                                realm_name=REALM_NAME)
        
        payload = {
            "clientId": "orchestrator-agent",
            "name": "Orchestrator Agent",
            "description": "Agent that exchanges tokens",
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": True,
            "authorizationServicesEnabled": True,
            "clientAuthenticatorType": "client-secret"
        }
        
        try:
            logger.info("Registering with Keycloak...")
            client_rep = kc_reg.register_client(token=iat, payload=payload)
            client_id = client_rep["clientId"]
            client_secret = client_rep["secret"]
            logger.info(f"Registration successful! Client ID: {client_id}")
            
            with open(CREDS_FILE, "w") as f:
                json.dump({"client_id": client_id, "client_secret": client_secret}, f)
                
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            raise e

    keycloak_openid = KeycloakOpenID(server_url=KEYCLOAK_URL,
                                     client_id=client_id,
                                     realm_name=REALM_NAME,
                                     client_secret_key=client_secret)
    logger.info("Keycloak client initialized.")

@app.get("/run-mission")
async def run_mission(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer Token")
    
    user_token = authorization.split(" ")[1]
    
    # 1. Token Exchange: Exchange User Token for a token accessing Specialist
    # grant_type=urn:ietf:params:oauth:grant-type:token-exchange
    # subject_token=user_token
    # audience=SPECIALIST_CLIENT_ID
    
    logger.info("Attempting Token Exchange...")
    try:
        # python-keycloak has exchange_token?
        # signature: exchange_token(self, token, scope=None, audience=None, ...)
        # Using the Authenticated Client (Orchestrator) to perform exchange.
        
        # NOTE: python-keycloak exchange_token checks 'token' param. 
        # Usually it sends subject_token.
        # Let's check docs/usage. 
        # client.exchange_token(token=user_token, audience=SPECIALIST_CLIENT_ID, requested_token_type="urn:ietf:params:oauth:token-type:access_token")
        
        exchanged = keycloak_openid.exchange_token(
            token=user_token,
            audience=SPECIALIST_CLIENT_ID,
            requested_token_type="urn:ietf:params:oauth:token-type:access_token"
        )
        
        new_token = exchanged["access_token"]
        logger.info("Token Exchange Successful!")
        
    except KeycloakPostError as e:
        logger.error(f"Token Exchange denied: {e}")
        if e.response_code == 403:
             raise HTTPException(status_code=403, detail="Token Exchange Forbidden by Policy")
        else:
             raise HTTPException(status_code=e.response_code, detail=f"Token Exchange Error: {e}")
    except Exception as e:
        logger.error(f"Token Exchange failed: {e}")
        raise HTTPException(status_code=500, detail=f"Token Exchange failed: {e}")

    # 2. Call Specialist
    logger.info("Calling Specialist Agent...")
    async with httpx.AsyncClient() as client:
        resp = await client.get(SPECIALIST_URL, headers={"Authorization": f"Bearer {new_token}"})
        
    if resp.status_code != 200:
        logger.error(f"Specialist returned {resp.status_code}: {resp.text}")
        raise HTTPException(status_code=resp.status_code, detail="Specialist call failed")
        
    logger.info("Mission Success!")
    return {
        "status": "mission_complete",
        "orchestrator_message": "I authenticated cleanly on your behalf.",
        "specialist_response": resp.json()
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8082)
