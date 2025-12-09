from keycloak import KeycloakAdmin
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fix-user")

KEYCLOAK_URL = "http://localhost:8080/"
USERNAME = "admin"
PASSWORD = "admin"
REALM_NAME = "agent-mesh"

def fix_user():
    # Correctly init admin: auth in master, manage agent-mesh
    ka = KeycloakAdmin(server_url=KEYCLOAK_URL,
                       username=USERNAME,
                       password=PASSWORD,
                       realm_name=REALM_NAME,
                       user_realm_name="master",
                       verify=False)
    
    # Create agent_user
    logger.info("Creating 'agent_user'...")
    try:
        ka.create_user({"username": "agent_user", "enabled": True, "emailVerified": True})
    except Exception as e:
        logger.info(f"agent_user creation: {e}")
        
    uid = ka.get_user_id("agent_user")
    ka.set_user_password(uid, "password", temporary=False)
    # Clear actions explicitly
    ka.update_user(uid, {"requiredActions": []})
    
    # Test Login
    import requests
    import json
    TOKEN_URL = f"{KEYCLOAK_URL}realms/{REALM_NAME}/protocol/openid-connect/token"
    
    with open("orchestrator_creds.json", "r") as f:
        creds = json.load(f)
        
    print("Testing Login with agent_user...")
    payload = {
        "client_id": creds["client_id"], 
        "client_secret": creds["client_secret"],
        "username": "agent_user",
        "password": "password",
        "grant_type": "password"
    }
    
    try:
        resp = requests.post(TOKEN_URL, data=payload)
        print(f"Login Response: {resp.status_code}")
        if resp.status_code != 200:
            print(resp.text)
        else:
            print("Login SUCCESS!")
            print(resp.json())
    except Exception as e:
        print(e)

if __name__ == "__main__":
    fix_user()
