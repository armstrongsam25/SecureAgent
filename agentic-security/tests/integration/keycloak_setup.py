import time
import json
import logging
from keycloak import KeycloakAdmin
from keycloak.exceptions import KeycloakError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

KEYCLOAK_URL = "http://localhost:8080/"
USERNAME = "admin"
PASSWORD = "admin"
REALM_NAME = "agent-mesh"

def wait_for_keycloak():
    logger.info("Waiting for Keycloak to start...")
    retries = 30
    while retries > 0:
        try:
            # Just try to connect
            admin = KeycloakAdmin(server_url=KEYCLOAK_URL,
                          username=USERNAME,
                          password=PASSWORD,
                          realm_name="master",
                          verify=False)
            logger.info("Keycloak is responding to admin login!")
            return admin
        except Exception as e:
            logger.info(f"Waiting for Keycloak... ({retries} retries left). Error: {e}")
            time.sleep(5)
            retries -= 1
    raise Exception("Keycloak failed to start in time.")

def setup_keycloak():
    keycloak_admin = wait_for_keycloak()
    # Give it a second to settle
    time.sleep(2)

    # 1. Create Realm
    try:
        if keycloak_admin.get_realm(REALM_NAME):
             logger.info(f"Realm '{REALM_NAME}' already exists.")
    except KeycloakError:
        pass
    
    # Create realm if it doesn't exist (or we just caught the error)
    # Checking via list is safer usually but get_realm throws 404
    
    realms = [r['realm'] for r in keycloak_admin.get_realms()]
    if REALM_NAME not in realms:
        logger.info(f"Creating realm '{REALM_NAME}'...")
        keycloak_admin.create_realm(payload={"realm": REALM_NAME, "enabled": True})

    # Switch to new realm
    keycloak_admin.realm_name = REALM_NAME
    keycloak_admin.connection.realm_name = REALM_NAME
    
    # 2. Create Initial Access Token (IAT)
    logger.info(f"Creating Initial Access Token in realm: {keycloak_admin.realm_name}...")
    iat = keycloak_admin.create_initial_access_token(count=100, expiration=31536000)
    logger.info(f"Initial Access Token: {iat['token']}")
    
    # Save IAT to file for agents to use
    with open("iat.txt", "w") as f:
        f.write(iat['token'])

    # 3. Create Test User
    logger.info("Creating test user 'testuser'...")
    try:
        user_id = keycloak_admin.create_user({
            "username": "testuser", 
            "enabled": True, 
            "emailVerified": True,
            "firstName": "Test",
            "lastName": "User"
        })
        keycloak_admin.set_user_password(user_id, "password", temporary=False)
    except KeycloakError as e:
        if "User exists" in str(e) or getattr(e, 'response_code', 0) == 409:
            logger.info("User 'testuser' already exists. Updating...")
            user_id = keycloak_admin.get_user_id("testuser")
            # Ensure password is set and actions cleared
            keycloak_admin.set_user_password(user_id, "password", temporary=False)
            keycloak_admin.update_user(user_id, {"emailVerified": True, "requiredActions": []})
        else:
            raise e
            
    logger.info("Setup complete. IAT saved to iat.txt")

if __name__ == "__main__":
    setup_keycloak()
