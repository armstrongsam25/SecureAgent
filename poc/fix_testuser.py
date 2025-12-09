from keycloak import KeycloakAdmin
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fix-testuser")

KEYCLOAK_URL = "http://localhost:8080/"
USERNAME = "admin"
PASSWORD = "admin"
REALM_NAME = "agent-mesh"

def fix_testuser():
    ka = KeycloakAdmin(server_url=KEYCLOAK_URL,
                       username=USERNAME,
                       password=PASSWORD,
                       realm_name=REALM_NAME,
                       user_realm_name="master",
                       verify=False)
    
    logger.info("Fixing 'testuser'...")
    try:
        uid = ka.get_user_id("testuser")
        logger.info(f"Found testuser ID: {uid}")
        
        # Set password again
        ka.set_user_password(uid, "password", temporary=False)
        
        # Clear actions
        ka.update_user(uid, {"requiredActions": [], "emailVerified": True, "enabled": True})
        logger.info("Required actions cleared.")
        
    except Exception as e:
        logger.error(f"Failed to fix user: {e}")

if __name__ == "__main__":
    fix_testuser()
