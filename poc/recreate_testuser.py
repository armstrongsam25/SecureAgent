from keycloak import KeycloakAdmin
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("recreate-testuser")

KEYCLOAK_URL = "http://localhost:8080/"
USERNAME = "admin"
PASSWORD = "admin"
REALM_NAME = "agent-mesh"

def recreate():
    ka = KeycloakAdmin(server_url=KEYCLOAK_URL,
                       username=USERNAME,
                       password=PASSWORD,
                       realm_name=REALM_NAME,
                       user_realm_name="master",
                       verify=False)
    
    # 1. Delete if exists
    try:
        uid = ka.get_user_id("testuser")
        if uid:
            logger.info(f"Deleting existing user {uid}...")
            ka.delete_user(uid)
    except Exception as e:
        logger.info(f"Delete warning: {e}")

    # 2. Create
    logger.info("Creating 'testuser'...")
    user_payload = {
        "username": "testuser",
        "enabled": True,
        "emailVerified": True,
        "firstName": "Test",
        "lastName": "User",
        "email": "test@example.com",
        "requiredActions": [] 
    }
    
    new_uid = ka.create_user(user_payload)
    logger.info(f"Created user {new_uid}")
    
    # 3. Set Password
    ka.set_user_password(new_uid, "password", temporary=False)
    logger.info("Password set.")
    
    # 4. Verify
    user = ka.get_user(new_uid)
    logger.info(f"User State: {json.dumps(user, indent=2)}")

if __name__ == "__main__":
    recreate()
