from keycloak import KeycloakAdmin
import json

KEYCLOAK_URL = "http://localhost:8080/"
USERNAME = "admin"
PASSWORD = "admin"
REALM_NAME = "agent-mesh"

def debug():
    ka = KeycloakAdmin(server_url=KEYCLOAK_URL,
                       username=USERNAME,
                       password=PASSWORD,
                       realm_name="master",
                       verify=False)
    
    ka.realm_name = REALM_NAME
    ka.connection.realm_name = REALM_NAME
    
    uid = ka.get_user_id("finaluser")
    user = ka.get_user(uid)
    print("User Details:")
    print(json.dumps(user, indent=2))
    
    # Check Realm settings for required actions?
    # realm = ka.get_realm(REALM_NAME)
    # print("Realm Details:")
    # print(json.dumps(realm, indent=2))

if __name__ == "__main__":
    debug()
