from keycloak import KeycloakAdmin
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("grant-exchange-v2")

KEYCLOAK_URL = "http://localhost:8080/"
USERNAME = "admin"
PASSWORD = "admin"
REALM_NAME = "agent-mesh"

def grant_exchange_v2():
    ka = KeycloakAdmin(server_url=KEYCLOAK_URL,
                       username=USERNAME,
                       password=PASSWORD,
                       realm_name=REALM_NAME,
                       user_realm_name="master",
                       verify=False)
    
    # 1. Get Client IDs
    specialist_id = ka.get_client_id("specialist-agent")
    orchestrator_id = ka.get_client_id("orchestrator-agent")
    
    # 2. Get Service Account User for Orchestrator
    # The username depends on Keycloak version, usually 'service-account-<clientId>'
    sa_username = "service-account-orchestrator-agent"
    users = ka.get_users({"username": sa_username})
    if not users:
        logger.error(f"Could not find service account user: {sa_username}")
        # Try finding by client?
        # In newer keycloak, maybe separate call?
        # Let's try searching 'orchestrator-agent' in users just in case
        return
    
    sa_user_id = users[0]['id']
    logger.info(f"Orchestrator SA User ID: {sa_user_id}")
    
    # 3. Setup Permission on Specialist
    realm_mgmt_id = ka.get_client_id("realm-management")
    authz_url = f"admin/realms/{REALM_NAME}/clients/{realm_mgmt_id}/authz/resource-server"
    
    # Get 'token-exchange' permission ID
    perm_url = f"admin/realms/{REALM_NAME}/clients/{specialist_id}/management/permissions"
    perms = ka.connection.raw_get(perm_url).json()
    token_exchange_policy_id = perms["scopePermissions"]["token-exchange"]
    
    # 4. Create User Policy
    policy_name = "Allow Orchestrator SA User"
    policy_payload = {
        "type": "user",
        "name": policy_name,
        "description": "Allows orchestrator SA to exchange",
        "logic": "POSITIVE",
        "decisionStrategy": "UNANIMOUS",
        "config": {
            "users": json.dumps([sa_user_id])
        }
    }
    
    # Check/Create Policy
    search_res = ka.connection.raw_get(f"{authz_url}/policy", params={"name": policy_name}).json()
    if search_res:
        policy_id = search_res[0]["id"]
        logger.info(f"Policy exists: {policy_id}")
    else:
        headers = {"Content-Type": "application/json"}
        resp = ka.connection.raw_post(f"{authz_url}/policy/user", data=json.dumps(policy_payload), headers=headers)
        if resp.status_code == 201:
            policy_id = resp.json()["id"]
            logger.info(f"Created Policy: {policy_id}")
        else:
            logger.error(f"Policy creation failed: {resp.text}")
            return

    # 5. Link Policy
    perm_obj_url = f"{authz_url}/permission/scope/{token_exchange_policy_id}"
    perm_obj = ka.connection.raw_get(perm_obj_url).json()
    
    existing_policies = [p if isinstance(p, str) else p['id'] for p in perm_obj.get("policies", [])]
    
    if policy_id not in existing_policies:
        perm_obj["policies"] = existing_policies + [policy_id]
        resp = ka.connection.raw_put(perm_obj_url, data=json.dumps(perm_obj), headers={"Content-Type": "application/json"})
        logger.info(f"Linked policy. Status: {resp.status_code}")
    else:
        logger.info("Policy already linked.")

if __name__ == "__main__":
    grant_exchange_v2()
