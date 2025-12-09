from keycloak import KeycloakAdmin
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("grant-exchange-v3")

KEYCLOAK_URL = "http://localhost:8080/"
USERNAME = "admin"
PASSWORD = "admin"
REALM_NAME = "agent-mesh"

def grant_exchange_v3():
    ka = KeycloakAdmin(server_url=KEYCLOAK_URL,
                       username=USERNAME,
                       password=PASSWORD,
                       realm_name=REALM_NAME,
                       user_realm_name="master",
                       verify=False)
    
    specialist_id = ka.get_client_id("specialist-agent")
    orchestrator_id = ka.get_client_id("orchestrator-agent")
    realm_mgmt_id = ka.get_client_id("realm-management")
    authz_url = f"admin/realms/{REALM_NAME}/clients/{realm_mgmt_id}/authz/resource-server"
    
    # 1. Get Permission ID
    perm_url = f"admin/realms/{REALM_NAME}/clients/{specialist_id}/management/permissions"
    perms_json = ka.connection.raw_get(perm_url).json()
    token_exchange_policy_id = perms_json["scopePermissions"]["token-exchange"]
    logger.info(f"Target Permission ID: {token_exchange_policy_id}")

    # 2. Check Existing Policies (Manual Filter)
    target_name = "Allow Orchestrator Exchange"
    policy_id = None
    
    all_policies = ka.connection.raw_get(f"{authz_url}/policy").json()
    for p in all_policies:
        if p["name"] == target_name:
            logger.info(f"Found existing policy '{target_name}': {p['id']}")
            policy_id = p["id"]
            break
            
    if not policy_id:
        # 3. Create Policy
        # Try Client Policy first
        logger.info("Creating Client Policy...")
        policy_payload = {
            "type": "client",
            "name": target_name,
            "description": "Allows orchestrator to exchange",
            "logic": "POSITIVE",
            "decisionStrategy": "UNANIMOUS",
            "config": {
                "clients": json.dumps([orchestrator_id])
            }
        }
        headers = {"Content-Type": "application/json"}
        
        resp = ka.connection.raw_post(f"{authz_url}/policy/client", data=json.dumps(policy_payload), headers=headers)
        if resp.status_code == 201:
            policy_id = resp.json()["id"]
            logger.info(f"Created Client Policy: {policy_id}")
        else:
            logger.error(f"Client Policy Creation Failed: {resp.status_code} {resp.text}")
            
            # FALLBACK: Service Account User Policy
            logger.info("Attempting Fallback to Service Account User Policy...")
            target_name_sa = "Allow Orchestrator SA User"
            
            # Check exist SA
            for p in all_policies:
                if p["name"] == target_name_sa:
                    policy_id = p["id"]
                    break
            
            if not policy_id:
                # Find User ID
                sa_username = "service-account-orchestrator-agent"
                users = ka.get_users({"username": sa_username})
                if not users:
                    logger.error("SA User not found.")
                    return
                sa_user_id = users[0]['id']
                
                user_policy_payload = {
                    "type": "user",
                    "name": target_name_sa,
                    "logic": "POSITIVE",
                    "decisionStrategy": "UNANIMOUS",
                    "config": {"users": json.dumps([sa_user_id])}
                }
                resp = ka.connection.raw_post(f"{authz_url}/policy/user", data=json.dumps(user_policy_payload), headers=headers)
                if resp.status_code == 201:
                    policy_id = resp.json()["id"]
                    logger.info(f"Created User Policy: {policy_id}")
                else:
                    logger.error(f"User Policy Creation Failed: {resp.status_code} {resp.text}")
                    return

    # 4. Link
    if policy_id:
        perm_obj_url = f"{authz_url}/permission/scope/{token_exchange_policy_id}"
        perm_obj = ka.connection.raw_get(perm_obj_url).json()
        
        current_policies = [p if isinstance(p, str) else p['id'] for p in perm_obj.get("policies", [])]
        if policy_id not in current_policies:
            perm_obj["policies"] = current_policies + [policy_id]
            resp = ka.connection.raw_put(perm_obj_url, data=json.dumps(perm_obj), headers={"Content-Type": "application/json"})
            logger.info(f"Linked Policy. Code: {resp.status_code}")
        else:
            logger.info("Policy already linked.")

if __name__ == "__main__":
    grant_exchange_v3()
