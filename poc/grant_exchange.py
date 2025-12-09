from keycloak import KeycloakAdmin
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("grant-exchange")

KEYCLOAK_URL = "http://localhost:8080/"
USERNAME = "admin"
PASSWORD = "admin"
REALM_NAME = "agent-mesh"

def grant_exchange():
    ka = KeycloakAdmin(server_url=KEYCLOAK_URL,
                       username=USERNAME,
                       password=PASSWORD,
                       realm_name=REALM_NAME,
                       user_realm_name="master",
                       verify=False)
    
    # 1. Get Client UUIDs
    try:
        specialist_id = ka.get_client_id("specialist-agent")
        orchestrator_id = ka.get_client_id("orchestrator-agent")
    except Exception as e:
        logger.error(f"Could not find agents: {e}")
        return

    logger.info(f"Specialist UUID: {specialist_id}")
    logger.info(f"Orchestrator UUID: {orchestrator_id}")
    
    # Ensure client has authz enabled
    ka.update_client(specialist_id, {"authorizationServicesEnabled": True, "serviceAccountsEnabled": True})
    
    # 2. Enable Permissions on Specialist
    # Endpoint: /admin/realms/{realm}/clients/{id}/management/permissions
    
    perm_url = f"admin/realms/{REALM_NAME}/clients/{specialist_id}/management/permissions"
    resp = ka.connection.raw_put(perm_url, data=json.dumps({"enabled": True}))
    logger.info(f"Enable Perms Response: {resp.text} Code: {resp.status_code}")
    
    # 3. Get 'token-exchange' permission policy
    # When enabled, Keycloak creates scope-based permissions.
    # We need to find the one for 'token-exchange'.
    # GET /admin/realms/{realm}/clients/{id}/management/permissions
    
    perms = ka.connection.raw_get(perm_url).json()
    logger.info(f"Perms JSON: {json.dumps(perms, indent=2)}")
    
    if "resource" not in perms:
        logger.warning("Resource field missing. Maybe Keycloak version difference or needs refresh?")
        # It might be that fine-grained authz is not fully init? 
        return

    resource_server_id = perms["resource"] # The "Client Identity" resource
    
    # We need the policy ID for 'token-exchange'.
    # It is usually named "token-exchange.permission.client.{id}"
    
    # Let's list policies in the 'realm-management' client? 
    # No, fine-grained client permissions are managed in 'realm-management' usually, 
    # but specific to the client?
    # Actually, Keycloak 24 might put it in the client's OWN authorization settings if 'authorizationServicesEnabled'?
    # No, 'management/permissions' refers to the Realm Management applied to this client.
    
    token_exchange_policy_id = perms["scopePermissions"]["token-exchange"]
    logger.info(f"Token Exchange Permission ID: {token_exchange_policy_id}")
    
    # 4. Create a Policy to Allow Orchestrator
    realm_mgmt_id = ka.get_client_id("realm-management")
    authz_url = f"admin/realms/{REALM_NAME}/clients/{realm_mgmt_id}/authz/resource-server"
    
    # Create Client Policy
    policy_name = "Allow Orchestrator Exchange"
    policy_payload = {
        "type": "client",
        "name": policy_name,
        "description": "Allows orchestrator to exchange",
        "logic": "POSITIVE",
        "decisionStrategy": "UNANIMOUS",
        "config": {
            "clients": json.dumps([orchestrator_id]) 
        }
    }
    
    logger.info(f"Creating Policy with payload: {json.dumps(policy_payload)}")
    
    # Check if exists first
    search_res = ka.connection.raw_get(f"{authz_url}/policy", params={"name": policy_name}).json()
    if search_res:
        logger.info(f"Policy '{policy_name}' already exists: {search_res[0]['id']}")
        policy_id = search_res[0]["id"]
    else:
        # Create
        # IMPORTANT: Ensure Content-Type header is set. 
        # python-keycloak raw_post should handle it if we use 'json=' but here we use data.
        # Let's try passing headers explicitly if possible, or assume default is OK but maybe fail.
        # Actually better to use json argument if supported? 
        # connection.raw_post(url, data=..., params=..., headers=...)
        
        headers = {"Content-Type": "application/json"}
        resp = ka.connection.raw_post(f"{authz_url}/policy/client", data=json.dumps(policy_payload), headers=headers)
        
        if resp.status_code == 201:
            policy_id = resp.json()["id"]
            logger.info(f"Created Policy: {policy_id}")
        else:
            logger.error(f"Policy Creation Failed: {resp.status_code} {resp.text}")
            raise Exception("Creation failed")

    # 5. Link Policy to Permission
    # PUT to /permission/scope/{permissionId}
    
    perm_obj_url = f"{authz_url}/permission/scope/{token_exchange_policy_id}"
    perm_obj = ka.connection.raw_get(perm_obj_url).json()
    
    existing_policies = [p if isinstance(p, str) else p['id'] for p in perm_obj.get("policies", [])]
    
    if policy_id not in existing_policies:
        # Add policy_id
        perm_obj["policies"] = existing_policies + [policy_id]
        
        # Update
        resp = ka.connection.raw_put(perm_obj_url, data=json.dumps(perm_obj), headers={"Content-Type": "application/json"})
        if resp.status_code < 300:
             logger.info("Linked policy to Token Exchange permission.")
        else:
             logger.error(f"Failed to link policy: {resp.status_code} {resp.text}")
    else:
        logger.info("Policy already linked.")

if __name__ == "__main__":
    grant_exchange()
