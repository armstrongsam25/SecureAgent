
# Fixed grant_exchange_v3.py
import json
import logging
import sys
from keycloak import KeycloakAdmin

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("grant-exchange-v3")

KEYCLOAK_URL = "http://localhost:8080/"
USERNAME = "admin"
PASSWORD = "admin"
REALM_NAME = "agent-mesh"

# Configuration for the test
TARGET_CLIENT_ID = "test-module-agent-v3"
REQUESTER_CLIENT_ID = "test-module-agent-v3"

def grant_exchange_v3():
    print(f"--- Granting Token Exchange for {TARGET_CLIENT_ID} ---")
    
    ka = KeycloakAdmin(server_url=KEYCLOAK_URL,
                       username=USERNAME,
                       password=PASSWORD,
                       realm_name=REALM_NAME,
                       user_realm_name="master",
                       verify=False)

    # 1. Get Target Client UUID
    target_uuid = ka.get_client_id(TARGET_CLIENT_ID)
    if not target_uuid:
        print(f"❌ Target client '{TARGET_CLIENT_ID}' not found.")
        return

    print(f"Target Client UUID: {target_uuid}")

    # 2. Enable Permissions (Fix for KeyError)
    mgmt_url = f"admin/realms/{REALM_NAME}/clients/{target_uuid}/management/permissions"
    try:
        # Check if enabled, or just enable it
        logger.info(f"Enabling Management Permissions for client...")
        ka.connection.raw_put(mgmt_url, data=json.dumps({"enabled": True}))
        print("✅ Permissions enabled on client.")
    except Exception as e:
        print(f"⚠️ Failed to enable permissions: {e}")

    # 3. Get Permission ID for 'token-exchange'
    perms_json = ka.connection.raw_get(mgmt_url).json()
    if "scopePermissions" not in perms_json:
        print("❌ 'scopePermissions' missing. Authorization services might not be fully enabled.")
        return
        
    token_exchange_policy_id = perms_json["scopePermissions"].get("token-exchange")
    if not token_exchange_policy_id:
        print("❌ 'token-exchange' scope permission not found.")
        return
        
    print(f"Token Exchange Permission ID: {token_exchange_policy_id}")

    # 4. Create Policy
    # We will try to create a Time Policy as it is simplest to define
    # We need to talk to the 'realm-management' client which manages these policies
    realm_mgmt_id = ka.get_client_id('realm-management')
    authz_url = f"admin/realms/{REALM_NAME}/clients/{realm_mgmt_id}/authz/resource-server"
    
    policy_name = f"Allow Exchange {TARGET_CLIENT_ID}"
    
    # Check if policy exists
    policy_id = None
    all_policies = ka.connection.raw_get(f"{authz_url}/policy?name={policy_name}").json()
    
    # Search because query param might be partial match
    for p in all_policies:
        if p["name"] == policy_name:
            policy_id = p["id"]
            break
            
    if not policy_id:
        print("Creating Client Policy via Raw API (Corrected Schema)...")
        
        # Strategy: Role Based Policy on 'default-roles-agent-mesh'
        default_role = ka.get_realm_role("default-roles-agent-mesh")
        if not default_role:
             default_role = ka.get_realm_role("uma_authorization") # Fallback
        
        if default_role:
            role_id = default_role['id']
            # Corrected Schema: 'roles' is top-level, no 'config' wrapper
            role_policy_payload = {
                "type": "role",
                "name": policy_name,
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "roles": [{"id": role_id, "required": True}] 
            }
            
            try:
                # Use raw_post to ensure no library interference
                resp = ka.connection.raw_post(f"{authz_url}/policy/role", 
                                              data=json.dumps(role_policy_payload), 
                                              headers={"Content-Type": "application/json"})
                                              
                if resp.status_code == 201:
                    policy_id = resp.json()['id']
                    print(f"✅ Created Role Policy: {policy_id}")
                else:
                    print(f"❌ Role Policy creation failed: {resp.status_code} {resp.text}")
                    return
            except Exception as e:
                print(f"❌ Exception creating policy: {e}")
                return
        else:
            print("❌ Could not find default role for policy.")
            return

    # 5. Link Policy to Permission
    perm_obj_url = f"{authz_url}/permission/scope/{token_exchange_policy_id}"
    perm_obj = ka.connection.raw_get(perm_obj_url).json()
    
    current_policies = [p if isinstance(p, str) else p['id'] for p in perm_obj.get("policies", [])]
    if policy_id not in current_policies:
        perm_obj["policies"] = current_policies + [policy_id]
        ka.connection.raw_put(perm_obj_url, data=json.dumps(perm_obj), headers={"Content-Type": "application/json"})
        print(f"✅ Linked Policy to Permission.")
    else:
        print("✅ Policy already linked.")

if __name__ == "__main__":
    grant_exchange_v3()
