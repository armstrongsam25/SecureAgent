
from keycloak import KeycloakAdmin
import json
import logging

logging.basicConfig(level=logging.ERROR)

ka = KeycloakAdmin(server_url="http://localhost:8080/",
                   username="admin",
                   password="admin",
                   realm_name="agent-mesh",
                   user_realm_name="master",
                   verify=False)

info = ka.get_server_info()
mappers = info.get("providers", {}).get("protocol-mapper", {}).get("providers", {})

print("--- Available Protocol Mappers ---")
found_script = False
for m in mappers:
    print(f"- {m}")
    if "script" in m:
        found_script = True

if found_script:
    print("\n✅ Script Mapper is AVAILABLE!")
else:
    print("\n❌ Script Mapper is MISSING.")
