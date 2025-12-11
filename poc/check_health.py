
import requests
import time
import sys

URL = "http://localhost:8080/realms/master"

print("Waiting for Keycloak to start...")
for i in range(60):
    try:
        resp = requests.get(URL)
        if resp.status_code == 200:
            print("✅ Keycloak is UP!")
            sys.exit(0)
    except:
        pass
    time.sleep(2)
    print(".", end="", flush=True)

print("\n❌ Keycloak timed out.")
sys.exit(1)
