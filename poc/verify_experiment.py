import requests
import sys
import time

KEYCLOAK_URL = "http://localhost:8080/realms/agent-mesh/protocol/openid-connect/token"
ORCHESTRATOR_URL = "http://localhost:8082/run-mission"
USERNAME = "finaluser2"
PASSWORD = "password"

def log(msg):
    print(f"[VERIFY] {msg}")

def main():
    # Step 1: Service Account Flow (Expected Failure)
    log("=== TEST 1: Service Account Flow (Machine-to-Machine) ===")
    log("Authenticating as Orchestrator Service Account...")
    try:
        # Read credentials
        import json
        with open("orchestrator_creds.json", "r") as f:
            creds = json.load(f)
            client_id = creds["client_id"]
            client_secret = creds["client_secret"]

        payload_sa = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials"
        }
        
        resp = requests.post(KEYCLOAK_URL, data=payload_sa)
        resp.raise_for_status()
        token_sa = resp.json()["access_token"]
        log("Service Account Token acquired.")
        
        log("Calling Orchestrator with SA Token...")
        headers = {"Authorization": f"Bearer {token_sa}"}
        resp = requests.get(ORCHESTRATOR_URL, headers=headers)
        
        if resp.status_code == 403:
             log("SUCCESS: Received expected 403 Forbidden for SA flow.")
        elif resp.status_code == 200:
             log("UNEXPECTED SUCCESS: SA flow should be forbidden by default policy!")
        else:
             log(f"Orchestrator returned: {resp.status_code} - {resp.text}")
             
    except Exception as e:
        log(f"Test 1 failed with exception: {e}")

    # Step 2: User Flow (Expected Success)
    log("\n=== TEST 2: User Flow (Human-in-the-Loop) ===")
    log("Authenticating 'testuser' via Orchestrator Client...")
    try:
        payload_user = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "password",
            "username": "testuser",
            "password": "password"
        }
        
        resp = requests.post(KEYCLOAK_URL, data=payload_user)
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            log(f"Login failed: {resp.text}")
            raise e
            
        token_user = resp.json()["access_token"]
        log("User Token acquired.")
        
        log("Calling Orchestrator with User Token...")
        headers = {"Authorization": f"Bearer {token_user}"}
        resp = requests.get(ORCHESTRATOR_URL, headers=headers)
        
        if resp.status_code == 200:
            data = resp.json()
            log("Orchestrator Response:")
            print(json.dumps(data, indent=2))
            
            if "Secret Crop Rotation Data" in str(data):
                log("SUCCESS: Identity Propagated via Token Exchange!")
            else:
                log("FAILURE: Secret data missing.")
                sys.exit(1)
        elif resp.status_code == 403:
            log("FAILURE: User flow was Forbidden. Policy missing?")
            sys.exit(1)
        else:
            log(f"Orchestrator failed: {resp.status_code} - {resp.text}")
            sys.exit(1)
            
    except Exception as e:
        log(f"Test 2 failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
