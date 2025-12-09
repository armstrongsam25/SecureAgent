# Agentic Security

A "Convention over Configuration" Python package for adding Agentic Identity to your AI Agents.

This package abstracts away the complexity of:
- **Dynamic Client Registration**: Automatically registers your agent with Keycloak if no credentials exist.
- **Token Exchange**: Implements RFC 8693 logic to exchange user tokens for downstream service access.
- **Token Verification**: Provides FastAPI dependencies to validate incoming Bearer tokens.

## Installation

```bash
pip install agentic-security
```

*Note: You may need to install from source or a private repository until published.*

## Usage

### Initialization

Initialize the security module with your realm URL and service details.

```python
from SecureAgent import AgentSecurity

security = AgentSecurity(
    realm_url="http://localhost:8080",
    service_name="my-specialist-agent",
    # initial_access_token is required only for the very first run to register the client
    initial_access_token="<YOUR_INITIAL_ACCESS_TOKEN>" 
)
```

The first time this runs, it will:
1. Check for `credentials.json`.
2. If missing, use `initial_access_token` to register `my-specialist-agent`.
3. Save the new `client_id` and `client_secret` to `credentials.json`.

### Protecting an Endpoint

Use the `verify_token` dependency to protect your FastAPI routes.

```python
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/secure-data")
def secure_endpoint(token_payload = Depends(security.verify_token)):
    return {
        "user": token_payload["sub"],
        "message": "You have access!"
    }
```

### Exchanging Tokens (The Orchestrator Pattern)

If your agent needs to call another agent, use `exchange_token`.

```python
def call_downstream_agent(user_token: str):
    # Exchange the incoming user token for a token to access 'target-service'
    downstream_token = security.exchange_token(
        user_token=user_token,
        target_client="target-service"
    )
    
    # Use the new token to make the request
    # headers = {"Authorization": f"Bearer {downstream_token}"}
    # requests.get(..., headers=headers)
```
