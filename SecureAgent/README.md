# SecureAgent

A "Convention over Configuration" Python package for adding Agentic Identity to your AI Agents.

This package abstracts away the complexity of:
- **Dynamic Client Registration**: Automatically registers your agent with Keycloak if no credentials exist.
- **Token Exchange**: Implements RFC 8693 logic to exchange user tokens for downstream service access.
- **Token Verification**: Provides FastAPI dependencies to validate incoming Bearer tokens.
- **Token Caching**: Automatic token caching with refresh-before-expiry logic.
- **Async Support**: Non-blocking async methods for FastAPI and aiohttp.
- **CLI Tools**: Bootstrap credentials easily with `secureagent init`.

## Installation

```bash
pip install SecureAgent
```

*Note: You may need to install from source or a private repository until published.*

## Quick Start with CLI

Bootstrap your agent's credentials using the CLI:

```bash
secureagent init --realm-url http://localhost:8080 --client-id my-agent
```

This will prompt for an Initial Access Token and create `credentials.json`.

## Usage

### Initialization

Initialize the security module with your realm URL and service details.

```python
from SecureAgent import AgentSecurity

security = AgentSecurity(
    realm_url="http://localhost:8080",
    service_name="my-specialist-agent",
    # initial_access_token is required only for first run to register the client
    initial_access_token="<YOUR_INITIAL_ACCESS_TOKEN>",
    # Optional: graceful degradation for development
    fail_open=False,  # Set True to return None instead of raising on errors
    cache_tokens=True  # Automatic token caching (default: True)
)
```

### Getting a Token (Client Credentials Flow)

```python
# Synchronous
token = security.get_token()

# Asynchronous (for FastAPI, aiohttp, etc.)
token = await security.get_token_async()
```

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
# Synchronous
downstream_token = security.exchange_token(
    user_token=user_token,
    target_client="target-service"
)

# Asynchronous
downstream_token = await security.exchange_token_async(
    user_token=user_token,
    target_client="target-service"
)

# Use the new token to make the request
headers = {"Authorization": f"Bearer {downstream_token}"}
```

### Cache Management

```python
# Clear all cached tokens
security.clear_cache()

# Clear specific cache entry
security.clear_cache("client_credentials")
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `secureagent init` | Register a new client and create credentials |
| `secureagent status` | Check credentials and Keycloak connectivity |
| `secureagent token` | Get an access token (for scripting) |

## Configuration Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `realm_url` | required | Keycloak server URL |
| `service_name` | required | Client ID for this agent |
| `realm_name` | `"agent-mesh"` | Keycloak realm name |
| `creds_file` | `"credentials.json"` | Path to store credentials |
| `fail_open` | `False` | Return None instead of raising on errors |
| `cache_tokens` | `True` | Enable automatic token caching |
| `cache_refresh_buffer` | `30` | Seconds before expiry to refresh |
