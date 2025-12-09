# Proof of Concept (POC) - Dynamic Authorization Framework

This directory contains the original scripts and configuration used to validate the Dynamic Authorization Framework before it was refactored into the `agentic-security` package.

## Components

- **Keycloak**: Identity Provider running in Docker.
- **Orchestrator Agent** (`orchestrator.py`): The agent that exchanges tokens.
- **Specialist Agent** (`specialist_agent.py`): The resource server protecting data.
- **Setup Scripts**: `keycloak_setup.py`, `grant_exchange_v3.py` for configuring policies.

## How to Run

### 1. Start Keycloak
```bash
docker-compose up -d
```
Wait for Keycloak to be healthy at [http://localhost:8080](http://localhost:8080).

### 2. Configure Keycloak
Run the setup script to create the realm and clients.
```bash
python keycloak_setup.py
```
*Note: Make sure to save the Initial Access Token (IAT) to `iat.txt` if not done automatically (the script usually prints it).*

### 3. Grant Permissions
Configure the specific permissions to allow the Orchestrator to impersonate/exchange tokens.
```bash
python grant_exchange_v3.py
```

### 4. Run Agents
Open separate terminals for each agent.

**Terminal 1: Specialist Agent**
```bash
python specialist_agent.py
```

**Terminal 2: Orchestrator Agent**
```bash
python orchestrator.py
```

### 5. Verify Experiment
Run the verification script to simulate a user request -> Orchestrator -> Specialist flow.
```bash
python verify_experiment.py
```
