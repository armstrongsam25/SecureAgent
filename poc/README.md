# Actor Claim Verification (POC)

This directory contains experimental scripts to validate the Delegated Authority Framework (DAF) by enforcing the generation of the `act` (Actor) claim in Keycloak tokens.

## Experiment Goal

To prove that an `exchange_token` call results in a nested `act` claim, identifying the Orchestrator (`test-module-agent-v3`) as the acting party on behalf of the User.

## Scripts

### test_module.py

The main verification suite. It performs the full login → exchange flow and asserts that:

*   The token exchange succeeds.
*   The resulting token contains an `act` claim.
*   The `act` claim correctly identifies the Orchestrator agent.

## How to Run

1.  Ensure the Docker stack is up: `docker-compose up -d`
2.  Run the setup script: `python poc/setup_poc.py`
3.  Run the verification: `python poc/test_module.py`
