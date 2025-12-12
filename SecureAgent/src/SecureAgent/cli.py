"""CLI tools for SecureAgent setup and management."""
import click
import os
import json
import logging
from typing import Optional

# Configure logging for CLI
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("SecureAgent.cli")


@click.group()
@click.version_option()
def main():
    """SecureAgent - Agentic Identity Framework for AI Agents."""
    pass


@main.command()
@click.option(
    '--realm-url', '-u',
    required=True,
    help='Keycloak server URL (e.g., http://localhost:8080)'
)
@click.option(
    '--realm', '-r',
    default='agent-mesh',
    help='Keycloak realm name (default: agent-mesh)'
)
@click.option(
    '--client-id', '-c',
    required=True,
    help='Client ID for this agent/service'
)
@click.option(
    '--output', '-o',
    default='credentials.json',
    help='Output file for credentials (default: credentials.json)'
)
@click.option(
    '--token', '-t',
    help='Initial Access Token (will prompt if not provided)'
)
def init(realm_url: str, realm: str, client_id: str, output: str, token: Optional[str]):
    """
    Initialize SecureAgent credentials for this agent.
    
    This command performs dynamic client registration with Keycloak
    and saves the credentials locally.
    
    Example:
        secureagent init --realm-url http://localhost:8080 --client-id my-agent
    """
    from .registration import register_client
    from .exceptions import RegistrationError
    
    # Check if credentials already exist
    if os.path.exists(output):
        if not click.confirm(f"Credentials file '{output}' already exists. Overwrite?"):
            click.echo("Aborted.")
            return
    
    # Get Initial Access Token if not provided
    if not token:
        click.echo("\nTo register a new client, you need an Initial Access Token from Keycloak.")
        click.echo("Get one from: Keycloak Admin Console → Clients → Initial Access Tokens\n")
        token = click.prompt("Initial Access Token", hide_input=True)
    
    if not token:
        click.echo("Error: Initial Access Token is required.", err=True)
        raise SystemExit(1)
    
    # Test connection first
    click.echo(f"\n🔗 Connecting to {realm_url}...")
    
    try:
        import httpx
        # Try to reach the realm
        well_known_url = f"{realm_url}/realms/{realm}/.well-known/openid-configuration"
        response = httpx.get(well_known_url, timeout=10)
        response.raise_for_status()
        click.echo(f"✓ Successfully connected to realm '{realm}'")
    except httpx.ConnectError:
        click.echo(f"\n❌ Could not connect to Keycloak at {realm_url}", err=True)
        click.echo("   Make sure Keycloak is running and the URL is correct.", err=True)
        raise SystemExit(1)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            click.echo(f"\n❌ Realm '{realm}' not found at {realm_url}", err=True)
            click.echo("   Check that the realm name is correct.", err=True)
        else:
            click.echo(f"\n❌ HTTP error: {e}", err=True)
        raise SystemExit(1)
    except Exception as e:
        click.echo(f"\n❌ Connection error: {e}", err=True)
        raise SystemExit(1)
    
    # Register the client
    click.echo(f"📝 Registering client '{client_id}'...")
    
    try:
        creds = register_client(
            server_url=realm_url,
            realm_name=realm,
            initial_access_token=token,
            client_id=client_id,
            creds_file=output
        )
        
        click.echo(f"✓ Client registered successfully!")
        click.echo(f"\n📁 Credentials saved to: {output}")
        click.echo(f"   Client ID: {creds['client_id']}")
        click.echo("\n🎉 Setup complete! You can now use SecureAgent in your application:")
        click.echo(f"""
from SecureAgent import AgentSecurity

security = AgentSecurity(
    realm_url="{realm_url}",
    service_name="{client_id}",
    realm_name="{realm}",
    creds_file="{output}"
)

# Get a token for this agent
token = security.get_token()
""")
        
    except RegistrationError as e:
        click.echo(f"\n❌ Registration failed: {e}", err=True)
        click.echo("\nCommon issues:", err=True)
        click.echo("  • Initial Access Token expired or already used", err=True)
        click.echo("  • Client ID already exists in Keycloak", err=True)
        click.echo("  • Insufficient permissions on the token", err=True)
        raise SystemExit(1)


@main.command()
@click.option(
    '--creds-file', '-f',
    default='credentials.json',
    help='Credentials file to check (default: credentials.json)'
)
def status(creds_file: str):
    """
    Check the status of SecureAgent credentials.
    """
    if not os.path.exists(creds_file):
        click.echo(f"❌ No credentials file found at '{creds_file}'")
        click.echo("\nRun 'secureagent init' to set up credentials.")
        raise SystemExit(1)
    
    try:
        with open(creds_file, 'r') as f:
            creds = json.load(f)
        
        click.echo(f"✓ Credentials file: {creds_file}")
        click.echo(f"  Server URL: {creds.get('server_url', 'N/A')}")
        click.echo(f"  Realm: {creds.get('realm_name', 'N/A')}")
        click.echo(f"  Client ID: {creds.get('client_id', 'N/A')}")
        click.echo(f"  Client Secret: {'*' * 8}... (hidden)")
        
        # Try to connect and get a token
        realm_url = creds.get('server_url')
        realm_name = creds.get('realm_name')
        
        if realm_url and realm_name:
            click.echo(f"\n🔗 Testing connection...")
            try:
                import httpx
                well_known_url = f"{realm_url}/realms/{realm_name}/.well-known/openid-configuration"
                response = httpx.get(well_known_url, timeout=10)
                response.raise_for_status()
                click.echo("✓ Keycloak is reachable")
            except Exception as e:
                click.echo(f"⚠ Could not connect to Keycloak: {e}")
                
    except json.JSONDecodeError:
        click.echo(f"❌ Invalid JSON in credentials file: {creds_file}", err=True)
        raise SystemExit(1)
    except Exception as e:
        click.echo(f"❌ Error reading credentials: {e}", err=True)
        raise SystemExit(1)


@main.command()
@click.option(
    '--creds-file', '-f',
    default='credentials.json',
    help='Credentials file (default: credentials.json)'
)
def token(creds_file: str):
    """
    Get an access token using stored credentials.
    
    Useful for testing or scripting.
    """
    if not os.path.exists(creds_file):
        click.echo(f"❌ No credentials file found at '{creds_file}'", err=True)
        click.echo("\nRun 'secureagent init' to set up credentials.", err=True)
        raise SystemExit(1)
    
    try:
        with open(creds_file, 'r') as f:
            creds = json.load(f)
        
        from .core import AgentSecurity
        
        security = AgentSecurity(
            realm_url=creds['server_url'],
            service_name=creds['client_id'],
            realm_name=creds['realm_name'],
            creds_file=creds_file
        )
        
        access_token = security.get_token()
        
        if access_token:
            click.echo(access_token)
        else:
            click.echo("❌ Failed to get token", err=True)
            raise SystemExit(1)
            
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
