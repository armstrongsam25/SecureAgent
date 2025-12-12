"""Tests for CLI commands."""
import pytest
import json
from click.testing import CliRunner
from SecureAgent.cli import main


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


class TestInitCommand:
    """Tests for 'secureagent init' command."""
    
    def test_init_shows_help(self, runner):
        """Test that init --help works."""
        result = runner.invoke(main, ['init', '--help'])
        
        assert result.exit_code == 0
        assert '--realm-url' in result.output
        assert '--client-id' in result.output
    
    def test_init_requires_realm_url(self, runner):
        """Test that init requires --realm-url."""
        result = runner.invoke(main, ['init', '--client-id', 'test'])
        
        assert result.exit_code != 0
        assert 'realm-url' in result.output.lower() or 'required' in result.output.lower()


class TestStatusCommand:
    """Tests for 'secureagent status' command."""
    
    def test_status_no_creds_file(self, runner):
        """Test status when no credentials file exists."""
        with runner.isolated_filesystem():
            result = runner.invoke(main, ['status', '-f', 'nonexistent.json'])
            
            assert result.exit_code == 1
            assert 'No credentials file found' in result.output
    
    def test_status_with_creds_file(self, runner):
        """Test status with valid credentials file."""
        with runner.isolated_filesystem():
            creds = {
                "client_id": "test-client",
                "client_secret": "test-secret",
                "server_url": "http://localhost:8080",
                "realm_name": "test-realm"
            }
            with open("credentials.json", "w") as f:
                json.dump(creds, f)
            
            result = runner.invoke(main, ['status'])
            
            assert result.exit_code == 0
            assert 'test-client' in result.output
            assert 'test-realm' in result.output


class TestTokenCommand:
    """Tests for 'secureagent token' command."""
    
    def test_token_no_creds_file(self, runner):
        """Test token when no credentials file exists."""
        with runner.isolated_filesystem():
            result = runner.invoke(main, ['token', '-f', 'nonexistent.json'])
            
            assert result.exit_code == 1
            assert 'No credentials file found' in result.output
