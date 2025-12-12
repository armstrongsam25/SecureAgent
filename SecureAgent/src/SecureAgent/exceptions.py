class AgenticSecurityError(Exception):
    """Base exception for SecureAgent"""
    pass

class RegistrationError(AgenticSecurityError):
    """Raised when client registration fails"""
    pass

class TokenExchangeError(AgenticSecurityError):
    """Raised when token exchange fails"""
    pass

class PolicyDenied(TokenExchangeError):
    """Raised when token exchange is forbidden (403)"""
    pass


class KeycloakConnectionError(AgenticSecurityError):
    """Raised when Keycloak server is unreachable"""
    pass


class TokenCacheError(AgenticSecurityError):
    """Raised when token caching operations fail"""
    pass


class InitialAccessTokenError(RegistrationError):
    """Raised when initial access token is missing or invalid"""
    
    def __init__(self, message: str = None):
        default_msg = (
            "Initial access token required for first-time registration. "
            "Get one from Keycloak Admin Console → Clients → Initial Access Tokens"
        )
        super().__init__(message or default_msg)

