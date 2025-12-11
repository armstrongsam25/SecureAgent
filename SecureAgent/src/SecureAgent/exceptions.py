class AgenticSecurityError(Exception):
    """Base exception for agentic-security"""
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
