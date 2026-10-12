"""Custom exceptions for BHARYDANGEROUS-Investigator."""

class ForensicError(Exception):
    """Base exception for all forensic errors."""
    pass

class ForensicIntegrityError(ForensicError):
    """Raised when evidence verification fails or hash mismatch is detected."""
    pass

class DecompressionBombError(ForensicError):
    """Raised when an archive exceeds safety compression ratios or sizes."""
    pass

class PathTraversalSecurityError(ForensicError):
    """Raised when an extracted path attempts to escape the designated workspace."""
    pass

class DependencyMissingError(ForensicError):
    """Raised when an external system tool or optional dependency is required but absent."""
    def __init__(self, tool_name: str, install_hint: str):
        self.tool_name = tool_name
        self.install_hint = install_hint
        super().__init__(f"Tool '{tool_name}' is not installed or not in PATH. {install_hint}")

class UnsupportedFormatError(ForensicError):
    """Raised when an unrecognized or unsupported forensic artifact is processed."""
    pass

class ConsentDeniedError(ForensicError):
    """Raised when user denies consent for AI data transmission or operation."""
    pass

class AIProviderError(ForensicError):
    """Raised when an AI provider fails, times out, or returns invalid outputs."""
    pass

class DatabaseError(ForensicError):
    """Raised when database operations encounter corruption or constraint violations."""
    pass
