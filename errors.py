class SkillCheckError(Exception):
    """Base exception for all Skill-Check errors."""
    pass

class AcquisitionError(SkillCheckError):
    """Raised when acquisition or extraction fails."""
    pass

class ScannerError(SkillCheckError):
    """Raised when a scanner phase fails or encounters a terminal error."""
    pass

class SandboxError(SkillCheckError):
    """Raised when the sandbox environment fails."""
    pass

class CircuitBreakerError(SkillCheckError):
    """Raised when a phase fail-closed policy is triggered."""
    pass
