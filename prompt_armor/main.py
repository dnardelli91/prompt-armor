"""Main Prompt Armor module - unified interface."""

from .detector import PromptDetector, scan_text as detect_injection, DetectionResult
from .guard import BoundaryGuard, Policy, GuardResult, create_strict_policy
from .filter import PIIFilter, scan_text as detect_pii, FilterResult
from .audit import AuditLogger, create_logger, AuditEvent


class Armor:
    """Unified Prompt Armor security layer."""
    
    def __init__(
        self,
        injection_threshold: float = 0.3,
        policy: Policy = None,
        log_path: str = None
    ):
        """Initialize Prompt Armor with all components."""
        self.detector = PromptDetector(threshold=injection_threshold)
        self.guard = BoundaryGuard(policy=policy)
        self.filter = PIIFilter()
        self.logger = AuditLogger(log_path=log_path) if log_path else None
    
    def check_input(self, text: str) -> DetectionResult:
        """Check input for prompt injection."""
        result = self.detector.detect(text)
        if self.logger:
            self.logger.log_injection(text, result)
        return result
    
    def check_output(self, text: str) -> FilterResult:
        """Check output for PII leakage."""
        result = self.filter.detect(text)
        if self.logger:
            self.logger.log_pii(text, result)
        return result
    
    def check_tool(self, tool_name: str) -> bool:
        """Check if tool access is allowed."""
        result = self.guard.check_action(tool_name)
        allowed = result.result.value == "allowed"
        if self.logger:
            self.logger.log_guard(tool_name, allowed)
        return allowed
    
    def check_command(self, action: str, resource: str = "") -> GuardResult:
        """Check if command is allowed."""
        result = self.guard.check_action(action, resource)
        if self.logger:
            self.logger.log_guard(action, result.result.value == "allowed")
        return result
    
    def sanitize(self, text: str) -> FilterResult:
        """Detect and redact PII from text."""
        result = self.filter.detect(text)
        if self.logger:
            self.logger.log_pii(text, result)
        return result
    
    def full_check(self, text: str) -> dict:
        """Run all checks on text."""
        injection = self.check_input(text)
        pii = self.check_output(text)
        
        return {
            "injection": {
                "detected": injection.is_injection,
                "confidence": injection.confidence,
                "patterns": injection.matched_patterns
            },
            "pii": {
                "detected": pii.has_pii,
                "types": list(pii.summary.keys())
            }
        }


__all__ = [
    "Armor",
    "PromptDetector",
    "BoundaryGuard", 
    "PIIFilter",
    "AuditLogger",
    "detect_injection",
    "detect_pii",
    "create_logger",
    "DetectionResult",
    "GuardResult",
    "FilterResult",
    "Policy",
    "create_strict_policy"
]