"""Prompt Armor - Runtime security layer for AI agents."""

from .main import Armor, detect_injection, detect_pii, create_logger
from .main import create_strict_policy
from .detector import PromptDetector, scan_text, DetectionResult
from .guard import BoundaryGuard, Policy, GuardResult, create_strict_policy as strict_policy
from .filter import PIIFilter, scan_text as scan_pii, FilterResult
from .audit import AuditLogger

__version__ = "0.1.0"

__all__ = [
    "Armor",
    "PromptDetector",
    "BoundaryGuard",
    "PIIFilter",
    "AuditLogger",
    "detect_injection",
    "detect_pii",
    "create_logger",
    "create_strict_policy",
    "DetectionResult",
    "GuardResult",
    "FilterResult",
    "Policy",
    "scan_text",
    "scan_pii",
    "strict_policy"
]