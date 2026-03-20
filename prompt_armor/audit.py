"""Audit logging for security events."""

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class AuditEvent:
    """Audit event record."""
    timestamp: str
    event_type: str
    severity: str  # low, medium, high, critical
    source: str
    details: Dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class AuditLogger:
    """JSON-based audit logger for security events."""
    
    def __init__(self, log_path: Optional[str] = None):
        """Initialize audit logger with optional log file path."""
        self.log_path = log_path
        self._events: List[AuditEvent] = []
        
        if log_path:
            # Ensure log directory exists
            log_dir = Path(log_path).parent
            log_dir.mkdir(parents=True, exist_ok=True)
            
            # Load existing events if file exists
            if os.path.exists(log_path):
                self._load_events()
    
    def _load_events(self):
        """Load existing events from log file."""
        try:
            with open(self.log_path, 'r') as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        self._events.append(AuditEvent(**data))
        except (json.JSONDecodeError, IOError):
            pass  # Start fresh if file is corrupted
    
    def log(
        self,
        event_type: str,
        severity: str,
        source: str,
        details: Optional[Dict[str, Any]] = None,
        blocked: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AuditEvent:
        """Log an audit event."""
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=event_type,
            severity=severity,
            source=source,
            details=details or {},
            blocked=blocked,
            metadata=metadata or {}
        )
        
        self._events.append(event)
        
        # Write to file immediately if path is set
        if self.log_path:
            self._write_event(event)
        
        return event
    
    def _write_event(self, event: AuditEvent):
        """Write event to log file."""
        try:
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(asdict(event)) + '\n')
        except IOError:
            pass  # Fail silently on write error
    
    def log_injection(self, text: str, result, metadata: Optional[Dict] = None):
        """Log a prompt injection check."""
        # Handle both old-style and new DetectionResult
        if hasattr(result, 'is_injection'):
            detected = result.is_injection
            score = result.confidence
            patterns = result.matched_patterns
        else:
            detected = result.detected
            score = result.score
            patterns = result.threats if hasattr(result, 'threats') else []
            
        return self.log(
            event_type="injection_detected",
            severity="high" if detected else "low",
            source="detector",
            details={
                "score": score,
                "patterns": patterns,
                "text_preview": text[:200] if len(text) > 200 else text
            },
            blocked=detected,
            metadata=metadata or {}
        )
    
    def log_guard(self, tool: str, allowed: bool, metadata: Optional[Dict] = None):
        """Log a boundary guard check."""
        return self.log(
            event_type="guard_check",
            severity="medium" if not allowed else "low",
            source="guard",
            details={"tool": tool, "allowed": allowed},
            blocked=not allowed,
            metadata=metadata or {}
        )
    
    def log_pii(self, text: str, result, metadata: Optional[Dict] = None):
        """Log a PII detection."""
        # Handle both old-style and new FilterResult
        if hasattr(result, 'has_pii'):
            detected = result.has_pii
            matches = result.matches
            summary = result.summary
        else:
            detected = result.detected
            matches = result.matches if hasattr(result, 'matches') else []
            summary = {"types": result.pi_types} if hasattr(result, 'pi_types') else {}
            
        return self.log(
            event_type="pii_detected",
            severity="medium" if detected else "low",
            source="filter",
            details={
                "types": list(summary.keys()) if summary else [],
                "match_count": len(matches)
            },
            blocked=detected,
            metadata=metadata or {}
        )
    
    def get_events(
        self,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        since: Optional[datetime] = None
    ) -> List[AuditEvent]:
        """Query audit events."""
        events = self._events
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        if severity:
            events = [e for e in events if e.severity == severity]
        
        if since:
            since_iso = since.isoformat()
            events = [e for e in events if e.timestamp >= since_iso]
        
        return events
    
    def summary(self) -> Dict[str, Any]:
        """Get summary of logged events."""
        return {
            "total_events": len(self._events),
            "by_type": self._count_by_field("event_type"),
            "by_severity": self._count_by_field("severity"),
            "blocked_count": sum(1 for e in self._events if e.blocked)
        }
    
    def _count_by_field(self, field: str) -> Dict[str, int]:
        """Count events by a specific field."""
        counts = {}
        for event in self._events:
            value = getattr(event, field, "unknown")
            counts[value] = counts.get(value, 0) + 1
        return counts


def create_logger(log_path: Optional[str] = None) -> AuditLogger:
    """Convenience function to create audit logger."""
    return AuditLogger(log_path)