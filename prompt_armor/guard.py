"""Boundary guard - enforce allowed/forbidden actions."""

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from enum import Enum


class ActionResult(Enum):
    """Result of action evaluation."""
    ALLOWED = "allowed"
    FORBIDDEN = "forbidden"
    NEEDS_APPROVAL = "needs_approval"


@dataclass
class Policy:
    """Security policy for boundary enforcement."""
    allowed_actions: Set[str] = field(default_factory=set)
    forbidden_actions: Set[str] = field(default_factory=set)
    allowed_resources: Set[str] = field(default_factory=set)
    forbidden_resources: Set[str] = field(default_factory=set)
    max_data_size_kb: int = 1024
    require_approval_for: Set[str] = field(default_factory=set)


@dataclass
class GuardResult:
    """Result of boundary guard check."""
    result: ActionResult
    message: str
    reason: Optional[str] = None
    policy_matched: Optional[str] = None


class BoundaryGuard:
    """Enforce strict tool/resource access policies."""
    
    def __init__(self, policy: Optional[Policy] = None):
        """
        Initialize boundary guard.
        
        Args:
            policy: Security policy to enforce
        """
        self.policy = policy or Policy()
        self._history: List[GuardResult] = []
    
    def check_action(self, action: str, resource: str = "", 
                     data_size_kb: int = 0) -> GuardResult:
        """
        Check if action is allowed.
        
        Args:
            action: Action to evaluate
            resource: Resource being accessed
            data_size_kb: Size of data involved
            
        Returns:
            GuardResult with decision
        """
        action = action.lower().strip()
        resource = resource.lower().strip()
        
        # Check forbidden actions first
        if action in self.policy.forbidden_actions:
            result = GuardResult(
                result=ActionResult.FORBIDDEN,
                message=f"Action '{action}' is explicitly forbidden",
                reason="forbidden_action",
                policy_matched="forbidden_actions"
            )
            self._history.append(result)
            return result
        
        # Check allowed actions (whitelist mode)
        if self.policy.allowed_actions and action not in self.policy.allowed_actions:
            result = GuardResult(
                result=ActionResult.FORBIDDEN,
                message=f"Action '{action}' not in allowed list",
                reason="not_whitelisted",
                policy_matched="allowed_actions"
            )
            self._history.append(result)
            return result
        
        # Check forbidden resources
        if resource:
            if resource in self.policy.forbidden_resources:
                result = GuardResult(
                    result=ActionResult.FORBIDDEN,
                    message=f"Resource '{resource}' is forbidden",
                    reason="forbidden_resource",
                    policy_matched="forbidden_resources"
                )
                self._history.append(result)
                return result
            
            if (self.policy.allowed_resources and 
                resource not in self.policy.allowed_resources):
                result = GuardResult(
                    result=ActionResult.FORBIDDEN,
                    message=f"Resource '{resource}' not in allowed list",
                    reason="resource_not_whitelisted",
                    policy_matched="allowed_resources"
                )
                self._history.append(result)
                return result
        
        # Check data size
        if data_size_kb > self.policy.max_data_size_kb:
            result = GuardResult(
                result=ActionResult.FORBIDDEN,
                message=f"Data size ({data_size_kb}KB) exceeds limit ({self.policy.max_data_size_kb}KB)",
                reason="data_size_exceeded",
                policy_matched="max_data_size_kb"
            )
            self._history.append(result)
            return result
        
        # Check if approval required
        if action in self.policy.require_approval_for:
            result = GuardResult(
                result=ActionResult.NEEDS_APPROVAL,
                message=f"Action '{action}' requires approval",
                reason="approval_required",
                policy_matched="require_approval_for"
            )
            self._history.append(result)
            return result
        
        result = GuardResult(
            result=ActionResult.ALLOWED,
            message=f"Action '{action}' is allowed",
            policy_matched="default"
        )
        self._history.append(result)
        return result
    
    def update_policy(self, policy: Policy):
        """Update the security policy."""
        self.policy = policy
    
    def get_history(self) -> List[GuardResult]:
        """Get evaluation history."""
        return self._history.copy()
    
    def reset_history(self):
        """Clear evaluation history."""
        self._history.clear()


def load_policy_from_file(path: str) -> Policy:
    """Load policy from JSON file."""
    with open(path, 'r') as f:
        data = json.load(f)
    
    return Policy(
        allowed_actions=set(data.get('allowed_actions', [])),
        forbidden_actions=set(data.get('forbidden_actions', [])),
        allowed_resources=set(data.get('allowed_resources', [])),
        forbidden_resources=set(data.get('forbidden_resources', [])),
        max_data_size_kb=data.get('max_data_size_kb', 1024),
        require_approval_for=set(data.get('require_approval_for', []))
    )


def create_strict_policy() -> Policy:
    """Create a strict default policy."""
    return Policy(
        forbidden_actions={
            "exec", "eval", "system", "shell", "delete", "drop",
            "sudo", "su", "chmod", "chown", "wget", "curl"
        },
        forbidden_resources={
            "/etc/passwd", "/etc/shadow", "/root", "/home/*/.ssh"
        },
        max_data_size_kb=512,
    )


def create_permissive_policy() -> Policy:
    """Create a permissive policy for testing."""
    return Policy(
        allowed_actions={
            "read", "write", "list", "search", "analyze", "detect"
        },
        allowed_resources={
            "/data", "/workspace", "/tmp"
        },
        max_data_size_kb=10240,
    )


if __name__ == "__main__":
    # Demo
    guard = BoundaryGuard(create_strict_policy())
    
    tests = [
        ("read", "/data/file.txt", 10),
        ("exec", "/bin/bash", 0),
        ("delete", "/important", 0),
        ("list", "/workspace", 5),
    ]
    
    for action, resource, size in tests:
        result = guard.check_action(action, resource, size)
        print(f"{action} {resource}: {result.result.value} - {result.message}")
