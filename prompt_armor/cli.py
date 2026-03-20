#!/usr/bin/env python3
"""Command-line interface for Prompt Armor."""

import argparse
import json
import sys
from pathlib import Path

from prompt_armor import (
    Armor, detect_injection, detect_pii, Policy, create_logger
)
from prompt_armor.detector import PromptDetector
from prompt_armor.guard import BoundaryGuard, create_strict_policy
from prompt_armor.filter import PIIFilter


def cmd_check(args):
    """Run security checks on input text."""
    text = args.text or sys.stdin.read().strip()
    
    if not text:
        print("Error: No input text provided", file=sys.stderr)
        return 1
    
    # Initialize armor with optional audit log
    logger = create_logger(args.log) if args.log else None
    
    policy = create_strict_policy() if args.restrictive else None
    
    armor = Armor(
        injection_threshold=args.threshold,
        policy=policy,
        log_path=args.log
    )
    
    if args.mode == "injection":
        result = armor.check_input(text)
        output = {
            "detected": result.is_injection,
            "confidence": result.confidence,
            "patterns": result.matched_patterns,
            "message": result.message
        }
    elif args.mode == "pii":
        result = armor.check_output(text)
        output = {
            "detected": result.has_pii,
            "summary": result.summary,
            "matches": [{"type": m.pii_type, "value": m.masked} for m in result.matches[:10]]
        }
    elif args.mode == "sanitize":
        result = armor.sanitize(text)
        output = {
            "detected": result.has_pii,
            "filtered": result.filtered_text
        }
    else:  # full
        result = armor.full_check(text)
        output = result
    
    print(json.dumps(output, indent=2))
    return 0


def cmd_detect(args):
    """Run only injection detection."""
    text = args.text or sys.stdin.read().strip()
    
    if not text:
        print("Error: No input text provided", file=sys.stderr)
        return 1
    
    detector = PromptDetector(threshold=args.threshold)
    result = detector.detect(text)
    
    output = {
        "detected": result.is_injection,
        "confidence": result.confidence,
        "patterns": result.matched_patterns,
        "message": result.message
    }
    
    print(json.dumps(output, indent=2))
    return 0 if not result.is_injection else 1


def cmd_guard(args):
    """Check tool/command access against policy."""
    # Get tool from either positional or option
    tool_name = getattr(args, 'tool', None) or getattr(args, 'tool_opt', None)
    
    if not tool_name and not args.command:
        print("Error: Provide tool name or --command", file=sys.stderr)
        return 1
    
    policy = create_strict_policy() if args.restrictive else Policy()
    guard = BoundaryGuard(policy=policy)
    
    if tool_name:
        result = guard.check_action(tool_name)
        output = {
            "action": tool_name,
            "result": result.result.value,
            "message": result.message
        }
    else:
        parts = args.command.split()
        action = parts[0] if parts else ""
        resource = parts[1] if len(parts) > 1 else ""
        result = guard.check_action(action, resource)
        output = {
            "result": result.result.value,
            "message": result.message
        }
    
    print(json.dumps(output, indent=2))
    return 0 if result.result.value == "allowed" else 1


def cmd_audit(args):
    """View audit logs."""
    logger = create_logger(args.log)
    
    if args.summary:
        print(json.dumps(logger.summary(), indent=2))
    else:
        events = logger.get_events(
            event_type=args.type,
            severity=args.severity
        )
        for event in events:
            print(json.dumps(event.__dict__, default=str))
    
    return 0


# Map function names to command names for workaround
_FUNC_TO_CMD = {
    'cmd_check': 'check',
    'cmd_detect': 'detect', 
    'cmd_guard': 'guard',
    'cmd_audit': 'audit'
}


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Prompt Armor - Runtime security layer for AI agents"
    )
    
    # Global options (must be added before subparsers for proper parsing)
    parser.add_argument("-l", "--log", help="Audit log path")
    parser.add_argument("-t", "--threshold", type=float, default=0.3,
                        help="Detection threshold (default: 0.5)")
    
    # Subparsers
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # check command
    check_parser = subparsers.add_parser("check", help="Run security checks")
    check_parser.add_argument("text", nargs="?", help="Text to check")
    check_parser.add_argument("-m", "--mode", 
                              choices=["injection", "pii", "sanitize", "full"],
                              default="full", help="Check mode")
    check_parser.add_argument("-r", "--restrictive", action="store_true",
                              help="Use restrictive policy")
    check_parser.set_defaults(func=cmd_check)
    
    # detect command
    detect_parser = subparsers.add_parser("detect", help="Detect injection")
    detect_parser.add_argument("text", nargs="?", help="Text to check")
    detect_parser.set_defaults(func=cmd_detect)
    
    # guard command
    guard_parser = subparsers.add_parser("guard", help="Check access policy")
    guard_parser.add_argument("tool", nargs="?", help="Tool name")
    guard_parser.add_argument("-T", "--tool", dest="tool_opt", help="Tool name (alt)")
    guard_parser.add_argument("-c", "--command", help="Command string")
    guard_parser.add_argument("-r", "--restrictive", action="store_true",
                              help="Use restrictive policy")
    guard_parser.set_defaults(func=cmd_guard)
    
    # audit command  
    audit_parser = subparsers.add_parser("audit", help="View audit logs")
    audit_parser.add_argument("-t", "--type", help="Filter by event type")
    audit_parser.add_argument("-s", "--severity", help="Filter by severity")
    audit_parser.add_argument("--summary", action="store_true", help="Show summary")
    audit_parser.set_defaults(func=cmd_audit)
    
    args = parser.parse_args()
    
    # Workaround for argparse bug: command may be None even when subparser matched
    # If func is set but command is None, infer command from func name
    if args.command is None:
        func_name = getattr(args, 'func', None).__name__ if hasattr(args, 'func') and args.func else None
        if func_name and func_name in _FUNC_TO_CMD:
            args.command = _FUNC_TO_CMD[func_name]
    
    if args.command is None:
        parser.print_help()
        return 1
    
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())