#!/usr/bin/env python3
"""CLI entry point for Prompt Armor."""

import argparse
import json
import sys
import os
from pathlib import Path
from typing import Optional

from prompt_armor.detector import PromptDetector, scan_text
from prompt_armor.guard import BoundaryGuard, load_policy_from_file, create_strict_policy, create_permissive_policy, ActionResult
from prompt_armor.filter import PIIFilter, scan_text as scan_pii
from prompt_armor.audit import AuditLogger, EventType, log_injection, log_guard_decision, log_pii_detected


def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="prompt-armor",
        description="Prompt Armor - AI Security Runtime Guard",
        epilog="Detect prompt injection, enforce boundaries, filter PII."
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan text for prompt injection")
    scan_parser.add_argument("text", help="Text to scan", nargs="?")
    scan_parser.add_argument("-f", "--file", help="Read from file")
    scan_parser.add_argument("-t", "--threshold", type=float, default=0.5,
                             help="Detection threshold (0-1)")
    scan_parser.add_argument("--json", action="store_true", help="Output JSON")
    
    # guard command
    guard_parser = subparsers.add_parser("guard", help="Check action against policy")
    guard_parser.add_argument("action", help="Action to check")
    guard_parser.add_argument("resource", help="Resource", nargs="?", default="")
    guard_parser.add_argument("-p", "--policy", help="Policy file (JSON)")
    guard_parser.add_argument("--strict", action="store_true", help="Use strict policy")
    guard_parser.add_argument("--permissive", action="store_true", help="Use permissive policy")
    guard_parser.add_argument("--json", action="store_true", help="Output JSON")
    
    # filter command
    filter_parser = subparsers.add_parser("filter", help="Filter PII from text")
    filter_parser.add_argument("text", help="Text to filter", nargs="?")
    filter_parser.add_argument("-f", "--file", help="Read from file")
    filter_parser.add_argument("-m", "--mask-level", choices=["full", "partial"],
                               default="partial", help="Masking level")
    filter_parser.add_argument("--json", action="store_true", help="Output JSON")
    
    # audit command
    audit_parser = subparsers.add_parser("audit", help="Query audit logs")
    audit_parser.add_argument("--stats", action="store_true", help="Show statistics")
    audit_parser.add_argument("--type", dest="event_type", help="Filter by event type")
    audit_parser.add_argument("--severity", help="Filter by severity")
    audit_parser.add_argument("--limit", type=int, default=10, help="Limit results")
    audit_parser.add_argument("-l", "--log-file", help="Audit log file")
    
    # version
    parser.add_argument("--version", action="version", version="Prompt Armor v0.1.0")
    
    return parser


def cmd_scan(args) -> int:
    """Handle scan command."""
    # Get text
    if args.file:
        with open(args.file, 'r') as f:
            text = f.read()
    elif args.text:
        text = args.text
    else:
        print("Error: Provide text or --file", file=sys.stderr)
        return 1
    
    # Detect
    detector = PromptDetector(threshold=args.threshold)
    result = detector.detect(text)
    
    # Setup logging
    log_file = os.environ.get("PROMPT_ARMOR_AUDIT_LOG")
    logger = AuditLogger(log_file=log_file) if log_file else None
    
    if logger:
        log_injection(
            text_preview=text[:200],
            confidence=result.confidence,
            patterns=result.matched_patterns,
            logger=logger
        )
    
    # Output
    if args.json:
        output = {
            "is_injection": result.is_injection,
            "confidence": result.confidence,
            "matched_patterns": result.matched_patterns,
            "message": result.message
        }
        print(json.dumps(output, indent=2))
    else:
        status = "🚨 BLOCKED" if result.is_injection else "✅ CLEAN"
        print(f"{status} - {result.message}")
        if result.matched_patterns:
            print(f"Patterns: {', '.join(result.matched_patterns[:5])}")
    
    return 0 if not result.is_injection else 1


def cmd_guard(args) -> int:
    """Handle guard command."""
    # Load policy
    if args.policy:
        policy = load_policy_from_file(args.policy)
    elif args.strict:
        policy = create_strict_policy()
    elif args.permissive:
        policy = create_permissive_policy()
    else:
        policy = create_strict_policy()
    
    guard = BoundaryGuard(policy)
    
    # Check action
    result = guard.check_action(args.action, args.resource)
    
    # Setup logging
    log_file = os.environ.get("PROMPT_ARMOR_AUDIT_LOG")
    logger = AuditLogger(log_file=log_file) if log_file else None
    
    if logger:
        log_guard_decision(
            action=args.action,
            resource=args.resource,
            result=result.result.value,
            reason=result.reason,
            logger=logger
        )
    
    # Output
    if args.json:
        output = {
            "result": result.result.value,
            "message": result.message,
            "reason": result.reason,
            "policy_matched": result.policy_matched
        }
        print(json.dumps(output, indent=2))
    else:
        icon = "⛔" if result.result == ActionResult.FORBIDDEN else "✅"
        print(f"{icon} {result.result.value.upper()} - {result.message}")
    
    return 0 if result.result == ActionResult.ALLOWED else 1


def cmd_filter(args) -> int:
    """Handle filter command."""
    # Get text
    if args.file:
        with open(args.file, 'r') as f:
            text = f.read()
    elif args.text:
        text = args.text
    else:
        print("Error: Provide text or --file", file=sys.stderr)
        return 1
    
    # Filter
    pii_filter = PIIFilter(mask_level=args.mask_level)
    result = pii_filter.detect(text)
    
    # Setup logging
    log_file = os.environ.get("PROMPT_ARMOR_AUDIT_LOG")
    logger = AuditLogger(log_file=log_file) if log_file else None
    
    if logger and result.has_pii:
        for match in result.matches:
            log_pii_detected(
                pii_type=match.pii_type,
                original=match.value,
                masked=match.masked,
                logger=logger
            )
    
    # Output
    if args.json:
        output = {
            "has_pii": result.has_pii,
            "summary": result.summary,
            "matches": [
                {
                    "type": m.pii_type,
                    "masked": m.masked
                }
                for m in result.matches
            ],
            "filtered_text": result.filtered_text
        }
        print(json.dumps(output, indent=2))
    else:
        if result.has_pii:
            print("⚠️  PII DETECTED")
            for pii_type, count in result.summary.items():
                print(f"  - {pii_type}: {count}")
            print("\nFiltered text:")
            print(result.filtered_text)
        else:
            print("✅ No PII detected")
    
    return 0 if not result.has_pii else 1


def cmd_audit(args) -> int:
    """Handle audit command."""
    log_file = args.log_file or "audit.jsonl"
    logger = AuditLogger(log_file=log_file)
    
    if args.stats:
        stats = logger.get_stats()
        print(json.dumps(stats, indent=2))
    else:
        event_type = EventType(args.event_type) if args.event_type else None
        events = logger.query(
            event_type=event_type,
            severity=args.severity,
            limit=args.limit
        )
        
        if not events:
            print("No events found")
            return 0
        
        for event in events:
            print(f"[{event.timestamp}] {event.severity} - {event.event_type}")
            print(f"  {json.dumps(event.details)}")
            print()
    
    return 0


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    commands = {
        "scan": cmd_scan,
        "guard": cmd_guard,
        "filter": cmd_filter,
        "audit": cmd_audit
    }
    
    if args.command in commands:
        return commands[args.command](args)
    
    print(f"Unknown command: {args.command}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
