"""PII detection filter - regex for email, phone, SSN, credit card."""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class PIIMatch:
    """Represents a PII match."""
    pii_type: str
    value: str
    start: int
    end: int
    masked: str


@dataclass
class FilterResult:
    """Result of PII filtering."""
    has_pii: bool
    matches: List[PIIMatch]
    filtered_text: str
    summary: Dict[str, int]


class PIIFilter:
    """Detect and filter PII from text using regex."""
    
    # Regex patterns for various PII types
    PATTERNS = {
        "email": (
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "EMAIL"
        ),
        "phone_us": (
            r'\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b',
            "PHONE"
        ),
        "phone_intl": (
            r'\b\+\d{1,3}[-.\s]?\d{2,4}[-.\s]?\d{2,4}[-.\s]?\d{2,4}\b',
            "PHONE"
        ),
        "ssn": (
            r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
            "SSN"
        ),
        "credit_card": (
            r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            "CREDIT_CARD"
        ),
        "credit_card_amex": (
            r'\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b',
            "CREDIT_CARD"
        ),
        "ipv4": (
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            "IP_ADDRESS"
        ),
        "ipv6": (
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            "IP_ADDRESS"
        ),
        "date_of_birth": (
            r'\b(?:DOB|Date\s*of\s*Birth|Born)[:\s]*(?:\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2})\b',
            "DOB"
        ),
        "passport": (
            r'\b[A-Z]{1,2}\d{6,9}\b',
            "PASSPORT"
        ),
        "drivers_license": (
            r'\b[A-Z]{1,2}\d{5,8}\b',
            "DRIVERS_LICENSE"
        ),
    }
    
    # Context keywords that increase confidence
    CONTEXT_KEYWORDS = {
        "email": ["email", "e-mail", "mail", "contact"],
        "phone": ["phone", "tel", "mobile", "cell", "fax"],
        "ssn": ["ssn", "social security", "sin"],
        "credit_card": ["credit", "card", "visa", "mastercard", "amex"],
        "ipv4": ["ip", "address", "server", "host"],
        "ipv6": ["ipv6", "ip"],
    }
    
    def __init__(self, mask_char: str = "*", mask_level: str = "partial"):
        """
        Initialize PII filter.
        
        Args:
            mask_char: Character to use for masking
            mask_level: "full" or "partial" (show last 4)
        """
        self.mask_char = mask_char
        self.mask_level = mask_level
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns."""
        self._patterns = {}
        for pii_type, (pattern, label) in self.PATTERNS.items():
            self._patterns[pii_type] = re.compile(pattern, re.IGNORECASE)
    
    def detect(self, text: str, context: Optional[str] = None) -> FilterResult:
        """
        Detect PII in text.
        
        Args:
            text: Text to scan
            context: Optional context for better detection
            
        Returns:
            FilterResult with matches
        """
        matches = []
        
        for pii_type, pattern in self._patterns.items():
            for match in pattern.finditer(text):
                masked = self._mask_value(match.group(), pii_type)
                matches.append(PIIMatch(
                    pii_type=pii_type,
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    masked=masked
                ))
        
        # Filter by context keywords if provided
        if context:
            matches = self._filter_by_context(matches, context.lower())
        
        # Build summary
        summary: Dict[str, int] = {}
        for m in matches:
            label = self.PATTERNS[m.pii_type][1]
            summary[label] = summary.get(label, 0) + 1
        
        # Generate filtered text
        filtered_text = self._apply_filter(text, matches)
        
        return FilterResult(
            has_pii=len(matches) > 0,
            matches=matches,
            filtered_text=filtered_text,
            summary=summary
        )
    
    def _mask_value(self, value: str, pii_type: str) -> str:
        """Mask PII value based on type."""
        if self.mask_level == "partial":
            # Show last 4 characters
            if len(value) > 4:
                return self.mask_char * (len(value) - 4) + value[-4:]
            return self.mask_char * len(value)
        else:
            # Full mask
            return self.mask_char * len(value)
    
    def _filter_by_context(self, matches: List[PIIMatch], context: str) -> List[PIIMatch]:
        """Filter matches by context keywords."""
        filtered = []
        for match in matches:
            keywords = self.CONTEXT_KEYWORDS.get(match.pii_type, [])
            if any(kw in context for kw in keywords):
                filtered.append(match)
            elif match.pii_type not in self.CONTEXT_KEYWORDS:
                # Keep if no context check needed
                filtered.append(match)
        return filtered
    
    def _apply_filter(self, text: str, matches: List[PIIMatch]) -> str:
        """Apply masking to text."""
        if not matches:
            return text
        
        # Sort by position (reverse) to replace from end
        sorted_matches = sorted(matches, key=lambda m: m.start, reverse=True)
        
        result = text
        for match in sorted_matches:
            result = result[:match.start] + match.masked + result[match.end:]
        
        return result
    
    def scan_and_filter(self, text: str) -> Tuple[FilterResult, str]:
        """Convenience function returning result and filtered text."""
        result = self.detect(text)
        return result, result.filtered_text
    
    def get_supported_types(self) -> List[str]:
        """Get list of supported PII types."""
        return list(self.PATTERNS.keys())


def scan_text(text: str) -> FilterResult:
    """Convenience function for quick PII scanning."""
    filter = PIIFilter()
    return filter.detect(text)


if __name__ == "__main__":
    # Demo
    test_text = """
    Contact: john.doe@example.com or jane@company.org
    Phone: +1-555-123-4567 or (555) 987-6543
    SSN: 123-45-6789
    Credit Card: 4532-1234-5678-9012
    IP: 192.168.1.1
    """
    
    pii_filter = PIIFilter(mask_level="partial")
    result = pii_filter.detect(test_text)
    
    print("Original text:")
    print(test_text)
    print("\nFiltered text:")
    print(result.filtered_text)
    print("\nSummary:", result.summary)
    print("\nMatches:")
    for m in result.matches:
        print(f"  {m.pii_type}: {m.value} → {m.masked}")
