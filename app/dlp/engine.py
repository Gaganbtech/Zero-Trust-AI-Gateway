import re
from typing import Any, Tuple, List, Set
from enum import Enum


class DLPAction(str, Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    BLOCK = "BLOCK"
    REQUIRE_REVIEW = "REQUIRE_REVIEW"


# Regular Expressions for Sensitive Data Patterns
REGEX_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
REGEX_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
REGEX_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
REGEX_PHONE = re.compile(r"(?<!\w)(?:\+\d{1,3}[ .-]?)?(?:\d{3,5}[ .-]){1,2}\d{4,5}(?!\w)")

# Secret Key Patterns
REGEX_AWS_KEY = re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b")
REGEX_GITHUB_TOKEN = re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b")
REGEX_JWT = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")
REGEX_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")


def luhn_checksum_valid(card_digits: str) -> bool:
    """Verifies credit card numbers using the standard Luhn algorithm."""
    digits = [int(c) for c in card_digits if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def redact_text_content(
    text: str,
    action: DLPAction = DLPAction.REDACT
) -> Tuple[str, List[str]]:
    """
    Inspects and sanitizes text for PII and sensitive credentials.
    Returns: (redacted_text, findings_list)
    """
    if not isinstance(text, str) or not text:
        return text, []

    findings: Set[str] = set()

    # 1. AWS Access Keys
    if REGEX_AWS_KEY.search(text):
        findings.add("aws_access_key")
        if action == DLPAction.REDACT:
            text = REGEX_AWS_KEY.sub("[REDACTED_AWS_KEY]", text)

    # 2. GitHub Tokens
    if REGEX_GITHUB_TOKEN.search(text):
        findings.add("github_token")
        if action == DLPAction.REDACT:
            text = REGEX_GITHUB_TOKEN.sub("[REDACTED_GITHUB_TOKEN]", text)

    # 3. Private Keys
    if REGEX_PRIVATE_KEY.search(text):
        findings.add("private_key")
        if action == DLPAction.REDACT:
            text = REGEX_PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", text)

    # 4. JWT Tokens
    if REGEX_JWT.search(text):
        findings.add("jwt_token")
        if action == DLPAction.REDACT:
            text = REGEX_JWT.sub("[REDACTED_JWT]", text)

    # 5. Email Addresses
    text, count = REGEX_EMAIL.subn("[REDACTED_EMAIL]", text) if action == DLPAction.REDACT else (text, len(REGEX_EMAIL.findall(text)))
    if count:
        findings.add("email")

    # 6. Social Security Numbers
    text, count = REGEX_SSN.subn("[REDACTED_SSN]", text) if action == DLPAction.REDACT else (text, len(REGEX_SSN.findall(text)))
    if count:
        findings.add("ssn")

    # 7. Credit Cards (with Luhn check)
    def mask_card(match):
        raw = match.group(0)
        digits = re.sub(r"\D", "", raw)
        if 13 <= len(digits) <= 19 and luhn_checksum_valid(digits):
            findings.add("card_pattern")
            return "[REDACTED_CARD]" if action == DLPAction.REDACT else raw
        return raw

    text = REGEX_CARD.sub(mask_card, text)

    # 8. Phone Numbers
    text, count = REGEX_PHONE.subn("[REDACTED_PHONE]", text) if action == DLPAction.REDACT else (text, len(REGEX_PHONE.findall(text)))
    if count:
        findings.add("phone")

    return text, sorted(findings)


def inspect_and_sanitize_payload(
    payload: Any,
    action: DLPAction = DLPAction.REDACT
) -> Tuple[Any, List[str]]:
    """
    Recursively inspects complex nested data structures (lists, dicts, strings)
    and redacts or identifies sensitive fields according to configured policy.
    """
    total_findings: Set[str] = set()

    if isinstance(payload, str):
        sanitized_str, findings = redact_text_content(payload, action)
        total_findings.update(findings)
        return sanitized_str, sorted(total_findings)

    elif isinstance(payload, list):
        sanitized_list = []
        for item in payload:
            clean_item, item_findings = inspect_and_sanitize_payload(item, action)
            sanitized_list.append(clean_item)
            total_findings.update(item_findings)
        return sanitized_list, sorted(total_findings)

    elif isinstance(payload, dict):
        sanitized_dict = {}
        for key, val in payload.items():
            # Check for sensitive key names explicitly
            lower_key = str(key).lower()
            if any(term in lower_key for term in ("card_number", "card_no", "cc_num")):
                if isinstance(val, str) and luhn_checksum_valid(re.sub(r"\D", "", val)):
                    total_findings.add("card_pattern")
                    sanitized_dict[key] = "[REDACTED_CARD]"
                    continue

            clean_val, val_findings = inspect_and_sanitize_payload(val, action)
            sanitized_dict[key] = clean_val
            total_findings.update(val_findings)
        return sanitized_dict, sorted(total_findings)

    return payload, []
