import re
from typing import Any

INJECTION_PATTERNS = [
    re.compile(r"\bignore\s+(all\s+)?(previous|prior|above)\s+instructions\b", re.I),
    re.compile(r"\b(reveal|print|dump|exfiltrate)\b.{0,50}\b(secret|credentials|customer records|system prompt|api key|all customer)\b", re.I),
    re.compile(r"\bact as (an? )?(unrestricted|unfiltered|different) (ai|assistant|agent)\b", re.I),
    re.compile(r"\bdisregard\s+(your|the)\s+(rules|instructions|safety)\b", re.I),
]
EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
PHONE = re.compile(r"(?<!\w)(?:\+\d{1,3}[ .-]?)?(?:\d{3,5}[ .-]){1,2}\d{4,5}(?!\w)")
SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")

def scan_prompt(prompt: str) -> tuple[bool, str]:
    for pattern in INJECTION_PATTERNS:
        if pattern.search(prompt): return True, "prompt_injection_heuristic"
    return False, "clean"

def luhn_valid(number: str) -> bool:
    total, parity = 0, len(number) % 2
    for i, char in enumerate(number):
        digit = int(char)
        if i % 2 == parity:
            digit *= 2
            if digit > 9: digit -= 9
        total += digit
    return total % 10 == 0

def redact_text(text: str) -> tuple[str, list[str]]:
    findings = []
    text, n = EMAIL.subn("[REDACTED_EMAIL]", text)
    if n: findings.append("email")
    text, n = SSN.subn("[REDACTED_SSN]", text)
    if n: findings.append("ssn")
    def mask_card(m):
        digits = re.sub(r"\D", "", m.group())
        return "[REDACTED_CARD]" if 13 <= len(digits) <= 19 and luhn_valid(digits) else m.group()
    text, n = CARD.subn(mask_card, text)
    if n: findings.append("card_pattern")
    text, n = PHONE.subn("[REDACTED_PHONE]", text)
    if n: findings.append("phone")
    return text, sorted(set(findings))

def redact_payload(value: Any) -> tuple[Any, list[str]]:
    found = set()
    if isinstance(value, str):
        value, items = redact_text(value); found.update(items)
    elif isinstance(value, list):
        result = []
        for item in value:
            clean, items = redact_payload(item); result.append(clean); found.update(items)
        value = result
    elif isinstance(value, dict):
        result = {}
        for key, item in value.items():
            clean, items = redact_payload(item); result[key] = clean; found.update(items)
        value = result
    return value, sorted(found)
