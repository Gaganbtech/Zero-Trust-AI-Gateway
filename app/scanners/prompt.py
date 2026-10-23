import re
from typing import Tuple, List, Dict, Any
from dataclasses import dataclass


@dataclass
class PromptScanResult:
    is_flagged: bool
    category: str
    reason: str
    confidence: float
    matched_patterns: List[str]
    sanitized_prompt: str


INJECTION_RULES = [
    # 1. Instruction overrides
    (
        "PROMPT_INJECTION_SUSPECTED",
        re.compile(r"\b(ignore|disregard|forget|bypass|override)\s+(all\s+)?(previous|prior|above|system)\s+(instructions|prompts|rules|commands|constraints)\b", re.I),
        0.95,
        "Instruction override directive detected"
    ),
    (
        "PROMPT_INJECTION_SUSPECTED",
        re.compile(r"\bdisregard\s+(your|the)\s+(rules|instructions|safety|guidelines|policies)\b", re.I),
        0.92,
        "Safety directive disregard detected"
    ),
    # 2. Secret disclosure & exfiltration attempts
    (
        "SECRET_DISCLOSURE_ATTEMPT",
        re.compile(r"\b(reveal|print|dump|exfiltrate|leak|display|show|send)\b.{0,60}\b(secret|credentials|password|system prompt|api key|master key|all customer|entire database|private key)\b", re.I),
        0.90,
        "Credential or sensitive dataset extraction instruction detected"
    ),
    # 3. Persona / Jailbreak hijacking
    (
        "PROMPT_INJECTION_SUSPECTED",
        re.compile(r"\b(act as|pretend to be|you are now)\s+(an? )?(unrestricted|unfiltered|jailbroken|different|evil|adversarial|DAN)\s+(ai|assistant|agent|model|mode)\b", re.I),
        0.94,
        "Adversarial persona hijacking detected"
    ),
    # 4. System prompt emulation / delimiter injection
    (
        "UNTRUSTED_CONTENT_INSTRUCTION",
        re.compile(r"(<\|im_start\|>|<\|system\|>|\[SYSTEM\]|<\s*system\s*>|###\s*System\s*Instruction)", re.I),
        0.88,
        "Synthetic system delimiter token injection"
    ),
    # 5. Base64 / Hex obfuscated instruction indicator
    (
        "UNTRUSTED_CONTENT_INSTRUCTION",
        re.compile(r"\b(decode\s+and\s+execute|execute\s+this\s+base64|run\s+the\s+encoded\s+command)\b", re.I),
        0.85,
        "Obfuscated instruction execution pattern"
    ),
]


def scan_prompt(prompt: str) -> PromptScanResult:
    """
    Evaluates input text against known prompt injection heuristics and malicious patterns.
    Note: Heuristic scanning is one defense-in-depth layer, not the primary zero-trust boundary.
    """
    if not prompt or not isinstance(prompt, str):
        return PromptScanResult(
            is_flagged=False,
            category="CLEAN",
            reason="clean",
            confidence=1.0,
            matched_patterns=[],
            sanitized_prompt=prompt or ""
        )

    # Length boundary check
    if len(prompt) > 4000:
        return PromptScanResult(
            is_flagged=True,
            category="PROMPT_LENGTH_EXCEEDED",
            reason="Prompt length exceeds maximum allowable 4000 characters",
            confidence=1.0,
            matched_patterns=["length > 4000"],
            sanitized_prompt=prompt[:4000]
        )

    matched = []
    top_confidence = 0.0
    flagged_category = "CLEAN"
    flagged_reason = "clean"

    for category, regex, confidence, reason in INJECTION_RULES:
        if regex.search(prompt):
            matched.append(reason)
            if confidence > top_confidence:
                top_confidence = confidence
                flagged_category = category
                flagged_reason = reason

    if matched:
        return PromptScanResult(
            is_flagged=True,
            category=flagged_category,
            reason="prompt_injection_heuristic" if flagged_category == "PROMPT_INJECTION_SUSPECTED" else flagged_reason,
            confidence=top_confidence,
            matched_patterns=matched,
            sanitized_prompt=prompt
        )

    return PromptScanResult(
        is_flagged=False,
        category="CLEAN",
        reason="clean",
        confidence=0.90,
        matched_patterns=[],
        sanitized_prompt=prompt
    )
