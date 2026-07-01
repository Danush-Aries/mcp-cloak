"""Secret and PII detectors: regex + Shannon entropy.

All detectors are pure functions over text. ``detect()`` returns a list of
non-overlapping :class:`Match` spans, resolved by class priority so that a
specific detector (e.g. AWS key) wins over a generic one (e.g. high-entropy
secret) on the same span.

An optional Microsoft Presidio backend can enrich PII detection when the
``presidio`` extra is installed and enabled in config. The regex path works
fully without it.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Match:
    """A detected secret/PII span within a piece of text."""

    start: int
    end: int
    cls: str
    value: str


# --- Regex detectors (ordered most-specific first) ------------------------

# Private key PEM blocks (RSA / EC / OPENSSH / generic).
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)

# JSON Web Tokens: header.payload.signature, header & payload start with "eyJ".
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")

# AWS access key IDs.
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b")

# Common provider-prefixed API tokens (OpenAI sk-, GitHub ghp_, Slack xoxb-,
# Google AIza..., Stripe-style pk/rk-).
PREFIXED_TOKEN_RE = re.compile(
    r"\b(?:sk|pk|rk)-[A-Za-z0-9_]{6,}\b"
    r"|\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}\b"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}\b"
    r"|\bAIza[0-9A-Za-z_-]{20,}\b"
)

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Phone numbers: require at least one separator so we do not swallow plain
# long digit runs (IDs, versions, etc.).
PHONE_RE = re.compile(
    r"(?<![\w.=/])"
    r"(?:\+\d{1,3}[-.\s]?)?"
    r"(?:\(\d{2,4}\)|\d{2,4})[-.\s]\d{3,4}[-.\s]\d{3,4}"
    r"(?![\w])"
)

# RFC1918 private IPv4 ranges.
PRIVATE_IP_RE = re.compile(
    r"\b(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r")\b"
)

# Internal hostnames on common private TLDs.
INTERNAL_HOST_RE = re.compile(
    r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*"
    r"\.(?:internal|local|corp|intranet|lan)\b"
)

# Generic candidate tokens for entropy analysis.
GENERIC_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_\-]{20,}")

# (class name, compiled regex). Priority = position in this list (earlier wins).
_REGEX_DETECTORS: list[tuple[str, re.Pattern[str]]] = [
    ("PRIVATE_KEY", PRIVATE_KEY_RE),
    ("JWT", JWT_RE),
    ("AWS_KEY", AWS_KEY_RE),
    ("APIKEY", PREFIXED_TOKEN_RE),
    ("EMAIL", EMAIL_RE),
    ("INTERNAL_HOST", INTERNAL_HOST_RE),
    ("PRIVATE_IP", PRIVATE_IP_RE),
    ("PHONE", PHONE_RE),
]

# Priority order for overlap resolution (lower index = higher priority).
_CLASS_PRIORITY = {
    name: i for i, (name, _) in enumerate(_REGEX_DETECTORS)
}
_CLASS_PRIORITY["SECRET"] = len(_CLASS_PRIORITY)  # entropy fallback, lowest


def shannon_entropy(s: str) -> float:
    """Return Shannon entropy of ``s`` in bits per character."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _entropy_matches(text: str, threshold: float) -> Iterable[Match]:
    """Yield high-entropy generic tokens that look like secrets."""
    for m in GENERIC_TOKEN_RE.finditer(text):
        tok = m.group(0)
        has_alpha = any(c.isalpha() for c in tok)
        has_digit = any(c.isdigit() for c in tok)
        if not (has_alpha and has_digit):
            continue
        if shannon_entropy(tok) < threshold:
            continue
        yield Match(m.start(), m.end(), "SECRET", tok)


def _resolve_overlaps(matches: list[Match]) -> list[Match]:
    """Drop overlapping matches, keeping higher priority / longer spans."""
    # Sort by start, then by priority, then by longer span first.
    ordered = sorted(
        matches,
        key=lambda m: (m.start, _CLASS_PRIORITY.get(m.cls, 99), -(m.end - m.start)),
    )
    chosen: list[Match] = []
    occupied_end = -1
    for m in ordered:
        if m.start >= occupied_end:
            chosen.append(m)
            occupied_end = m.end
    return chosen


def detect(
    text: str,
    *,
    enabled: set[str] | None = None,
    entropy_enabled: bool = True,
    entropy_threshold: float = 3.5,
    use_presidio: bool = False,
) -> list[Match]:
    """Detect secrets/PII in ``text``.

    Args:
        text: The text to scan.
        enabled: Optional set of class names to restrict detection to. ``None``
            means all classes are enabled.
        entropy_enabled: Whether to run the high-entropy generic-secret detector.
        entropy_threshold: Minimum bits/char for a token to be flagged as SECRET.
        use_presidio: If True and Presidio is installed, enrich PII detection.

    Returns:
        Non-overlapping matches sorted by start offset.
    """
    if not isinstance(text, str) or not text:
        return []

    matches: list[Match] = []
    for cls, regex in _REGEX_DETECTORS:
        if enabled is not None and cls not in enabled:
            continue
        for m in regex.finditer(text):
            matches.append(Match(m.start(), m.end(), cls, m.group(0)))

    if entropy_enabled and (enabled is None or "SECRET" in enabled):
        matches.extend(_entropy_matches(text, entropy_threshold))

    if use_presidio:
        matches.extend(_presidio_matches(text, enabled))

    return _resolve_overlaps(matches)


def _presidio_matches(text: str, enabled: set[str] | None) -> list[Match]:
    """Optional Presidio-backed PII detection. No-op if Presidio missing."""
    try:  # pragma: no cover - optional dependency
        from presidio_analyzer import AnalyzerEngine
    except Exception:  # pragma: no cover
        return []

    global _PRESIDIO_ENGINE  # noqa: PLW0603
    try:
        engine = _PRESIDIO_ENGINE  # type: ignore[name-defined]
    except NameError:  # pragma: no cover
        engine = _PRESIDIO_ENGINE = AnalyzerEngine()

    out: list[Match] = []
    for r in engine.analyze(text=text, language="en"):  # pragma: no cover
        cls = f"PII_{r.entity_type}"
        if enabled is not None and cls not in enabled:
            continue
        out.append(Match(r.start, r.end, cls, text[r.start : r.end]))
    return out
