"""Detector precision/recall on the seeded fixture."""

from mcp_cloak.detectors import detect, shannon_entropy

from .fixtures import NEGATIVE_CASES, POSITIVE_CASES


def test_recall_all_positive_cases_detected():
    """Every seeded secret must be detected with the correct class."""
    misses = []
    for text, expected_cls in POSITIVE_CASES:
        classes = {m.cls for m in detect(text)}
        if expected_cls not in classes:
            misses.append((text, expected_cls, classes))
    assert not misses, f"missed detections: {misses}"


def test_positive_case_covers_full_value():
    """The detected span should cover the whole secret token."""
    for text, expected_cls in POSITIVE_CASES:
        matches = [m for m in detect(text) if m.cls == expected_cls]
        assert matches, text
        assert any(m.value == text for m in matches), (text, matches)


def test_precision_no_false_positives_on_clean_text():
    """Clean, non-sensitive strings must not trigger detection."""
    false_positives = []
    for text in NEGATIVE_CASES:
        matches = detect(text)
        if matches:
            false_positives.append((text, [(m.cls, m.value) for m in matches]))
    assert not false_positives, f"false positives: {false_positives}"


def test_entropy_can_be_disabled():
    high_entropy = "Zx9Qw3Kp7Lm2Vn8Rt5Yb4Hc6Jd0"  # mixed, no known prefix
    assert any(m.cls == "SECRET" for m in detect(high_entropy, entropy_enabled=True))
    assert not detect(high_entropy, entropy_enabled=False)


def test_shannon_entropy_bounds():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") > 1.0


def test_overlap_resolution_prefers_specific_class():
    # An AWS key contains a long alnum run; the AWS_KEY class must win over SECRET.
    text = "key AKIAFAKE1234567890XY end"
    matches = detect(text)
    aws = [m for m in matches if m.value == "AKIAFAKE1234567890XY"]
    assert aws and aws[0].cls == "AWS_KEY"


def test_enabled_subset_restricts_classes():
    text = "alice@example.com and sk-FAKE1234567890abcdefghijABCD"
    only_email = detect(text, enabled={"EMAIL"})
    assert {m.cls for m in only_email} == {"EMAIL"}
