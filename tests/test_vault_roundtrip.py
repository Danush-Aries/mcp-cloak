"""Round-trip property test: restore(mask(x)) == x for the vault.

Uses a dependency-free randomized generator (always runs) and, when available,
a Hypothesis-based property test for extra coverage.
"""

import random
import string

import pytest

from mcp_cloak.vault import Vault
from tests.fixtures import RAW_SECRETS

TOKENS = RAW_SECRETS + [
    "just some words",
    "no secrets here at all",
    "",
    "trailing space ",
    "unicode ñ é 日本語 text",
    "multiple alice@example.com and bob@example.org emails",
]


def _fresh_vault(tmp_path):
    return Vault(tmp_path / "vault.json")


def _random_text(rng):
    parts = []
    for _ in range(rng.randint(0, 6)):
        choice = rng.random()
        if choice < 0.4:
            parts.append(rng.choice(RAW_SECRETS))
        elif choice < 0.7:
            n = rng.randint(1, 12)
            parts.append("".join(rng.choice(string.ascii_letters + " .,") for _ in range(n)))
        else:
            n = rng.randint(1, 8)
            parts.append("".join(rng.choice(string.digits) for _ in range(n)))
    return " ".join(parts)


def test_roundtrip_on_curated_inputs(tmp_path):
    vault = _fresh_vault(tmp_path)
    for text in TOKENS:
        masked = vault.mask_text(text)
        assert vault.restore_text(masked) == text


def test_roundtrip_property_randomized(tmp_path):
    """1000 randomized inputs must all satisfy restore(mask(x)) == x."""
    vault = _fresh_vault(tmp_path)
    rng = random.Random(1234)
    for _ in range(1000):
        text = _random_text(rng)
        masked = vault.mask_text(text)
        assert vault.restore_text(masked) == text, text


def test_same_value_maps_to_stable_placeholder(tmp_path):
    vault = _fresh_vault(tmp_path)
    m1 = vault.mask_text("contact alice@example.com now")
    m2 = vault.mask_text("again alice@example.com again")
    ph1 = m1.split("contact ")[1].split(" now")[0]
    ph2 = m2.split("again ")[1].split(" again")[0]
    assert ph1 == ph2
    assert ph1.startswith("⟪EMAIL_")


def test_json_roundtrip(tmp_path):
    vault = _fresh_vault(tmp_path)
    obj = {
        "user": {"email": "alice@example.com", "tags": ["vip", "sk-FAKE1234567890abcdefghij"]},
        "count": 3,
        "active": True,
        "note": None,
    }
    masked = vault.mask_json(obj)
    assert masked["user"]["email"].startswith("⟪EMAIL_")
    assert vault.restore_json(masked) == obj


def test_vault_persists_for_cross_process_reveal(tmp_path):
    path = tmp_path / "vault.json"
    v1 = Vault(path)
    masked = v1.mask_text("alice@example.com")
    # A brand-new Vault (simulating the `reveal` process) reads the same file.
    v2 = Vault(path)
    assert v2.reveal(masked) == "alice@example.com"


# Optional Hypothesis-based property test (skipped if hypothesis is absent).
hypothesis = pytest.importorskip("hypothesis", reason="hypothesis not installed")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

_secret_or_text = st.one_of(
    st.sampled_from(RAW_SECRETS),
    st.text(alphabet=string.ascii_letters + string.digits + " .,-_", max_size=40),
)


@settings(max_examples=300, deadline=None)
@given(st.lists(_secret_or_text, max_size=8))
def test_roundtrip_hypothesis(parts):
    vault = Vault(None)  # in-memory, no persistence
    text = " ".join(parts)
    assert vault.restore_text(vault.mask_text(text)) == text
