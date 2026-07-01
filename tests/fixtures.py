"""Seeded fixtures for detector precision/recall and leak tests.

Every secret below is obviously fake (sk-FAKE..., example.com, RFC1918 IPs).
"""

# (text, expected_class) pairs that MUST be detected (recall = 1.0).
POSITIVE_CASES = [
    ("alice@example.com", "EMAIL"),
    ("bob.smith+tag@sub.example.org", "EMAIL"),
    ("sk-FAKE1234567890abcdefghijABCD", "APIKEY"),
    ("ghp_FAKE0000abcdefghijklmnopqrstuvwx12", "APIKEY"),
    ("AKIAFAKE1234567890XY", "AWS_KEY"),
    ("+1-415-555-0142", "PHONE"),
    ("10.1.2.3", "PRIVATE_IP"),
    ("192.168.0.42", "PRIVATE_IP"),
    ("crm-db-01.internal", "INTERNAL_HOST"),
    ("auth.service.corp", "INTERNAL_HOST"),
    (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiJmYWtlIn0.FAKEsignature1234567",
        "JWT",
    ),
]

# Strings that MUST NOT trigger any detection (precision guard).
NEGATIVE_CASES = [
    "The quarterly meeting is at 3pm on Tuesday.",
    "version 1.2.3 released today",
    "hello world",
    "customer id cust_1001",
    "a short note about pricing",
    "https://example.com/docs/getting-started",  # public host, not internal TLD
    "The answer is 42.",
]

# A single blob combining several secrets, used by leak-canary tests.
SECRET_BLOB = {
    "email": "alice@example.com",
    "api_key": "sk-FAKE1234567890abcdefghijABCD",
    "aws": "AKIAFAKE1234567890XY",
    "host": "crm-db-01.internal",
    "ip": "10.1.2.3",
    "phone": "+1-415-555-0142",
    "clean": "The meeting is at 3pm.",
}

RAW_SECRETS = [
    "alice@example.com",
    "sk-FAKE1234567890abcdefghijABCD",
    "AKIAFAKE1234567890XY",
    "crm-db-01.internal",
    "10.1.2.3",
    "+1-415-555-0142",
]
