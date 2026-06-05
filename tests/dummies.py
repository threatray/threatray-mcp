"""Centralised dummy fixture values shared across unit + integration tests.

Tests historically embedded real sample hashes, UUIDs, and analyst Twitter URLs
that bled through into the public test corpus. Anything in here is intentionally
recognisable-as-fake (all-1s / all-2s hashes, example.com URLs, monotone UUID
sequence) so a future reader knows the value carries no real-world meaning.
"""

# sha256 fixtures (64 hex chars). Different values for tests that need to
# distinguish two samples in the same payload.
DUMMY_SHA256 = "1" * 64
DUMMY_SHA256_B = "2" * 64
DUMMY_SHA256_C = "3" * 64

# Shorter hashes for the HashAny code paths.
DUMMY_MD5 = "1" * 32
DUMMY_SHA1 = "1" * 40

# UUID-shaped IDs. The trailing nibble carries the "which one" so test failures
# print readable diffs.
DUMMY_SAMPLE_ANALYSIS_ID = "00000000-0000-0000-0000-000000000001"
DUMMY_SAMPLE_ANALYSIS_ID_B = "00000000-0000-0000-0000-000000000002"
DUMMY_AI_ANALYSIS_ID = "00000000-0000-0000-0000-0000000000a1"
DUMMY_SUBMISSION_ID = "00000000-0000-0000-0000-0000000000b1"

# OSINT report fixtures. The URL is example.com — no real threat-intel handle.
DUMMY_OSINT_URL = "https://example.com/threat-report/1"
DUMMY_OSINT_TITLE = "Example Threat Report"
DUMMY_OSINT_AUTHOR = "@example_threat_intel"
