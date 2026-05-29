"""
Sanity-check tests for the fingerprint database.

These tests do NOT call the network — they validate the schema of every
entry in TAKEOVER_FINGERPRINTS so contributors can't accidentally break
the database structure when adding new services.
"""

import pytest
from subreaper.data.fingerprints import TAKEOVER_FINGERPRINTS

REQUIRED_KEYS = {
    "service", "cname_patterns", "response_fingerprints",
    "http_codes", "confidence", "references",
}

VALID_CONFIDENCE = {"HIGH", "MEDIUM"}
VALID_HTTP_CODES = set(range(100, 600))


class TestFingerprintSchema:
    def test_database_not_empty(self):
        assert len(TAKEOVER_FINGERPRINTS) > 0, "Fingerprint DB must not be empty"

    @pytest.mark.parametrize("entry", TAKEOVER_FINGERPRINTS)
    def test_required_keys_present(self, entry):
        missing = REQUIRED_KEYS - set(entry.keys())
        assert not missing, f"[{entry.get('service')}] missing keys: {missing}"

    @pytest.mark.parametrize("entry", TAKEOVER_FINGERPRINTS)
    def test_service_is_non_empty_string(self, entry):
        assert isinstance(entry["service"], str) and entry["service"].strip()

    @pytest.mark.parametrize("entry", TAKEOVER_FINGERPRINTS)
    def test_cname_patterns_is_non_empty_list_of_strings(self, entry):
        patterns = entry["cname_patterns"]
        assert isinstance(patterns, list) and len(patterns) > 0
        for p in patterns:
            assert isinstance(p, str) and p.strip(), \
                f"[{entry['service']}] cname_patterns contains empty string"

    @pytest.mark.parametrize("entry", TAKEOVER_FINGERPRINTS)
    def test_response_fingerprints_is_non_empty_list_of_strings(self, entry):
        fps = entry["response_fingerprints"]
        assert isinstance(fps, list) and len(fps) > 0
        for fp in fps:
            assert isinstance(fp, str) and fp.strip(), \
                f"[{entry['service']}] response_fingerprints contains empty string"

    @pytest.mark.parametrize("entry", TAKEOVER_FINGERPRINTS)
    def test_http_codes_are_valid(self, entry):
        codes = entry["http_codes"]
        assert isinstance(codes, list) and len(codes) > 0
        for code in codes:
            assert code in VALID_HTTP_CODES, \
                f"[{entry['service']}] invalid HTTP code: {code}"

    @pytest.mark.parametrize("entry", TAKEOVER_FINGERPRINTS)
    def test_confidence_is_valid(self, entry):
        assert entry["confidence"] in VALID_CONFIDENCE, \
            f"[{entry['service']}] confidence must be HIGH or MEDIUM"

    @pytest.mark.parametrize("entry", TAKEOVER_FINGERPRINTS)
    def test_references_is_non_empty_string(self, entry):
        assert isinstance(entry["references"], str) and entry["references"].strip()

    def test_no_duplicate_service_names(self):
        names = [e["service"] for e in TAKEOVER_FINGERPRINTS]
        seen, dupes = set(), set()
        for n in names:
            if n in seen:
                dupes.add(n)
            seen.add(n)
        assert not dupes, f"Duplicate service names in fingerprint DB: {dupes}"