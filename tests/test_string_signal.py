"""Tests for high-signal strings reassignment (reforge/string_signal.py).

The user requirement: when the local LLM says a string is in the wrong group, the string must be
ACTUALLY moved and the move must be durable — not a transient browser-only effect. These tests
exercise the server-side single-source-of-truth that makes the move real and persistent.

Covered:
  * classify(): deterministic categories mirror the UI heuristics.
  * normalize_category(): aliases + rejection of unknown categories (untrusted LLM input).
  * parse_reassignments(): REASSIGN/=>/-> line extraction.
  * match_string(): exact, unique-substring, ambiguous(skip), absent(skip).
  * apply_reassignments(): persists the move; back-to-static clears; invalid is skipped.
  * round-trip persistence through Session.to_dict()/from_dict().
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from reforge import string_signal as SS          # noqa: E402
from reforge.session import Session              # noqa: E402


# --------------------------------------------------------------------------- classify
@pytest.mark.parametrize("s,expect", [
    ("https://evil.example/cb", "url"),
    ("192.168.1.10", "network"),
    # The "persistence" category was removed with the malware-behaviour vocabulary: a Run key
    # is a registry location, and that is what it is classified as.
    ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "registry"),
    # command-injection sink markers (these used to fall through: \\b cannot match before "/")
    ("/bin/sh", "command"),
    ("system(", "command"),
    ("HKCU\\Software\\Foo", "registry"),
    ("api_key=abcd", "secret"),
    ("powershell.exe -enc", "command"),
    ("ntdll.dll", "dll"),
    ("C:\\Users\\victim\\AppData\\Local\\Temp\\stage.bin", "path"),
    ("AES-256-CBC", "crypto"),
    ("user@example.com", "identity"),
    ("\\\\.\\pipe\\mychan", "ipc"),
    ("Content-Type: application/json", "format"),
    ("just some words here", "generic"),
])
def test_classify(s, expect):
    assert SS.classify(s) == expect


# --------------------------------------------------------------------------- normalize_category
@pytest.mark.parametrize("raw,expect", [
    ("secret", "secret"), ("Secrets", "secret"), ("tokens", "secret"),
    ("endpoint", "url"), ("host", "network"), ("registrykey", "registry"),
    ("REGISTRY", "registry"), ("nonsense_category", ""), ("", ""),
])
def test_normalize_category(raw, expect):
    assert SS.normalize_category(raw) == expect


# --------------------------------------------------------------------------- parse_reassignments
def test_parse_reassignments_variants():
    text = (
        "Here is my analysis.\n"
        "REASSIGN: `192.168.1.10` => network\n"
        "REASSIGN: 'config.value' -> config\n"
        "`some.dll` => dll\n"               # no REASSIGN prefix but has =>
        "not a reassignment line\n"
        "REASSIGN: `x` => totally_unknown\n"  # unknown category -> dropped
    )
    pairs = SS.parse_reassignments(text)
    assert ("192.168.1.10", "network") in pairs
    assert ("config.value", "config") in pairs
    assert ("some.dll", "dll") in pairs
    assert all(cat != "" for _, cat in pairs)
    assert not any(ref == "x" for ref, _ in pairs)   # unknown category filtered out


# --------------------------------------------------------------------------- match_string
def test_match_string_exact_unique_ambiguous_absent():
    corpus = ["https://a.example/x", "C:\\Temp\\a.bin", "C:\\Temp\\b.bin", "ntdll.dll"]
    assert SS.match_string("ntdll.dll", corpus) == "ntdll.dll"          # exact
    assert SS.match_string("a.example", corpus) == "https://a.example/x"  # unique substring
    assert SS.match_string("C:\\Temp\\", corpus) is None                # ambiguous -> skip
    assert SS.match_string("does-not-exist", corpus) is None            # absent -> skip


# --------------------------------------------------------------------------- apply_reassignments
class _FakeSession:
    def __init__(self, strings):
        self.static_strings = list(strings)
        self.string_overrides = {}
        self.persisted = 0

    def persist(self):
        self.persisted += 1


def test_apply_moves_string_and_persists():
    # A path-looking string that the static classifier puts in "path", moved to "config".
    s = _FakeSession(["C:\\app\\settings.ini"])
    assert SS.classify("C:\\app\\settings.ini") == "path"
    res = SS.apply_reassignments(s, "REASSIGN: `settings.ini` => config")
    assert res["applied"] and res["applied"][0]["to"] == "config"
    assert s.string_overrides["C:\\app\\settings.ini"] == "config"
    assert SS.effective_kind("C:\\app\\settings.ini", s.string_overrides) == "config"
    assert s.persisted == 1


def test_apply_back_to_static_clears_override():
    s = _FakeSession(["ntdll.dll"])                 # static = dll
    s.string_overrides = {"ntdll.dll": "config"}    # previously moved
    res = SS.apply_reassignments(s, "REASSIGN: `ntdll.dll` => dll")
    assert "ntdll.dll" in res["cleared"]
    assert "ntdll.dll" not in s.string_overrides    # override dropped, not stored as no-op


def test_apply_skips_unknown_string_and_redundant():
    s = _FakeSession(["ntdll.dll"])
    res = SS.apply_reassignments(s, "REASSIGN: `not-present` => secret\nREASSIGN: `ntdll.dll` => dll")
    # 'not-present' absent -> skipped; 'ntdll.dll'=>dll equals static -> skipped (no change)
    assert not res["applied"]
    assert s.string_overrides == {}
    assert s.persisted == 0                         # nothing applied -> no persist


def test_apply_rejects_unknown_category():
    s = _FakeSession(["ntdll.dll"])
    res = SS.apply_reassignments(s, "REASSIGN: `ntdll.dll` => boguscat")
    assert not res["applied"]
    assert s.string_overrides == {}


# --------------------------------------------------------------------------- persistence round-trip
def test_overrides_survive_session_roundtrip():
    s = Session(name="t")
    s.static_strings = ["C:\\app\\settings.ini", "ntdll.dll"]
    s.string_overrides = {"C:\\app\\settings.ini": "config"}
    restored = Session.from_dict(s.to_dict())
    assert restored.string_overrides == {"C:\\app\\settings.ini": "config"}
    # effective_kind on the restored session honours the persisted move
    assert SS.effective_kind("C:\\app\\settings.ini", restored.string_overrides) == "config"


# --------------------------------------------------------------------------- grouped overview
def test_grouped_overview_honours_overrides():
    s = _FakeSession(["C:\\app\\settings.ini", "ntdll.dll", "https://x.example/y"])
    s.string_overrides = {"C:\\app\\settings.ini": "config"}
    ov = SS.grouped_overview(s)
    assert ov["counts"].get("config") == 1
    assert ov["counts"].get("url") == 1
    assert ov["counts"].get("dll") == 1
    assert "path" not in ov["counts"]               # the only path-like string was moved to config


# --------------------------------------------------------------------------- v6.1: JSON reclassify
def test_coerce_pairs_accepts_json_dict():
    from reforge import string_signal as SS
    data = {"reassignments": [{"string": "C:\\a.ini", "category": "config"},
                              {"value": "ntdll.dll", "to": "dll"}]}
    pairs = SS._coerce_pairs(data)
    assert ("C:\\a.ini", "config") in pairs
    assert ("ntdll.dll", "dll") in pairs


def test_coerce_pairs_accepts_json_in_prose():
    from reforge import string_signal as SS
    text = 'Sure! {"reassignments":[{"string":"settings.ini","category":"config"}]} done'
    assert ("settings.ini", "config") in SS._coerce_pairs(text)


def test_coerce_pairs_accepts_reassign_text():
    from reforge import string_signal as SS
    assert ("ntdll.dll", "config") in SS._coerce_pairs("REASSIGN: `ntdll.dll` => config")


def test_coerce_pairs_rejects_unknown_category():
    from reforge import string_signal as SS
    pairs = SS._coerce_pairs({"reassignments": [{"string": "x", "category": "bogus"}]})
    assert pairs == []


class _FakeJsonLLM:
    available = True
    last_usage = {}

    def __init__(self, payload):
        self._payload = payload

    async def complete_json(self, system, user):
        return self._payload


def test_llm_reclassify_applies_and_persists():
    import asyncio
    from reforge import string_signal as SS

    class S:
        static_strings = ["C:\\app\\settings.ini", "ntdll.dll"]
        string_overrides = {}
        persisted = 0
        def persist(self): self.persisted += 1

    s = S()
    llm = _FakeJsonLLM({"reassignments": [{"string": "settings.ini", "category": "config"},
                                          {"string": "ABSENT", "category": "secret"}]})
    res = asyncio.run(SS.llm_reclassify(s, llm))
    assert res["applied"] and res["applied"][0]["to"] == "config"
    assert s.string_overrides["C:\\app\\settings.ini"] == "config"
    assert "ABSENT" in res["skipped"]
    assert s.persisted >= 1


def test_llm_reclassify_empty_payload_no_crash():
    import asyncio
    from reforge import string_signal as SS

    class S:
        static_strings = ["ntdll.dll"]
        string_overrides = {}
        def persist(self): pass

    res = asyncio.run(SS.llm_reclassify(S(), _FakeJsonLLM({})))   # model returned nothing
    assert res["applied"] == []
