"""Unit tests for user-agent fingerprinting.

The invariants under test: a known tool is labelled precisely, an unknown or
empty string is reported as such and never guessed, and matching is
case-insensitive so a scanner's casing does not defeat it.
"""

from __future__ import annotations

from pipeline.enrichment.ua_parser import fingerprint


def test_mirai_botnet_signature():
    assert fingerprint("Mirai") == ("botnet", "mirai")
    assert fingerprint("Hello, World") == ("botnet", "mirai")


def test_scanner_tools():
    assert fingerprint("masscan/1.3") == ("scanner", "masscan")
    assert fingerprint("Nmap Scripting Engine") == ("scanner", "nmap")
    assert fingerprint("Mozilla/5.0 zgrab/0.x") == ("scanner", "zgrab")


def test_cli_tools():
    assert fingerprint("curl/8.1.2") == ("cli", "curl")
    assert fingerprint("Wget/1.21.4") == ("cli", "wget")


def test_script_clients():
    assert fingerprint("python-requests/2.31.0") == ("script", "python")
    assert fingerprint("Go-http-client/1.1") == ("script", "go")


def test_browsers():
    assert fingerprint("Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0") == ("browser", "chrome")
    assert fingerprint("Mozilla/5.0 Firefox/121.0") == ("browser", "firefox")


def test_empty_agent_is_empty_not_unknown():
    assert fingerprint("") == ("empty", "empty")
    assert fingerprint(None) == ("empty", "empty")


def test_unknown_agent_is_not_guessed():
    assert fingerprint("something-unheard-of/9.9") == ("unknown", "unknown")


def test_matching_is_case_insensitive():
    assert fingerprint("MIRAI") == ("botnet", "mirai")
    assert fingerprint("CURL/7.88") == ("cli", "curl")
