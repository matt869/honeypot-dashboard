"""User-agent fingerprinting.

The HTTP bait records a ``user_agent`` on every request. Raw UA strings are too
varied to group on directly, so this module reduces one to a compact
``(family, tool)`` pair — the smallest label that still lets an analyst see
*what* is scanning, not just that something is.

Matching is an ordered list of anchored substring patterns rather than a
third-party UA database. That is a deliberate trade: a curated list of the
handful of tools that actually matter (curl, wget, python, Go, nmap, Masscan,
the Mirai family, browser engines) is honest about its coverage and never
reaches the network, where a parsing library would be more complete but
heavier and less auditable.

Unknown strings are never guessed: they return ``("unknown", "unknown")`` so a
missing fingerprint reads as missing, never as a confident wrong answer.
"""

from __future__ import annotations

from typing import Any

BOTNET = "botnet"
SCANNER = "scanner"
CLI = "cli"
SCRIPT = "script"
BROWSER = "browser"

# Ordered matchers. First match wins, so the most specific signatures come
# first. Needles are lowercased; input is lowercased before matching.
_MATCHERS: list[tuple[tuple[str, ...], str, str]] = [
    (("mirai", "hello, world"), BOTNET, "mirai"),
    (("masscan",), SCANNER, "masscan"),
    (("zgrab",), SCANNER, "zgrab"),
    (("nmap",), SCANNER, "nmap"),
    (("curl/",), CLI, "curl"),
    (("wget/",), CLI, "wget"),
    (("go-http-client",), SCRIPT, "go"),
    (("python-requests", "python-urllib", "python/"), SCRIPT, "python"),
    (("libwww-perl",), SCRIPT, "perl"),
    (("java/",), SCRIPT, "java"),
    (("chrome/", "chromium/"), BROWSER, "chrome"),
    (("firefox/",), BROWSER, "firefox"),
    (("safari/",), BROWSER, "safari"),
    (("edg/", "edge/", "msie ", "trident/"), BROWSER, "edge"),
]


def fingerprint(user_agent: str | None) -> tuple[str, str]:
    """Reduce a user-agent string to a ``(family, tool)`` pair."""
    ua = (user_agent or "").strip().lower()
    if not ua:
        return "empty", "empty"
    for needles, family, tool in _MATCHERS:
        if any(needle in ua for needle in needles):
            return family, tool
    return "unknown", "unknown"


def summarize(user_agent: str | None) -> dict[str, Any]:
    """Fingerprint plus the original string, for storage or display."""
    family, tool = fingerprint(user_agent)
    return {"user_agent": user_agent, "ua_family": family, "ua_tool": tool}


__all__ = [
    "fingerprint",
    "summarize",
    "BOTNET",
    "SCANNER",
    "CLI",
    "SCRIPT",
    "BROWSER",
]
