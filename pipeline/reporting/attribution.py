"""Attribution case file for a single source address.

    python -m pipeline.reporting.attribution --ip 45.33.32.156
    python -m pipeline.reporting.attribution --ip 45.33.32.156 --format json

The dashboard returns a source's profile as JSON; this produces the thing an
analyst actually files: one Markdown/text document gathering everything the
system knows about an address — profile, campaign membership, sessions,
commands, artefacts and alerts — so a decision (block, watch, ignore) can be
kept with the evidence that justified it.

Read-only: it never writes back to the database.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any

from sqlalchemy import func, select

from storage import queries
from storage.db import session_scope
from storage.models import Event, ensure_utc, utcnow


def build_case(db, src_ip: str, *, session_limit: int = 20, top: int = 20) -> dict[str, Any]:
    """Gather everything known about one address into a single dict."""
    attacker = queries.get_attacker(db, src_ip)
    sessions = queries.attacker_sessions(db, src_ip, limit=session_limit)
    payloads = queries.payloads_for_attacker(db, src_ip, limit=top)
    campaign = queries.campaign_for_attacker(db, src_ip)
    alerts, _ = queries.list_alerts(db, src_ip=src_ip, limit=top)

    command_stmt = (
        select(Event.command, func.count(Event.id).label("n"))
        .where(Event.src_ip == src_ip, Event.command.is_not(None))
        .group_by(Event.command)
        .order_by(func.count(Event.id).desc())
        .limit(top)
    )
    commands = [(row.command, int(row.n)) for row in db.execute(command_stmt)]

    return {
        "src_ip": src_ip,
        "generated_at": utcnow().isoformat(),
        "attacker": _attacker_row(attacker),
        "campaign": _campaign_row(campaign),
        "sessions": [_session_row(s) for s in sessions],
        "commands": commands,
        "payloads": [_payload_row(p) for p in payloads],
        "alerts": [_alert_row(a) for a in alerts],
    }


def _attacker_row(a) -> dict[str, Any] | None:
    if a is None:
        return None
    return {
        "first_seen": ensure_utc(a.first_seen).isoformat() if a.first_seen else None,
        "last_seen": ensure_utc(a.last_seen).isoformat() if a.last_seen else None,
        "event_count": a.event_count,
        "session_count": a.session_count,
        "auth_attempts": a.auth_attempts,
        "commands_run": a.commands_run,
        "services": a.services or [],
        "top_usernames": a.top_usernames or [],
        "top_passwords": a.top_passwords or [],
        "top_paths": a.top_paths or [],
        "country": a.country,
        "country_name": a.country_name,
        "asn": a.asn,
        "as_org": a.as_org,
        "threat_score": a.threat_score,
        "classification": a.classification,
        "tags": a.tags or [],
    }


def _session_row(s) -> dict[str, Any]:
    return {
        "session_id": s.session_id,
        "service": s.service,
        "started_at": ensure_utc(s.started_at).isoformat() if s.started_at else None,
        "duration_ms": s.duration_ms,
        "event_count": s.event_count,
        "commands_run": s.commands_run,
        "auth_attempts": s.auth_attempts,
    }


def _payload_row(p) -> dict[str, Any]:
    return {
        "sha256": p.sha256,
        "file_type": p.file_type,
        "arch": p.arch,
        "size": p.size,
        "likely_packed": p.likely_packed,
        "behaviour_tags": p.behaviour_tags or [],
    }


def _campaign_row(c) -> dict[str, Any] | None:
    if c is None:
        return None
    return {
        "campaign_id": c.campaign_id,
        "size": c.size,
        "cohesion": c.cohesion,
        "shared_credentials": c.shared_credentials or [],
        "shared_payloads": c.shared_payloads or [],
    }


def _alert_row(a) -> dict[str, Any]:
    return {
        "rule_id": a.rule_id,
        "rule_name": a.rule_name,
        "severity": a.severity,
        "title": a.title,
        "hit_count": a.hit_count,
        "status": a.status,
        "first_seen": ensure_utc(a.first_seen).isoformat() if a.first_seen else None,
        "last_seen": ensure_utc(a.last_seen).isoformat() if a.last_seen else None,
    }


def render_markdown(case: dict[str, Any]) -> str:
    out = [f"# Attribution case file — {case['src_ip']}", ""]
    attacker = case["attacker"]
    if attacker is None:
        out.append("_No activity recorded for this address._")
        return "\n".join(out)

    out += [
        f"- **classification**: {attacker['classification']} (score {attacker['threat_score']:.0f})",
        f"- **seen**: {attacker['first_seen']} → {attacker['last_seen']}",
        f"- **activity**: {attacker['event_count']:,} events · "
        f"{attacker['session_count']} sessions · {attacker['commands_run']} commands",
        f"- **geo**: {attacker['country_name'] or attacker['country'] or '??'} · "
        f"ASN {attacker['asn'] or '??'} ({attacker['as_org'] or 'unknown'})",
        "",
    ]
    if attacker["tags"]:
        out += [f"- **tags**: {', '.join(attacker['tags'])}", ""]
    if attacker["top_usernames"]:
        out += [f"- **usernames tried**: {', '.join(attacker['top_usernames'][:8])}", ""]
    if attacker["top_passwords"]:
        out += [f"- **passwords tried**: {', '.join(attacker['top_passwords'][:8])}", ""]

    if case["campaign"]:
        c = case["campaign"]
        out += [
            "## Campaign",
            "",
            f"- member of `{c['campaign_id'][:12]}…` ({c['size']} sources, cohesion {c['cohesion']:.2f})",
            "",
        ]
        if c["shared_credentials"]:
            out += [f"- shared credentials: {', '.join(c['shared_credentials'][:5])}", ""]
        if c["shared_payloads"]:
            out += [f"- shared payloads: {', '.join(p[:12] for p in c['shared_payloads'][:4])}", ""]

    out += [f"## Sessions ({len(case['sessions'])})", ""]
    if case["sessions"]:
        out += [
            "| service | started | commands | events | duration |",
            "| --- | --- | ---: | ---: | ---: |",
        ]
        for s in case["sessions"]:
            out.append(
                f"| {s['service']} | {s['started_at']} | {s['commands_run']} | "
                f"{s['event_count']} | {s['duration_ms'] or 0}ms |"
            )
        out.append("")

    out += [f"## Commands ({len(case['commands'])})", ""]
    for command, n in case["commands"]:
        out.append(f"- `{command[:80]}` × {n}")
    out.append("")

    out += [f"## Artefacts ({len(case['payloads'])})", ""]
    for p in case["payloads"]:
        packed = ", packed" if p["likely_packed"] else ""
        out.append(
            f"- `{p['sha256'][:12]}…` {p['file_type'] or '?'} {p['arch'] or '?'} "
            f"({p['size']:,} bytes{packed})"
        )
    out.append("")

    out += [f"## Alerts ({len(case['alerts'])})", ""]
    for a in case["alerts"]:
        out.append(
            f"- **{a['severity']}** [{a['rule_id']}] {a['title']} (×{a['hit_count']}, {a['status']})"
        )
    out.append("")

    return "\n".join(out)


def render_text(case: dict[str, Any]) -> str:
    markdown = render_markdown(case)
    text = re.sub(r"^#+\s*", "", markdown, flags=re.M)
    text = text.replace("|", " ").replace("**", "").replace("`", "")
    return re.sub(r"^\s*-+\s+-+\s+-+.*$", "", text, flags=re.M)


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

    parser = argparse.ArgumentParser(description="Build an attribution case file for one source")
    parser.add_argument("--ip", required=True, help="source address")
    parser.add_argument("--format", choices=("markdown", "text", "json"), default="markdown")
    parser.add_argument("--out", help="write to this file instead of stdout")
    args = parser.parse_args(argv)

    with session_scope() as db:
        case = build_case(db, args.ip)

    if args.format == "json":
        rendered = json.dumps(case, indent=2, default=str)
    elif args.format == "text":
        rendered = render_text(case)
    else:
        rendered = render_markdown(case)

    if args.out:
        from pathlib import Path

        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
        print(f"wrote {path} ({len(rendered):,} bytes)", file=sys.stderr)
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
