"""Database health and staleness check for the honeypot datastore.

    python -m tools.db_health
    python -m tools.db_health --json

Operators run this to answer, in one command, the questions that matter when a
sensor "looks fine but has gone quiet":

* Is the newest event fresh, or did capture silently stop hours ago?
* How large is each table, and how many alerts still need a decision?

It reads only and needs no privileges beyond the connection the rest of the
system already uses. The connection string is never echoed — it may contain
credentials — so the output reports only the engine (sqlite vs postgres).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from sqlalchemy import func, select

from storage.db import database_url, session_scope
from storage.models import Alert, Attacker, Campaign, Event, Payload, Session, ensure_utc, utcnow

_TABLES = {
    "events": Event,
    "sessions": Session,
    "attackers": Attacker,
    "alerts": Alert,
    "payloads": Payload,
    "campaigns": Campaign,
}

_STALE_MINUTES = 60.0


def collect(db) -> dict[str, Any]:
    now = utcnow()
    counts = {
        name: int(db.execute(select(func.count()).select_from(model)).scalar_one())
        for name, model in _TABLES.items()
    }
    newest = ensure_utc(db.execute(select(func.max(Event.ts))).scalar_one_or_none())
    oldest = ensure_utc(db.execute(select(func.min(Event.ts))).scalar_one_or_none())
    open_alerts = int(
        db.execute(
            select(func.count()).select_from(Alert).where(Alert.status == "new")
        ).scalar_one()
    )

    stale_minutes = round((now - newest).total_seconds() / 60.0, 1) if newest else None
    url = database_url()
    return {
        "generated_at": now.isoformat(),
        "engine": "sqlite" if url.startswith("sqlite") else "postgres",
        "counts": counts,
        "oldest_event": oldest.isoformat() if oldest else None,
        "newest_event": newest.isoformat() if newest else None,
        "stale_minutes": stale_minutes,
        "stale": stale_minutes is not None and stale_minutes > _STALE_MINUTES,
        "open_alerts": open_alerts,
    }


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

    parser = argparse.ArgumentParser(description="Check the honeypot database for staleness")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)

    with session_scope() as db:
        health = collect(db)

    if args.json:
        print(json.dumps(health, indent=2))
        return 0

    counts = ", ".join(f"{name}={n:,}" for name, n in health["counts"].items())
    print(f"engine: {health['engine']}  open alerts: {health['open_alerts']}")
    print(f"counts: {counts}")
    if health["newest_event"]:
        age = health["stale_minutes"]
        status = "STALE — capture may have stopped" if health["stale"] else "fresh"
        print(f"newest event: {health['newest_event']} ({age:.0f}m ago, {status})")
        print(f"oldest event: {health['oldest_event']}")
    else:
        print("no events in the datastore yet")
    return 0


if __name__ == "__main__":
    sys.exit(main())
