"""Pull sessions out of the database for offline ML work.

    python -m ml.export                          # sessions.jsonl -> ml/data/
    python -m ml.export --format csv --out ml/data/sessions.csv
    python -m ml.export --format features --out ml/data/features.csv

The production pipeline keeps everything in the database; the ML experiments
in this package want a flat file they can load with pandas or sklearn without
touching SQLAlchemy. This is the seam: one command, one flat dataset per
format, written under ``ml/data/`` (git-ignored -- see the root ``.gitignore``)
so exported datasets never enter version control.

Sessions are the unit because a single TCP conversation is the smallest
behaviour the dashboard already reasons about, and the replay browser uses the
same rows -- so an ML feature row can always be traced back to a session you
can watch.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from pathlib import Path
from typing import Any

from ml.features import build_dataset, fetch_sessions
from storage.db import session_scope
from storage.models import Session, ensure_utc

SESSION_COLUMNS = [
    "session_id",
    "sensor",
    "service",
    "src_ip",
    "src_port",
    "dst_port",
    "started_at",
    "ended_at",
    "duration_ms",
    "event_count",
    "auth_attempts",
    "commands_run",
    "bytes_in",
    "client_banner",
    "closed_by",
    "country",
    "asn",
]

_DEFAULT_NAMES = {"csv": "sessions.csv", "jsonl": "sessions.jsonl", "features": "features.csv"}


def _session_row(session: Session) -> dict[str, Any]:
    row = {name: getattr(session, name, None) for name in SESSION_COLUMNS}
    if session.started_at is not None:
        row["started_at"] = ensure_utc(session.started_at).isoformat()
    if session.ended_at is not None:
        row["ended_at"] = ensure_utc(session.ended_at).isoformat()
    return row


def export_sessions_csv(sessions: list[Session]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=SESSION_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for session in sessions:
        writer.writerow(_session_row(session))
    return buffer.getvalue()


def export_sessions_jsonl(sessions: list[Session]) -> str:
    lines = [json.dumps(_session_row(s), default=str) for s in sessions]
    return "\n".join(lines) + ("\n" if lines else "")


def export_features_csv(sessions: list[Session]) -> str:
    columns, rows, meta = build_dataset(sessions)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["session_id", "src_ip", "service", *columns])
    for row, m in zip(rows, meta, strict=True):
        writer.writerow([m["session_id"], m["src_ip"], m["service"], *row])
    return buffer.getvalue()


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

    parser = argparse.ArgumentParser(description="Export sessions for offline ML")
    parser.add_argument("--format", choices=("csv", "jsonl", "features"), default="jsonl")
    parser.add_argument("--out", help="output file (default: ml/data/<format>)")
    parser.add_argument("--hours", type=float, help="only sessions started in the last N hours")
    parser.add_argument("--min-events", type=int, help="only sessions with at least N events")
    parser.add_argument("--limit", type=int, default=100_000)
    args = parser.parse_args(argv)

    with session_scope() as db:
        sessions = fetch_sessions(
            db, limit=args.limit, since_hours=args.hours, min_events=args.min_events
        )

    if args.format == "csv":
        output = export_sessions_csv(sessions)
    elif args.format == "jsonl":
        output = export_sessions_jsonl(sessions)
    else:
        output = export_features_csv(sessions)

    out = (
        Path(args.out)
        if args.out
        else Path(__file__).resolve().parent / "data" / _DEFAULT_NAMES[args.format]
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(output, encoding="utf-8")
    print(f"wrote {len(sessions):,} sessions to {out} ({len(output):,} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
