"""Retention: delete what the sensor should no longer be holding.

    python -m pipeline.retention --older-than 90            # dry run, the default
    python -m pipeline.retention --older-than 90 --apply
    python -m pipeline.retention --older-than 90 --apply --keep-payload-files

A honeypot accumulates two kinds of liability, and the previous prune addressed
neither of them properly.

**Captured credentials are real people's passwords.** ``FINDINGS.md`` has said
so from the start. Holding them indefinitely is a choice, and it should be one
somebody made on purpose rather than the default that happens when nothing
expires.

**Captured payloads are live malware.** This is the gap that prompted the
module. ``tools/reset_db.py --prune`` deleted events, sessions and alerts and
left ``data/payloads/`` completely untouched, so the *records* of an intrusion
expired while the working malware sat on disk forever. That is exactly the wrong
way round. Files are removed here only once no remaining event references their
hash — a sample still tied to a live observation is evidence, not litter.

**Dry run is the default.** Everything this module deletes is irreplaceable:
you cannot re-observe an attack that happened in March. ``--apply`` is required
to remove anything, and the dry run prints the same report so the two can be
compared before committing.
"""

from __future__ import annotations

import argparse
import datetime as dt
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import delete, func, select

from storage.models import Alert, Attacker, Campaign, Event, Payload, Session, ensure_utc, utcnow

log = logging.getLogger("pipeline.retention")


@dataclass
class RetentionReport:
    """What was removed, or would be."""

    cutoff: dt.datetime
    dry_run: bool = True
    events: int = 0
    sessions: int = 0
    alerts: int = 0
    payload_rows: int = 0
    payload_files: int = 0
    payload_bytes: int = 0
    campaigns: int = 0
    attackers_rebuilt: int = 0
    retained_payloads: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "cutoff": self.cutoff.isoformat(),
            "dry_run": self.dry_run,
            "events": self.events,
            "sessions": self.sessions,
            "alerts": self.alerts,
            "payload_rows": self.payload_rows,
            "payload_files": self.payload_files,
            "payload_bytes": self.payload_bytes,
            "campaigns": self.campaigns,
            "attackers_rebuilt": self.attackers_rebuilt,
            "retained_payloads": self.retained_payloads,
            "errors": self.errors,
        }

    def render(self) -> str:
        verb = "would remove" if self.dry_run else "removed"
        lines = [
            f"retention cutoff {self.cutoff.isoformat()} — {verb}:",
            f"  events            {self.events:>8,}",
            f"  sessions          {self.sessions:>8,}",
            f"  alerts            {self.alerts:>8,}",
            f"  payload rows      {self.payload_rows:>8,}",
            f"  payload files     {self.payload_files:>8,}  ({self.payload_bytes:,} bytes)",
            f"  stored campaigns  {self.campaigns:>8,}",
        ]
        if self.retained_payloads:
            lines.append(
                f"  kept {self.retained_payloads:,} payload(s) still referenced by live events"
            )
        if not self.dry_run:
            lines.append(f"  attackers rebuilt {self.attackers_rebuilt:>8,}")
        if self.errors:
            lines.append(f"  errors: {len(self.errors)}")
        if self.dry_run:
            lines.append("\nDry run. Nothing was deleted — pass --apply to act.")
        return "\n".join(lines)


def _count(db, model, column, cutoff) -> int:
    return int(
        db.execute(select(func.count()).select_from(model).where(column < cutoff)).scalar_one()
    )


def expired_payloads(db, cutoff: dt.datetime) -> tuple[list[Payload], int]:
    """Payload rows past the cutoff with nothing still pointing at them.

    Returns ``(expired, retained)``. A payload whose hash still appears on any
    event is kept regardless of age — it is attached to a live observation, and
    deleting the sample would leave a record referring to bytes nobody can look
    at any more.
    """
    expired: list[Payload] = []
    retained = 0

    for payload in db.execute(select(Payload)).scalars():
        # Count only events that will *survive* this run, not every event
        # currently present. On a real run the expired ones are already gone
        # and the extra predicate is a no-op; on a dry run it is what makes the
        # preview match what would actually happen. Without it the dry run
        # reported zero payload deletions and then --apply removed files —
        # a misleading preview of an irreversible operation is worse than none.
        still_referenced = db.execute(
            select(func.count())
            .select_from(Event)
            .where(Event.payload_sha256 == payload.sha256)
            .where(Event.ts >= cutoff)
        ).scalar_one()
        if still_referenced:
            retained += 1
            continue
        # No events left. Age it by last_seen when known, and by when it was
        # analysed otherwise — a hand-dropped file has no sightings at all.
        #
        # ensure_utc is not optional here: SQLite has no timestamp type and
        # hands back naive datetimes, so comparing one to an aware cutoff
        # raises rather than returning False. Getting this wrong would abort
        # the whole run partway through a deletion.
        stamp = ensure_utc(payload.last_seen) or ensure_utc(payload.analyzed_at)
        if stamp is None or stamp < cutoff:
            expired.append(payload)
        else:
            retained += 1

    return expired, retained


def apply_retention(
    db,
    *,
    older_than_days: float,
    payload_dir: str | Path | None = None,
    dry_run: bool = True,
    delete_payload_files: bool = True,
) -> RetentionReport:
    """Expire data older than ``older_than_days``.

    The order matters. Events go first so payload reachability is computed
    against what actually remains, and the attacker aggregate is rebuilt last
    because its counters would otherwise still describe rows that are gone.
    """
    from pipeline.analysis.static import DEFAULT_PAYLOAD_DIR

    cutoff = utcnow() - dt.timedelta(days=older_than_days)
    report = RetentionReport(cutoff=cutoff, dry_run=dry_run)
    directory = Path(payload_dir or DEFAULT_PAYLOAD_DIR)

    report.events = _count(db, Event, Event.ts, cutoff)
    report.sessions = _count(db, Session, Session.started_at, cutoff)
    report.alerts = _count(db, Alert, Alert.last_seen, cutoff)

    if not dry_run:
        db.execute(delete(Event).where(Event.ts < cutoff))
        db.execute(delete(Session).where(Session.started_at < cutoff))
        db.execute(delete(Alert).where(Alert.last_seen < cutoff))
        db.flush()

    expired, retained = expired_payloads(db, cutoff)
    report.payload_rows = len(expired)
    report.retained_payloads = retained

    for payload in expired:
        path = directory / f"{payload.sha256}.bin"
        if path.exists():
            try:
                size = path.stat().st_size
            except OSError as exc:  # pragma: no cover - racing with the sensor
                report.errors.append(f"{path.name}: {exc}")
                continue
            report.payload_files += 1
            report.payload_bytes += size
            if not dry_run and delete_payload_files:
                try:
                    path.unlink()
                except OSError as exc:
                    report.errors.append(f"{path.name}: {exc}")
        if not dry_run:
            db.delete(payload)

    # Stored campaigns name source addresses. Once the events behind them are
    # gone the grouping describes something nobody can inspect any more, so it
    # is dropped rather than left as an unfalsifiable claim.
    report.campaigns = int(db.execute(select(func.count()).select_from(Campaign)).scalar_one())
    if not dry_run and report.campaigns:
        db.execute(delete(Campaign))

    if not dry_run:
        db.flush()
        db.execute(delete(Attacker))
        db.flush()
        from storage import queries

        report.attackers_rebuilt = queries.rebuild_attackers(db)

    return report


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(
        description="Expire old captures. Dry run unless --apply is given."
    )
    parser.add_argument(
        "--older-than",
        type=float,
        required=True,
        metavar="DAYS",
        help="expire data older than this many days",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="actually delete. Without this nothing is removed and the report is a preview.",
    )
    parser.add_argument("--dir", help="payload directory (default: data/payloads)")
    parser.add_argument(
        "--keep-payload-files",
        action="store_true",
        help="expire the payload rows but leave the files on disk",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.older_than <= 0:
        parser.error("--older-than must be greater than zero")

    from storage.db import session_scope

    with session_scope() as db:
        report = apply_retention(
            db,
            older_than_days=args.older_than,
            payload_dir=args.dir,
            dry_run=not args.apply,
            delete_payload_files=not args.keep_payload_files,
        )
        if args.apply:
            db.commit()

    if args.json:
        import json

        print(json.dumps(report.as_dict(), indent=2))
    else:
        print(report.render())
    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["apply_retention", "expired_payloads", "RetentionReport"]
