"""Shared feature extraction and data loading for the ``ml`` experiments.

Every model in this package eats the same matrix: one row per session, eleven
numeric columns plus one-hot service columns. Keeping that construction in one
place means a change to the feature definition changes every experiment at
once -- and, more importantly, the same row order and column order across
``kmeans``, ``autoencoder`` and ``transformer``, so their outputs are
comparable.

The extraction is pure Python and needs only the SQLAlchemy ``Session`` rows
already in memory; numpy/sklearn/torch conversion happens in the model scripts.
``fetch_sessions`` lives here too, because the models all need the same
"load sessions with their events eagerly" query and duplicating it would
produce three subtly different datasets.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from storage.models import Event, Service, Session, utcnow

# Numeric columns, in order. duration_ms and bytes_in are left unscaled here;
# the models standardise their own inputs because the right scaler depends on
# the model (k-means wants the standard scaler, an autoencoder does not care).
NUMERIC_FEATURES: list[str] = [
    "duration_ms",
    "event_count",
    "auth_attempts",
    "commands_run",
    "bytes_in",
    "distinct_commands",
    "distinct_paths",
    "distinct_usernames",
    "distinct_passwords",
    "payload_bytes",
    "max_threat_score",
]

SERVICES: list[str] = [s.value for s in Service]
CATEGORICAL_FEATURES: list[str] = [f"service_{s}" for s in SERVICES]

FEATURE_COLUMNS: list[str] = [*NUMERIC_FEATURES, *CATEGORICAL_FEATURES]


def _num(value: Any, default: float = 0.0) -> float:
    """Coerce a possibly-None column value to a float."""
    return float(value) if value is not None else default


def fetch_sessions(
    db,
    *,
    limit: int = 100_000,
    since_hours: float | None = None,
    min_events: int | None = None,
) -> list[Session]:
    """Load sessions with their events eagerly, newest first.

    Events are eager-loaded so feature extraction does not trigger an N+1
    query storm: one query for the sessions, one for all of their events.
    """
    stmt = select(Session).options(selectinload(Session.events))
    if since_hours is not None:
        stmt = stmt.where(Session.started_at >= utcnow() - dt.timedelta(hours=since_hours))
    if min_events is not None:
        stmt = stmt.where(Session.event_count >= min_events)
    stmt = stmt.order_by(Session.started_at.desc()).limit(limit)
    return list(db.execute(stmt).scalars())


def extract_session_features(session: Session) -> dict[str, float]:
    """Reduce one session (plus its events) to the shared feature dict."""
    events: list[Event] = list(session.events or [])

    commands = {e.command for e in events if e.command}
    paths = {e.path for e in events if e.path}
    usernames = {e.username for e in events if e.username}
    passwords = {e.password for e in events if e.password}
    payload_bytes = sum(e.payload_size or 0 for e in events)
    max_score = max((e.threat_score or 0.0 for e in events), default=0.0)

    row: dict[str, float] = {
        "duration_ms": _num(session.duration_ms),
        "event_count": _num(session.event_count),
        "auth_attempts": _num(session.auth_attempts),
        "commands_run": _num(session.commands_run),
        "bytes_in": _num(session.bytes_in),
        "distinct_commands": float(len(commands)),
        "distinct_paths": float(len(paths)),
        "distinct_usernames": float(len(usernames)),
        "distinct_passwords": float(len(passwords)),
        "payload_bytes": float(payload_bytes),
        "max_threat_score": float(max_score),
    }
    for service in SERVICES:
        row[f"service_{service}"] = 1.0 if session.service == service else 0.0
    return row


def session_metadata(session: Session) -> dict[str, Any]:
    """The identifying columns kept alongside each feature row."""
    return {
        "session_id": session.session_id,
        "src_ip": session.src_ip,
        "service": session.service,
        "started_at": session.started_at.isoformat() if session.started_at else None,
    }


def build_dataset(
    sessions: Iterable[Session],
) -> tuple[list[str], list[list[float]], list[dict[str, Any]]]:
    """Return ``(columns, rows, metadata)`` for a batch of sessions.

    ``rows`` is a list of lists in ``FEATURE_COLUMNS`` order; ``metadata`` is
    one dict per session in the same order, carrying the identifiers a model
    must report back -- an anomaly labelled only by matrix row number is useless.
    """
    columns = list(FEATURE_COLUMNS)
    rows: list[list[float]] = []
    meta: list[dict[str, Any]] = []
    for session in sessions:
        feats = extract_session_features(session)
        rows.append([feats[col] for col in columns])
        meta.append(session_metadata(session))
    return columns, rows, meta


__all__ = [
    "NUMERIC_FEATURES",
    "CATEGORICAL_FEATURES",
    "FEATURE_COLUMNS",
    "SERVICES",
    "fetch_sessions",
    "extract_session_features",
    "session_metadata",
    "build_dataset",
]
