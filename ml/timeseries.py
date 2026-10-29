"""Time-series anomaly detection over capture volume.

    python -m ml.timeseries --hours 168 --json

The dashboard draws event counts per bucket; this module asks which buckets are
*unusual* relative to the ones before them. It is a rolling Z-score over a
trailing window: a bucket whose count is ``threshold`` standard deviations from
the recent mean is flagged.

Two asymmetries matter and are deliberate:

* **A zero bucket when the baseline is busy is flagged as ``silence``, not just
  ``drop``.** A sensor that goes quiet is usually a sensor that has fallen
  over, not a calm internet — the same reason the daily digest reports a
  zero-event day explicitly. Silence is a different failure than a dip.
* **Nothing is flagged without enough history.** The first ``window`` buckets
  have no baseline and are reported as ``baseline``, never as normal, because
  "not anomalous yet" is not the same claim as "normal".

The core (:func:`detect_anomalies`) is pure Python over ``(ts, value)`` pairs
so it can be unit-tested without a database; the CLI wires it to
``storage.queries.events_timeseries``.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from storage import queries
from storage.db import session_scope


def _mean_std(values: list[float]) -> tuple[float, float]:
    n = len(values)
    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / n
    return mean, variance**0.5


def detect_anomalies(
    points: list[dict[str, Any]], *, window: int = 24, threshold: float = 3.0
) -> list[dict[str, Any]]:
    """Flag buckets that are unusual relative to their ``window`` predecessors.

    ``points`` is a list of dicts with at least a ``value`` key (numeric); every
    other key is preserved on the returned records. Each result gains ``zscore``
    and ``kind``, where ``kind`` is one of ``baseline``, ``normal``, ``spike``,
    ``drop`` or ``silence``.
    """
    results: list[dict[str, Any]] = []
    for i, point in enumerate(points):
        value = float(point["value"])
        if i < window:
            results.append({**point, "zscore": None, "kind": "baseline"})
            continue

        prior = [float(p["value"]) for p in points[i - window : i]]
        mean, std = _mean_std(prior)

        if std == 0.0:
            # A flat baseline carries no variance, so a Z-score is undefined.
            # Classify by direction instead: up is a spike, down to zero is a
            # sensor going quiet, anything else is unremarkable.
            if value > mean:
                kind = "spike"
            elif value == 0.0:
                kind = "silence"
            else:
                kind = "normal"
            results.append({**point, "zscore": None, "kind": kind})
            continue

        zscore = (value - mean) / std
        if value == 0.0 and mean > 0.0:
            kind = "silence"
        elif zscore > threshold:
            kind = "spike"
        elif zscore < -threshold:
            kind = "drop"
        else:
            kind = "normal"
        results.append({**point, "zscore": round(zscore, 3), "kind": kind})

    return results


def _is_flag(result: dict[str, Any]) -> bool:
    return result["kind"] not in ("normal", "baseline")


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

    parser = argparse.ArgumentParser(description="Detect anomalies in capture volume")
    parser.add_argument("--hours", type=float, default=168.0, help="window to analyse")
    parser.add_argument("--bucket", choices=("1m", "5m", "15m", "1h", "6h", "1d"), default="1h")
    parser.add_argument("--window", type=int, default=24, help="trailing buckets for the baseline")
    parser.add_argument("--threshold", type=float, default=3.0)
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)

    with session_scope() as db:
        series = queries.events_timeseries(
            db, since_hours=args.hours, bucket=args.bucket, by="none"
        )

    points = [{"ts": p["ts"], "value": float(p["total"])} for p in series["points"]]
    results = detect_anomalies(points, window=args.window, threshold=args.threshold)
    flagged = [r for r in results if _is_flag(r)]

    if args.json:
        print(json.dumps(flagged, indent=2))
        return 0

    print(f"{len(flagged)} anomalous bucket(s) of {len(results)} analysed\n")
    for r in flagged:
        print(f"  {r['kind']:8}  {r['ts']}  value={r['value']:>7.0f}  z={r['zscore']}")
    if not flagged:
        print("nothing unusual in the window")
    return 0


if __name__ == "__main__":
    sys.exit(main())
