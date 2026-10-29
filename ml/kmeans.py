"""Phase 2 -- cluster sessions into behavioural groups with k-means.

    python -m ml.kmeans --k 6 --out ml/data/clusters.csv

The production pipeline groups *attackers* into campaigns with interpretable
set overlap (``pipeline/analysis/campaigns.py``). This is a different tool for
a different question: given a fixed number of behaviours you already believe
exist, what does a k-means partition of the *session* feature space look like?

K-means is used here deliberately, not because it is clever but because its
limitations are well understood. It needs ``k`` up front, assumes convex
clusters of similar size, and is sensitive to scaling -- the entrypoint
standardises the inputs and the caller must supply ``k``, which forces the
question to be "how many behaviours?" rather than "are there clusters?".
Where the production campaign clustering asks "who is the same operator?",
this asks "how many distinct behaviours are in this capture, and which
sessions belong to each?" -- a question that only becomes answerable once
there is enough volume to make the categories visible, hence Phase 2.

Requires ``scikit-learn``; install with ``pip install -r ml/requirements.txt``.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

from ml.features import build_dataset, fetch_sessions
from storage.db import session_scope


def cluster_sessions(
    rows: list[list[float]], *, k: int, random_state: int = 0
) -> tuple[list[int], float]:
    """Return ``(cluster_labels, inertia)`` for the given feature rows.

    Rows are standardised first: k-means uses Euclidean distance, so an
    unscaled ``bytes_in`` (tens of thousands) would drown ``auth_attempts``
    (single digits) and the partition would collapse to a function of one
    column.
    """
    if not rows:
        return [], 0.0
    try:
        import numpy as np
        from sklearn.cluster import KMeans
        from sklearn.preprocessing import StandardScaler
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise SystemExit(
            "k-means needs scikit-learn and numpy; install them with "
            "`pip install -r ml/requirements.txt`."
        ) from exc

    x = np.asarray(rows, dtype=float)
    if x.shape[0] < k:
        raise ValueError(f"cannot find {k} clusters in {x.shape[0]} sessions; lower --k")

    x = StandardScaler().fit_transform(x)
    model = KMeans(n_clusters=k, random_state=random_state, n_init=10).fit(x)
    return model.labels_.astype(int).tolist(), float(model.inertia_)


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

    parser = argparse.ArgumentParser(description="Cluster sessions with k-means (Phase 2)")
    parser.add_argument("--k", type=int, default=6, help="number of behavioural clusters")
    parser.add_argument("--limit", type=int, default=100_000)
    parser.add_argument("--hours", type=float, help="only sessions started in the last N hours")
    parser.add_argument("--min-events", type=int, default=1)
    parser.add_argument("--out", help="write labelled sessions to this CSV")
    args = parser.parse_args(argv)

    with session_scope() as db:
        sessions = fetch_sessions(
            db, limit=args.limit, since_hours=args.hours, min_events=args.min_events
        )

    columns, rows, meta = build_dataset(sessions)
    if not rows:
        print("no sessions to cluster", file=sys.stderr)
        return 0

    labels, inertia = cluster_sessions(rows, k=args.k)
    counts = Counter(labels)
    cmd_idx = columns.index("commands_run")

    print(f"k={args.k}  inertia={inertia:.2f}  sessions={len(rows):,}\n")
    for cluster in sorted(counts):
        members = [(meta[i], rows[i]) for i, label in enumerate(labels) if label == cluster]
        services = Counter(m["service"] for m, _ in members)
        top_service = services.most_common(1)[0][0] if services else "-"
        avg_commands = sum(r[cmd_idx] for _, r in members) / len(members)
        print(
            f"  cluster {cluster}: {counts[cluster]:>5} sessions  "
            f"service={top_service}  avg_commands={avg_commands:.1f}"
        )

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["cluster", "session_id", "src_ip", "service", "started_at"])
            for m, label in zip(meta, labels, strict=True):
                writer.writerow(
                    [label, m["session_id"], m["src_ip"], m["service"], m["started_at"]]
                )
        print(f"\nwrote {len(labels):,} labelled sessions to {out}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
