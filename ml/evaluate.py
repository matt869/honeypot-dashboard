"""Evaluate the ML experiments against each other and the production scorer.

    python -m ml.evaluate --k-max 10
    python -m ml.evaluate --anomaly-correlation --limit 2000

Two questions, each answered with a concrete number:

1. **How many clusters?** k-means needs ``k`` up front. Sweeping ``k`` and
   reporting the silhouette coefficient at each value turns "pick a number"
   into "pick the knee on a curve". Silhouette is bounded [-1, 1]; higher is
   more coherent, but a single number never justifies a choice on its own.

2. **Does the autoencoder agree with the rules?** The production scorer flags
   *known-bad* behaviour; the autoencoder flags *unusual* behaviour. The
   Spearman rank correlation between the two tells you whether "unusual" is
   mostly "known-bad" (high positive) or whether the model is surfacing
   something the rules miss (near zero). Both are useful; they mean different
   things.

Requires ``scikit-learn`` / ``torch`` as exercised; see ``ml/requirements.txt``.
"""

from __future__ import annotations

import argparse
import sys

from ml.features import build_dataset, fetch_sessions
from storage.db import session_scope


def silhouette_scores(
    rows: list[list[float]], ks: list[int], *, random_state: int = 0
) -> list[tuple[int, float]]:
    """Silhouette coefficient for each ``k`` in ``ks`` (skipped if invalid)."""
    try:
        import numpy as np
        from sklearn.cluster import KMeans
        from sklearn.metrics import silhouette_score
        from sklearn.preprocessing import StandardScaler
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise SystemExit(
            "the silhouette sweep needs scikit-learn; install it with "
            "`pip install -r ml/requirements.txt`."
        ) from exc

    x = StandardScaler().fit_transform(np.asarray(rows, dtype=float))
    results: list[tuple[int, float]] = []
    for k in ks:
        if k < 2 or k >= x.shape[0]:
            continue
        labels = KMeans(n_clusters=k, random_state=random_state, n_init=10).fit_predict(x)
        results.append((int(k), float(silhouette_score(x, labels))))
    return results


def _rankdata(values):
    import numpy as np

    v = np.asarray(values, dtype=float)
    order = np.argsort(v, kind="mergesort")
    ranks = np.empty(len(v), dtype=float)
    ranks[order] = np.arange(1.0, len(v) + 1.0)
    _, inverse, counts = np.unique(v, return_inverse=True, return_counts=True)
    for idx in np.flatnonzero(counts > 1):
        mask = inverse == idx
        ranks[mask] = ranks[mask].mean()
    return ranks


def spearman(a, b) -> float:
    """Spearman rank correlation between two sequences (average ranks for ties)."""
    import numpy as np

    x = np.asarray(_rankdata(a), dtype=float)
    y = np.asarray(_rankdata(b), dtype=float)
    xm = x - x.mean()
    ym = y - y.mean()
    denominator = float((xm**2).sum() * (ym**2).sum())
    if denominator == 0.0:
        return 0.0
    return float((xm * ym).sum() / (denominator**0.5))


def anomaly_correlation(rows: list[list[float]], columns: list[str]) -> tuple[float, list[float]]:
    """Spearman correlation of autoencoder error against ``max_threat_score``."""
    from ml.autoencoder import anomaly_scores

    errors = anomaly_scores(rows)
    score_idx = columns.index("max_threat_score")
    scores = [row[score_idx] for row in rows]
    return spearman(errors, scores), errors


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

    parser = argparse.ArgumentParser(description="Evaluate the ML experiments")
    parser.add_argument("--limit", type=int, default=100_000)
    parser.add_argument("--hours", type=float, help="only sessions started in the last N hours")
    parser.add_argument("--k-max", type=int, default=10, help="largest k for the silhouette sweep")
    parser.add_argument("--no-silhouette", action="store_true")
    parser.add_argument("--no-anomaly", action="store_true")
    parser.add_argument("--epochs", type=int, default=200)
    parser.add_argument("--bottleneck", type=int, default=4)
    args = parser.parse_args(argv)

    with session_scope() as db:
        sessions = fetch_sessions(db, limit=args.limit, since_hours=args.hours, min_events=1)

    columns, rows, _meta = build_dataset(sessions)
    if not rows:
        print("no sessions to evaluate", file=sys.stderr)
        return 0

    if not args.no_silhouette:
        ks = list(range(2, min(args.k_max, len(rows)) + 1))
        print("k  silhouette")
        for k, score in silhouette_scores(rows, ks):
            print(f"{k:>3}  {score:8.3f}")
        print()

    if not args.no_anomaly:
        rho, _errors = anomaly_correlation(rows, columns)
        print(f"spearman(anomaly_error, threat_score) = {rho:+.3f}")
        print("  +1.0 -> unusual is mostly known-bad; ~0 -> the model sees what the rules miss")

    return 0


if __name__ == "__main__":
    sys.exit(main())
