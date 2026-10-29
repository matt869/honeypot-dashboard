"""Phase 3 -- flag anomalous sessions with a reconstruction autoencoder.

    python -m ml.autoencoder --top 20

An autoencoder compresses each session's feature vector to a small bottleneck
and then reconstructs it; the reconstruction error measures how well the model
can explain the session in terms of the patterns it learned from the rest of
the capture. Sessions it cannot reconstruct are the interesting ones -- they
do not look like anything the model has seen, which in honeypot data usually
means a novel tool, a hand-run intrusion, or a scanner that has changed its
script.

This complements the production scorer, which flags *known-bad* behaviour from
declarative rules. An autoencoder flags *unusual* behaviour, which is a
different claim and useful precisely when an attacker does something the rules
have not been written for yet.

Requires ``torch`` and ``numpy``; install with ``pip install -r ml/requirements.txt``.
"""

from __future__ import annotations

import argparse
import sys

from ml.features import build_dataset, fetch_sessions
from storage.db import session_scope


def anomaly_scores(
    rows: list[list[float]], *, bottleneck: int = 4, epochs: int = 200, seed: int = 0
) -> list[float]:
    """Train an autoencoder on the rows and return per-row reconstruction error.

    Errors are returned in the same order as ``rows``, so the caller can line
    them back up with the session metadata.
    """
    try:
        import numpy as np
        import torch
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise SystemExit(
            "the autoencoder needs torch and numpy; install them with "
            "`pip install -r ml/requirements.txt`."
        ) from exc

    x = np.asarray(rows, dtype=float)
    if x.shape[0] < 10:
        raise ValueError("need at least 10 sessions to train the autoencoder")

    # Standardise so a single high-variance column cannot dominate the loss.
    mean = x.mean(axis=0)
    std = x.std(axis=0)
    std[std == 0] = 1.0
    x = (x - mean) / std

    class Autoencoder(torch.nn.Module):
        def __init__(self, input_dim: int, bottleneck: int):
            super().__init__()
            self.encoder = torch.nn.Sequential(
                torch.nn.Linear(input_dim, 64),
                torch.nn.ReLU(),
                torch.nn.Linear(64, bottleneck),
            )
            self.decoder = torch.nn.Sequential(
                torch.nn.Linear(bottleneck, 64),
                torch.nn.ReLU(),
                torch.nn.Linear(64, input_dim),
            )

        def forward(self, z):
            return self.decoder(self.encoder(z))

    torch.manual_seed(seed)
    data = torch.tensor(x, dtype=torch.float32)
    model = Autoencoder(x.shape[1], bottleneck)
    optimiser = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = torch.nn.MSELoss()

    model.train()
    for _ in range(epochs):
        optimiser.zero_grad()
        reconstructed = model(data)
        loss = loss_fn(reconstructed, data)
        loss.backward()
        optimiser.step()

    model.eval()
    with torch.no_grad():
        reconstructed = model(data)
        errors = ((reconstructed - data) ** 2).sum(dim=1).numpy()
    return errors.tolist()


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

    parser = argparse.ArgumentParser(
        description="Flag anomalous sessions with an autoencoder (Phase 3)"
    )
    parser.add_argument("--top", type=int, default=20, help="sessions to report")
    parser.add_argument("--bottleneck", type=int, default=4)
    parser.add_argument("--epochs", type=int, default=200)
    parser.add_argument("--limit", type=int, default=100_000)
    parser.add_argument("--hours", type=float, help="only sessions started in the last N hours")
    args = parser.parse_args(argv)

    with session_scope() as db:
        sessions = fetch_sessions(db, limit=args.limit, since_hours=args.hours, min_events=1)

    _, rows, meta = build_dataset(sessions)
    if not rows:
        print("no sessions to score", file=sys.stderr)
        return 0

    errors = anomaly_scores(rows, bottleneck=args.bottleneck, epochs=args.epochs)
    order = sorted(range(len(rows)), key=lambda i: errors[i], reverse=True)[: args.top]

    print(f"scored {len(rows):,} sessions; highest reconstruction error first\n")
    for i in order:
        m = meta[i]
        print(
            f"  {errors[i]:8.3f}  {m['service']:6}  {m['src_ip']:15}  "
            f"{m['session_id']}  {m['started_at']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
