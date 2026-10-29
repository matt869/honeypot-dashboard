"""Phase 4 -- model command sequences with a small transformer.

    python -m ml.transformer --epochs 20 --save ml/data/transformer.pt

Phases 2 and 3 look at a session as a bag of features -- how many commands,
how long, which service. That flattens the part of a session that matters
most: the *order* in which commands happen. "wget then chmod then ./run" and
"cd then ls then rm" are the same length and the same count, but they are
different operators doing different things.

This module trains a tiny decoder-only transformer to predict the next command
in a session given the ones before it. The trained model scores how expected a
sequence is (perplexity), which is a richer anomaly signal than the
autoencoder's reconstruction error -- and needs correspondingly more data to
be trusted, hence Phase 4.

Commands are reduced to their first whitespace token (the verb: ``wget``,
``cd``, ``rm``) and lowercased, so ``cd /tmp`` and ``cd /var`` share a token.
Anything outside the top ``--vocab`` verbs becomes ``<unk>``.

Requires ``torch``; install with ``pip install -r ml/requirements.txt``.
"""

from __future__ import annotations

import argparse
import math
import sys
from collections import Counter
from pathlib import Path

from ml.features import fetch_sessions
from storage.db import session_scope
from storage.models import Session

PAD, UNK, BOS = "<pad>", "<unk>", "<bos>"


def command_verbs(session: Session) -> list[str]:
    """Return the ordered command verbs of a session, lowercased."""
    ordered = sorted((e for e in (session.events or []) if e.command), key=lambda e: e.ts)
    return [e.command.split()[0].lower() for e in ordered]


def build_vocab(sequences: list[list[str]], max_tokens: int) -> dict[str, int]:
    """Map the most common verbs (plus the special tokens) to integer ids."""
    counts = Counter(token for seq in sequences for token in seq)
    stoi: dict[str, int] = {PAD: 0, UNK: 1, BOS: 2}
    for token, _ in counts.most_common(max_tokens - len(stoi)):
        stoi[token] = len(stoi)
    return stoi


def _encode(sequence: list[str], stoi: dict[str, int], length: int) -> list[int]:
    ids = [stoi[BOS], *(stoi.get(token, stoi[UNK]) for token in sequence)]
    ids = ids[:length]
    return [*ids, *([stoi[PAD]] * (length - len(ids)))]


def train(
    sequences: list[list[str]],
    stoi: dict[str, int],
    *,
    seq_len: int = 32,
    epochs: int = 20,
    seed: int = 0,
):
    """Train a next-verb predictor; return ``(model, final_loss)``."""
    try:
        import torch
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise SystemExit(
            "the transformer needs torch; install it with `pip install -r ml/requirements.txt`."
        ) from exc

    encoded = [_encode(seq, stoi, seq_len) for seq in sequences if len(seq) >= 2]
    if not encoded:
        raise ValueError("no command sequences long enough to train on (need >= 2 verbs)")

    torch.manual_seed(seed)

    class CommandTransformer(torch.nn.Module):
        def __init__(self, vocab_size: int, block_size: int):
            super().__init__()
            d_model = 64
            self.token_embedding = torch.nn.Embedding(vocab_size, d_model, padding_idx=stoi[PAD])
            self.position_embedding = torch.nn.Embedding(block_size, d_model)
            causal = torch.triu(torch.full((block_size, block_size), float("-inf")), diagonal=1)
            self.register_buffer("mask", causal)
            layer = torch.nn.TransformerEncoderLayer(
                d_model=d_model, nhead=4, dim_feedforward=128, batch_first=True, dropout=0.1
            )
            self.encoder = torch.nn.TransformerEncoder(layer, num_layers=2)
            self.head = torch.nn.Linear(d_model, vocab_size)

        def forward(self, x):
            positions = torch.arange(x.size(1), device=x.device)
            embedded = self.token_embedding(x) + self.position_embedding(positions)
            hidden = self.encoder(embedded, mask=self.mask)
            return self.head(hidden)

    full = torch.tensor(encoded, dtype=torch.long)
    inputs, targets = full[:, :-1], full[:, 1:]
    model = CommandTransformer(len(stoi), inputs.size(1))
    optimiser = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = torch.nn.CrossEntropyLoss(ignore_index=stoi[PAD])

    model.train()
    for _ in range(epochs):
        optimiser.zero_grad()
        logits = model(inputs)
        loss = loss_fn(logits.reshape(-1, logits.size(-1)), targets.reshape(-1))
        loss.backward()
        optimiser.step()

    model.eval()
    with torch.no_grad():
        logits = model(inputs)
        final = loss_fn(logits.reshape(-1, logits.size(-1)), targets.reshape(-1)).item()
    return model, final


def save_checkpoint(model, stoi: dict[str, int], path: Path) -> None:
    import torch

    path.parent.mkdir(parents=True, exist_ok=True)
    torch.save({"state_dict": model.state_dict(), "vocab": stoi}, path)


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

    parser = argparse.ArgumentParser(description="Model command sequences (Phase 4)")
    parser.add_argument("--vocab", type=int, default=200, help="top verbs to keep")
    parser.add_argument("--seq-len", type=int, default=32)
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--limit", type=int, default=100_000)
    parser.add_argument("--min-commands", type=int, default=2)
    parser.add_argument("--save", help="save the checkpoint to this path")
    args = parser.parse_args(argv)

    with session_scope() as db:
        sessions = fetch_sessions(db, limit=args.limit)

    sequences = []
    for session in sessions:
        verbs = command_verbs(session)
        if len(verbs) >= args.min_commands:
            sequences.append(verbs)

    if not sequences:
        print("no sessions with enough commands to train on", file=sys.stderr)
        return 0

    stoi = build_vocab(sequences, args.vocab)
    model, loss = train(sequences, stoi, seq_len=args.seq_len, epochs=args.epochs)

    print(
        f"trained on {len(sequences):,} sessions, vocab {len(stoi)} verbs, "
        f"loss {loss:.3f} (perplexity {math.exp(min(loss, 20)):.1f})"
    )
    if args.save:
        path = Path(args.save)
        save_checkpoint(model, stoi, path)
        print(f"saved checkpoint to {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
