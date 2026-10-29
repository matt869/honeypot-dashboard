# ml/notebooks/ -- experiments and charts

Jupyter notebooks live here. They are committed (unlike `ml/data/`, which is
regenerated) because a chart without the notebook that produced it is an
assertion without a derivation.

## Conventions

- Start from a dataset produced by `python -m ml.export`, or call
  `ml.features.fetch_sessions` directly for quick iteration.
- Keep the first cell a comment saying which dataset/date it was run against --
  the capture changes daily and a figure is only meaningful relative to it.
- Prefer the scripts (`kmeans.py`, `autoencoder.py`, `transformer.py`) for
  anything repeatable, and use a notebook for the exploration that leads to a
  script.

## Notebook dependencies

```bash
pip install jupyter matplotlib pandas
jupyter notebook ml/notebooks
```
