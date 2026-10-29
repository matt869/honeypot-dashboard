# ml/ -- machine-learning experiments over captured sessions

The production pipeline (`pipeline/`) is deterministic, dependency-free and
runs on the sensor and the API. This directory is the analyst's sandbox: the
questions that need heavier, optional tooling (scikit-learn, PyTorch) and are
run by hand against a snapshot of the data, not on a schedule.

| File | Phase | Question it answers |
|---|---|---|
| `export.py` | -- | Pull sessions out of the database into `ml/data/` |
| `features.py` | -- | Shared data loading + feature extraction for every model |
| `kmeans.py` | 2 | How many distinct *behaviours* are in this capture? |
| `autoencoder.py` | 3 | Which sessions do not look like anything seen before? |
| `transformer.py` | 4 | How predictable is a session's command sequence? |

**The production code does not import anything here.** A missing optional
dependency can only break the experiment being run, never the sensor or the
dashboard.

## Quick start

```bash
pip install -r requirements.txt -r ml/requirements.txt

python -m ml.export --format features --out ml/data/features.csv
python -m ml.kmeans --k 6 --out ml/data/clusters.csv
python -m ml.autoencoder --top 20
python -m ml.transformer --epochs 20 --save ml/data/transformer.pt
```

`ml/data/` is git-ignored -- exported datasets and checkpoints are
regenerated, never committed. `ml/notebooks/` is for experiments and charts.

## The phase labels

The phases here are a local, ML-focused sequence layered on top of the
project-wide roadmap in `docs/ROADMAP.md`:

- **Phase 2 -- clustering.** The production campaign clustering is set-overlap
  and interpretable; k-means is the complementary "fixed number of behaviours"
  view once there is enough volume for categories to be visible.
- **Phase 3 -- anomaly detection.** The production scorer flags *known-bad*
  behaviour from rules; an autoencoder flags *unusual* behaviour, which is the
  claim that catches an attacker the rules have not been written for.
- **Phase 4 -- sequence modelling.** Bag-of-features models (Phases 2 and 3)
  flatten command order; a transformer learns it. This needs the most data to
  be trustworthy.

## Safety

Nothing here reaches the network and nothing is executed. Every model reads
only the local database and writes only under `ml/data/`.
