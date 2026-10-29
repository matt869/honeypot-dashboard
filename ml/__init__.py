"""Machine-learning experiments over captured honeypot sessions.

This package is the analyst's sandbox, deliberately kept out of the sensor,
API and pipeline import graph. The production pipeline is deterministic and
dependency-free; these modules ask the questions that need heavier, optional
tooling (scikit-learn, PyTorch) and are run by hand, not on a schedule.

* :mod:`ml.export` -- pull sessions out of the database into ``ml/data/``
* :mod:`ml.features` -- shared data loading and feature extraction
* :mod:`ml.kmeans` -- Phase 2: cluster sessions into behavioural groups
* :mod:`ml.autoencoder` -- Phase 3: flag anomalous sessions by reconstruction error
* :mod:`ml.transformer` -- Phase 4: model command sequences
* :mod:`ml.evaluate` -- how many clusters, and does the model agree with the scorer?
* :mod:`ml.timeseries` -- flag unusual capture volume (spikes and silence)

Nothing here reaches the network, and nothing here is imported by production
code, so a missing optional dependency can only ever break the experiment
being run.
"""
