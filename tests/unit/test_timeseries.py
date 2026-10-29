"""Unit tests for rolling Z-score anomaly detection.

The core is pure and database-free; these tests state the two asymmetries the
module is built on: silence (zero when the baseline is busy) is its own kind,
and a short series has no baseline to judge against.
"""

from __future__ import annotations

from ml.timeseries import detect_anomalies


def _pts(values: list[int]) -> list[dict]:
    return [{"ts": f"t{i}", "value": v} for i, v in enumerate(values)]


def test_flat_series_is_normal():
    result = detect_anomalies(_pts([10] * 30), window=5)
    assert all(r["kind"] in ("baseline", "normal") for r in result)


def test_a_spike_is_flagged():
    result = detect_anomalies(_pts([10] * 24 + [100]), window=10)
    spikes = [r for r in result if r["kind"] == "spike"]
    assert len(spikes) == 1
    assert spikes[0]["value"] == 100


def test_silence_is_distinct_from_drop():
    # A busy baseline falling to zero is "silence" (sensor died), not "drop".
    result = detect_anomalies(_pts([10] * 24 + [0]), window=10)
    assert any(r["kind"] == "silence" for r in result)


def test_short_series_has_no_baseline():
    result = detect_anomalies(_pts([5, 500]), window=5)
    assert all(r["kind"] == "baseline" for r in result)


def test_extra_fields_are_preserved():
    points = [{"ts": f"t{i}", "value": 1, "note": "x"} for i in range(10)]
    result = detect_anomalies(points, window=3)
    assert all("note" in r for r in result)
