"""API-level tests for the campaigns endpoint.

These drive the real app, so they also cover the schema boundary: a field the
clusterer computes but ``CampaignOut`` never declares would silently vanish
from the response, and only a test that reads the JSON notices.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from storage.db import get_engine, init_db, reset_state, session_scope
from storage.models import Event, EventType, Severity, utcnow


def event(src_ip: str, **kwargs) -> Event:
    defaults = dict(
        event_id=str(uuid.uuid4()),
        ts=utcnow(),
        sensor="t",
        service="ssh",
        event_type=EventType.AUTH_ATTEMPT.value,
        severity=Severity.MEDIUM.value,
        src_ip=src_ip,
        dst_port=22,
        tags=[],
        threat_tags=[],
        extra={},
    )
    defaults.update(kwargs)
    return Event(**defaults)


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Two credential-sharing sources, plus one unrelated scanner."""
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'c.db').as_posix()}")
    reset_state()
    init_db(get_engine())

    with session_scope() as db:
        for ip in ("45.33.32.1", "45.33.32.2"):
            for _ in range(3):
                db.add(event(ip, username="root", password="hunter2", path="/shell.php"))
        db.add(event("93.184.216.9", username="nobody", password="zzz", path="/unrelated"))

    from storage import queries

    with session_scope() as db:
        queries.rebuild_attackers(db)

    from api.main import app

    with TestClient(app) as c:
        yield c
    reset_state()


class TestRecompute:
    """The live path, opted into with recompute=true."""

    def test_groups_the_credential_sharers(self, client):
        body = client.get("/api/campaigns?recompute=true").json()
        assert len(body["items"]) == 1
        assert body["items"][0]["members"] == ["45.33.32.1", "45.33.32.2"]

    def test_excludes_the_unrelated_source(self, client):
        body = client.get("/api/campaigns?recompute=true").json()
        assert "93.184.216.9" not in body["items"][0]["members"]

    def test_reports_the_evidence(self, client):
        campaign = client.get("/api/campaigns?recompute=true").json()["items"][0]
        assert campaign["shared_credentials"] == ["root:hunter2"]
        assert campaign["shared_paths"] == ["/shell.php"]

    def test_reports_size_events_and_cohesion(self, client):
        campaign = client.get("/api/campaigns?recompute=true").json()["items"][0]
        assert campaign["size"] == 2
        assert campaign["event_count"] == 6
        assert 0.0 <= campaign["cohesion"] <= 1.0

    def test_an_unreachable_threshold_returns_nothing(self, client):
        body = client.get("/api/campaigns?recompute=true&threshold=1.0&min_size=3").json()
        assert body["items"] == []

    def test_provenance_says_computed(self, client):
        assert client.get("/api/campaigns?recompute=true").json()["source"] == "computed"


class TestStoredByDefault:
    """The default path reads rows written by the rebuild command."""

    def test_nothing_stored_yields_an_empty_page_not_a_slow_recompute(self, client):
        body = client.get("/api/campaigns").json()
        assert body["items"] == []
        assert body["source"] == "stored"
        assert body["computed_at"] is None

    def test_stored_rows_are_served(self, client):
        from pipeline.analysis.campaigns import DEFAULT_THRESHOLD, rebuild_campaigns
        from storage.db import session_scope

        with session_scope() as db:
            stored = rebuild_campaigns(db)
        assert stored == 1

        body = client.get("/api/campaigns").json()
        assert body["source"] == "stored"
        assert body["computed_at"] is not None
        assert body["items"][0]["members"] == ["45.33.32.1", "45.33.32.2"]
        assert body["threshold"] == DEFAULT_THRESHOLD

    def test_stored_rows_carry_the_evidence(self, client):
        from pipeline.analysis.campaigns import rebuild_campaigns
        from storage.db import session_scope

        with session_scope() as db:
            rebuild_campaigns(db)
        campaign = client.get("/api/campaigns").json()["items"][0]
        assert campaign["shared_credentials"] == ["root:hunter2"]

    def test_available_thresholds_are_reported(self, client):
        from pipeline.analysis.campaigns import rebuild_campaigns
        from storage.db import session_scope

        with session_scope() as db:
            rebuild_campaigns(db, threshold=0.35)
            rebuild_campaigns(db, threshold=0.5)
        assert client.get("/api/campaigns").json()["available_thresholds"] == [0.35, 0.5]

    def test_a_threshold_with_no_stored_rows_is_empty(self, client):
        from pipeline.analysis.campaigns import rebuild_campaigns
        from storage.db import session_scope

        with session_scope() as db:
            rebuild_campaigns(db, threshold=0.35)
        assert client.get("/api/campaigns?threshold=0.9").json()["items"] == []


class TestCampaignsEndpoint:
    def test_threshold_is_bounded(self, client):
        assert client.get("/api/campaigns?threshold=1.5").status_code == 422
        assert client.get("/api/campaigns?threshold=-0.1").status_code == 422

    def test_min_size_filters_small_groups(self, client):
        assert client.get("/api/campaigns?recompute=true&min_size=5").json()["items"] == []

    def test_limit_is_bounded(self, client):
        # Clustering is O(n²), so an unbounded limit is a self-inflicted denial
        # of service on a synchronous endpoint.
        assert client.get("/api/campaigns?limit=999999").status_code == 422
        assert client.get("/api/campaigns?limit=2001").status_code == 422
        assert client.get("/api/campaigns?limit=2000").status_code == 200

    def test_default_limit_is_conservative(self, client):
        import inspect

        from api.routes.campaigns import list_campaigns

        default = inspect.signature(list_campaigns).parameters["limit"].default
        assert default.default == 500

    def test_response_is_json_serialisable_end_to_end(self, client):
        response = client.get("/api/campaigns")
        assert response.status_code == 200
        assert isinstance(response.json()["items"], list)
