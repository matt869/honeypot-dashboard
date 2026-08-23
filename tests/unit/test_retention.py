"""Tests for retention.

Two properties carry this module, and both are about not destroying the wrong
thing. Everything here deletes is irreplaceable — an attack that happened in
March cannot be re-observed — so the dry run must genuinely change nothing, and
a payload still referenced by a live event must survive regardless of age.

The bug that prompted the module has its own test: the old prune deleted
events, sessions and alerts and left ``data/payloads/`` untouched, so the record
of an intrusion expired while the working malware stayed on disk forever.
"""

from __future__ import annotations

import datetime as dt

import pytest

from pipeline import retention
from storage.models import Alert, Campaign, Event, Payload, Session, utcnow


@pytest.fixture
def payload_dir(tmp_path):
    directory = tmp_path / "payloads"
    directory.mkdir()
    return directory


def add_payload(db, directory, sha: str, *, last_seen=None, analyzed_at=None, data=b"MZ\x00\x00"):
    (directory / f"{sha}.bin").write_bytes(data)
    db.add(
        Payload(
            sha256=sha,
            size=len(data),
            file_type="pe",
            entropy=1.0,
            last_seen=last_seen,
            analyzed_at=analyzed_at or utcnow(),
        )
    )
    return directory / f"{sha}.bin"


@pytest.fixture
def aged(db, make_event, payload_dir):
    """An old capture and a recent one, each with a payload on disk."""
    now = utcnow()
    old, recent = now - dt.timedelta(days=200), now - dt.timedelta(days=1)

    old_sha, recent_sha = "a" * 64, "b" * 64
    db.add_all(
        [
            make_event(src_ip="45.33.32.1", ts=old, payload_sha256=old_sha),
            make_event(src_ip="45.33.32.1", ts=old),
            make_event(src_ip="93.184.216.1", ts=recent, payload_sha256=recent_sha),
        ]
    )
    db.add(Session(session_id="old-session", service="ssh", src_ip="45.33.32.1", started_at=old))
    db.add(
        Session(session_id="new-session", service="ssh", src_ip="93.184.216.1", started_at=recent)
    )
    db.add(
        Alert(
            alert_id="old-alert",
            rule_id="r1",
            rule_name="old",
            severity="high",
            title="old",
            dedupe_key="k1",
            first_seen=old,
            last_seen=old,
        )
    )
    add_payload(db, payload_dir, old_sha, last_seen=old)
    add_payload(db, payload_dir, recent_sha, last_seen=recent)
    db.commit()
    return {"old_sha": old_sha, "recent_sha": recent_sha, "dir": payload_dir}


def run(db, aged, **kwargs):
    return retention.apply_retention(db, older_than_days=90, payload_dir=aged["dir"], **kwargs)


# --------------------------------------------------------------------------- #
# The dry run must be inert
# --------------------------------------------------------------------------- #


class TestDryRun:
    def test_is_the_default(self, db, aged):
        assert retention.apply_retention(db, older_than_days=90, payload_dir=aged["dir"]).dry_run

    def test_deletes_no_rows(self, db, aged):
        before = db.query(Event).count()
        run(db, aged)
        assert db.query(Event).count() == before

    def test_deletes_no_files(self, db, aged):
        run(db, aged)
        assert (aged["dir"] / f"{aged['old_sha']}.bin").exists()

    def test_still_reports_what_would_go(self, db, aged):
        report = run(db, aged)
        assert report.events == 2
        assert report.payload_files == 1

    def test_report_matches_the_real_run(self, db, aged):
        preview = run(db, aged)
        actual = run(db, aged, dry_run=False)
        assert (preview.events, preview.payload_rows) == (actual.events, actual.payload_rows)

    def test_render_says_it_changed_nothing(self, db, aged):
        assert "Dry run" in run(db, aged).render()


# --------------------------------------------------------------------------- #
# Expiry
# --------------------------------------------------------------------------- #


class TestApply:
    def test_old_events_go(self, db, aged):
        run(db, aged, dry_run=False)
        db.commit()
        assert db.query(Event).count() == 1

    def test_recent_events_stay(self, db, aged):
        run(db, aged, dry_run=False)
        db.commit()
        assert db.query(Event).one().src_ip == "93.184.216.1"

    def test_old_sessions_and_alerts_go(self, db, aged):
        run(db, aged, dry_run=False)
        db.commit()
        assert db.query(Session).count() == 1
        assert db.query(Alert).count() == 0

    def test_the_malware_is_actually_deleted(self, db, aged):
        # The bug this module exists for: the old prune removed the record of
        # an intrusion and left the working sample on disk indefinitely.
        run(db, aged, dry_run=False)
        db.commit()
        assert not (aged["dir"] / f"{aged['old_sha']}.bin").exists()

    def test_the_expired_payload_row_goes_too(self, db, aged):
        run(db, aged, dry_run=False)
        db.commit()
        assert db.get(Payload, aged["old_sha"]) is None

    def test_bytes_reclaimed_are_reported(self, db, aged):
        report = run(db, aged, dry_run=False)
        assert report.payload_bytes > 0

    def test_attackers_are_rebuilt_not_left_stale(self, db, aged):
        # Their counters would otherwise still describe deleted events.
        from storage.models import Attacker

        run(db, aged, dry_run=False)
        db.commit()
        assert {a.src_ip for a in db.query(Attacker).all()} == {"93.184.216.1"}


class TestPayloadsStillInUseSurvive:
    def test_a_referenced_payload_is_kept_however_old(self, db, aged, make_event):
        # Age it past the cutoff but keep an event pointing at it. The sample is
        # evidence attached to a live observation, not litter.
        old = utcnow() - dt.timedelta(days=300)
        sha = "c" * 64
        add_payload(db, aged["dir"], sha, last_seen=old)
        db.add(make_event(src_ip="8.8.8.8", ts=utcnow(), payload_sha256=sha))
        db.commit()

        run(db, aged, dry_run=False)
        db.commit()
        assert (aged["dir"] / f"{sha}.bin").exists()
        assert db.get(Payload, sha) is not None

    def test_recent_payload_is_kept(self, db, aged):
        run(db, aged, dry_run=False)
        db.commit()
        assert (aged["dir"] / f"{aged['recent_sha']}.bin").exists()

    def test_retained_count_is_reported(self, db, aged):
        assert run(db, aged).retained_payloads >= 1

    def test_a_hand_dropped_file_ages_by_when_it_was_analysed(self, db, aged):
        # No events ever referenced it, so last_seen is null and analyzed_at is
        # the only clock available.
        sha = "d" * 64
        add_payload(db, aged["dir"], sha, analyzed_at=utcnow() - dt.timedelta(days=400))
        db.commit()
        run(db, aged, dry_run=False)
        db.commit()
        assert db.get(Payload, sha) is None

    def test_a_recently_analysed_orphan_is_kept(self, db, aged):
        sha = "e" * 64
        add_payload(db, aged["dir"], sha, analyzed_at=utcnow())
        db.commit()
        run(db, aged, dry_run=False)
        db.commit()
        assert db.get(Payload, sha) is not None


class TestKeepFiles:
    def test_rows_expire_but_files_stay(self, db, aged):
        # For deployments that archive samples elsewhere before pruning.
        run(db, aged, dry_run=False, delete_payload_files=False)
        db.commit()
        assert (aged["dir"] / f"{aged['old_sha']}.bin").exists()
        assert db.get(Payload, aged["old_sha"]) is None


class TestCampaigns:
    def test_stored_campaigns_are_dropped(self, db, aged):
        # They name addresses whose events are gone, so the grouping becomes an
        # unfalsifiable claim about data nobody can inspect.
        db.add(
            Campaign(campaign_id="c1", threshold=0.35, size=2, members=["45.33.32.1", "45.33.32.2"])
        )
        db.commit()
        run(db, aged, dry_run=False)
        db.commit()
        assert db.query(Campaign).count() == 0


class TestRobustness:
    def test_missing_payload_directory_is_survivable(self, db, aged, tmp_path):
        report = retention.apply_retention(
            db, older_than_days=90, payload_dir=tmp_path / "gone", dry_run=False
        )
        assert report.payload_files == 0

    def test_a_row_whose_file_is_already_gone(self, db, aged):
        (aged["dir"] / f"{aged['old_sha']}.bin").unlink()
        report = run(db, aged, dry_run=False)
        db.commit()
        assert report.payload_files == 0
        assert db.get(Payload, aged["old_sha"]) is None

    def test_nothing_old_enough_removes_nothing(self, db, aged):
        report = retention.apply_retention(
            db, older_than_days=3650, payload_dir=aged["dir"], dry_run=False
        )
        assert report.events == 0
        assert (aged["dir"] / f"{aged['old_sha']}.bin").exists()

    def test_empty_database(self, db, payload_dir):
        report = retention.apply_retention(
            db, older_than_days=30, payload_dir=payload_dir, dry_run=False
        )
        assert report.events == 0


class TestCli:
    def test_dry_run_by_default(self, db, aged, monkeypatch, capsys, db_url):
        monkeypatch.setenv("DATABASE_URL", db_url)
        assert retention.main(["--older-than", "90", "--dir", str(aged["dir"])]) == 0
        out = capsys.readouterr().out
        assert "Dry run" in out
        assert (aged["dir"] / f"{aged['old_sha']}.bin").exists()

    def test_apply_deletes(self, db, aged, monkeypatch, capsys, db_url):
        monkeypatch.setenv("DATABASE_URL", db_url)
        retention.main(["--older-than", "90", "--dir", str(aged["dir"]), "--apply"])
        assert "Dry run" not in capsys.readouterr().out
        assert not (aged["dir"] / f"{aged['old_sha']}.bin").exists()

    def test_json_output(self, db, aged, monkeypatch, capsys, db_url):
        import json

        monkeypatch.setenv("DATABASE_URL", db_url)
        retention.main(["--older-than", "90", "--dir", str(aged["dir"]), "--json"])
        assert json.loads(capsys.readouterr().out)["dry_run"] is True

    def test_older_than_is_required(self):
        with pytest.raises(SystemExit):
            retention.main([])

    def test_zero_days_is_rejected(self):
        # Would expire everything including what arrived this second.
        with pytest.raises(SystemExit):
            retention.main(["--older-than", "0", "--apply"])

    def test_a_run_that_expires_nothing_keeps_the_clustering(self, db, aged):
        # Seen against the live capture: 0 events expiring but 9 campaigns
        # queued for deletion. Nothing went stale, so wiping the clustering
        # would only force a pointless recompute.
        db.add(Campaign(campaign_id="c2", threshold=0.35, size=2, members=["a", "b"]))
        db.commit()
        report = retention.apply_retention(
            db, older_than_days=3650, payload_dir=aged["dir"], dry_run=False
        )
        db.commit()
        assert report.campaigns == 0
        assert db.query(Campaign).count() == 1
