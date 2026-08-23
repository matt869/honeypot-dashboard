"""Unit tests for the Elasticsearch emulator.

An exposed cluster attracts two quite different operators, and the value of
this service is telling them apart. One is reading — `_cat/indices` then
`_search`, and the index they ask for by name says what they came for. The
other is deleting: the ransom sweeps take out every index and leave a note.
Scoring those the same would bury the wipe in the noise of the crawlers.

The severity ladder is therefore the thing under test. Reading the banner is
what the whole internet does and must stay low; `DELETE /*` is the end of
somebody's data and must be critical, regardless of how ordinary the request
looks on the wire.
"""

from __future__ import annotations

import json

import pytest

from honeypot.services.elasticsearch_service import (
    ElasticsearchService,
    classify_path,
    index_from_path,
)
from storage.models import EventType, Severity


def http(method: str, path: str, body: str = "", headers: dict[str, str] | None = None) -> bytes:
    lines = [f"{method} {path} HTTP/1.1", "host: 10.0.0.1:9200"]
    for name, value in (headers or {}).items():
        lines.append(f"{name}: {value}")
    if body:
        lines.append(f"content-length: {len(body)}")
    lines.append("")
    lines.append(body)
    return "\r\n".join(lines).encode()


def only_event(logger) -> dict:
    events = logger.of_type(EventType.HTTP_REQUEST)
    assert events, "no request was recorded"
    return events[0]


# --------------------------------------------------------------------------- #
# Routing
# --------------------------------------------------------------------------- #


class TestClassifyPath:
    @pytest.mark.parametrize(
        ("method", "path", "expected"),
        [
            ("GET", "/", "root-banner"),
            ("GET", "/_cat/indices", "cat-api"),
            ("GET", "/_cat/indices?v&format=json", "cat-api"),
            ("GET", "/_cluster/health", "cluster-info"),
            ("GET", "/_nodes/stats", "nodes-info"),
            ("GET", "/_search", "search"),
            ("POST", "/users/_search", "search"),
            ("POST", "/_bulk", "bulk"),
            ("DELETE", "/logs-2026.08", "delete-index"),
            ("DELETE", "/*", "delete-index"),
            ("PUT", "/newindex", "write-index"),
            ("GET", "/logs-2026.08", "read-index"),
        ],
    )
    def test_routes(self, method, path, expected):
        assert classify_path(method, path) == expected

    def test_trailing_slash_does_not_change_the_route(self):
        assert classify_path("GET", "/_cat/indices/") == "cat-api"

    def test_query_string_is_ignored(self):
        assert classify_path("GET", "/?pretty=true") == "root-banner"


class TestIndexFromPath:
    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("/users/_search", "users"),
            ("/logs-2026.08", "logs-2026.08"),
            ("/customers/_doc/1", "customers"),
            ("/*", "*"),
            ("/_all", None),
            ("/_search", None),
            ("/_cat/indices", None),
            ("/", None),
            ("", None),
        ],
    )
    def test_extracts_the_index(self, path, expected):
        assert index_from_path(path) == expected

    def test_absurdly_long_index_is_truncated(self):
        assert len(index_from_path("/" + "x" * 500)) == 128


# --------------------------------------------------------------------------- #
# The severity ladder
# --------------------------------------------------------------------------- #


class TestSeverity:
    def test_banner_read_is_low(self, protocol_harness):
        # Every scanner on the internet does this. If it is not low, nothing is.
        _, logger, _ = protocol_harness(ElasticsearchService, http("GET", "/"))
        event = only_event(logger)
        assert event["severity"] == Severity.LOW.value
        assert "es-recon" in event["tags"]

    def test_listing_indices_is_medium(self, protocol_harness):
        # How a data-theft run starts.
        _, logger, _ = protocol_harness(ElasticsearchService, http("GET", "/_cat/indices"))
        event = only_event(logger)
        assert event["severity"] == Severity.MEDIUM.value
        assert "es-enumerate-indices" in event["tags"]

    def test_search_is_medium(self, protocol_harness):
        _, logger, _ = protocol_harness(ElasticsearchService, http("GET", "/_search"))
        assert only_event(logger)["severity"] == Severity.MEDIUM.value

    def test_writing_is_high(self, protocol_harness):
        _, logger, _ = protocol_harness(ElasticsearchService, http("PUT", "/newindex", '{"a":1}'))
        event = only_event(logger)
        assert event["severity"] == Severity.HIGH.value
        assert "es-write" in event["tags"]

    def test_deleting_one_index_is_high(self, protocol_harness):
        _, logger, _ = protocol_harness(ElasticsearchService, http("DELETE", "/logs-2026.08"))
        event = only_event(logger)
        assert event["severity"] == Severity.HIGH.value
        assert "es-delete" in event["tags"]

    @pytest.mark.parametrize("path", ["/*", "/_all"])
    def test_deleting_everything_is_critical(self, protocol_harness, path):
        # The Meow-style ransom sweep. This must not read as routine cleanup.
        _, logger, _ = protocol_harness(ElasticsearchService, http("DELETE", path))
        event = only_event(logger)
        assert event["severity"] == Severity.CRITICAL.value
        assert "es-destroy-all" in event["tags"]

    def test_naming_a_sensitive_index_raises_severity(self, protocol_harness):
        # Asking for "customers" by name is knowing what you came for, not
        # enumerating whatever happens to be there.
        _, logger, _ = protocol_harness(ElasticsearchService, http("GET", "/customers/_search"))
        event = only_event(logger)
        assert event["severity"] == Severity.HIGH.value
        assert "es-sensitive-index" in event["tags"]

    def test_an_ordinary_index_name_does_not_raise_severity(self, protocol_harness):
        _, logger, _ = protocol_harness(ElasticsearchService, http("GET", "/logs-2026.08/_search"))
        event = only_event(logger)
        assert "es-sensitive-index" not in event["tags"]
        assert event["severity"] == Severity.MEDIUM.value

    def test_severity_never_drops_after_being_raised(self, protocol_harness):
        # A sensitive index on a read must not be lowered back to medium.
        _, logger, _ = protocol_harness(ElasticsearchService, http("GET", "/passwords"))
        assert only_event(logger)["severity"] == Severity.HIGH.value


class TestExploitDetection:
    @pytest.mark.parametrize(
        "body",
        [
            '{"script": "java.lang.Runtime.getRuntime().exec(\\"id\\")"}',
            '{"query":{"filtered":{"script_fields":{"x":{"script":"1"}}}}}',
            '{"size":1,"script_fields":{"c":{"script":"Math.class.forName(\\"java.lang.Runtime\\")"}}}',
            '{"script":{"lang":"groovy","inline":"1+1"}}',
            '{"script":{"lang":"painless","source":"ctx"}}',
        ],
    )
    def test_scripting_payloads_are_critical(self, protocol_harness, body):
        # CVE-2014-3120 / CVE-2015-1427 era. The scanners were never retired.
        _, logger, _ = protocol_harness(ElasticsearchService, http("POST", "/_search", body))
        event = only_event(logger)
        assert event["severity"] == Severity.CRITICAL.value
        assert "es-script-rce" in event["tags"]

    def test_an_ordinary_query_is_not_flagged_as_rce(self, protocol_harness):
        body = '{"query":{"match_all":{}},"size":10}'
        _, logger, _ = protocol_harness(ElasticsearchService, http("POST", "/_search", body))
        event = only_event(logger)
        assert "es-script-rce" not in event["tags"]

    def test_ransom_note_is_critical(self, protocol_harness):
        _, logger, _ = protocol_harness(ElasticsearchService, http("PUT", "/read_me_to_recover"))
        event = only_event(logger)
        assert event["severity"] == Severity.CRITICAL.value
        assert "es-ransom-note" in event["tags"]

    def test_the_request_body_is_captured(self, protocol_harness):
        body = '{"script":"whoami"}'
        _, logger, _ = protocol_harness(ElasticsearchService, http("POST", "/_search", body))
        assert only_event(logger)["command"] == body


# --------------------------------------------------------------------------- #
# Responses
# --------------------------------------------------------------------------- #


class TestResponses:
    def _json(self, writer):
        text = writer.text
        return json.loads(text.split("\r\n\r\n", 1)[1])

    def test_banner_looks_like_a_real_cluster(self, protocol_harness):
        # A client that cannot parse the greeting hangs up before revealing
        # what it wanted.
        writer, _, _ = protocol_harness(ElasticsearchService, http("GET", "/"))
        body = self._json(writer)
        assert body["tagline"] == "You Know, for Search"
        assert body["version"]["number"]

    def test_content_length_matches_the_body(self, protocol_harness):
        # A wrong length makes a real client hang waiting for bytes.
        writer, _, _ = protocol_harness(ElasticsearchService, http("GET", "/"))
        head, _, body = writer.text.partition("\r\n\r\n")
        declared = int(
            [line for line in head.splitlines() if line.lower().startswith("content-length")][0]
            .split(":")[1]
            .strip()
        )
        assert declared == len(body.encode())

    def test_cat_api_names_indices_so_the_run_continues(self, protocol_harness):
        writer, _, _ = protocol_harness(ElasticsearchService, http("GET", "/_cat/indices"))
        names = [row["index"] for row in self._json(writer)]
        assert "logs-2026.08" in names

    def test_search_returns_no_documents(self, protocol_harness):
        # Nothing real is ever served, however convincing the cluster looks.
        writer, _, _ = protocol_harness(ElasticsearchService, http("GET", "/_search"))
        body = self._json(writer)
        assert body["hits"]["hits"] == []
        assert body["hits"]["total"] == 0

    def test_delete_is_acknowledged_without_deleting_anything(self, protocol_harness):
        writer, _, _ = protocol_harness(ElasticsearchService, http("DELETE", "/*"))
        assert self._json(writer)["acknowledged"] is True


# --------------------------------------------------------------------------- #
# Robustness
# --------------------------------------------------------------------------- #


class TestRobustness:
    def test_multiple_requests_on_one_connection(self, protocol_harness):
        script = http("GET", "/") + http("GET", "/_cat/indices")
        _, logger, _ = protocol_harness(ElasticsearchService, script)
        assert len(logger.of_type(EventType.HTTP_REQUEST)) == 2

    def test_connection_close_ends_the_session(self, protocol_harness):
        script = http("GET", "/", headers={"connection": "close"}) + http("GET", "/_cat/indices")
        _, logger, _ = protocol_harness(ElasticsearchService, script)
        assert len(logger.of_type(EventType.HTTP_REQUEST)) == 1

    def test_lying_content_length_does_not_exhaust_memory(self, protocol_harness):
        # The declared length is an attacker's claim, not a fact.
        raw = b"POST /_search HTTP/1.1\r\ncontent-length: 999999999\r\n\r\nshort"
        _, _, session = protocol_harness(ElasticsearchService, raw)
        assert session.bytes_in < 1_000_000

    def test_non_numeric_content_length_is_survivable(self, protocol_harness):
        raw = b"POST /_search HTTP/1.1\r\ncontent-length: abc\r\n\r\n{}"
        protocol_harness(ElasticsearchService, raw)

    def test_garbage_request_line_ends_the_session(self, protocol_harness):
        _, logger, _ = protocol_harness(ElasticsearchService, b"\x00\x01\x02\r\n\r\n")
        assert logger.of_type(EventType.HTTP_REQUEST) == []

    def test_empty_input_records_nothing(self, protocol_harness):
        _, logger, _ = protocol_harness(ElasticsearchService, b"")
        assert logger.events == []

    def test_binary_garbage_does_not_raise(self, protocol_harness):
        protocol_harness(ElasticsearchService, bytes(range(256)) * 4)

    def test_the_route_and_index_are_recorded(self, protocol_harness):
        _, logger, _ = protocol_harness(ElasticsearchService, http("GET", "/customers/_search"))
        extra = only_event(logger)["extra"]
        assert extra["es_route"] == "search"
        assert extra["index"] == "customers"


class TestRegistration:
    def test_the_service_is_in_the_registry(self):
        from honeypot.services import SERVICE_REGISTRY

        assert SERVICE_REGISTRY["elasticsearch"] is ElasticsearchService

    def test_it_is_enabled_by_default_on_9200(self):
        from honeypot.config import Settings

        entry = next(s for s in Settings().services() if s.name == "elasticsearch")
        assert entry.enabled is True
        assert entry.port == 9200

    def test_the_service_enum_knows_it(self):
        from storage.models import Service

        assert Service.ELASTICSEARCH.value == "elasticsearch"
