"""A scanner speaking HTTP at port 23 must not become a captured credential.

Found on the live sensor, which is the only place it shows. Scanners sweep
every port with an HTTP request, so the telnet login prompt was reading
``GET / HTTP/1.1`` as a username and ``Host: <sensor>:23`` as a password. Those
rows then poisoned three things downstream: the top-usernames chart, the
unique-credential-pair count, and campaign clustering — which grouped four
unrelated hosts on a "shared credential" of ``GET / HTTP/1.1:Host: …:23``.

The detector is deliberately conservative. A false positive throws away a real
captured credential, which is the observation the sensor exists to collect, so
anything that could plausibly be an IoT username stays a username.
"""

from __future__ import annotations

import pytest

from honeypot.services.telnet_service import TelnetService, _looks_like_http
from storage.models import EventType


def script(*lines: str) -> bytes:
    return "".join(f"{line}\r\n" for line in lines).encode()


class TestLooksLikeHttp:
    @pytest.mark.parametrize(
        "field",
        [
            "GET / HTTP/1.1",
            "GET /index.php?a=1 HTTP/1.0",
            "POST /cgi-bin/x HTTP/1.1",
            "HEAD / HTTP/1.1",
            "OPTIONS * HTTP/1.1",
            "Host: 198.51.100.23:23",
            "User-Agent: curl/7.81.0",
            "Connection: keep-alive",
        ],
    )
    def test_detects_http(self, field):
        assert _looks_like_http(field) is True

    @pytest.mark.parametrize(
        "field",
        [
            "root",
            "admin",
            "support",
            "get",  # a bare verb is not a request line
            "GET",
            "getty",  # a real account name that starts with the verb
            "gets",
            "hostmaster",  # starts with "host" but is not a header
            "user",
            "telnetadmin",
            "",
            "   ",
        ],
    )
    def test_leaves_plausible_credentials_alone(self, field):
        assert _looks_like_http(field) is False

    def test_verb_without_a_version_is_not_a_request_line(self):
        # "GET the door" is a strange username, but it is not HTTP and
        # discarding it would lose a real capture.
        assert _looks_like_http("GET the door") is False


class TestTelnetSession:
    def test_http_request_is_recorded_as_a_protocol_mismatch(self, protocol_harness):
        _, logger, _ = protocol_harness(
            TelnetService, script("GET / HTTP/1.1", "Host: 198.51.100.23:23", "")
        )
        event = logger.tagged("http-on-telnet")[0]
        assert event["event_type"] == EventType.COMMAND.value
        assert event["command"] == "GET / HTTP/1.1"
        assert "protocol-mismatch" in event["tags"]

    def test_no_credential_is_recorded_for_an_http_probe(self, protocol_harness):
        # The whole point: nothing lands in the username or password columns.
        _, logger, session = protocol_harness(
            TelnetService, script("GET / HTTP/1.1", "Host: x:23", "")
        )
        assert logger.of_type(EventType.AUTH_ATTEMPT) == []
        assert session.seen_credentials == set()
        assert session.auth_attempts == 0

    def test_the_probe_is_still_observed(self, protocol_harness):
        # Refusing to call it a login must not mean dropping the observation.
        _, logger, _ = protocol_harness(TelnetService, script("GET / HTTP/1.1", ""))
        assert logger.tagged("http-on-telnet")

    def test_session_ends_rather_than_prompting_again(self, protocol_harness):
        writer, _, _ = protocol_harness(TelnetService, script("GET / HTTP/1.1", "root", "root"))
        # One login prompt, not three: the client is not speaking telnet.
        assert writer.text.count("login: ") == 1

    def test_a_real_login_still_works(self, protocol_harness):
        _, logger, session = protocol_harness(TelnetService, script("root", "xc3511"))
        event = logger.of_type(EventType.AUTH_ATTEMPT)[0]
        assert event["username"] == "root"
        assert event["password"] == "xc3511"
        assert "iot-default-credential" in event["tags"]

    def test_a_username_starting_with_a_verb_still_logs_in(self, protocol_harness):
        _, logger, _ = protocol_harness(TelnetService, script("getty", "getty"))
        assert logger.of_type(EventType.AUTH_ATTEMPT)[0]["username"] == "getty"
