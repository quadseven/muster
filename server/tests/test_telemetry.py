"""What muster reports, and the two things it must never report.

The tests that carry weight here are `a_pairing_code_never_reaches_a_log_line`
and `a_failing_socket_never_breaks_a_request`. One is a disclosure bug, the
other is an availability bug where the observability takes down the thing it
was added to observe - and both are the kind that ship green.
"""
from __future__ import annotations

import io
import json
import socket

import pytest

from muster import telemetry


@pytest.fixture()
def emitter():
    """Disabled, which is the default everywhere except the pod. It still
    records what it WOULD have sent, so behaviour is assertable with no agent."""
    return telemetry.Telemetry()


# ---- the two that carry the security ------------------------------------


def test_a_pairing_code_never_reaches_a_log_line():
    """A code is short-lived but it is live WHILE it is in the log, and a log
    is the one place a secret cannot be deleted from afterwards.

    Not truncated either: 6 digits is 10^6, and a prefix narrows that to
    something a script walks well inside the code's lifetime.
    """
    stream = io.StringIO()
    telemetry.configure_logging(stream)
    telemetry.event("device presented", code="123456", device_name="pixel-6a")

    written = stream.getvalue()
    assert "123456" not in written, "the pairing code was written to the log"
    payload = json.loads(written)
    assert payload["device_name"] == "pixel-6a", "the useful fields survived"
    assert payload["redacted"] == ["code"], "the drop is recorded, not silent"


@pytest.mark.parametrize(
    "field",
    [
        "code", "pairing_code", "token", "admin_token", "secret",
        # Managed application configuration. muster pushes another app's
        # settings to a device, and two of the ones it pushes for zippie -
        # `announceToken` and `ddClientToken` - are credentials.
        "announceToken", "announce_token", "ddClientToken", "dd_client_token",
    ],
)
def test_every_named_secret_is_dropped(field):
    stream = io.StringIO()
    telemetry.configure_logging(stream)
    telemetry.event("something happened", **{field: "s3cret-value"})
    assert "s3cret-value" not in stream.getvalue()


@pytest.mark.parametrize("field", ["value", "values"])
def test_a_bare_configuration_value_is_dropped_whatever_it_is_called(field):
    """A CONFIGURATION VALUE IS A CREDENTIAL UNTIL PROVEN OTHERWISE.

    muster cannot know which of another app's keys are secret - `announceToken`
    is, `ddSite` is not, and the next app draws that line somewhere else. A
    list of the key names we happen to know today is a list that rots silently
    the first time somebody adds a key; refusing the FIELD a value would arrive
    in does not, because there is nowhere else for one to go.
    """
    stream = io.StringIO()
    telemetry.configure_logging(stream)
    telemetry.event("app configured", package="app.zippie.companion",
                    **{field: "zk_live_7f3a91c4e08b46d2a5"})

    written = stream.getvalue()
    assert "zk_live_7f3a91c4e08b46d2a5" not in written
    payload = json.loads(written)
    assert payload["package"] == "app.zippie.companion", "the useful field survived"
    assert payload["redacted"] == [field], "the drop is recorded, not silent"


@pytest.mark.parametrize(
    "field",
    ["config", "configuration", "content", "contents", "file", "files", "payload", "body"],
)
def test_a_configuration_in_flight_to_a_device_is_dropped(field):
    """THE SAME RULE, NOW THAT CONFIGURATION TRAVELS OVER HTTP (muster#46).

    A device fetches its own `app-config` file, so the whole credential-bearing
    file is a string in this process and one f-string away from a log line. The
    field it would arrive in has an obvious name and none of them is safe, so
    they are refused - and the fix at the call site is to name the field for the
    safe thing being logged, which is `file_names` and which a reviewer can see.
    """
    stream = io.StringIO()
    telemetry.configure_logging(stream)
    telemetry.event(
        "device configuration served",
        key_id="a" * 64,
        **{field: "set app.zippie.companion announceToken zk_live_7f3a91c4e08b46d2a5"},
    )

    written = stream.getvalue()
    assert "zk_live_7f3a91c4e08b46d2a5" not in written
    payload = json.loads(written)
    assert payload["key_id"] == "a" * 64, "the useful field survived"
    assert payload["redacted"] == [field], "the drop is recorded, not silent"


def test_the_names_of_the_files_served_are_not_dropped():
    """The other half. A guard that also swallowed `file_names` would leave a
    fetch unanswerable - "which configuration did this device get" is the first
    question anybody asks about a device that came up wrong."""
    stream = io.StringIO()
    telemetry.configure_logging(stream)
    telemetry.event(
        "device configuration served",
        revision="deadbeef",
        file_names=["app-config", "restrictions"],
    )
    payload = json.loads(stream.getvalue())
    assert payload["file_names"] == ["app-config", "restrictions"]
    assert "redacted" not in payload


def test_a_failing_socket_never_breaks_a_request(monkeypatch):
    """A metric is not worth a 500 on the endpoint a device in a hotel is
    trying to reach. The emitter must swallow the error and carry on."""
    live = telemetry.Telemetry(host="203.0.113.1")

    class Broken:
        def sendto(self, *_args):
            raise OSError("network is unreachable")

        def close(self):
            pass

    monkeypatch.setattr(socket, "socket", lambda *a, **k: Broken())
    live.count("enroll.code.minted")          # must not raise
    live.gauge("whatever", 1.0)
    live.timing("whatever", 12.5)
    with live.timed("whatever"):
        pass


def test_an_exception_inside_timed_is_still_timed(emitter):
    """The failing case is the one worth timing: a CA call that has started
    taking seconds is a problem before it starts erroring."""
    with pytest.raises(ValueError):
        with emitter.timed("ca.issue.duration"):
            raise ValueError("boom")
    assert any("ca.issue.duration" in line for line in emitter.sent)


# ---- the wire format -----------------------------------------------------


def test_the_line_is_dogstatsd(emitter):
    emitter.count("enroll.code.minted")
    assert emitter.sent == ["custom.muster.enroll.code.minted:1|c"]


def test_tags_are_appended_in_dogstatsd_form(emitter):
    emitter.count("enroll.vouch.refused", tags=["reason:fingerprint-mismatch"])
    assert emitter.sent == [
        "custom.muster.enroll.vouch.refused:1|c|#reason:fingerprint-mismatch"
    ]


def test_env_and_service_tags_ride_on_every_metric(monkeypatch):
    monkeypatch.setenv("DD_ENV", "prod")
    monkeypatch.setenv("DD_SERVICE", "muster")
    monkeypatch.delenv("DD_AGENT_HOST", raising=False)
    built = telemetry.Telemetry.from_env()
    built.count("enroll.code.minted")
    assert built.sent == ["custom.muster.enroll.code.minted:1|c|#env:prod,service:muster"]


def test_no_agent_host_means_disabled_not_broken(monkeypatch):
    """Runnable by somebody who has never heard of Datadog. This has to stay a
    supported mode rather than an error, or the tests and a laptop both fail."""
    monkeypatch.delenv("DD_AGENT_HOST", raising=False)
    built = telemetry.Telemetry.from_env()
    assert built.enabled is False
    built.count("enroll.code.minted")           # records, sends nothing
    assert built.sent


def test_the_prefix_is_custom_muster(emitter):
    """`custom.` separates what this estate emits from what an integration
    invented, and matches custom.zippie."""
    emitter.gauge("anything", 1)
    assert emitter.sent[0].startswith("custom.muster.")


# ---- the log format ------------------------------------------------------


def test_a_log_line_is_one_json_object(monkeypatch):
    """The agent collects these with source:python, so structure here is the
    difference between a facet and a grep somebody invents under pressure."""
    monkeypatch.setenv("DD_SERVICE", "muster")
    stream = io.StringIO()
    telemetry.configure_logging(stream)
    telemetry.event("certificate issued", serial="ab12", device_name="pixel-6a")

    payload = json.loads(stream.getvalue())
    assert payload["message"] == "certificate issued"
    assert payload["level"] == "INFO"
    assert payload["service"] == "muster"
    assert payload["serial"] == "ab12"
    assert payload["timestamp"].endswith("Z")


def test_logging_is_not_duplicated_by_the_root_logger():
    """propagate=False, or every line appears twice - once as JSON here and
    once as plain text through the root handler."""
    stream = io.StringIO()
    telemetry.configure_logging(stream)
    telemetry.event("once")
    assert stream.getvalue().count('"message":"once"') == 1


def test_uvicorn_logs_are_json_too(monkeypatch):
    """Half a stream in JSON and half in uvicorn's default text is worse than
    either alone: the status code and path - where "what is failing" lives -
    stay a string nobody can facet on while everything around them is
    structured."""
    stream = io.StringIO()
    telemetry.configure_logging(stream)

    import logging
    logging.getLogger("uvicorn.access").info('%s - "%s %s" %d', "10.0.0.1", "GET", "/readyz", 200)

    payload = json.loads(stream.getvalue())
    assert payload["message"] == '10.0.0.1 - "GET /readyz" 200'
    assert payload["level"] == "INFO"


def test_uvicorn_logs_are_not_duplicated():
    stream = io.StringIO()
    telemetry.configure_logging(stream)
    import logging
    logging.getLogger("uvicorn.error").info("started")
    assert stream.getvalue().count('"message":"started"') == 1
