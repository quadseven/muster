"""What muster tells Datadog about itself.

TWO RULES SHAPE EVERYTHING HERE.

**Nothing secret is ever emitted.** This process holds the CA private key and
hands out pairing codes, and a metric tag or a log line is the easiest way for
either to end up somewhere it cannot be deleted from. So: a pairing code is
NEVER a tag, a value, or a log field - not even truncated, because a 6-digit
code has 10^6 possibilities and a prefix narrows that to something a script can
walk while the code is still alive. The admin token is never touched at all.
Fingerprints ARE emitted: they exist to be read aloud off two screens, so they
are not secret, and they are the only way to follow one device through a log.

**Absent telemetry must never take the service down.** A control plane that
stops issuing certificates because a metrics socket went away has traded a
working estate for a graph. Every send is wrapped, DogStatsD is UDP (fire and
forget, no connect, no retry), and with no DD_AGENT_HOST this whole module is a
no-op that still lets the tests assert what WOULD have been sent.

WHY STDLIB UDP AND NOT THE datadog PACKAGE. The image installs fastapi and
cryptography and nothing else it does not need; a dependency added to the
process that signs certificates is a dependency in the blast radius of the CA.
DogStatsD is a line-oriented text protocol over UDP - `name:value|type|#tags` -
so the whole client is the twenty lines below. zippie's telemetry.py reached the
same conclusion for the same reason.

WHY THE REFUSAL REASON IS A TAG. "Devices are failing to enroll" is not an
answerable question without it: a code that expired, a code that was already
used, a wrong guess, and a fingerprint mismatch are four completely different
problems - the last one is somebody enrolling against your code, and it is the
one that must never be lost in a total. The reasons are a closed set (api._STATUS
and proof.Verdict), so tagging by them cannot explode cardinality.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import sys
import time
from contextlib import contextmanager

# custom.muster, matching custom.zippie. The `custom.` prefix is what separates
# metrics this estate emits from ones an integration invented.
PREFIX = "custom.muster"

log = logging.getLogger("muster")


def configure_logging(stream=None) -> None:
    """One JSON object per line on stdout, which is what the agent collects.

    JSON rather than a human format because the ad.datadoghq.com/*.logs
    annotation declares `"source":"python"`, and a structured line arrives with
    its fields already facets - so `status:refused reason:fingerprint-mismatch`
    is a filter rather than a grep somebody has to invent under pressure.
    """
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(_JsonFormatter())
    level = os.environ.get("MUSTER_LOG_LEVEL", "INFO").upper()

    # UVICORN'S LOGGERS TOO, not just muster's. Half a log stream in JSON and
    # half in uvicorn's default text is worse than either alone: the HTTP status
    # code and path - which is where "what is actually failing" lives - stay a
    # string nobody can facet on, while everything around them is structured.
    # uvicorn.access is the one that matters; uvicorn.error carries startup and
    # shutdown, which is where a crash loop explains itself.
    for name in ("muster", "uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers[:] = [handler]
        logger.setLevel(level)
        # Do not ALSO emit through the root logger's handler, or every line is
        # duplicated: once as JSON here and once as plain text there.
        logger.propagate = False


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)
            ),
            "level": record.levelname,
            "service": os.environ.get("DD_SERVICE", "muster"),
            "message": record.getMessage(),
        }
        # Anything passed as extra={...}, so a call site adds a field without
        # this formatter having to know about it.
        for key, value in getattr(record, "fields", {}).items():
            payload[key] = value
        if record.exc_info:
            payload["error"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)


class Telemetry:
    """DogStatsD over UDP to the node-local agent.

    `host` empty disables everything. That is the default in tests and on a
    laptop, and it must stay a supported mode rather than an error: muster has
    to be runnable by somebody who has never heard of Datadog.
    """

    def __init__(
        self,
        host: str = "",
        port: int = 8125,
        extra_tags: list[str] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.extra_tags = list(extra_tags or [])
        self._sock: socket.socket | None = None
        self.sent: list[str] = []          # what WOULD go out; the test seam
        self._record_only = not host

    @classmethod
    def from_env(cls) -> "Telemetry":
        tags = []
        if env := os.environ.get("DD_ENV"):
            tags.append(f"env:{env}")
        if service := os.environ.get("DD_SERVICE"):
            tags.append(f"service:{service}")
        return cls(host=os.environ.get("DD_AGENT_HOST", ""), extra_tags=tags)

    @property
    def enabled(self) -> bool:
        return not self._record_only

    def count(self, name: str, value: int = 1, tags: list[str] | None = None) -> None:
        self._send(f"{PREFIX}.{name}:{value}|c", tags)

    def gauge(self, name: str, value: float, tags: list[str] | None = None) -> None:
        self._send(f"{PREFIX}.{name}:{value}|g", tags)

    def timing(self, name: str, ms: float, tags: list[str] | None = None) -> None:
        self._send(f"{PREFIX}.{name}:{ms:.3f}|ms", tags)

    @contextmanager
    def timed(self, name: str, tags: list[str] | None = None):
        """Wall time for an operation, emitted even when it raises.

        The failing case is the one worth timing: a CA signing call that has
        started taking seconds is a problem long before it starts erroring.
        """
        started = time.monotonic()
        try:
            yield
        finally:
            self.timing(name, (time.monotonic() - started) * 1000.0, tags)

    def _send(self, line: str, tags: list[str] | None) -> None:
        all_tags = self.extra_tags + list(tags or [])
        if all_tags:
            line = f"{line}|#{','.join(all_tags)}"
        # Recorded whether or not it is sent, so a test can assert the metric a
        # code path emits without needing a socket or an agent.
        self.sent.append(line)
        if self._record_only:
            return
        try:
            if self._sock is None:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.sendto(line.encode(), (self.host, self.port))
        except OSError as exc:
            # Never raise into a request. A metric is not worth a 500 on the one
            # endpoint a device in a hotel is trying to reach.
            self._sock = None
            log.debug("dogstatsd send failed: %s", exc)

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None


def event(message: str, **fields) -> None:
    """A structured log line, with anything secret dropped before it is written.

    The guard is here rather than at each call site on purpose. There are a
    dozen places that could log a code and only one that has to be right, and a
    reviewer checking that no call site passes `code=` is doing a job a function
    can do once. See the module docstring for why a truncated code is not a
    compromise worth taking.

    What was dropped is REPORTED rather than hidden: `redacted` names the
    fields, so a call site quietly losing a field it thought it was logging is
    visible in the log itself.
    """
    safe = {k: v for k, v in fields.items() if k not in _NEVER_LOG}
    if len(safe) != len(fields):
        safe["redacted"] = sorted(set(fields) - set(safe))
    log.info(message, extra={"fields": safe})


# A CONFIGURATION VALUE IS A CREDENTIAL UNTIL PROVEN OTHERWISE, which is why
# the bare `value`/`values` are here alongside the named tokens. muster pushes
# managed application configuration to other apps (`cli.py app-config`), and it
# cannot know which of another app's keys are secret - `announceToken` and
# `ddClientToken` are, `ddSite` is not, and the next app will draw that line
# somewhere else. Naming only the keys we happen to know about today is a list
# that rots silently; refusing the field a value would arrive in does not.
#
# THE SAME CONFIGURATION NOW TRAVELS OVER HTTP (muster#46, muster/policy.py),
# which is what the second group below is for. A device fetches its own
# `app-config` file, so the whole credential-bearing file is a string in this
# process, one f-string away from a log line - and the obvious names for the
# field it would arrive in are `files`, `content` and `config`. Refused for the
# same reason as `value`: the fix is to name the field for the safe thing being
# logged (`file_names`), which is a rename a reviewer can see, rather than to
# trust that nobody ever passes the wrong one.
_NEVER_LOG = frozenset(
    {
        "code",
        "pairing_code",
        "token",
        "admin_token",
        "secret",
        "value",
        "values",
        "announce_token",
        "announceToken",
        "dd_client_token",
        "ddClientToken",
        # Configuration in flight to a device.
        "config",
        "configuration",
        "content",
        "contents",
        "file",
        "files",
        "payload",
        "body",
    }
)
