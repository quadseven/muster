"""No hostname in this repo may name a host somebody actually runs.

WHY THIS EXISTS. A public-readiness scrub ran over this repo once and caught
the credentials - Cognito IDs, the tunnel ID, the registry password, device
serials. It missed the topology, and the operator's real zone survived it in 42
places across ten files: the enrollment endpoint in tests and docs, and the CA
subject line. A one-time scrub cannot see the next pull request, so the class
is pinned here rather than cleaned twice.

THE RULE IS AN ALLOWLIST, NOT A DENYLIST. A denylist of "hosts we know are
private" only ever knows about the leak that already happened; the next one is
by definition not on it. So every hostname-shaped token in the tree must be
reserved documentation space, a literal address, cluster-internal, or on the
reviewed list of vendor hosts below.

IT MUST CATCH BARE HOSTNAMES, NOT JUST URLs. The first draft of this guard
matched only `https?://host`, and it PASSED when the pre-scrub value was put
back - because three of the real occurrences were bare `enroll.<zone>` in
backticks and one was a `CN=` subject line, none of them URLs. A guard that
only sees the shape the leak did not take is a guard that reports clean.

NOT A SECRET TABLE. Nothing here names the operator's estate: it lists what is
PERMITTED, and every control string below is synthetic. A guard that hunts a
private hostname by embedding that hostname publishes it on the first push.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

# A dotted token is treated as a hostname when its LAST label is one of these.
#
# DELIBERATELY OMITTED, because they collide with ordinary code and filenames
# far more often than they would ever carry a leak: `info` (logging.info), `run`
# (subprocess.run, asyncio.run), `ca` (this project's own muster.ca module),
# `sh` and `zip` (filenames), `mov`, `to`, `co`. Each omission is a hole; each
# inclusion would be noise that gets the whole guard switched off. The TLDs that
# actually carry personal domains are all present.
HOST_TLDS = frozenset(
    """
    com net org io me dev app casa xyz cloud tech live site online
    link page ai gg tv fm eu de uk us fr nl ca_intentionally_absent
    """.split()
) - {"ca_intentionally_absent"}

# A dotted token STARTING with one of these is a package or namespace, not a
# host: `java.io`, `com.google.android`, `org.junit.Test`. The discriminator is
# position - a TLD is last in a hostname and first in a reverse-DNS package.
PACKAGE_ROOTS = frozenset(
    "java javax kotlin kotlinx android androidx com org net io app de sun jdk".split()
)

# Hosts that are fine to name in a public repo, plus the handful of dotted code
# tokens that survive the rules above. Every entry is reviewed; adding one is a
# deliberate line in a diff.
ALLOWED = frozenset(
    {
        # vendor / package infrastructure
        "ad.datadoghq.com",
        "api.cloudflare.com",
        "api.nextdns.io",
        "datadoghq.eu",
        "developers.google.com",
        "files.pythonhosted.org",
        "ghcr.io",
        "github.com",
        "kubectl.kubernetes.io",
        "pypi.org",
        "schemas.android.com",
        "services.gradle.org",
        "support.google.com",
        "tags.datadoghq.com",
        "www.apache.org",
        # RFC 2606 documentation domain, explicitly fine
        "example.com",
        # not a host: attribute access that happens to end in a TLD
        "client.app",
    }
)

RESERVED = re.compile(
    # Anchored to the end of a label so `.example` does not also match the
    # perfectly real `host.example-corp.net` - a hyphen is a word boundary, and
    # a guard that rejects real hostnames is a guard somebody switches off.
    r"\.(?:example|test|invalid|localhost)$"
    r"|^localhost$"
    r"|\.svc\.cluster\.local$"
    r"|\.internal$",
    re.IGNORECASE,
)

LITERAL_ADDRESS = re.compile(
    r"^(?:"
    r"127\.[0-9.]+|0\.0\.0\.0|\[?::1\]?"
    r"|10\.[0-9.]+"
    r"|192\.168\.[0-9.]+"
    r"|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9.]+"
    r"|192\.0\.2\.[0-9]+|198\.51\.100\.[0-9]+|203\.0\.113\.[0-9]+"
    r"|224\.0\.0\.[0-9]+"
    r")$"
)

# Maximal dotted run, so `org.apache.commons.util.io` is judged by `org`
# (a package root) rather than by its `util.io` tail.
TOKEN = re.compile(
    r"(?<![A-Za-z0-9._-])[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+(?![A-Za-z0-9._-])"
)

SKIP_SUFFIX = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".jar", ".keystore"}


def is_allowed(token: str) -> bool:
    """True if `token` is safe to name in a public repo."""
    host = token.lower().rstrip(".")
    labels = host.split(".")
    if len(labels) < 2:
        return True
    if labels[-1] not in HOST_TLDS:
        # Not hostname-shaped at all: a filename, a method call, a package.
        return True
    if labels[0] in PACKAGE_ROOTS:
        return True
    return (
        host in ALLOWED
        or bool(RESERVED.search(host))
        or bool(LITERAL_ADDRESS.match(host))
    )


def _repo_root() -> Path:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=Path(__file__).parent, capture_output=True, text=True, check=True,
    )
    return Path(out.stdout.strip())


# --------------------------------------------------------------------------
# The detector's own proof. SYNTHETIC hosts only - this file never contains the
# thing it defends against.
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "host",
    [
        "enroll.some-operator.casa",   # the exact shape that survived the scrub
        "registry.ts.some-handle.me",  # a personal tailnet name
        "control.example-operator.io",
        "someones-box.dev",
    ],
)
def test_a_live_looking_host_is_refused(host: str) -> None:
    assert not is_allowed(host), f"{host} must be refused - it names a real box"


@pytest.mark.parametrize(
    "token",
    [
        "enroll.muster.example",
        "identity.example.test",
        "thing.example.invalid",
        "localhost",
        "127.0.0.1",
        "10.0.0.5",
        "muster.muster.svc.cluster.local",
        "files.pythonhosted.org",
        "github.com",
        # dotted code tokens that must never be findings
        "java.io.File",
        "com.google.android.thing",
        "app.muster.agent",
        "logging.info",
        "subprocess.run",
        "muster.ca",
        "build.gradle.kts",
    ],
)
def test_a_safe_token_is_permitted(token: str) -> None:
    assert is_allowed(token), f"{token} must be permitted"


def test_reserved_tld_is_anchored_to_a_label() -> None:
    """`.example` must not match `example-corp.net`, or the guard is unusable."""
    assert not is_allowed("host.example-corp.net")


def test_the_detector_catches_a_bare_hostname_not_only_a_url() -> None:
    """The bug the first draft of this guard had, pinned so it cannot return."""
    assert not is_allowed("enroll.some-operator.casa")


# --------------------------------------------------------------------------
# The scan itself.
# --------------------------------------------------------------------------
def test_no_tracked_file_names_a_live_host() -> None:
    root = _repo_root()
    files = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True
    ).stdout.decode().split("\0")

    # THIS FILE EXCLUDES ITSELF, and it has to. Its must-catch controls are
    # live-looking hostnames by construction, so scanning itself makes the guard
    # fail on the very strings that prove it works. Found the honest way: the
    # first push went red in CI, because a local run had scanned the file while
    # it was still untracked and `git ls-files` could not see it.
    me = str(Path(__file__).resolve().relative_to(root))

    offenders: list[str] = []
    read = 0
    for rel in files:
        if not rel or rel == me or Path(rel).suffix.lower() in SKIP_SUFFIX:
            continue
        try:
            text = (root / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        read += 1
        for lineno, line in enumerate(text.splitlines(), 1):
            for token in TOKEN.findall(line):
                if not is_allowed(token):
                    offenders.append(f"{rel}:{lineno}: {token}")

    # A SCAN THAT READ NOTHING MUST NOT REPORT CLEAN. This test's whole value is
    # an absence, and an absence produced by reading zero files is not evidence.
    assert read > 50, (
        f"only {read} files were read - this scan did not see the tree, so its "
        "'clean' result means nothing. Refusing to pass."
    )

    assert not offenders, (
        "these tokens name hosts that are not documentation space:\n  "
        + "\n  ".join(offenders)
        + "\n\nUse RFC 2606 documentation space (.example / .test / .invalid) "
        "for anything a reader should substitute, or add a genuine vendor host "
        "to ALLOWED in this file with a reviewer looking at it."
    )
