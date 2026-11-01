"""Device standing: every verb from every state, written down as one table.

THE LITERALS ARE THE POINT. A device holds one of four standings (active,
revoked, erase queued, erase queued over a lifted revocation), each with or
without a reboot waiting, so there are eight states. Eight verbs reach them.
`TRANSITIONS` states what each pair does today, read from the code and D29 and
D30, and the tests walk it through the routes and through `Kith`, on both
Records adapters when a database is available.

A cell is the state afterwards, or the status a route refuses with.

    A    active                 R    revoked
    Q    erase queued           QR   erase queued over a lifted revocation
    +B   a reboot is waiting
    *    this verb stamped that time; without it the earlier time stands

An erase queued over a revocation reads the same as a plain one, because no
read returns the revocation set aside. It is told apart the only way a caller
can: by calling the erase off and seeing what comes back.
"""
from __future__ import annotations

import base64
import datetime as dt
import os
import secrets
from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from muster import kith as kith_store
from muster import policy, standing
from muster.enroll import fingerprint, key_id
from muster.kith import Certificate, Device, Kith, MemoryRecords
from tests.test_api import (
    ADMIN,
    _collect_identity,
    _enrolled_device,
    _fetch_config,
    _kith_state,
    _published_and_proving,
)

START = dt.datetime(2026, 8, 19, 12, 0, tzinfo=dt.timezone.utc)

VERBS = (
    "revoke", "readmit", "wipe", "call_off_wipe",
    "reboot", "call_off_reboot", "ack_wipe", "ack_reboot",
)

# How each state is reached, using only verbs: nothing writes a column.
RECIPES = {
    "A": (),
    "R": ("revoke",),
    "Q": ("wipe",),
    "QR": ("revoke", "wipe"),
    "A+B": ("reboot",),
    "R+B": ("reboot", "revoke"),
    "Q+B": ("wipe", "reboot"),
    "QR+B": ("revoke", "wipe", "reboot"),
}

_ROWS = {
    #        revoke    readmit  wipe     call_off_wipe  reboot   call_off_reboot  ack_wipe  ack_reboot
    "A":    ("R*",     "A",     "Q*",    "A",           "A+B*",  "A",             409,      409),
    "R":    ("R*",     "A",     "QR*",   "R",           409,     "R",             403,      403),
    "Q":    ("R*",     "A",     "Q*",    "A",           "Q+B*",  "Q",             "R*",     409),
    "QR":   ("R*",     "A",     "QR*",   "R",           "QR+B*", "QR",            "R*",     409),
    "A+B":  ("R*+B",   "A+B",   "Q*+B",  "A+B",         "A+B*",  "A",             409,      "A"),
    "R+B":  ("R*+B",   "A+B",   "QR*+B", "R+B",         409,     "R",             403,      403),
    "Q+B":  ("R*+B",   "A+B",   "Q*+B",  "A+B",         "Q+B*",  "Q",             "R*+B",   "Q"),
    "QR+B": ("R*+B",   "A+B",   "QR*+B", "R+B",         "QR+B*", "QR",            "R*+B",   "QR"),
}

TRANSITIONS = {
    (state, verb): row[index]
    for state, row in _ROWS.items()
    for index, verb in enumerate(VERBS)
}

# WHAT `Kith` DOES WHEN THE ROUTE IN FRONT OF IT IS NOT THERE. Three cells differ
# because the refusal lives above this seam today: `_proven_device` stops a
# revoked device, and the reboot route refuses to arm one. Worth pinning, because
# anything that moves those checks has to move them on purpose.
PAST_THE_ROUTES = {
    ("R", "reboot"): "R+B*",
    ("R+B", "reboot"): "R+B*",
    ("R+B", "ack_reboot"): "R",
}

# What each state is answered on the device channel: a status, then the files
# that matter. An erase answers alone and needs no policy directory (D29); a
# reboot joins the ordinary answer (D30).
SERVED = {
    "A": (200, {"restrictions"}),
    "R": (403, None),
    "Q": (200, {policy.WIPE_FILE}),
    "QR": (200, {policy.WIPE_FILE}),
    "A+B": (200, {"restrictions", policy.REBOOT_FILE}),
    "R+B": (403, None),
    "Q+B": (200, {policy.WIPE_FILE}),
    "QR+B": (200, {policy.WIPE_FILE}),
}

ALL_PAIRS = list(TRANSITIONS)


class Ticking:
    """A clock that moves on every read, so each stamp names its own verb."""

    def __init__(self) -> None:
        self.t = START

    def __call__(self) -> dt.datetime:
        self.t += dt.timedelta(seconds=1)
        return self.t


@dataclass(frozen=True)
class Seen:
    """What a caller can read of a device's standing."""

    revoked_at: dt.datetime | None
    wipe_at: dt.datetime | None
    reboot_at: dt.datetime | None
    restored_at: dt.datetime | None  # what calling the erase off brought back


def _render(seen: Seen, original: dt.datetime | None, since: dt.datetime) -> str:
    """One state in the table's notation.

    `original` is the revocation the setup made. A revocation this verb did not
    stamp must still carry that exact time, so a restored one is checked too.
    """
    def star(stamp) -> str:
        return "*" if stamp >= since else ""

    if seen.wipe_at is not None:
        assert seen.revoked_at is None, "an erase left the device refused (D29)"
        assert seen.restored_at in (None, original)
        lifted = seen.restored_at is not None
        standing = ("QR" if lifted else "Q") + star(seen.wipe_at)
    elif seen.revoked_at is not None:
        assert seen.revoked_at >= since or seen.revoked_at == original
        standing = "R" + star(seen.revoked_at)
    else:
        standing = "A"
    return standing + ("" if seen.reboot_at is None else "+B" + star(seen.reboot_at))


# ---- at the module's own interface ------------------------------------------


def _device_in(state: str) -> Device:
    """A row in `state`, written directly: this seam takes a row and no store."""
    at = START
    return Device(
        key_id="k",
        fingerprint="f",
        name="n",
        first_seen=at,
        last_seen=at,
        revoked_at=at if state.startswith("R") else None,
        wipe_pending_at=at if state.startswith("Q") else None,
        reboot_requested_at=at if state.endswith("+B") else None,
    )


@pytest.mark.parametrize("state", sorted(SERVED))
def test_served_answers_the_device_channel_table(state):
    status, files = SERVED[state]
    answer = standing.served(_device_in(state))

    assert answer.refused is (status == 403)
    if files is not None:
        assert answer.wipe is (policy.WIPE_FILE in files)
        assert answer.reboot is ("+B" in state)


@pytest.mark.parametrize(
    "name,verb",
    [
        ("reboot", standing.Verb.REBOOT),
        ("ack_wipe", standing.Verb.ACKNOWLEDGE_WIPE),
        ("ack_reboot", standing.Verb.ACKNOWLEDGE_REBOOT),
    ],
)
@pytest.mark.parametrize("state", sorted(SERVED))
def test_permits_answers_the_transition_table(state, name, verb):
    cell = TRANSITIONS[state, name]
    answer = standing.permits(_device_in(state), verb)

    if cell == 409:
        assert answer is False
    elif isinstance(cell, str):
        assert answer is True


def test_a_key_with_no_row_may_acknowledge_nothing():
    assert standing.permits(None, standing.Verb.ACKNOWLEDGE_WIPE) is False
    assert standing.permits(None, standing.Verb.ACKNOWLEDGE_REBOOT) is False
    assert standing.permits(None, standing.Verb.REBOOT) is True


# ---- through Kith, on each Records adapter ---------------------------------

_LIVE_DSN = os.environ.get("MUSTER_TEST_DATABASE_URL", "").strip()


@pytest.fixture(params=["memory", "postgres"])
def held(request):
    """A device held by a `Kith` on one adapter, removed again afterwards."""
    public = secrets.token_bytes(32)
    device = Device(
        key_id=key_id(public),
        fingerprint=fingerprint(public),
        name="Pixel 6a",
        first_seen=START,
        last_seen=START,
    )
    certificate = Certificate(
        serial=secrets.token_hex(8).upper(),
        request_id=secrets.token_hex(8),
        not_before=START,
        not_after=START + dt.timedelta(days=90),
        issued_at=START,
        certificate_pem="not a real certificate",
    )
    if request.param == "memory":
        records = MemoryRecords()
    elif _LIVE_DSN:
        records = kith_store.PostgresRecords(_LIVE_DSN)
    else:
        pytest.skip("MUSTER_TEST_DATABASE_URL is not set")
    clock = Ticking()
    kith = Kith(records, clock=clock)
    kith.issued(device, certificate)
    yield kith, device.key_id, clock
    if request.param == "postgres":
        import psycopg

        with psycopg.connect(_LIVE_DSN) as connection:
            connection.execute(
                "DELETE FROM kith_certificate WHERE key_id = %s", (device.key_id,)
            )
            connection.execute(
                "DELETE FROM kith_device WHERE key_id = %s", (device.key_id,)
            )


def _on_kith(kith: Kith, key: str, verb: str) -> bool:
    return {
        "revoke": lambda: kith.set_revoked(key, True),
        "readmit": lambda: kith.set_revoked(key, False),
        "wipe": lambda: kith.set_wipe_pending(key, True),
        "call_off_wipe": lambda: kith.set_wipe_pending(key, False),
        "reboot": lambda: kith.set_reboot_requested(key, True),
        "call_off_reboot": lambda: kith.set_reboot_requested(key, False),
        "ack_wipe": lambda: kith.acknowledged_wipe(key),
        "ack_reboot": lambda: kith.acknowledged_reboot(key),
    }[verb]()


def _end_on_kith(kith: Kith, key: str) -> Seen:
    """Read the state, then call off any erase to learn what it had set aside."""
    device = kith.member(key).device
    restored = None
    if device.wipe_pending_at is not None:
        kith.set_wipe_pending(key, False)
        restored = kith.member(key).device.revoked_at
    return Seen(
        device.revoked_at,
        device.wipe_pending_at,
        device.reboot_requested_at,
        restored,
    )


@pytest.mark.parametrize("state,verb", ALL_PAIRS)
def test_every_verb_from_every_state_through_kith(held, state, verb):
    kith, key, clock = held
    original = None
    for step in RECIPES[state]:
        assert _on_kith(kith, key, step)
        original = original or kith.member(key).device.revoked_at
    since = clock() + dt.timedelta(seconds=1)

    expected = PAST_THE_ROUTES.get((state, verb), TRANSITIONS[state, verb])
    answered = _on_kith(kith, key, verb)

    assert answered is not isinstance(expected, int)
    ended = state if isinstance(expected, int) else expected
    assert _render(_end_on_kith(kith, key), original, since) == ended


@pytest.mark.parametrize("verb", VERBS)
def test_no_verb_invents_a_device(held, verb):
    kith, _key, _clock = held
    assert _on_kith(kith, "no-such-key", verb) is False
    assert kith.member("no-such-key") is None


# ---- through the routes ----------------------------------------------------


@dataclass(frozen=True)
class Enrolled:
    client: object
    key: str
    device_key: object
    identity: object
    clock: Ticking


@pytest.fixture()
def enrolled(tmp_path):
    """A really-enrolled device whose kith stamps a new time on every write."""
    root = tmp_path / "policy"
    root.mkdir()
    (root / "kith.restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    clock = Ticking()
    state, _records = _kith_state(clock_=clock)
    state.policies = policy.Policies(root=root)
    client, _apk = _published_and_proving(state, tmp_path)
    key, device_key = _enrolled_device(client, state, tmp_path)
    return Enrolled(client, key, device_key, _collect_identity(client, state), clock)


def _proof(enrolled: Enrolled) -> dict:
    nonce = enrolled.client.post("/v1/auth/challenge", json={}).json()["nonce"]
    return {
        "nonce": nonce,
        "signature_b64": base64.b64encode(
            enrolled.device_key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))
        ).decode(),
        "certificate_pem": enrolled.identity.certificate_pem.decode(),
    }


def _on_route(enrolled: Enrolled, verb: str):
    client = enrolled.client
    if verb == "ack_wipe":
        return client.post("/v1/device/wipe", json=_proof(enrolled))
    if verb == "ack_reboot":
        return client.post("/v1/device/reboot", json=_proof(enrolled))
    path, body = {
        "revoke": ("revoke", {"revoked": True}),
        "readmit": ("revoke", {"revoked": False}),
        "wipe": ("wipe", {"wipe": True}),
        "call_off_wipe": ("wipe", {"wipe": False}),
        "reboot": ("reboot", {"reboot": True}),
        "call_off_reboot": ("reboot", {"reboot": False}),
    }[verb]
    return client.post(f"/v1/kith/{enrolled.key}/{path}", json=body, cookies=ADMIN)


def _stamp(value: str | None) -> dt.datetime | None:
    return None if value is None else dt.datetime.fromisoformat(value)


def _device_view(enrolled: Enrolled) -> dict:
    path = f"/v1/kith/{enrolled.key}"
    return enrolled.client.get(path, cookies=ADMIN).json()["device"]


def _end_on_route(enrolled: Enrolled) -> Seen:
    """Read the state, then call off any erase to learn what it had set aside."""
    device = _device_view(enrolled)
    restored = None
    if device["wipe_pending_at"] is not None:
        assert _on_route(enrolled, "call_off_wipe").status_code == 200
        restored = _stamp(_device_view(enrolled)["revoked_at"])
    return Seen(
        _stamp(device["revoked_at"]),
        _stamp(device["wipe_pending_at"]),
        _stamp(device["reboot_requested_at"]),
        restored,
    )


def _in_state(enrolled: Enrolled, state: str) -> tuple[dt.datetime | None, dt.datetime]:
    """Drive the device there. Returns its revocation, and when the setup ended."""
    original = None
    for step in RECIPES[state]:
        assert _on_route(enrolled, step).status_code == 200
        original = original or _stamp(_device_view(enrolled)["revoked_at"])
    return original, enrolled.clock() + dt.timedelta(seconds=1)


@pytest.mark.parametrize("state,verb", ALL_PAIRS)
def test_every_verb_from_every_state_through_the_routes(enrolled, state, verb):
    original, since = _in_state(enrolled, state)
    expected = TRANSITIONS[state, verb]

    response = _on_route(enrolled, verb)

    refused = isinstance(expected, int)
    assert response.status_code == (expected if refused else 200)
    ended = state if refused else expected
    assert _render(_end_on_route(enrolled), original, since) == ended


@pytest.mark.parametrize("state", sorted(SERVED))
def test_what_each_state_is_served(enrolled, state):
    _in_state(enrolled, state)
    status, files = SERVED[state]

    response = _fetch_config(enrolled.client, enrolled.device_key, enrolled.identity)

    assert response.status_code == status
    if files is not None:
        assert set(response.json()["files"]) == files
