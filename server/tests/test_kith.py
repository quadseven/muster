"""The kith as a record, and what it does when the record cannot be reached.

Two groups of tests, and they are testing opposite properties.

The first group is about IDENTITY: a device is its key, so a renewal has to land
on the device that already exists rather than beside it. Read
`test_a_renewal_updates_the_same_device` first - it is the reason the tables are
shaped the way they are, and the reason the device table is not keyed on the
certificate.

The second group is about AVAILABILITY, and it is the one that would be easy to
leave untested because everything in it is a failure path. muster holds a CA. If
a database outage stops it signing, devices stop renewing, and a device that
stops renewing LAPSES - which is not a retry, it is a human, a pairing code and,
on a Device Owner phone, a factory reset. So `test_issuing_carries_on_when_the
_store_is_down` is not an edge case; it is the property the store was allowed to
exist on condition of.
"""
from __future__ import annotations

import datetime as dt

import pytest

from muster import kith as kith_store
from muster.enroll import fingerprint, key_id
from muster.kith import Certificate, Device, Kith, MemoryRecords, Unreachable

START = dt.datetime(2026, 8, 19, 12, 0, tzinfo=dt.timezone.utc)


class Clock:
    """A clock a test can move, because every rule below is about time."""

    def __init__(self) -> None:
        self.t = START

    def __call__(self) -> dt.datetime:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += dt.timedelta(seconds=seconds)


class Breakable(MemoryRecords):
    """A real store that can be told to stop answering, and counts attempts.

    Subclasses MemoryRecords rather than faking the interface, so a test that
    breaks it and then mends it is checking that the SAME store recovers - which
    is what a database coming back looks like. Counting attempts is how the
    cooldown is tested at all: "it did not fail" and "it did not try" look
    identical from the outside.
    """

    def __init__(self) -> None:
        super().__init__()
        self.up = True
        self.attempts = 0

    def _check(self) -> None:
        self.attempts += 1
        if not self.up:
            raise OSError("connection refused")

    def describe(self) -> str:
        return "breakable"

    def record_issuance(self, device, certificate) -> None:
        self._check()
        super().record_issuance(device, certificate)

    def record_seen(self, key_id_, at) -> None:
        self._check()
        super().record_seen(key_id_, at)

    def record_collected(self, request_id, at) -> None:
        self._check()
        super().record_collected(request_id, at)

    def roll(self):
        self._check()
        return super().roll()

    def member(self, key_id_):
        self._check()
        return super().member(key_id_)

    def history(self, key_id_):
        self._check()
        return super().history(key_id_)

    def awaiting_collection(self, request_id):
        self._check()
        return super().awaiting_collection(request_id)


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def records():
    return Breakable()


@pytest.fixture()
def kith(records, clock):
    return Kith(records, clock=clock)


def a_device(key: bytes = b"device-one", name: str = "Pixel 6a", at=START) -> Device:
    return Device(
        key_id=key_id(key),
        fingerprint=fingerprint(key),
        name=name,
        first_seen=at,
        last_seen=at,
    )


def a_certificate(serial: str, request_id: str = "req-1", at=START) -> Certificate:
    return Certificate(
        serial=serial,
        request_id=request_id,
        not_before=at,
        not_after=at + dt.timedelta(days=90),
        issued_at=at,
        certificate_pem=f"-----BEGIN CERTIFICATE-----{serial}",
    )


# ---- identity: a device is its key --------------------------------------


def test_a_renewal_updates_the_same_device(kith, clock):
    """THE test for the shape of the tables.

    Renewal issues a NEW certificate to the SAME device: the device keeps the
    key it generated in its own hardware and asks for a fresh certificate over
    it. A store keyed on the certificate would answer "two devices" here, and
    the device list would silently become a certificate list - growing an extra
    phone every ninety days for a fleet that had not changed.
    """
    kith.issued(a_device(), a_certificate("AAAA", request_id="req-1"))

    clock.advance(60 * 60 * 24 * 60)  # sixty days later, renewal time
    kith.issued(
        a_device(at=clock()), a_certificate("BBBB", request_id="req-2", at=clock())
    )

    roll = kith.roll()
    assert len(roll) == 1, f"a renewal created a second device: {roll}"
    assert roll[0].certificates == 2
    assert roll[0].current_serial == "BBBB", "the newest certificate is the current one"

    serials = [c.serial for c in kith.history(roll[0].device.key_id)]
    assert serials == ["AAAA", "BBBB"], "the history is both certificates, in order"


def test_a_renewal_does_not_move_first_seen(kith, clock):
    """When a device joined the kith is not when it last renewed.

    Overwriting first_seen would make every device look like it enrolled at its
    most recent renewal, so the one column that answers "how long has this been
    here" would only ever say "about ninety days" for the whole estate.
    """
    kith.issued(a_device(), a_certificate("AAAA"))
    clock.advance(60 * 60 * 24 * 60)
    kith.issued(a_device(at=clock()), a_certificate("BBBB", at=clock()))

    device = kith.roll()[0].device
    assert device.first_seen == START
    assert device.last_seen == clock()


def test_a_new_key_is_a_new_device(kith):
    """A device that generates a fresh key has to be vouched for again.

    Not a limitation to work around - the same rule from the other end. The
    administrator vouched for a FINGERPRINT (CONTEXT.md), so a different key is
    something nobody has approved, and it must not inherit an existing device's
    row and its history.
    """
    kith.issued(a_device(key=b"device-one"), a_certificate("AAAA"))
    kith.issued(a_device(key=b"device-two"), a_certificate("BBBB", request_id="req-2"))

    assert len(kith.roll()) == 2


def test_the_short_fingerprint_is_a_rendering_of_the_key_id():
    """The console and the table must be talking about the same key.

    The fingerprint on screen is deliberately truncated so a human can read it
    aloud; the kith is keyed on the whole digest. If those two ever stopped
    being the same hash of the same bytes, an operator would search for what
    they read off a phone and find nothing.
    """
    key = b"some-public-key-der"
    assert fingerprint(key).replace(" ", "") == key_id(key).upper()[:16]


def test_replaying_a_write_does_not_duplicate_a_certificate(kith, records):
    """A deferred write may be applied twice; the record must not double.

    The backlog is replayed on recovery, and a drain that failed halfway can
    replay an entry the store had actually accepted. Making that free is why
    both implementations key certificates on the serial.
    """
    kith.issued(a_device(), a_certificate("AAAA"))
    records.record_issuance(a_device(), a_certificate("AAAA"))

    assert kith.roll()[0].certificates == 1


def test_certificate_status_follows_the_device_across_renewals(kith, clock):
    """Revocation is on the key, while relying parties ask about serials.

    Both issued certificates have to inherit the one device decision. Looking
    up only the current certificate would let an older, still-valid identity
    answer good after the administrator revoked the device that holds it.
    """
    kith.issued(a_device(), a_certificate("AAAA", request_id="req-1"))
    clock.advance(3600)
    kith.issued(
        a_device(at=clock()), a_certificate("BBBB", request_id="req-2", at=clock())
    )
    kith.set_revoked(key_id(b"device-one"), True)

    assert kith.certificate_status("AAAA").revoked_at == clock()
    assert kith.certificate_status("BBBB").revoked_at == clock()


def test_expired_certificates_drop_out_of_the_revocation_list(kith, clock):
    expired = a_certificate("AAAA")
    current = a_certificate(
        "BBBB", request_id="req-2", at=START + dt.timedelta(days=1)
    )
    kith.issued(a_device(), expired)
    kith.issued(a_device(at=current.issued_at), current)
    kith.set_revoked(key_id(b"device-one"), True)

    clock.t = expired.not_after

    assert [
        status.certificate.serial
        for status in kith.unexpired_revocations(clock())
    ] == ["BBBB"]


def test_last_seen_only_moves_forward(kith, clock):
    """A deferred touch that drains late must not drag last_seen backwards."""
    kith.issued(a_device(), a_certificate("AAAA"))
    clock.advance(3600)
    kith.seen(key_id(b"device-one"))
    later = clock()

    records_view = kith.roll()[0].device
    assert records_view.last_seen == later

    clock.t = START  # a stale entry, drained out of order
    kith.seen(key_id(b"device-one"))
    assert kith.roll()[0].device.last_seen == later


def test_a_proof_from_a_device_the_store_never_heard_of_is_not_an_error(kith):
    """Exactly what happens after an outage swallowed a device's issuance.

    The device holds a real certificate - that is its membership - so proving
    possession must not blow up because no row was ever written for it.
    """
    kith.seen(key_id(b"never-recorded"))
    assert kith.roll() == []


# ---- availability: the store is allowed to fail, issuance is not --------


def test_issuing_carries_on_when_the_store_is_down(kith, records):
    """THE test the whole design exists for.

    A write that raised here would propagate to the vouch endpoint, and an
    administrator standing next to a phone would get a 500 for a certificate
    that had already been signed. Worse, the same failure on renewal means every
    device whose certificate expires during a database outage LAPSES, and lapse
    is not a retry - it is a wipe and a re-enrollment with a human present.
    """
    records.up = False

    kith.issued(a_device(), a_certificate("AAAA"))  # must not raise
    kith.seen(key_id(b"device-one"))
    kith.collected("req-1")

    assert kith.status()["state"] == "deferring"
    assert kith.status()["deferred"] == 3


def test_what_happened_during_an_outage_is_written_when_the_store_returns(
    kith, records, clock
):
    records.up = False
    kith.issued(a_device(), a_certificate("AAAA", request_id="req-1"))
    kith.collected("req-1")

    records.up = True
    clock.advance(kith_store.COOLDOWN_S)

    assert kith.flush() == 0, "the backlog was not replayed"
    roll = kith.roll()
    assert len(roll) == 1
    assert kith.history(roll[0].device.key_id)[0].collected_at is not None


def test_a_read_during_an_outage_refuses_rather_than_saying_the_kith_is_empty(
    kith, records
):
    """An empty list is a lie that reads exactly like a fleet that vanished.

    The console would render "no devices" and the operator's next move would be
    to go looking for phones rather than for a database.
    """
    records.up = False
    kith.issued(a_device(), a_certificate("AAAA"))

    with pytest.raises(Unreachable):
        kith.roll()
    with pytest.raises(Unreachable):
        kith.member(key_id(b"device-one"))
    with pytest.raises(Unreachable):
        kith.awaiting_collection("req-1")


def test_a_failed_store_is_left_alone_for_the_cooldown(kith, records, clock):
    """"It does not fail" is not enough; it must not BLOCK either.

    Without a cooldown every request during an outage pays a full connect
    timeout, so issuing a certificate would take seconds each. A control plane
    that is merely very slow gets debugged as though it were down.
    """
    records.up = False
    kith.issued(a_device(), a_certificate("AAAA"))
    attempts_after_first_failure = records.attempts

    for _ in range(10):
        kith.issued(a_device(), a_certificate("BBBB"))
    with pytest.raises(Unreachable):
        kith.roll()

    assert records.attempts == attempts_after_first_failure, (
        "the store was touched again while it was known to be down"
    )


def test_the_cooldown_ends_and_the_store_is_tried_again(records, clock):
    from muster import telemetry

    emitter = telemetry.Telemetry()
    kith = Kith(records, clock=clock, emitter=emitter)
    records.up = False
    kith.issued(a_device(), a_certificate("AAAA"))
    quiet = records.attempts

    clock.advance(kith_store.COOLDOWN_S)
    records.up = True
    kith.seen(key_id(b"device-one"))

    assert records.attempts > quiet
    assert kith.status()["state"] == "ok"
    assert kith.status()["deferred"] == 0
    assert "custom.muster.kith.store.recovered:1|c" in emitter.sent, emitter.sent


def test_recovery_is_declared_on_a_success_and_never_on_the_clock(records, clock):
    """The cooldown expiring says the store is worth TRYING, not that it is back.

    Written as a test because the obvious implementation gets it wrong in a way
    that never shows up: if the breaker clears itself when the clock passes, the
    recovery log and metric can never fire - the flag they key off is already
    gone - and `/readyz` reports a healthy store nothing has spoken to. Both
    failures are invisible precisely while somebody is trying to find out
    whether the database came back.
    """
    from muster import telemetry

    emitter = telemetry.Telemetry()
    kith = Kith(records, clock=clock, emitter=emitter)
    records.up = False
    kith.issued(a_device(), a_certificate("AAAA"))

    clock.advance(kith_store.COOLDOWN_S * 10)  # the clock alone
    assert kith.status()["state"] == "deferring", "it healed itself on a timer"
    assert not [line for line in emitter.sent if "kith.store.recovered" in line]

    records.up = True
    assert kith.flush() == 0
    assert kith.status()["state"] == "ok"
    assert "custom.muster.kith.store.recovered:1|c" in emitter.sent


def test_an_outage_with_nothing_owed_does_not_announce_recovery_each_retry(
    records, clock
):
    """Draining an EMPTY backlog proves nothing about the store.

    The case is an outage that only ever hit reads - a console being reloaded
    while nobody is enrolling - so there is nothing owed. Treating "the backlog
    is empty" as "the store answered" would log a recovery and then an outage on
    every single retry, which is precisely the alternating noise the once-per-
    outage guard exists to avoid, with a false metric on top.
    """
    from muster import telemetry

    emitter = telemetry.Telemetry()
    kith = Kith(records, clock=clock, emitter=emitter)
    records.up = False

    with pytest.raises(Unreachable):
        kith.roll()
    clock.advance(kith_store.COOLDOWN_S)
    with pytest.raises(Unreachable):
        kith.roll()

    assert not [line for line in emitter.sent if "kith.store.recovered" in line], (
        "it announced a recovery while the store was still down"
    )
    assert kith.status()["state"] == "deferring"


def test_the_backlog_is_bounded_and_says_when_it_drops_something(records, clock):
    """An unbounded backlog turns a store outage into an OOM kill.

    Which would stop issuance by the back door - the exact outcome the deferral
    exists to prevent. Every dropped entry is counted rather than merely
    dropped: a bound nobody can see is a fleet quietly ceasing to be listed.
    """
    from muster import telemetry

    emitter = telemetry.Telemetry()
    kith = Kith(records, clock=clock, emitter=emitter, backlog_max=3)
    records.up = False

    for n in range(6):
        kith.issued(a_device(), a_certificate(f"CERT{n}", request_id=f"req-{n}"))

    assert kith.status()["deferred"] == 3
    dropped = [line for line in emitter.sent if "kith.write.dropped" in line]
    assert len(dropped) == 3, emitter.sent


def test_a_drain_stops_at_the_first_refusal_and_keeps_the_order(records, clock):
    """Replay is oldest-first and stops, so a renewal never lands before an issue.

    Applying a later entry over a failed earlier one would try to record a
    renewal for a device whose first issuance had not been written, which the
    foreign key refuses - one row at a time, forever.
    """
    kith = Kith(records, clock=clock)
    records.up = False
    kith.issued(a_device(), a_certificate("AAAA", request_id="req-1"))
    kith.issued(a_device(at=clock()), a_certificate("BBBB", request_id="req-2"))

    # The store comes back but refuses the FIRST entry once more.
    calls = {"n": 0}
    original = records.record_issuance

    def flaky(device, certificate):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("still settling")
        original(device, certificate)

    records.up = True
    records.record_issuance = flaky  # type: ignore[method-assign]
    clock.advance(kith_store.COOLDOWN_S)

    assert kith.flush() == 2, "a failed head must not let the tail through"

    clock.advance(kith_store.COOLDOWN_S)
    assert kith.flush() == 0
    assert [c.serial for c in kith.history(key_id(b"device-one"))] == ["AAAA", "BBBB"]


def test_the_background_flusher_drains_with_no_other_traffic(records, clock):
    """Otherwise the backlog is decoration.

    Deferred writes are replayed by the next enrollment, proof or console load,
    and muster is quiet by design - devices renew every ninety days. A store that
    came back an hour after it left would hold the rows in memory until something
    happened to knock on it, and a pod restarted first would lose them.
    """
    import time

    kith = Kith(records, clock=clock, cooldown_s=0)
    records.up = False
    kith.issued(a_device(), a_certificate("AAAA"))
    assert kith.status()["deferred"] == 1

    records.up = True
    kith.start_flushing(0.01)
    try:
        deadline = time.monotonic() + 5.0
        while kith.status()["deferred"] and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        kith.stop_flushing()

    assert kith.status()["deferred"] == 0, "the flusher never replayed the backlog"
    assert len(records.roll()) == 1


class Rejecting(MemoryRecords):
    """A store that refuses ONE row on its merits and is otherwise healthy.

    The real one is a device name carrying a NUL byte: PostgreSQL `text` cannot
    hold one, so that row is undeliverable no matter how long anybody waits.
    """

    def __init__(self, refuse_serial: str) -> None:
        super().__init__()
        self._refuse = refuse_serial

    def describe(self) -> str:
        return "rejecting"

    def permanent(self, exc: BaseException) -> bool:
        return isinstance(exc, ValueError)

    def record_issuance(self, device, certificate) -> None:
        if certificate.serial == self._refuse:
            raise ValueError("text cannot hold a NUL byte")
        super().record_issuance(device, certificate)


def test_a_row_the_store_will_never_accept_is_dropped_rather_than_retried_forever(clock):
    """The wedge, and it is worse than losing the row.

    An ordered backlog retrying an undeliverable head blocks every later write
    behind it AND opens the breaker, so reads start answering "the store is
    unreachable" while the database is perfectly healthy. Recovery would need
    512 more writes to evict it, or a restart that discards the lot.
    """
    from muster import telemetry

    emitter = telemetry.Telemetry()
    kith = Kith(Rejecting("BAD"), clock=clock, emitter=emitter)

    kith.issued(a_device(key=b"device-one"), a_certificate("BAD", request_id="r1"))
    kith.issued(a_device(key=b"device-two"), a_certificate("GOOD", request_id="r2"))

    assert kith.status()["deferred"] == 0, "the refused row blocked the queue"
    assert kith.status()["state"] == "ok", "a refused row was reported as an outage"
    assert "custom.muster.kith.write.poison:1|c" in emitter.sent, emitter.sent

    # The healthy device got through, and reads still work.
    assert [m.device.key_id for m in kith.roll()] == [key_id(b"device-two")]


def test_a_store_that_cannot_classify_a_failure_still_cannot_fail_a_vouch(clock):
    """The last unguarded call on the write path, closed.

    `permanent()` hands control back to the store from inside an exception
    handler. If it raised, that would come out of `_defer`, into the vouch
    endpoint, and turn a certificate that had already been signed into a 500 -
    breaking the one promise this module exists to make, through the code that
    was added to keep it.
    """
    class Confused(MemoryRecords):
        def permanent(self, exc):
            raise RuntimeError("the classifier itself is broken")

        def record_issuance(self, device, certificate):
            raise OSError("connection refused")

    kith = Kith(Confused(), clock=clock)

    kith.issued(a_device(), a_certificate("AAAA"))  # must not raise

    # Kept, not dropped: an entry that might be undeliverable is recoverable,
    # one that was fine and got thrown away is not.
    assert kith.status()["deferred"] == 1
    assert kith.status()["state"] == "deferring"


def test_status_answers_while_another_thread_is_inside_a_slow_store(records, clock):
    """/readyz must never queue behind a database call.

    Doing no I/O is not enough. A read holding the lock through a query that has
    gone silent would block this for as long as the query took; the probe allows
    one second by default and three failures remove the pod from the Service. A
    slow database would have stopped issuance without anything consulting it.
    """
    import threading
    import time

    kith = Kith(records, clock=clock)
    inside = threading.Event()
    release = threading.Event()

    def slow_roll():
        inside.set()
        release.wait(5.0)
        return []

    records.roll = slow_roll  # type: ignore[method-assign]
    reader = threading.Thread(target=kith.roll, daemon=True)
    reader.start()
    assert inside.wait(5.0), "the slow read never started"

    started = time.monotonic()
    answer = kith.status()
    elapsed = time.monotonic() - started

    release.set()
    reader.join(5.0)

    assert elapsed < 0.5, f"status queued behind the store for {elapsed:.2f}s"
    assert answer["records"] == "breakable"


def test_shutdown_makes_one_last_attempt_to_write_what_is_owed(records, clock):
    """Everything deferred dies with this process, so shutdown is the last chance.

    And the cooldown is cleared first on purpose: a deploy landing inside those
    thirty seconds would otherwise throw the backlog away without ever asking a
    store that may well be answering again.
    """
    kith = Kith(records, clock=clock)
    records.up = False
    kith.issued(a_device(), a_certificate("AAAA"))
    assert kith.status()["deferred"] == 1

    records.up = True  # back, but still inside the cooldown
    kith.stop_flushing()

    assert kith.status()["deferred"] == 0, "the backlog was discarded at shutdown"
    assert len(records.roll()) == 1


def test_a_stale_replay_does_not_revert_the_device_name(kith, clock):
    """`name = EXCLUDED.name` is order-dependent, and replay is where order is lost.

    A deferred issuance draining after a live one would quietly put a device's
    old name back - during recovery from an outage, which is exactly when nobody
    is looking at the device list for that.
    """
    kith.issued(a_device(name="Pixel 6a"), a_certificate("AAAA", request_id="r1"))
    clock.advance(3600)
    kith.issued(
        a_device(name="hall thermostat", at=clock()),
        a_certificate("BBBB", request_id="r2", at=clock()),
    )
    # An entry from BEFORE the rename, draining late.
    kith.issued(
        a_device(name="Pixel 6a", at=START), a_certificate("CCCC", request_id="r3")
    )

    assert kith.roll()[0].device.name == "hall thermostat"


def test_the_current_certificate_is_settled_when_the_timestamps_tie(kith):
    """Two certificates drained from one backlog can share a timestamp.

    The roll reads the current serial and its expiry as two independent
    subqueries, so an unsettled order lets one line describe two different
    certificates. Serial is unique, which makes the order total.
    """
    for serial in ("AAAA", "FFFF", "BBBB"):
        kith.issued(a_device(), a_certificate(serial, request_id=f"r-{serial}"))

    member = kith.roll()[0]
    assert member.certificates == 3
    assert member.current_serial == "FFFF"
    assert [c.serial for c in kith.history(member.device.key_id)] == [
        "AAAA", "BBBB", "FFFF"
    ]


def test_status_never_touches_the_store(kith, records):
    """`/readyz` calls this every ten seconds; it must not become load.

    And, more importantly, it must not be able to fail - a readiness probe that
    consults the database is a readiness probe that takes the pod out of the
    Service when the database goes away, which stops issuance through the health
    check rather than through the code.
    """
    records.up = False
    kith.issued(a_device(), a_certificate("AAAA"))
    before = records.attempts

    assert kith.status()["state"] == "deferring"
    assert kith.status()["records"] == "breakable"
    assert records.attempts == before


def test_with_no_database_configured_the_kith_is_memory_and_says_so(monkeypatch):
    """Running without a store is a supported mode, not an error.

    Refusing to start would make the database a hard dependency of a process
    that must keep signing when the database is gone. What is NOT acceptable is
    doing it silently, so the mode is on /readyz and in the boot log.
    """
    monkeypatch.delenv("MUSTER_DATABASE_URL", raising=False)
    assert kith_store.from_env().status()["records"] == "memory"


def test_a_dsn_with_a_trailing_newline_is_stripped(monkeypatch):
    """The trap that has already cost this estate a live lockout, once.

    `kubectl create secret --from-file` fed by `print()` stores the newline, and
    a DSN with one in it fails to connect in a way that names neither the
    newline nor the secret. api.py strips the admin token for the same reason; a
    fix in one place only is a fix the next copy-paste undoes.

    Asserted on what reaches the DRIVER, not on the mode the store reports: the
    mode would say "postgres" whether or not the newline had been dealt with.
    """
    monkeypatch.setenv("MUSTER_DATABASE_URL", "  postgresql://muster@host/muster\n")
    assert kith_store.from_env().status()["records"] == "postgres"

    seen = []
    records = kith_store.PostgresRecords(
        "postgresql://muster@host/muster\n",
        connect=lambda dsn, timeout: seen.append(dsn) or FakeConnection(),
    )
    records.record_seen("abc", START)
    assert seen == ["postgresql://muster@host/muster"]


# ---- the SQL, as far as it can be checked without a Postgres ------------


class FakeCursor:
    def __init__(self, log: list, rows: list) -> None:
        self.log = log
        self._rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.log.append((sql, params))

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None


class FakeConnection:
    """Enough of a DBAPI connection to prove the wiring, and nothing more.

    THIS DOES NOT PROVE THE SQL IS VALID. There is no Postgres on the workstation
    or on the CI runner, so what these tests check is that the right statements
    are issued, in the right order, with the values passed as PARAMETERS rather
    than interpolated. Whether Postgres accepts them is settled by an operator
    running sql/0001_kith.sql, and docs/what-is-deployed.md says so.
    """

    def __init__(self, rows=None, fail_cursor_calls=()) -> None:
        self.log: list = []
        self.rows = rows or []
        self.commits = 0
        self.closed = False
        self.cursor_calls = 0
        # 1-based indices of the cursor() calls that should fail. Call 1 on a
        # fresh connection is the schema; the work comes after it. Indices
        # rather than a flag, because "the schema failed" and "a statement on an
        # established connection failed" are different code paths and a test has
        # to be able to pick one.
        self.fail_cursor_calls = set(fail_cursor_calls)

    def cursor(self):
        self.cursor_calls += 1
        if self.cursor_calls in self.fail_cursor_calls:
            raise OSError("server closed the connection unexpectedly")
        return FakeCursor(self.log, self.rows)

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True


def test_the_schema_is_applied_when_a_connection_is_opened():
    """A store that came back empty must start working without a human.

    A restored volume, a recreated cluster, a database nobody remembered to run
    the SQL against - all of them otherwise send every write to the backlog
    forever, with the pod perfectly healthy.
    """
    opened = []

    def connect(dsn, timeout):
        opened.append((dsn, timeout))
        return FakeConnection()

    records = kith_store.PostgresRecords("postgresql://x", connect=connect)
    records.record_seen("abc", START)

    assert opened == [("postgresql://x", kith_store.CONNECT_TIMEOUT_S)]
    assert "CREATE TABLE IF NOT EXISTS kith_device" in records._connection.log[0][0]


def test_a_renewal_upserts_the_device_and_leaves_first_seen_alone():
    """The one clause that makes renewal update rather than insert.

    Asserted on the statement text because the alternative is a Postgres, and
    there is not one here. It is worth asserting anyway: an ON CONFLICT list
    that grew `first_seen = EXCLUDED.first_seen` would pass every other test in
    this file and quietly rewrite when each device joined the kith.
    """
    connection = FakeConnection()
    records = kith_store.PostgresRecords(
        "postgresql://x", connect=lambda dsn, timeout: connection
    )
    records.record_issuance(a_device(), a_certificate("AAAA"))

    device_sql = next(sql for sql, _ in connection.log if "INSERT INTO kith_device" in sql)
    assert "ON CONFLICT (key_id) DO UPDATE" in device_sql
    assert "first_seen" not in device_sql.split("DO UPDATE")[1], (
        "first_seen must not be overwritten by a renewal"
    )

    certificate_sql = next(
        sql for sql, _ in connection.log if "INSERT INTO kith_certificate" in sql
    )
    assert "ON CONFLICT (serial) DO NOTHING" in certificate_sql

    # The name follows the NEWER row, not the last writer. A bare
    # `name = EXCLUDED.name` passes every behavioral test in this file against
    # MemoryRecords and still reverts a device's name during backlog replay.
    updates = device_sql.split("DO UPDATE")[1]
    assert "GREATEST(kith_device.last_seen, EXCLUDED.last_seen)" in updates
    assert "CASE WHEN EXCLUDED.last_seen >= kith_device.last_seen" in updates


def test_the_roll_settles_which_certificate_is_current():
    """BOTH subqueries, or one line describes two certificates.

    The serial and the expiry come from two independent scalar subqueries. On an
    issued_at tie - two certificates written from the same drained backlog -
    PostgreSQL may pick a different row for each unless the order is total.
    Asserting the count is what catches fixing only one of them, which is what a
    careless edit does.
    """
    connection = FakeConnection(rows=[])
    records = kith_store.PostgresRecords(
        "postgresql://x", connect=lambda dsn, timeout: connection
    )
    records.roll()

    sql = next(s for s, _ in connection.log if "FROM kith_device d" in s)
    assert sql.count("ORDER BY n.issued_at DESC, n.serial DESC LIMIT 1") == 2, sql


def test_revocation_queries_join_device_identity_to_certificate_serials():
    connection = FakeConnection()
    records = kith_store.PostgresRecords(
        "postgresql://x", connect=lambda dsn, timeout: connection
    )

    records.certificate_status("AAAA")
    records.unexpired_revocations(START)

    statements = [
        sql for sql, _ in connection.log
        if "JOIN kith_device d ON d.key_id = c.key_id" in sql
    ]
    assert len(statements) == 2
    assert "c.serial = %s" in statements[0]
    assert "d.revoked_at IS NOT NULL AND c.not_after > %s" in statements[1]


def test_values_are_passed_as_parameters_and_never_interpolated():
    """A device name comes from an operator's keyboard and lands in SQL."""
    connection = FakeConnection()
    records = kith_store.PostgresRecords(
        "postgresql://x", connect=lambda dsn, timeout: connection
    )
    records.record_issuance(a_device(name="Robert'); DROP TABLE kith_device;--"),
                            a_certificate("AAAA"))

    for sql, _params in connection.log:
        assert "DROP TABLE" not in sql
    assert any(
        params and "Robert'); DROP TABLE kith_device;--" in params
        for _, params in connection.log
    )


def test_a_stale_connection_is_retried_once_on_a_fresh_one():
    """The common case, because muster's one connection is almost always idle.

    A handful of devices renewing every ninety days means the socket sits unused
    for days, and an unused socket is the one a server, a CNPG switchover or a
    conntrack table drops without telling anybody. Reporting that as an outage
    would make muster answer 503 for thirty seconds every single time the
    database quietly closed a connection nobody was using.
    """
    connections = []

    def connect(dsn, timeout):
        connection = FakeConnection()
        connections.append(connection)
        return connection

    records = kith_store.PostgresRecords("postgresql://x", connect=connect)
    records.record_seen("abc", START)
    # Call 1 was the schema, call 2 the work; the next one is the work again on
    # the connection now being held.
    connections[0].fail_cursor_calls = {3}

    records.record_seen("abc", START)  # must NOT raise

    assert connections[0].closed, "the dead connection was kept"
    assert len(connections) == 2, "it did not open a fresh connection"


def test_a_failure_on_a_FRESH_connection_is_reported_rather_than_retried():
    """Retrying a connection that was already new just doubles time-to-notice.

    The retry above is for a socket that went stale while nobody was looking. If
    the connection was opened for this very call and still failed, the store
    really is unreachable and saying so promptly is the whole point of the
    cooldown.
    """
    connections = []

    def connect(dsn, timeout):
        # Call 1 is the schema, call 2 is the work: let the connection open and
        # the schema apply, then fail the statement.
        connection = FakeConnection(fail_cursor_calls={2})
        connections.append(connection)
        return connection

    records = kith_store.PostgresRecords("postgresql://x", connect=connect)
    with pytest.raises(OSError):
        records.record_seen("abc", START)

    assert len(connections) == 1, "it retried a connection that was already fresh"
    assert connections[0].closed


def test_the_connection_is_opened_with_every_timeout_that_defaults_to_forever():
    """connect_timeout alone leaves a query on an open socket unbounded.

    That is the failure that matters: not a refused connection, which returns
    instantly, but a peer that goes silent and leaves libpq in recv() until the
    kernel stops retransmitting - about fifteen minutes on Linux, inside a lock
    that /readyz would otherwise be queueing behind.
    """
    import psycopg

    seen = {}

    def fake_connect(dsn, **kwargs):
        seen.update(kwargs)
        seen["dsn"] = dsn
        return FakeConnection()

    original, psycopg.connect = psycopg.connect, fake_connect
    try:
        kith_store._connect_psycopg("postgresql://x", 3)
    finally:
        psycopg.connect = original

    assert seen["connect_timeout"] == 3
    assert f"statement_timeout={kith_store.STATEMENT_TIMEOUT_MS}" in seen["options"]
    assert seen["keepalives"] == 1
    assert seen["tcp_user_timeout"] == 3000
    assert seen["autocommit"] is False


def test_a_mistyped_dsn_defers_rather_than_discarding_every_device(clock):
    """The quietest failure this module could possibly have had.

    psycopg raises ProgrammingError for a connection string it cannot parse -
    the same class that otherwise means "the server refused this row and always
    will". Without the NoConnection wrapper, one typo in a secret nobody types
    twice would make muster drop every device it issued to, one at a time, as
    undeliverable, while /readyz reported a perfectly healthy store.
    """
    import psycopg

    from muster import telemetry

    def refuse_to_parse(dsn, timeout):
        raise psycopg.ProgrammingError(f"invalid connection option in {dsn!r}")

    emitter = telemetry.Telemetry()
    records = kith_store.PostgresRecords("nonsense://x", connect=refuse_to_parse)
    kith = Kith(records, clock=clock, emitter=emitter)

    kith.issued(a_device(), a_certificate("AAAA"))

    assert kith.status()["deferred"] == 1, "the device was thrown away"
    assert kith.status()["state"] == "deferring"
    assert not [line for line in emitter.sent if "kith.write.poison" in line]


def test_a_role_that_cannot_apply_the_schema_defers_rather_than_dropping(clock):
    """Same shape, different cause: the store is not ready, the rows are fine.

    A `muster` role created without CREATE on its own database fails the schema
    with ProgrammingError. That is a grant to fix, not two hundred devices to
    discard.
    """
    def connect(dsn, timeout):
        return FakeConnection(fail_cursor_calls={1})

    records = kith_store.PostgresRecords("postgresql://x", connect=connect)
    kith = Kith(records, clock=clock)
    kith.issued(a_device(), a_certificate("AAAA"))

    assert kith.status()["deferred"] == 1
    assert not records.permanent(kith_store.NoConnection("permission denied"))


def test_the_driver_says_which_failures_are_the_row_and_which_are_the_store():
    """The classification the whole deferral policy turns on.

    Retrying an OperationalError forever is correct - that is what the backlog
    is for. Retrying a DataError forever wedges the queue behind a row the
    server will refuse identically in an hour, and reports a healthy database as
    unreachable while it does it.
    """
    import psycopg

    records = kith_store.PostgresRecords(
        "postgresql://x", connect=lambda dsn, timeout: FakeConnection()
    )
    assert records.permanent(psycopg.DataError("text cannot hold a NUL byte"))
    assert records.permanent(psycopg.IntegrityError("duplicate key"))
    assert records.permanent(psycopg.ProgrammingError("no such column"))

    assert not records.permanent(psycopg.OperationalError("connection refused"))
    assert not records.permanent(psycopg.InterfaceError("the connection is closed"))
    assert not records.permanent(OSError("network is unreachable"))


def test_a_connection_whose_schema_fails_is_closed_rather_than_leaked():
    """A role without CREATE would otherwise leak a socket every sixty seconds.

    The retry loop reopens on a timer, and this connection has not been stored
    yet when the schema runs - so the ordinary cleanup path cannot see it, and
    "the pod slowly runs out of file descriptors" is a long way from "the
    database role is missing a grant".
    """
    connections = []

    def connect(dsn, timeout):
        # Call 1 is the schema: it opens, then fails before it can be stored.
        connection = FakeConnection(fail_cursor_calls={1})
        connections.append(connection)
        return connection

    records = kith_store.PostgresRecords("postgresql://x", connect=connect)
    for _ in range(3):
        # NoConnection and not the driver's own class: a schema that will not
        # apply is a store that is not ready, never a verdict on a row.
        with pytest.raises(kith_store.NoConnection):
            records.record_seen("abc", START)

    assert len(connections) == 3, "it reused a connection it never made work"
    assert all(c.closed for c in connections), "a failed connection was left open"


def test_every_statement_is_something_postgresql_can_actually_parse():
    """The nearest thing to a real database this repo has.

    pglast embeds PostgreSQL's own parser, so this is the actual grammar and not
    a lookalike. It settles the questions a fake connection cannot: whether
    `serial` is usable as a column name, whether `GREATEST` and the `CASE` in
    the ON CONFLICT list are well formed, whether a `GROUP BY` on the primary
    key parses with ungrouped columns beside it.

    IT PROVES SYNTAX AND NOT MEANING. A column that does not exist parses
    perfectly. What settles the rest is an operator running step 7 of
    docs/what-is-deployed.md once, and `/readyz` then saying "postgres" with
    state "ok" - the PR and that document both say so.
    """
    import pglast

    connection = FakeConnection(rows=[])
    records = kith_store.PostgresRecords(
        "postgresql://x", connect=lambda dsn, timeout: connection
    )
    # Every method that issues SQL, so a statement added later cannot avoid this
    # by being new.
    records.record_issuance(a_device(), a_certificate("AAAA"))
    records.record_seen("abc", START)
    records.record_collected("req-1", START)
    records.roll()
    records.member("abc")
    records.history("abc")
    records.certificate_status("AAAA")
    records.unexpired_revocations(START)
    records.awaiting_collection("req-1")

    statements = [sql for sql, _ in connection.log]
    assert len(statements) >= 10, statements

    for sql in statements:
        # psycopg substitutes %s client-side, so the placeholder never reaches
        # a server and is not part of the grammar. NULL stands in for it here
        # and preserves the shape of every expression around it.
        parsed = pglast.parse_sql(sql.replace("%s", "NULL"))
        assert parsed, sql


def test_the_schema_keeps_the_serial_out_of_an_integer_column():
    """x509.random_serial_number() is up to 159 bits and bigint holds 63.

    So the wrong type here is not a rare overflow, it is every single row - and
    it would only be discovered by the first certificate ever issued against a
    real database.
    """
    # Comments stripped first: this file explains the trap in prose, and a test
    # that matched the explanation instead of the declaration would pass whatever
    # the column actually was.
    statements = "\n".join(
        line for line in kith_store.SCHEMA.read_text().splitlines()
        if not line.lstrip().startswith("--")
    )
    assert "serial" in statements
    assert "bigint" not in statements
    assert "integer" not in statements


# ---- roles (muster#70) ---------------------------------------------------


def _roled(role: str, at=START) -> Device:
    d = a_device(at=at)
    return Device(
        key_id=d.key_id, fingerprint=d.fingerprint, name=d.name,
        first_seen=d.first_seen, last_seen=at, role=role,
    )


def test_a_role_survives_a_renewal(kith, clock):
    """A device does not stop being a zippie android in ninety days.

    The role is on the DEVICE and renewal issues a new CERTIFICATE, so this is
    really a test that the device row is updated rather than replaced.
    """
    kith.issued(_roled("zippie"), a_certificate("AAAA"))
    later = START + dt.timedelta(days=80)
    kith.issued(_roled("zippie", at=later), a_certificate("BBBB", at=later))
    assert kith.member(a_device().key_id).device.role == "zippie"


def test_a_re_enrolment_with_no_role_does_not_strip_one(kith):
    """THE FAILURE THIS GUARDS. An operator mints a plain QR for a device that
    already carries a role; without this the device silently stops being a
    zippie android and nothing anywhere says so."""
    kith.issued(_roled("zippie"), a_certificate("AAAA"))
    later = START + dt.timedelta(days=1)
    kith.issued(_roled("", at=later), a_certificate("BBBB", at=later))
    assert kith.member(a_device().key_id).device.role == "zippie"


def test_a_role_can_be_changed_by_re_enrolling_with_another(kith):
    """The reverse of the guard above: a NON-empty role does replace, which is
    how an operator re-roles a handset without wiping it."""
    kith.issued(_roled("zippie"), a_certificate("AAAA"))
    later = START + dt.timedelta(days=1)
    kith.issued(_roled("kiosk", at=later), a_certificate("BBBB", at=later))
    assert kith.member(a_device().key_id).device.role == "kiosk"


def test_no_role_is_the_ordinary_case(kith):
    kith.issued(a_device(), a_certificate("AAAA"))
    assert kith.member(a_device().key_id).device.role == ""


def test_being_seen_does_not_cost_a_device_its_role(kith, clock):
    """THE BUG THIS EXISTS FOR, and it was invisible in every other test.

    `_proven_device` calls `seen()` on every proven request, so a device was
    stripped of its role on the way IN to the very config fetch that needed it.
    `MemoryRecords.record_seen` rebuilt the Device field by field and simply did
    not mention `role`; the SQL store does `UPDATE ... SET last_seen` and kept
    it. The two disagreed, and only the in-memory one is exercised here.

    Written against the OBSERVABLE behaviour rather than the implementation, so
    it still holds if that method is rewritten again.
    """
    kith.issued(_roled("zippie"), a_certificate("AAAA"))
    # THE CLOCK HAS TO MOVE. `record_seen` returns early when the stored
    # last_seen is already at or past `at`, so against a frozen clock this
    # method does nothing at all - and a test written without this line passes
    # whatever the method does, which is what the first draft of it did.
    clock.advance(60)
    kith.seen(a_device().key_id)
    assert kith.member(a_device().key_id).device.role == "zippie"


def test_being_seen_does_not_cost_a_device_anything_else_either(kith, clock):
    """The general form. Any field added to `Device` later is covered by this
    without anybody remembering to extend it - it compares every field the
    dataclass has except the one this method is supposed to change."""
    from dataclasses import fields

    before = _roled("zippie")
    kith.issued(before, a_certificate("AAAA"))
    clock.advance(60)  # see the test above: without this, seen() is a no-op
    kith.seen(before.key_id)
    after = kith.member(before.key_id).device

    changed = {"last_seen"}
    for field in fields(before):
        if field.name in changed:
            continue
        assert getattr(after, field.name) == getattr(before, field.name), field.name
    assert after.last_seen > before.last_seen, "seen() did not record anything"


def test_a_device_can_be_re_roled_without_re_enrolling(kith):
    """muster#73. A role was fixed at issuance, so changing one meant wiping a
    handset and provisioning it again - for a text field. That is a limitation
    of how the role got there, not of what a role is."""
    kith.issued(a_device(), a_certificate("AAAA"))
    kith.set_role(a_device().key_id, "zippie")
    assert kith.member(a_device().key_id).device.role == "zippie"


def test_a_role_can_be_taken_OFF_a_device_deliberately(kith):
    """DIFFERENT FROM `record_issuance`, ON PURPOSE. There, an empty role never
    overwrites a set one - a re-enrolment against a plain QR must not silently
    strip a handset. Here an operator is saying "this is no longer a zippie
    android" in as many words, and refusing to do it would leave no way back."""
    kith.issued(a_device(), a_certificate("AAAA"))
    kith.set_role(a_device().key_id, "zippie")
    kith.set_role(a_device().key_id, "")
    assert kith.member(a_device().key_id).device.role == ""


def test_re_roling_costs_a_device_nothing_else(kith):
    """The general form, the same shape as the `seen()` guard: any field added
    to `Device` later is covered without anybody remembering to extend this."""
    from dataclasses import fields

    kith.issued(_roled("kiosk"), a_certificate("AAAA"))
    before = kith.member(a_device().key_id).device
    kith.set_role(before.key_id, "zippie")
    after = kith.member(before.key_id).device
    for field in fields(before):
        if field.name == "role":
            continue
        assert getattr(after, field.name) == getattr(before, field.name), field.name


def test_re_roling_a_device_the_kith_never_heard_of_says_so(kith):
    """Not an error and not a silent success: a caller has to be able to tell
    "that device is not in the kith" from "done"."""
    assert kith.set_role("z" * 64, "zippie") is False
    assert kith.set_role(a_device().key_id, "zippie") is False


def test_re_roling_a_known_device_reports_that_it_happened(kith):
    kith.issued(a_device(), a_certificate("AAAA"))
    assert kith.set_role(a_device().key_id, "zippie") is True
