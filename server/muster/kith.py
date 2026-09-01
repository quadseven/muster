"""The kith, written down: which devices muster has issued to, and what it issued.

CONTEXT.md calls the kith "the set of devices muster recognizes ... the answer
to a question (is this yours?), not a table". This module is deliberately NOT
that answer. It is the RECORD of it, and the difference is the entire
availability design, so it is worth being exact:

    the certificate    decides whether a device is in the kith
    this module        remembers what muster did about it

A device's membership IS its certificate - there is no enable flag, because a
flag can disagree with what a device can actually do and a certificate cannot
(CONTEXT.md, ca.py). Nothing here is ever consulted to decide whether to sign.

**WHY THE STORE IS ALLOWED TO FAIL, AND ISSUANCE IS NOT.** If signing asked the
database for permission, then a database outage would stop renewal, and every
device whose certificate expired during the outage would LAPSE. Lapse is the
revocation mechanism (CONTEXT.md) and it is close to irreversible: a lapsed
device cannot renew its way back, it has to enroll again from a fresh pairing
code with a human holding the handset - and for a Device Owner phone that means
a factory reset. So the two failures are not comparable:

    store down, issuance continues   ->  a device list missing some rows,
                                         filled in when the store returns
    store down, issuance stops       ->  a fleet that lapses, one wipe each

Trading the second for the first is not a close call, and it is the reason this
module has the shape it has.

**SO EVERY WRITE IS DEFERRED, NEVER REFUSED.** `Kith` appends what happened to a
bounded in-memory backlog and then tries to drain it. In the healthy case the
drain succeeds on the same call and the backlog is empty again; in an outage it
accumulates and is replayed when the store answers. One code path, not a happy
one and a fallback one - a fallback path that only runs during an outage is a
path that is broken during every outage.

**READS ARE NOT DEFERRED. THEY RAISE.** `roll()` and the rest raise
`Unreachable` rather than returning an empty list, because an empty list is a
lie that reads as "you have no devices" on a console. The API turns it into a
503, which says the same thing honestly.

**AND "DEFERRED" MUST NOT MEAN "FOREVER".** The backlog is ordered and replayed
from the head, so an entry the store will NEVER accept - a device name carrying
a NUL byte, which a Postgres `text` column cannot hold - is not a delay but a
wedge: every write behind it waits, and because a failed drain opens the
breaker, reads start reporting an outage while the database is perfectly
healthy. So the store is asked to classify its own failures (`Records.permanent`)
and a row that was REFUSED, as opposed to never delivered, is dropped loudly
rather than retried. The distinction is narrow and the two mistakes are not
symmetric, so it is drawn conservatively: anything that did not reach a server
at all is wrapped in `NoConnection` and always retried.

Not blocking is also literal. Nothing here may HANG: a query has a timeout, the
connection has keepalives, a failed store is left alone for a cooldown, and
`status()` - which `/readyz` publishes - takes no lock and does no I/O, so a
slow database can never make Kubernetes take the pod out of the Service and stop
issuance through the health check.

WHAT IS STILL LOST. A deferred write lives in one pod's memory. If the store is
unreachable AND that pod restarts before it recovers, those rows are gone for
good - the device keeps working, because its certificate is its membership, but
muster will not list it until it renews or proves possession again. The backlog
is bounded for the same reason: an unbounded one turns a store outage into an
out-of-memory kill, which would take issuance down by the back door.
"""
from __future__ import annotations

import datetime as dt
import os
import pathlib
import threading
from collections import deque
from dataclasses import dataclass, replace
from typing import Callable, Protocol

from muster import telemetry

# How long to stop touching a store that just failed. Without this, every
# request during an outage pays a full connect timeout - so "issuance does not
# fail" would still mean "issuance takes three seconds per certificate", and a
# control plane that is merely very slow is one an operator debugs as if it were
# down. Short enough that recovery is noticed within a poll or two.
COOLDOWN_S = 30.0

# How long OPENING a connection may take before it is treated as a failure. This
# bounds the one request that discovers an outage; every request after it is
# answered by the cooldown above without touching the network.
CONNECT_TIMEOUT_S = 3

# How long a statement may take on a connection that is ALREADY OPEN.
#
# CONNECT_TIMEOUT DOES NOT COVER THIS, and believing it did was a real bug here.
# `connect_timeout` is a libpq connect-phase parameter; nothing in it bounds a
# query on an established socket. The failure that matters is not a refused
# connection - that returns instantly - it is a socket that goes SILENT: a CNPG
# primary that moves without sending a RST, a node going NotReady, a security
# rule changing underneath. libpq then sits in recv() until the kernel gives up
# retransmitting, which on Linux defaults to roughly fifteen minutes.
#
# Fifteen minutes inside a lock that `/readyz` also wants is how a database
# problem becomes an ISSUANCE problem: the probe times out, three failures take
# the pod out of the Service, and enrollment and renewal stop for the whole
# fleet - through the health check rather than through any code path a test of
# issuance would cover. Hence this, plus the TCP keepalives below, plus
# `status()` never taking the lock at all. Any one of the three alone leaves the
# hole open.
STATEMENT_TIMEOUT_MS = 3000

# How many deferred writes to hold. This estate has a handful of devices, so
# reaching this bound means an outage of days rather than minutes. Bounded
# anyway: the pod holding the CA must not be OOM-killed by its own bookkeeping.
BACKLOG_MAX = 512

# How often the background flusher retries a backlog when nothing else is
# happening. Without it, a deferred write waits for the next enrollment, proof
# or console load - which on a fleet that renews every 90 days can be weeks, and
# a mechanism that only runs when something else happens to run is decoration.
FLUSH_INTERVAL_S = 60.0

SCHEMA = pathlib.Path(__file__).with_name("sql") / "0001_kith.sql"


class Unreachable(Exception):
    """The record could not be read. NOT "there is nothing there"."""


class NoConnection(Exception):
    """There was no usable connection, so NOTHING ever saw the statement.

    Wraps whatever the driver raised while connecting or preparing a connection,
    and exists to keep that failure away from `Records.permanent`, which asks
    whether the SERVER refused a row.

    THE CASE THAT MAKES IT NECESSARY: a DSN with a typo in it. psycopg raises
    `ProgrammingError` for a connection string it cannot parse, and that is
    exactly the class that otherwise means "this row will never insert". Without
    this wrapper a single mistyped secret would make muster drop every device it
    issued to as undeliverable, one at a time, while reporting a healthy store -
    which is the quietest possible version of the failure this module is built
    to make loud.
    """


# ONE sentence, whether this is the first failure or the thousandth. The first
# read of an outage fails inside the driver and every later one is short-circuited
# by the cooldown, and it would be easy to let those two produce different
# messages - so an operator would see a raw libpq string once and a useful
# sentence afterwards, and would reasonably think they were different faults.
UNREACHABLE = (
    "the kith store is unreachable; muster is still issuing and renewing, and "
    "what it recorded meanwhile is waiting to be written"
)


@dataclass(frozen=True)
class Device:
    """A device as it is written down. The KEY is the identity.

    `key_id` is the full SHA-256 of the public key; `fingerprint` is the same
    digest in the truncated, grouped form a human compares by eye. Both are
    kept: one is what the table is keyed on, the other is what an operator has
    written on a sticky note.
    """

    key_id: str
    fingerprint: str
    name: str
    first_seen: dt.datetime
    last_seen: dt.datetime
    # What this device is FOR, from the pairing code it enrolled with
    # (muster#70). Empty is the ordinary case: the kith's policy and nothing
    # else. It is on the DEVICE rather than the certificate because it survives
    # renewal - a device does not stop being a zippie android in ninety days.
    role: str = ""
    # When an administrator said this device is no longer ours. None means it
    # still is. On the DEVICE for the same reason `role` is: revocation is a
    # statement about the KEY, and the key is what was vouched for. Revoking a
    # certificate would leave the device free to renew into a new one.
    revoked_at: dt.datetime | None = None
    # When an administrator asked for the device to be erased first, BEFORE the
    # refusal above. The two must be different states rather than one action:
    # `_proven_device` refuses `revoked_at`, so a wipe that also revokes in the
    # same step would remove the only channel the wipe instruction could travel
    # down. This state still serves configuration and specifically serves the
    # wipe file; it becomes `revoked_at` only after the device acknowledges the
    # instruction (muster#15).
    wipe_pending_at: dt.datetime | None = None


@dataclass(frozen=True)
class Certificate:
    """One certificate muster signed. A renewal is another of these, same device."""

    serial: str
    request_id: str
    not_before: dt.datetime
    not_after: dt.datetime
    issued_at: dt.datetime
    certificate_pem: str
    collected_at: dt.datetime | None = None


@dataclass(frozen=True)
class CertificateStatus:
    """One issued certificate and the device-level revocation that governs it.

    PKI status is asked by serial, but muster revokes the stable device key. The
    join between those two identities belongs in the store rather than in a
    caller walking the roll: doing it here gives Postgres one authoritative
    query and keeps renewal visible as every certificate issued to that key.
    """

    certificate: Certificate
    revoked_at: dt.datetime | None


@dataclass(frozen=True)
class Member:
    """A device on the roll, with the shape of its certificate history.

    Separate from `Device` on purpose. `Device` is what gets written; this is
    what gets read, and it carries counts that only exist once the store has
    been asked. One type with a `certificates: int = 0` field would let a caller
    write a device claiming zero certificates and never notice.
    """

    device: Device
    certificates: int
    current_serial: str | None
    not_after: dt.datetime | None


class Records(Protocol):
    """Somewhere to put the kith. Two implementations: memory, and Postgres.

    Every method may raise anything at all; `Kith` is what turns that into the
    deferral policy. Keeping the policy out of here means the Postgres
    implementation is just SQL, and the memory one is just dicts.
    """

    def record_issuance(self, device: Device, certificate: Certificate) -> None: ...

    def record_seen(self, key_id: str, at: dt.datetime) -> None: ...

    def record_role(self, key_id: str, role: str) -> bool: ...

    def record_revocation(self, key_id: str, at: dt.datetime | None) -> bool: ...

    def record_wipe_pending(self, key_id: str, at: dt.datetime | None) -> bool: ...

    def record_wipe_acknowledged(self, key_id: str, at: dt.datetime) -> bool: ...

    def record_collected(self, request_id: str, at: dt.datetime) -> None: ...

    def roll(self) -> list[Member]: ...

    def member(self, key_id: str) -> Member | None: ...

    def history(self, key_id: str) -> list[Certificate]: ...

    def certificate_status(self, serial: str) -> CertificateStatus | None: ...

    def unexpired_revocations(self, at: dt.datetime) -> list[CertificateStatus]: ...

    def awaiting_collection(self, request_id: str) -> Certificate | None: ...

    def describe(self) -> str: ...

    def permanent(self, exc: BaseException) -> bool:
        """Will this exact write NEVER succeed, however long we wait?

        The distinction the deferral policy cannot make for itself, and getting
        it wrong is a wedged control plane: a row the store will always refuse,
        retried at the head of an ordered backlog, blocks every write behind it
        forever AND makes a perfectly healthy database report as unreachable.

        It lives on the store rather than in `Kith` because only the store knows
        its driver's exception hierarchy, and `Kith` must not import a database
        driver to find out.
        """
        ...


class MemoryRecords:
    """The kith in this process, for tests and for running without a database.

    A REAL implementation, not a stub: it answers reads truthfully and enforces
    the same identity rule as the SQL. What it does not do is survive a restart,
    which is the whole reason the Postgres one exists - so anything that runs on
    this must say so out loud rather than looking durable. `/readyz` and
    `/v1/kith` both report which one is in use.
    """

    def __init__(self) -> None:
        self._devices: dict[str, Device] = {}
        self._certificates: dict[str, list[Certificate]] = {}

    def describe(self) -> str:
        return "memory"

    def permanent(self, exc: BaseException) -> bool:
        """Nothing here is permanently unwritable: it is a dict."""
        return False

    def record_issuance(self, device: Device, certificate: Certificate) -> None:
        existing = self._devices.get(device.key_id)
        if existing is None:
            self._devices[device.key_id] = device
        else:
            # first_seen is NOT overwritten. It is the answer to "when did this
            # device join the kith", and a renewal moving it forward would make
            # every device look like it enrolled at its last renewal.
            #
            # The name follows the NEWER record rather than the last writer, and
            # so does the SQL. A backlog replays in order, but a replay that
            # lands after a live write is out of order by definition, and an
            # unconditional overwrite would quietly revert a device's name to a
            # stale one during recovery from an outage.
            newer = device.last_seen >= existing.last_seen
            # `replace` ON THE EXISTING ROW, so a field nobody thought about
            # here keeps whatever the store already had rather than silently
            # reverting to a default. `record_seen` below lost `role` exactly
            # that way. Every field this method has an OPINION about is named;
            # anything else is carried.
            self._devices[device.key_id] = replace(
                existing,
                name=device.name if newer else existing.name,
                last_seen=max(existing.last_seen, device.last_seen),
                # The role follows the newer record like the name, WITH ONE
                # ADDITION that the SQL makes too: an empty incoming role never
                # overwrites a set one. A device re-enrolling against a plain
                # code would otherwise be silently stripped of its role, and the
                # symptom is a zippie android that quietly stops being one.
                #
                # This line was missing when roles landed, and rebuilding the
                # Device without it dropped the role on every path but the
                # first - which is exactly the divergence the paragraph above
                # says these two implementations must not have.
                role=device.role if (newer and device.role) else existing.role,
            )
        held = self._certificates.setdefault(device.key_id, [])
        # Replaying a deferred write must not duplicate a certificate. Serials
        # are unique by construction, so this is the same guard the SQL primary
        # key gives, stated here so both implementations behave identically.
        if any(c.serial == certificate.serial for c in held):
            return
        held.append(certificate)

    def record_seen(self, key_id: str, at: dt.datetime) -> None:
        device = self._devices.get(key_id)
        # Unknown key: nothing to touch. Not an error - a device can hold a
        # valid certificate this store has never heard of, which is exactly what
        # happens after an outage swallowed its issuance.
        if device is None or device.last_seen >= at:
            return
        # `replace`, NOT A FIELD-BY-FIELD REBUILD. This method touches exactly
        # one field, and listing the others meant every field added to `Device`
        # afterwards was silently dropped here - which is what happened to
        # `role` (muster#70): `_proven_device` calls `seen()` on every proven
        # request, so a device lost its role on the way IN to the very fetch
        # that needed it, and the SQL store - a plain `UPDATE ... SET last_seen`
        # - kept it. The two disagreed, and only the in-memory one is exercised
        # by the tests.
        self._devices[key_id] = replace(device, last_seen=at)

    def record_role(self, key_id: str, role: str) -> bool:
        device = self._devices.get(key_id)
        if device is None:
            return False
        # `replace`, for the reason `record_seen` above gives at length. NO
        # GUARD ON AN EMPTY ROLE, unlike `record_issuance`: there an empty one
        # never overwrites, so a re-enrolment cannot silently strip a handset;
        # here an operator is saying so deliberately and needs a way back.
        self._devices[key_id] = replace(device, role=role)
        return True

    def record_revocation(self, key_id: str, at: dt.datetime | None) -> bool:
        device = self._devices.get(key_id)
        if device is None:
            return False
        # BOTH DIRECTIONS THROUGH ONE METHOD, `at=None` being readmission. A
        # separate un-revoke would be a second write path to the same column,
        # and the one used less often is the one that would rot.
        #
        # A REVOCATION OR A READMISSION ALSO CLEARS WIPE-PENDING. Revoking and
        # wiping are two states, not one; an administrator choosing the second
        # state directly is saying the first no longer applies, and readmitting
        # a device that was waiting to be erased would otherwise be readmitted
        # into a wipe it did not ask for.
        self._devices[key_id] = replace(device, revoked_at=at, wipe_pending_at=None)
        return True

    def record_wipe_pending(self, key_id: str, at: dt.datetime | None) -> bool:
        device = self._devices.get(key_id)
        if device is None:
            return False
        # SETTING WIPE-PENDING CLEARS REVOCATION, and that ordering is the
        # whole of muster#15: `_proven_device` refuses a revoked key before it
        # serves anything, so a wipe requested on a revoked device would never
        # travel. The state that serves the wipe must therefore be the state
        # that removes the refusal.
        self._devices[key_id] = replace(device, revoked_at=None, wipe_pending_at=at)
        return True

    def record_wipe_acknowledged(self, key_id: str, at: dt.datetime) -> bool:
        device = self._devices.get(key_id)
        if device is None or device.wipe_pending_at is None:
            return False
        # THE DEVICE SAID IT IS ABOUT TO WIPE, so now - and only now - the
        # wipe-pending state becomes the refusal. Doing this in the same admin
        # call that set wipe-pending would starve the instruction; doing it
        # never would leave a wiped device readmitted as soon as it renewed.
        self._devices[key_id] = replace(device, revoked_at=at, wipe_pending_at=None)
        return True

    def record_collected(self, request_id: str, at: dt.datetime) -> None:
        for held in self._certificates.values():
            for index, certificate in enumerate(held):
                if certificate.request_id == request_id and certificate.collected_at is None:
                    held[index] = Certificate(
                        serial=certificate.serial,
                        request_id=certificate.request_id,
                        not_before=certificate.not_before,
                        not_after=certificate.not_after,
                        issued_at=certificate.issued_at,
                        certificate_pem=certificate.certificate_pem,
                        collected_at=at,
                    )
                    return

    def roll(self) -> list[Member]:
        members = [self._member(device) for device in self._devices.values()]
        members.sort(key=lambda m: m.device.first_seen)
        return members

    def member(self, key_id: str) -> Member | None:
        device = self._devices.get(key_id)
        return self._member(device) if device is not None else None

    def _member(self, device: Device) -> Member:
        held = self.history(device.key_id)
        newest = held[-1] if held else None
        return Member(
            device=device,
            certificates=len(held),
            current_serial=newest.serial if newest else None,
            not_after=newest.not_after if newest else None,
        )

    def history(self, key_id: str) -> list[Certificate]:
        # By (issued_at, serial), matching the SQL's ORDER BY. Sorting on the
        # timestamp alone leaves two certificates drained from the same backlog
        # in whatever order they happened to arrive, and `_member` takes the
        # last of these as the current one - so the two implementations would
        # disagree about which certificate a device is holding.
        return sorted(
            self._certificates.get(key_id, []), key=lambda c: (c.issued_at, c.serial)
        )

    def certificate_status(self, serial: str) -> CertificateStatus | None:
        for key_id, held in self._certificates.items():
            for certificate in held:
                if certificate.serial == serial:
                    return CertificateStatus(
                        certificate=certificate,
                        revoked_at=self._devices[key_id].revoked_at,
                    )
        return None

    def unexpired_revocations(self, at: dt.datetime) -> list[CertificateStatus]:
        statuses = [
            CertificateStatus(certificate=certificate, revoked_at=device.revoked_at)
            for key_id, device in self._devices.items()
            if device.revoked_at is not None
            for certificate in self._certificates.get(key_id, [])
            if certificate.not_after > at
        ]
        return sorted(statuses, key=lambda status: status.certificate.serial)

    def awaiting_collection(self, request_id: str) -> Certificate | None:
        for held in self._certificates.values():
            for certificate in held:
                if certificate.request_id == request_id and certificate.collected_at is None:
                    return certificate
        return None


def _close_quietly(connection) -> None:
    """Close a connection that is already on its way out.

    Logged at debug rather than swallowed outright: failing to close a socket
    that has just failed is genuinely uninteresting, but "uninteresting" and
    "invisible" are not the same thing, and a bare `except: pass` is how a
    surprising one goes unseen forever.
    """
    try:
        connection.close()
    except Exception as exc:  # noqa: BLE001 - already failing; closing is courtesy
        telemetry.log.debug("closing a failed kith connection raised: %s", exc)


def _connect_psycopg(dsn: str, timeout_s: int):
    """Open a connection that cannot hang, importing the driver when first needed.

    LAZY AND INJECTED. Lazy so that importing muster.api does not drag a
    database driver into the process that signs certificates until something
    actually needs one; injected so the tests can exercise every branch below
    without a Postgres, which neither the workstation nor the CI runner has.

    EVERY TIMEOUT HERE EXISTS BECAUSE THE DEFAULT IS "FOREVER":

      connect_timeout    the connect phase only
      statement_timeout  a query on an already-open socket, which
                         connect_timeout does not cover at all
      keepalives         notices a peer that went away silently, rather than
                         waiting for the next write to fail
      tcp_user_timeout   caps the kernel's retransmit budget, which otherwise
                         runs to about fifteen minutes on Linux

    A hang is worse here than an error, because an error is deferred and
    survived while a hang is held inside a lock (see STATEMENT_TIMEOUT_MS).
    """
    import psycopg

    return psycopg.connect(
        dsn,
        connect_timeout=timeout_s,
        # libpq takes server settings this way; -c options are applied to the
        # session as it opens, so the very first statement is already covered.
        options=f"-c statement_timeout={STATEMENT_TIMEOUT_MS}",
        keepalives=1,
        keepalives_idle=30,
        keepalives_interval=5,
        keepalives_count=3,
        # Linux only; libpq accepts and ignores it elsewhere, and production is
        # Linux. This is the one that bounds a silent peer.
        tcp_user_timeout=timeout_s * 1000,
        autocommit=False,
    )


class PostgresRecords:
    """The kith in the estate's CloudNativePG cluster.

    ONE CONNECTION, REOPENED ON FAILURE, rather than a pool. muster is
    replicas: 1 serving a handful of devices that renew every 90 days; a pool
    would add a dependency and a set of failure modes to a workload whose peak
    is a person clicking vouch. An idle connection does eventually get closed by
    the server or the network, so every failure closes it and the next attempt
    opens a fresh one - which is the same code path as recovering from the
    database having been down, and therefore the path that actually gets
    exercised.

    THE SCHEMA IS APPLIED ON EVERY (RE)CONNECT. It is create-only and
    idempotent, so this costs nothing, and it means a store that came back empty
    - a restored volume, a recreated cluster, a database nobody remembered to
    run the SQL against - starts working again without anybody diagnosing it.
    """

    def __init__(
        self,
        dsn: str,
        *,
        connect: Callable[[str, int], object] = _connect_psycopg,
        timeout_s: int = CONNECT_TIMEOUT_S,
    ) -> None:
        # .strip(), for the same reason api.py strips the admin token: a secret
        # created with `--from-file` fed by `print()` carries a trailing newline,
        # and a DSN with a newline in it fails to parse in a way that names
        # neither the newline nor the secret.
        self._dsn = dsn.strip()
        self._connect = connect
        self._timeout_s = timeout_s
        self._connection = None

    def describe(self) -> str:
        return "postgres"

    def permanent(self, exc: BaseException) -> bool:
        """Did the SERVER reject this row, as opposed to being out of reach?

        The split is psycopg's own: `OperationalError` and `InterfaceError` mean
        the connection - retry those forever, that is what the backlog is for.
        `DataError`, `IntegrityError` and `ProgrammingError` mean the server read
        the statement and refused it, and it will refuse it identically in an
        hour. A device named with a NUL byte is the concrete case: PostgreSQL
        `text` cannot hold one, so that row is undeliverable, and retrying it at
        the head of an ordered queue blocks every later write and reports a
        healthy database as unreachable.

        Imported here rather than at module scope for the same reason the
        connection is: nothing should pull in a database driver until a database
        is involved. By the time this is called one is - the exception came from
        it - so the import is already paid for.
        """
        if isinstance(exc, NoConnection):
            # Nothing ever saw the statement, so nothing has judged it.
            #
            # DELIBERATELY REDUNDANT with the isinstance list below, which
            # already cannot match NoConnection because it is not a psycopg
            # class. Kept because the thing it protects - a mistyped DSN raising
            # ProgrammingError out of psycopg's own parser, and being read as
            # "this row will never insert" - is silent, expensive, and one edit
            # to that tuple away. Stating it here puts the rule where a future
            # edit is, rather than leaving it to be inferred from a class
            # hierarchy in another library.
            return False
        try:
            import psycopg
        except ImportError:
            # No driver means this exception did not come from one, so it is not
            # ours to call permanent. Retry it; the backlog is bounded anyway.
            return False
        return isinstance(
            exc, (psycopg.DataError, psycopg.IntegrityError, psycopg.ProgrammingError)
        )

    # ---- connection ------------------------------------------------------

    def _open(self):
        if self._connection is not None:
            return self._connection
        try:
            connection = self._connect(self._dsn, self._timeout_s)
        except Exception as exc:  # noqa: BLE001 - anything here means no server
            # A bad host, a refused port, a DSN that will not parse: none of
            # them reached a server, so none of them can be a judgment on the
            # row. See NoConnection.
            raise NoConnection(f"{type(exc).__name__}: {exc}") from exc
        try:
            # No parameters, deliberately: psycopg only permits several
            # statements in one execute() when none are passed, and the schema
            # is several. There is nothing to parameterize in it anyway.
            with connection.cursor() as cursor:
                cursor.execute(SCHEMA.read_text())
            connection.commit()
        except Exception as exc:  # noqa: BLE001 - re-raised below, wrapped
            # Closed HERE, because this connection has not been stored yet and
            # so _run's cleanup cannot see it. A schema statement that fails -
            # a role without CREATE, say - would otherwise leak one socket per
            # attempt, forever, on a process that retries every sixty seconds.
            _close_quietly(connection)
            # NoConnection, not the driver's own class. A role that cannot
            # CREATE fails the schema with ProgrammingError, and that is not a
            # verdict on any row - every row is fine and the store is not ready.
            raise NoConnection(f"{type(exc).__name__}: {exc}") from exc
        self._connection = connection
        return connection

    def _run(self, work):
        """One unit of work, retried ONCE if the connection we had was stale.

        muster is quiet by design - a handful of devices renewing every ninety
        days - so its one connection is almost always idle, and an idle
        connection is the one a server, a CNPG switchover or a conntrack table
        eventually drops without telling anybody. The first request after a lull
        would then fail, open the breaker, and make muster answer 503 for the
        next thirty seconds every single time the database had quietly closed a
        socket nobody was using.

        So: if the connection was one we had been HOLDING, try once on a fresh
        one before calling the store unreachable. If it was fresh already, the
        failure is real and is reported as one - retrying that would just double
        the time an outage takes to be noticed.
        """
        reused = self._connection is not None
        try:
            return self._attempt(work)
        except Exception:
            if not reused:
                raise
            return self._attempt(work)

    def _attempt(self, work):
        """Run the work in one transaction, dropping the connection on error.

        The connection is discarded rather than reused after a failure because
        the cheap failures here are the ones that leave it unusable: a server
        that closed an idle socket, a CNPG primary that moved during failover.
        Reusing it would turn one outage into a permanent one for this pod.
        """
        connection = self._open()
        try:
            with connection.cursor() as cursor:
                result = work(cursor)
            connection.commit()
            return result
        except Exception:
            self._connection = None
            _close_quietly(connection)
            raise

    # ---- writes ----------------------------------------------------------

    def record_issuance(self, device: Device, certificate: Certificate) -> None:
        def work(cursor):
            # ON CONFLICT ON THE KEY, and first_seen is deliberately absent from
            # the update list. This one clause is what makes a renewal update
            # the same device instead of inserting a second one, and leaving
            # first_seen out is what stops every device looking like it enrolled
            # at its most recent renewal.
            cursor.execute(
                "INSERT INTO kith_device"
                " (key_id, fingerprint, name, first_seen, last_seen, role)"
                " VALUES (%s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (key_id) DO UPDATE SET"
                # The name follows the NEWER record, not the last writer. A
                # plain `name = EXCLUDED.name` is order-dependent, and the
                # backlog replays precisely when order has been lost: a deferred
                # issuance draining after a live one would revert the device's
                # name to the stale value, during recovery, silently.
                "   name = CASE WHEN EXCLUDED.last_seen >= kith_device.last_seen"
                "               THEN EXCLUDED.name ELSE kith_device.name END,"
                # The role follows the newer record for the same reason the name
                # does, and with one addition: an EMPTY incoming role never
                # overwrites a set one. A re-enrolment against a plain code
                # would otherwise silently strip a device of its role, and the
                # symptom is a zippie android that quietly stops being one.
                "   role = CASE WHEN EXCLUDED.role <> ''"
                "                AND EXCLUDED.last_seen >= kith_device.last_seen"
                "               THEN EXCLUDED.role ELSE kith_device.role END,"
                "   last_seen = GREATEST(kith_device.last_seen, EXCLUDED.last_seen)",
                (
                    device.key_id,
                    device.fingerprint,
                    device.name,
                    device.first_seen,
                    device.last_seen,
                    device.role,
                ),
            )
            # DO NOTHING, so replaying a deferred write is free. A backlog that
            # could not be replayed twice would have to be exactly-once, and
            # exactly-once across a network partition is not a thing this
            # process should be trying to implement.
            cursor.execute(
                "INSERT INTO kith_certificate"
                " (serial, key_id, request_id, not_before, not_after, issued_at,"
                "  certificate_pem)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (serial) DO NOTHING",
                (
                    certificate.serial,
                    device.key_id,
                    certificate.request_id,
                    certificate.not_before,
                    certificate.not_after,
                    certificate.issued_at,
                    certificate.certificate_pem,
                ),
            )

        self._run(work)

    def record_seen(self, key_id: str, at: dt.datetime) -> None:
        def work(cursor):
            # `last_seen < %s` makes replay order-independent: a deferred touch
            # that drains after a newer one cannot drag last_seen backwards.
            cursor.execute(
                "UPDATE kith_device SET last_seen = %s"
                " WHERE key_id = %s AND last_seen < %s",
                (at, key_id, at),
            )

        self._run(work)

    def record_role(self, key_id: str, role: str) -> bool:
        def work(cursor):
            # NO GUARD ON THE INCOMING VALUE, unlike the issuance upsert, which
            # refuses to let an empty role overwrite a set one. That rule exists
            # so a re-enrolment against a plain QR cannot silently strip a
            # handset; here an operator is saying "this is no longer a zippie
            # android" in as many words, and refusing would leave no way back.
            cursor.execute(
                "UPDATE kith_device SET role = %s WHERE key_id = %s",
                (role, key_id),
            )
            return cursor.rowcount

        return bool(self._run(work))

    def record_revocation(self, key_id: str, at: dt.datetime | None) -> bool:
        def work(cursor):
            # ONE STATEMENT BOTH WAYS. `at=None` writes NULL, which is
            # readmission. A separate un-revoke would be a second write path to
            # one column, and the one used less often is the one that rots.
            #
            # NOT TOUCHED BY THE ISSUANCE UPSERT, and that omission is
            # load-bearing rather than an oversight: `record_issuance`'s
            # DO UPDATE SET list has no `revoked_at`, so a renewal or a replayed
            # deferred write cannot readmit a device an administrator revoked.
            # Adding it there would also reintroduce the ordering hazard the
            # `name` and `role` clauses guard against, with a worse consequence.
            #
            # A REVOCATION OR A READMISSION ALSO CLEARS WIPE-PENDING, for the
            # reason `MemoryRecords` states: the two states are alternatives,
            # and a readmitted wipe-pending device must not walk back into a
            # wipe it did not ask for.
            cursor.execute(
                "UPDATE kith_device SET revoked_at = %s, wipe_pending_at = NULL"
                " WHERE key_id = %s",
                (at, key_id),
            )
            return cursor.rowcount

        return bool(self._run(work))

    def record_wipe_pending(self, key_id: str, at: dt.datetime | None) -> bool:
        def work(cursor):
            # SETTING WIPE-PENDING CLEARS REVOCATION. This is the ordering that
            # must not be got backwards: `_proven_device` refuses `revoked_at`
            # before any route serves anything, so a wipe-pending device that
            # stayed revoked would never receive the wipe file.
            cursor.execute(
                "UPDATE kith_device SET revoked_at = NULL, wipe_pending_at = %s"
                " WHERE key_id = %s",
                (at, key_id),
            )
            return cursor.rowcount

        return bool(self._run(work))

    def record_wipe_acknowledged(self, key_id: str, at: dt.datetime) -> bool:
        def work(cursor):
            # ONLY FROM WIPE-PENDING, and only once. The device has received the
            # instruction and is about to erase itself, so the serving state
            # becomes the refusing state at the moment the channel has done its
            # one job. Repeating the acknowledgement is refused rather than
            # making a second revocation row.
            cursor.execute(
                "UPDATE kith_device"
                "   SET revoked_at = %s, wipe_pending_at = NULL"
                " WHERE key_id = %s AND wipe_pending_at IS NOT NULL",
                (at, key_id),
            )
            return cursor.rowcount

        return bool(self._run(work))

    def record_collected(self, request_id: str, at: dt.datetime) -> None:
        def work(cursor):
            cursor.execute(
                "UPDATE kith_certificate SET collected_at = %s"
                " WHERE request_id = %s AND collected_at IS NULL",
                (at, request_id),
            )

        self._run(work)

    # ---- reads -----------------------------------------------------------

    # The roll and one member differ only by a WHERE, so they share the text.
    # Two near-identical queries is two places for the "newest certificate"
    # definition to drift, and a device list that disagreed with the device page
    # about which certificate is current would be a bad thing to debug.
    # `issued_at DESC, serial DESC`, AND THE SECOND KEY IS NOT DECORATION. These
    # are two independent scalar subqueries, so on an issued_at tie - two
    # certificates written from the same drained backlog, sharing a timestamp -
    # PostgreSQL is free to pick a different row for each, and the serial and
    # the expiry on one line would describe two different certificates. Serial
    # is unique, so it makes the order total. `MemoryRecords` sorts by the same
    # pair for the same reason; the two must not disagree about which
    # certificate is the current one.
    _ROLL = (
        "SELECT d.key_id, d.fingerprint, d.name, d.first_seen, d.last_seen,"
        "       count(c.serial),"
        "       (SELECT serial FROM kith_certificate n"
        "          WHERE n.key_id = d.key_id"
        "          ORDER BY n.issued_at DESC, n.serial DESC LIMIT 1),"
        "       (SELECT not_after FROM kith_certificate n"
        "          WHERE n.key_id = d.key_id"
        "          ORDER BY n.issued_at DESC, n.serial DESC LIMIT 1),"
        # LAST in the list, deliberately: `_member_from_row` reads by position,
        # so appending leaves every existing index meaning what it meant.
        "       d.role,"
        "       d.revoked_at,"
        # LAST, after revoked_at: `_member_from_row` reads by position, so
        # appending leaves every existing index meaning what it meant.
        "       d.wipe_pending_at"
        "  FROM kith_device d"
        "  LEFT JOIN kith_certificate c ON c.key_id = d.key_id"
    )

    def roll(self) -> list[Member]:
        def work(cursor):
            cursor.execute(self._ROLL + " GROUP BY d.key_id ORDER BY d.first_seen")
            return cursor.fetchall()

        return [_member_from_row(row) for row in self._run(work)]

    def member(self, key_id: str) -> Member | None:
        def work(cursor):
            cursor.execute(
                self._ROLL + " WHERE d.key_id = %s GROUP BY d.key_id", (key_id,)
            )
            return cursor.fetchone()

        row = self._run(work)
        return _member_from_row(row) if row is not None else None

    def history(self, key_id: str) -> list[Certificate]:
        def work(cursor):
            cursor.execute(
                "SELECT serial, request_id, not_before, not_after, issued_at,"
                "       certificate_pem, collected_at"
                "  FROM kith_certificate WHERE key_id = %s ORDER BY issued_at",
                (key_id,),
            )
            return cursor.fetchall()

        return [_certificate_from_row(row) for row in self._run(work)]

    def certificate_status(self, serial: str) -> CertificateStatus | None:
        def work(cursor):
            cursor.execute(
                "SELECT c.serial, c.request_id, c.not_before, c.not_after,"
                "       c.issued_at, c.certificate_pem, c.collected_at,"
                "       d.revoked_at"
                "  FROM kith_certificate c"
                "  JOIN kith_device d ON d.key_id = c.key_id"
                " WHERE c.serial = %s",
                (serial,),
            )
            return cursor.fetchone()

        row = self._run(work)
        return _certificate_status_from_row(row) if row is not None else None

    def unexpired_revocations(self, at: dt.datetime) -> list[CertificateStatus]:
        def work(cursor):
            cursor.execute(
                "SELECT c.serial, c.request_id, c.not_before, c.not_after,"
                "       c.issued_at, c.certificate_pem, c.collected_at,"
                "       d.revoked_at"
                "  FROM kith_certificate c"
                "  JOIN kith_device d ON d.key_id = c.key_id"
                " WHERE d.revoked_at IS NOT NULL AND c.not_after > %s"
                " ORDER BY c.serial",
                (at,),
            )
            return cursor.fetchall()

        return [_certificate_status_from_row(row) for row in self._run(work)]

    def awaiting_collection(self, request_id: str) -> Certificate | None:
        def work(cursor):
            cursor.execute(
                "SELECT serial, request_id, not_before, not_after, issued_at,"
                "       certificate_pem, collected_at"
                "  FROM kith_certificate"
                " WHERE request_id = %s AND collected_at IS NULL"
                " ORDER BY issued_at DESC LIMIT 1",
                (request_id,),
            )
            return cursor.fetchone()

        row = self._run(work)
        return _certificate_from_row(row) if row is not None else None


def _member_from_row(row) -> Member:
    return Member(
        device=Device(
            key_id=row[0],
            fingerprint=row[1],
            name=row[2],
            first_seen=row[3],
            last_seen=row[4],
            role=row[8] if len(row) > 8 else "",
            # SAME LENGTH GUARD AS `role`, and for the same reason: a row can
            # arrive from an older query shape during a rolling read, and
            # `None` here means "not revoked", which is the safe reading of a
            # column that is not there. Defaulting the other way would strand a
            # fleet on a column-ordering mistake.
            revoked_at=row[9] if len(row) > 9 else None,
            wipe_pending_at=row[10] if len(row) > 10 else None,
        ),
        certificates=row[5],
        current_serial=row[6],
        not_after=row[7],
    )


def _certificate_from_row(row) -> Certificate:
    return Certificate(
        serial=row[0],
        request_id=row[1],
        not_before=row[2],
        not_after=row[3],
        issued_at=row[4],
        certificate_pem=row[5],
        collected_at=row[6],
    )


def _certificate_status_from_row(row) -> CertificateStatus:
    return CertificateStatus(
        certificate=_certificate_from_row(row),
        revoked_at=row[7],
    )


# ---- the deferred writes, as data ---------------------------------------
#
# Modeled rather than closed over, so the backlog can be counted, inspected in
# a test, and replayed in the order it happened. A backlog of lambdas is a
# backlog nobody can look at when it is the thing that went wrong.


@dataclass(frozen=True)
class _Issuance:
    device: Device
    certificate: Certificate

    def apply(self, records: Records) -> None:
        records.record_issuance(self.device, self.certificate)


@dataclass(frozen=True)
class _Seen:
    key_id: str
    at: dt.datetime

    def apply(self, records: Records) -> None:
        records.record_seen(self.key_id, self.at)


@dataclass(frozen=True)
class _Collected:
    request_id: str
    at: dt.datetime

    def apply(self, records: Records) -> None:
        records.record_collected(self.request_id, self.at)


class Kith:
    """The record of the kith, and the policy that stops it taking muster down.

    Writes never raise. Reads raise `Unreachable`. See the module docstring for
    why those are different answers to the same outage.
    """

    def __init__(
        self,
        records: Records | None = None,
        *,
        clock: Callable[[], dt.datetime] | None = None,
        emitter: telemetry.Telemetry | None = None,
        backlog_max: int = BACKLOG_MAX,
        cooldown_s: float = COOLDOWN_S,
    ) -> None:
        self._records: Records = records if records is not None else MemoryRecords()
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        # A disabled emitter rather than None, so no call site needs a guard -
        # the guard that gets forgotten is always on the failure path.
        self._telemetry = emitter or telemetry.Telemetry()
        self._backlog: deque = deque()
        self._backlog_max = backlog_max
        self._cooldown_s = cooldown_s
        self._quiet_until: dt.datetime | None = None
        # ONE lock over the backlog and the records together. FastAPI runs these
        # sync endpoints in a threadpool, so two vouches can land at once, and a
        # single reused connection is not safe to share between them.
        self._lock = threading.RLock()
        self._flusher: threading.Thread | None = None
        self._stop = threading.Event()

    # ---- state, without touching the network -----------------------------

    def now(self) -> dt.datetime:
        """The kith's own clock, so a caller building a record uses this one.

        Exposed rather than letting call sites reach for datetime.now(): the
        clock is injected so tests can move it, and a call site with its own
        clock is a call site the tests cannot move.
        """
        return self._clock()

    def status(self) -> dict:
        """What to say on a health endpoint. No I/O, AND NO LOCK.

        A readiness probe that opens a database connection is a readiness probe
        that takes the pod out of service when the database goes away - which is
        precisely the outage this module exists to survive. It would stop
        issuance by a route no test of the issuance path would ever catch.

        NOT TAKING THE LOCK IS HALF OF THAT, and doing so was a bug here. Doing
        no I/O is not enough if the answer has to queue behind somebody else's:
        a read holding the lock through a slow query would block this call for
        as long as the query took, `/readyz` would time out (the probe allows
        one second by default), and three of those in a row would remove the pod
        from the Service. The database would then have stopped issuance without
        anything ever having consulted it.

        Safe without the lock because it only reads: one attribute and one deque
        length, neither of which can be observed half-updated. A slightly stale
        answer is exactly right for a health endpoint - a fresh answer that
        arrived too late is worth nothing.
        """
        return {
            "records": self._records.describe(),
            "state": "deferring" if self._quiet_until is not None else "ok",
            "deferred": len(self._backlog),
        }

    # ---- writes: deferred, never refused ---------------------------------

    def issued(self, device: Device, certificate: Certificate) -> None:
        self._defer(_Issuance(device=device, certificate=certificate), "issued")

    def seen(self, key_id: str) -> None:
        self._defer(_Seen(key_id=key_id, at=self._clock()), "seen")

    def set_role(self, key_id: str, role: str) -> bool:
        """Change what a device is for, without re-enrolling it.

        SYNCHRONOUS, AND DELIBERATELY NOT DEFERRED like `seen` and `collected`
        beside it. Those are best-effort: losing one costs a timestamp, and an
        outage must never fail the request a device is making. This is an
        OPERATOR ACTION with a person waiting on the answer - they are about to
        go and look at a handset expecting different policy - so a write that
        quietly joined a backlog would report success for something that had not
        happened yet.

        Returns whether a device was actually changed. False means the kith has
        never heard of that key, which a caller has to be able to tell apart
        from "done".
        """
        return bool(self._write_now(lambda records: records.record_role(key_id, role)))

    def set_revoked(self, key_id: str, revoked: bool) -> bool:
        """Say this device is no longer ours, or that it is again.

        SYNCHRONOUS, for the reason `set_role` above gives at length and one
        more that is specific to this: a revocation that quietly joined a
        backlog would tell an administrator a stolen device was cut off while it
        was still being answered. Of every write in this class, this is the one
        where "reported done, actually queued" is worst.

        Returns whether a device was actually changed. False means the kith has
        never heard of that key - which an administrator typing a key_id by hand
        needs to be able to tell apart from success.
        """
        return bool(
            self._write_now(
                lambda records: records.record_revocation(
                    key_id, self._clock() if revoked else None
                )
            )
        )

    def set_wipe_pending(self, key_id: str, wipe: bool) -> bool:
        """Ask for the device to be erased, without refusing it first.

        SYNCHRONOUS FOR THE SAME REASON AS `set_revoked`. An operator standing
        at the console needs to know whether the wipe-pending state was written,
        because the next thing they expect is the handset erasing itself - and a
        queued write would report that expectation as fact.

        Returns whether a device was actually changed. False means the kith has
        never heard of that key.
        """
        return bool(
            self._write_now(
                lambda records: records.record_wipe_pending(
                    key_id, self._clock() if wipe else None
                )
            )
        )

    def acknowledged_wipe(self, key_id: str) -> bool:
        """The wipe-pending device has received the instruction and is acting on it.

        SYNCHRONOUS, not deferred: this is the transition that turns the serving
        state into the refusing state, and losing it in a backlog would leave a
        device that has just wiped itself able to renew back into the kith.

        Returns whether a wipe-pending device was found and moved to revoked.
        False means there was no such device, or it was not wipe-pending - which
        a caller must be able to tell apart from success.
        """
        return bool(
            self._write_now(
                lambda records: records.record_wipe_acknowledged(key_id, self._clock())
            )
        )

    def collected(self, request_id: str) -> None:
        self._defer(_Collected(request_id=request_id, at=self._clock()), "collected")

    def _defer(self, entry, kind: str) -> None:
        with self._lock:
            if len(self._backlog) >= self._backlog_max:
                # The oldest goes. Every dropped entry is a device that exists
                # and will not be listed until it renews, so this is counted
                # rather than merely bounded - a silent bound is a fleet that
                # quietly stops appearing.
                self._backlog.popleft()
                self._telemetry.count("kith.write.dropped")
                telemetry.event(
                    "kith backlog full, dropped the oldest deferred write",
                    backlog=self._backlog_max,
                )
            self._backlog.append(entry)
            self._telemetry.count("kith.write", tags=[f"kind:{kind}"])
            self._drain()

    def flush(self) -> int:
        """Try the backlog. Returns how many entries are still deferred."""
        with self._lock:
            self._drain()
            return len(self._backlog)

    def _drain(self) -> None:
        """Replay what is owed, oldest first, stopping at the first UNREACHABLE.

        Stopping matters: the entries are ordered, and applying a later one over
        a failed earlier one would record a renewal for a device whose first
        issuance never landed - which the foreign key would refuse anyway, one
        row at a time, forever.

        THE ENTRY THE STORE WILL NEVER ACCEPT IS THE OTHER CASE, and treating it
        as an outage was a bug here. A row PostgreSQL refuses on its merits - a
        device name carrying a NUL byte, say - fails identically on every retry.
        At the head of an ordered queue that is not a delay, it is a wedge: every
        later write queues behind it forever, and because a failed drain opens
        the breaker, reads start answering "the store is unreachable" while the
        database is perfectly healthy. So a permanent refusal is dropped, loudly,
        and the drain carries on with the rest.
        """
        if self._quiet():
            return
        applied = False
        while self._backlog:
            entry = self._backlog[0]
            try:
                entry.apply(self._records)
            except Exception as exc:  # noqa: BLE001 - the store says which kind
                if not self._is_permanent(exc):
                    self._failed("write", exc)
                    return
                self._backlog.popleft()
                self._telemetry.count("kith.write.poison")
                # Named in the log, because this is a device that exists and
                # will never be listed, and the only way anybody learns which
                # one is if this line says so.
                telemetry.event(
                    "dropped a deferred kith write the store will never accept",
                    entry=type(entry).__name__.lstrip("_"),
                    error=f"{type(exc).__name__}: {exc}",
                )
                continue
            self._backlog.popleft()
            applied = True
        # Recovery is declared on a DEMONSTRATED success, never on an empty
        # backlog and never on the clock alone. Draining nothing proves nothing,
        # and a store that reported itself healthy because a timer expired would
        # be state this process made up.
        if applied:
            self._recovered()

    def _is_permanent(self, exc: Exception) -> bool:
        """Ask the store to classify a failure, and survive it not being able to.

        THE LAST UNGUARDED CALL ON THE WRITE PATH. Everything else in `_drain`
        is either a catch or arithmetic, but this one hands control back to the
        store while already inside an exception handler - and a classifier that
        raised would come straight out of `_defer`, into the vouch endpoint, and
        turn a certificate that was successfully signed into a 500. That is the
        single promise this module makes, so it should not rest on a method
        nobody expects to fail.

        Treated as NOT permanent, so the entry stays in the backlog: keeping a
        row that might be undeliverable is recoverable, and dropping one that
        was fine is not.
        """
        try:
            return self._records.permanent(exc)
        except Exception as unclassifiable:  # noqa: BLE001 - see the docstring
            telemetry.event(
                "the kith store could not say whether a write failure was permanent; "
                "keeping the entry",
                error=f"{type(unclassifiable).__name__}: {unclassifiable}",
            )
            return False

    # ---- reads: raise, never lie -----------------------------------------

    def roll(self) -> list[Member]:
        return self._read(lambda records: records.roll())

    def member(self, key_id: str) -> Member | None:
        return self._read(lambda records: records.member(key_id))

    def history(self, key_id: str) -> list[Certificate]:
        return self._read(lambda records: records.history(key_id))

    def certificate_status(self, serial: str) -> CertificateStatus | None:
        return self._read(lambda records: records.certificate_status(serial))

    def unexpired_revocations(self, at: dt.datetime) -> list[CertificateStatus]:
        return self._read(lambda records: records.unexpired_revocations(at))

    def awaiting_collection(self, request_id: str) -> Certificate | None:
        return self._read(lambda records: records.awaiting_collection(request_id))

    def _write_now(self, do):
        """A write that must NOT be deferred, with a caller waiting on it.

        THE SAME MACHINERY AS `_read` AND NOT AN ACCIDENT: drain the backlog
        first, refuse while the breaker is open, and report an unreachable store
        as `Unreachable` rather than as a quiet success. What makes it a
        different method is the intent it documents - `_defer` is for writes a
        DEVICE causes, where losing one costs a timestamp and failing the
        request would be worse; this is for writes an OPERATOR causes, where a
        silent queue means the console says done and the handset disagrees.
        """
        return self._read(do)

    def _read(self, ask):
        with self._lock:
            # Drained first, so a console reloaded after an outage both flushes
            # the backlog and then reads a store that already contains it.
            self._drain()
            if self._quiet():
                self._telemetry.count("kith.read.unreachable")
                raise Unreachable(UNREACHABLE)
            try:
                answer = ask(self._records)
            except Exception as exc:  # noqa: BLE001
                self._failed("read", exc)
                # The driver's own words go to the log, where they are useful,
                # and not into an HTTP response, where they are a libpq string
                # in a console and possibly a hostname on a screen.
                raise Unreachable(UNREACHABLE) from exc
            self._recovered()  # a read that answered is a store that is back
            return answer

    # ---- the breaker -----------------------------------------------------

    def _quiet(self) -> bool:
        """Are we still inside the cooldown after a failure?

        READ-ONLY. It deliberately does not clear the flag when the cooldown
        expires, which is the obvious way to write it and is wrong twice: the
        recovery log and metric would then never fire, because the flag they key
        off would already be gone by the time anything succeeded; and
        `status()`, which `/readyz` publishes, would flip back to "ok" on the
        clock alone, reporting a healthy store nothing had spoken to. Only
        `_recovered`, on a demonstrated success, clears it.
        """
        return self._quiet_until is not None and self._clock() < self._quiet_until

    def _failed(self, operation: str, exc: Exception) -> None:
        first = self._quiet_until is None
        self._quiet_until = self._clock() + dt.timedelta(seconds=self._cooldown_s)
        self._telemetry.count(
            "kith.store.unreachable", tags=[f"operation:{operation}"]
        )
        self._telemetry.gauge("kith.deferred", len(self._backlog))
        if first:
            # Once per outage, not once per request. A store that is down for an
            # hour would otherwise write the same line a thousand times and bury
            # whatever else was happening.
            telemetry.event(
                "the kith store is unreachable; issuing and renewing continue, "
                "and what happens meanwhile is being held to write later",
                operation=operation,
                error=f"{type(exc).__name__}: {exc}",
                deferred=len(self._backlog),
            )

    def _recovered(self) -> None:
        if self._quiet_until is None:
            return
        self._quiet_until = None
        telemetry.event("the kith store is answering again")
        self._telemetry.count("kith.store.recovered")

    # ---- the background flusher ------------------------------------------

    def start_flushing(self, interval_s: float = FLUSH_INTERVAL_S) -> None:
        """Retry the backlog on a timer, because nothing else may ever run.

        Deferred writes are otherwise replayed by the next enrollment, proof or
        console load, and on a fleet that renews every 90 days that can be
        weeks. A pod restarted in the meantime loses them. Daemon thread, so it
        can never hold a shutdown open.
        """
        if self._flusher is not None:
            return
        self._stop.clear()

        def loop() -> None:
            while not self._stop.wait(interval_s):
                self.flush()

        self._flusher = threading.Thread(
            target=loop, name="kith-flusher", daemon=True
        )
        self._flusher.start()

    def stop_flushing(self) -> None:
        """Stop retrying, then try ONE more time on the way out.

        Everything still deferred lives in this process and dies with it, so
        shutdown is the last chance it will ever get. The cooldown is cleared
        first, deliberately: a deploy that lands inside those thirty seconds
        would otherwise throw the backlog away without asking a store that may
        well be answering again. Bounded by the connect and statement timeouts,
        so it cannot hold the pod's termination grace period open.
        """
        self._stop.set()
        flusher, self._flusher = self._flusher, None
        if flusher is not None:
            flusher.join(timeout=5.0)
        with self._lock:
            if self._backlog:
                self._quiet_until = None
                self._drain()


def from_env(
    *,
    clock: Callable[[], dt.datetime] | None = None,
    emitter: telemetry.Telemetry | None = None,
) -> Kith:
    """Wire the kith from the environment.

    NO DSN IS NOT A STARTUP FAILURE, unlike administrator sign-in. Refusing to boot
    without a database would make the database a hard dependency of a process
    that must keep signing when the database is gone - the pod would
    CrashLoopBackOff through an outage it was designed to ride out. It falls
    back to memory and says so, at boot, in the logs and on /readyz, because
    "configured but absent" is the failure this estate keeps rediscovering.
    """
    dsn = os.environ.get("MUSTER_DATABASE_URL", "").strip()
    records: Records = PostgresRecords(dsn) if dsn else MemoryRecords()
    if not dsn:
        telemetry.event(
            "MUSTER_DATABASE_URL is not set: the kith is in memory only and will "
            "not survive a restart. Devices already issued to keep working - "
            "their certificate is their membership - but muster will not list "
            "them after a restart until they renew.",
            kith_durable=False,
        )
    return Kith(records, clock=clock, emitter=emitter)
