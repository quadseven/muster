"""Kith administration: who muster has issued to, and what an administrator may change.

Split out of api.py by audience (muster#218). Every route here is
administrator-only. `/v1/device/asset` used to be registered in
`_register_kith_routes` although a device reaches it; it now lives in
device_channel.py with the other routes that call `_proven_device`.

503 RATHER THAN AN EMPTY LIST when the store cannot be read, for the reason
`_register_kith_routes` gives.
"""
from __future__ import annotations

import datetime as dt
import os
from typing import TYPE_CHECKING, Callable

from fastapi import Body, FastAPI, HTTPException

from muster import kith as kith_store
from muster import policy, short_renewal, standing, telemetry

if TYPE_CHECKING:
    from muster.api import State

CHECK_IN_STALE_AFTER_PERIODS = int(
    os.environ.get("MUSTER_CHECK_IN_STALE_AFTER_PERIODS", "3")
)
if CHECK_IN_STALE_AFTER_PERIODS < 1:
    raise ValueError("MUSTER_CHECK_IN_STALE_AFTER_PERIODS must be at least 1")


def register(app: FastAPI, state: State, admin) -> None:
    """Every administrator route over the kith, in the order they must match.

    `/v1/kith/unrecorded` FIRST, because `/v1/kith/{key_id}` would otherwise
    take "unrecorded" as a key id and answer 404.
    """
    _register_unrecorded_route(app, state, admin)
    _register_short_renewal_route(app, state, admin)
    _register_kith_routes(app, state, admin)


def _role_or_400(role: str) -> str:
    """A role, or a 400 saying what one may be.

    THE SAME PATTERN AS EVERY OTHER DOOR A ROLE COMES THROUGH. `enroll.mint`
    checks at the QR, `policy.for_device` checks before it becomes half a
    filename, and this checks before it becomes a row. Without it a typo is a
    500 with a traceback in the log of the process that holds the CA, for what
    is an operator mistyping into a text box.
    """
    if not role:
        return ""
    if not enroll_role_pattern().match(role):
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{role}' is not a role: lowercase letters, digits and dashes, "
                "starting with a letter, at most 31 characters. A role becomes "
                "half of a policy file name and a Kubernetes Secret key."
            ),
        )
    return role


def enroll_role_pattern():
    """The one pattern, imported rather than restated.

    `enroll` and `policy` each keep their own copy and a test pins them equal -
    that is the house convention for a boundary check. A THIRD copy here would
    be a third thing to keep in step, and this module is not a boundary of the
    same kind: it is the console's door, and the console is not a device.
    """
    from muster.enroll import _ROLE

    return _ROLE


def _report_view(report: kith_store.Report | None) -> dict | None:
    """A stored report as JSON, with its concern count up front for a monitor."""
    if report is None:
        return None
    return {
        "received_at": report.received_at.isoformat(),
        "concerns": sum(len(step.concerns) for step in report.steps),
        "steps": [
            {"name": s.name, "outcome": s.outcome, "concerns": list(s.concerns)}
            for s in report.steps
        ],
        "packages": [
            {"package": p.package, "version_code": p.version_code}
            for p in report.packages
        ],
        "security_patch": report.security_patch,
        "build_id": report.build_id,
        "pending_update": report.pending_update,
    }


# WHAT COUNTS AS DRIFT (muster#162). `ahead` is not: the agent leaves a newer
# build alone because Android refuses the downgrade, and a newer version is what
# a hand-installed build looks like. `unreadable` is: muster cannot read a
# version from the line, the agent refuses it, and nothing will update it.
_DRIFTED = frozenset({"behind", "absent", "unreported", "unreadable"})


def _package_state(expected: int | None, reported: bool, installed: int | None) -> str:
    """Where one package a device is told to carry stands against its report."""
    if expected is None:
        return "unreadable"
    if not reported:
        # Named now, and not in the report: the policy moved on after it.
        return "unreported"
    if installed is None:
        return "absent"
    if installed < expected:
        return "behind"
    return "current" if installed == expected else "ahead"


def _drift_view(report: kith_store.Report, expected: dict[str, int | None]) -> dict:
    """Each package `install-apps` names for this device, against what it reported.

    ONLY WHAT MUSTER SHIPS. The expectation is `install-apps` and nothing
    else, so a package the device reports that muster does not install - a
    Play-managed application, say - is never drift. muster cannot update it,
    and a row saying it is behind would be a promise nothing here can keep.
    """
    installed = {p.package: p.version_code for p in report.packages}
    packages = [
        {
            "package": package,
            "expected_version_code": wanted,
            "installed_version_code": installed.get(package),
            "state": _package_state(wanted, package in installed, installed.get(package)),
        }
        for package, wanted in expected.items()
    ]
    return {
        "known": True,
        "drifted": sum(p["state"] in _DRIFTED for p in packages),
        "packages": packages,
    }


def _drift(state: State, device: kith_store.Device, report) -> dict | None:
    """The device's drift, null if it never reported, or why it is unknown.

    UNKNOWN IS SAID, NOT SHORTENED. A policy muster cannot read is not "nothing
    expected", so it does not become an empty list that reads as nothing
    behind. Nor is it a 503: this route also carries the device's certificates,
    and a question about applications should not hide them.
    """
    if report is None:
        return None
    try:
        served = state.policies.for_device(device.key_id, role=device.role)
    except (policy.Unreadable, policy.NoSource) as cannot_say:
        telemetry.event(
            "muster cannot say what a device should carry",
            key_id=device.key_id, error=str(cannot_say),
        )
        return {"known": False, "reason": str(cannot_say)}
    install_apps = served.files.get(policy.INSTALL_APPS_FILE, "")
    return _drift_view(report, policy.expected_versions(install_apps))


def _policy_concerns(state: State, device: kith_store.Device) -> dict:
    """Policy shadowing this device's operator should see (muster#181).

    A role or device file may override a kith-level `install-apps` package -
    the merge allows it, and the device gets the more specific line. This is
    where that override is said out loud: an operator writing "every device
    runs agent N" at the kith level can see which of their devices are
    actually carrying a different line for that package.

    THE SHAPE IS DRIFT'S SHAPE, and for the same reason. A policy muster
    cannot read is not "nothing shadowed", so it says `known: False` and the
    reason rather than an empty list - but it is still not a 503, because this
    route also carries the device's certificates and a question about policy
    should not hide them.
    """
    try:
        shadowed = state.policies.install_apps_shadowed(
            device.key_id, role=device.role
        )
    except (policy.Unreadable, policy.NoSource) as cannot_say:
        telemetry.event(
            "muster cannot say what a device should carry",
            key_id=device.key_id,
            error=str(cannot_say),
        )
        return {"known": False, "reason": str(cannot_say)}
    return {
        "known": True,
        "concerns": [
            {
                "package": s.package,
                "scope": s.scope,
                # Which role, when the role file won; null for a device file.
                "role": s.role or None,
                "shadowed_line": s.shadowed_line,
                "winner_line": s.winner_line,
            }
            for s in shadowed
        ],
    }


def _register_short_renewal_route(app: FastAPI, state: State, admin) -> None:
    """The administrator's lever for muster#22. Its own registrar, because
    `_register_kith_routes` is already over the complexity cap."""

    @app.post("/v1/kith/{key_id}/short-renewal", dependencies=[admin])
    def set_short_renewal(
        key_id: str,
        armed: bool = Body(default=True, embed=True),
        lifetime_hours: int = Body(
            default=short_renewal.DEFAULT_HOURS,
            embed=True,
            ge=short_renewal.MIN_HOURS,
            le=short_renewal.MAX_HOURS,
        ),
    ):
        """Make this device's NEXT renewal short-lived, once (muster#22).

        The device's next check-in is told it may renew now; the renewal after
        that is issued for `lifetime_hours` with the 14-day runway floor waived
        for that issuance only, and this clears itself. The renewal after THAT
        finds nothing armed and returns a standard certificate.

        `armed: false` cancels a request not yet used. Neither direction can
        touch any other device, and neither revokes or replaces the certificate
        the device holds now.

        REFUSES A REVOKED DEVICE, which could not renew anyway: arming it would
        be an instruction that sits unused while reading as if it would act.
        """
        if not armed:
            dropped = state.short_renewals.disarm(key_id)
            telemetry.event(
                "short renewal cancelled", key_id=key_id, was_armed=dropped is not None
            )
            return {"key_id": key_id, "short_renewal": None}
        try:
            member = state.kith.member(key_id)
        except kith_store.Unreachable as exc:
            state.telemetry.count("kith.read.refused")
            raise HTTPException(
                status_code=503,
                detail=f"{exc}. Nothing was armed; retry.",
            ) from exc
        if member is None:
            raise HTTPException(status_code=404, detail="no such device")
        if member.device.revoked_at is not None:
            raise HTTPException(
                status_code=409,
                detail="this device is revoked and cannot renew; readmit it first",
            )
        request = short_renewal.Armed(
            lifetime=dt.timedelta(hours=lifetime_hours),
            armed_at=state.kith.now(),
        )
        state.short_renewals.arm(key_id, request)
        telemetry.event(
            "short renewal armed",
            key_id=key_id,
            lifetime_hours=lifetime_hours,
            armed_at=request.armed_at.isoformat(),
        )
        state.telemetry.count("kith.short_renewal.armed")
        return {
            "key_id": key_id,
            "short_renewal": {
                "lifetime_hours": lifetime_hours,
                "armed_at": request.armed_at.isoformat(),
            },
        }


def _changed_or_refused(write, unreachable) -> None:
    """One shape for every administrator write to a device row.

    `set_role` and `set_revoked` had this three-line dance each, character for
    character, and it is three lines where getting any of them wrong is silent:
    a swallowed `Unreachable` reports done for a write that never happened, and
    a dropped rowcount check reports done for a key_id that does not exist. An
    administrator acts on both answers - they go and look at a handset, or they
    stop looking for a device they believe is cut off - so "wrong but quiet" is
    the whole failure mode.

    AT MODULE LEVEL rather than nested in the registrar, which is not stylistic:
    complexity is scored over a function's whole subtree, so a helper defined
    inside `_register_kith_routes` would move these branches around without
    removing them from its count. Out here it is also independently readable,
    which is the actual point.
    """
    try:
        changed = write()
    except kith_store.Unreachable as exc:
        raise unreachable(exc) from exc
    if not changed:
        raise HTTPException(status_code=404, detail="no such device")


def _refuse_unless_permitted(
    state: State,
    key_id: str,
    verb: str,
    unreachable: Callable[[kith_store.Unreachable], HTTPException],
) -> None:
    """The refusal `standing.permits` gives an administrator verb, if any (muster#217).

    READS ONLY WHEN A REFUSAL IS POSSIBLE. Most administrator verbs are
    permitted from every standing, and `standing.refusable` says which are
    not, so revoke and wipe keep writing without a read in front of them.
    Arming a reboot on a revoked device is the one refusal today (D30): a
    plain read before the write, which D30 accepts because the race it leaves
    lands an inert flag on a device that is refused every request anyway.

    A missing device is not refused here: the write after this answers 404,
    the same as every other administrator write to a device row.

    THE UNREACHABLE-HANDLER IS A PARAMETER, matching `_changed_or_refused`,
    because `_unreachable` is a closure in another registrar (muster#59).
    """
    if not standing.refusable(verb):
        return
    try:
        member = state.kith.member(key_id)
    except kith_store.Unreachable as exc:
        raise unreachable(exc) from exc
    if member is None:
        return
    answer = standing.permits(standing.Standing.of(member.device), verb)
    if isinstance(answer, standing.Refusal):
        raise HTTPException(status_code=answer.status, detail=answer.detail)


def _register_unrecorded_route(app: FastAPI, state: State, admin) -> None:
    """What muster signed and the store does not hold (muster#166).

    ITS OWN REGISTRAR, CALLED BEFORE `_register_kith_routes`, because
    `/v1/kith/{key_id}` would otherwise take "unrecorded" as a key id and
    answer 404.
    """

    @app.get("/v1/kith/unrecorded", dependencies=[admin])
    def unrecorded():
        """Every certificate signed here that the store does not hold, by device.

        NEVER 503. It reads only this process's memory, so it answers while the
        store is down, which is when the roll cannot and when the question "is
        THIS phone on the roll" has an interesting answer.
        """
        return {"store": state.kith.status(), "unrecorded": _unrecorded(state)}


def _register_kith_routes(app: FastAPI, state: State, admin) -> None:
    """Who muster has issued to. The first endpoints that can answer at all.

    503 RATHER THAN AN EMPTY LIST when the store cannot be read. A console
    rendering "no devices" over an unreachable database is a lie that reads
    exactly like a fleet that has vanished, and the operator's next move is to
    go looking for devices rather than for a database.
    """

    def _unreachable(exc: kith_store.Unreachable) -> HTTPException:
        state.telemetry.count("kith.read.refused")
        return HTTPException(
            status_code=503,
            detail=f"{exc}. Devices already issued to are unaffected: a "
                   "certificate is what makes a device part of the kith.",
        )

    @app.get("/v1/kith", dependencies=[admin])
    def roll():
        try:
            members = state.kith.roll()
            reports = state.kith.reports()
        except kith_store.Unreachable as exc:
            raise _unreachable(exc) from exc
        return {
            "store": state.kith.status(),
            "devices": [_member(m, reports.get(m.device.key_id)) for m in members],
            # BESIDE THE ROLL, the devices muster signed for and the store does
            # not hold (muster#166). After an outage that dropped writes, the
            # roll answers again and these are the phones missing from it.
            "unrecorded": _unrecorded(state),
        }

    @app.post("/v1/kith/{key_id}/role", dependencies=[admin])
    def set_device_role(key_id: str, role: str = Body(default="", embed=True)):
        """Change what a device is FOR, without re-enrolling it.

        WHY THIS EXISTS (muster#73). A role arrived on a pairing code and was
        written at issuance, so changing one meant wiping a handset and
        provisioning it again - for a text field. That was a limitation of how
        the role got there, not of what a role is: policy is resolved from the
        kith on every fetch, so the device picks up its new scope at its next
        check-in with nothing else to do.

        AN EMPTY ROLE IS A DELIBERATE CLEAR, not a no-op. `record_issuance`
        refuses to let an empty role overwrite a set one, because a re-enrolment
        against a plain QR must not silently strip a handset. Here an operator
        is saying "this is no longer a zippie android" in as many words, and
        refusing would leave no way back.

        ADMINISTRATOR-ONLY, and it belongs to that set rather than the device
        one for a reason worth stating: a role selects which policy scope is
        served, INCLUDING `app-config`, which carries write tokens. A device
        that could set its own role could ask for another role's credentials.
        """
        # NOT a silent success on either failure. The operator is about to go
        # and look at a handset expecting different policy.
        _changed_or_refused(
            lambda: state.kith.set_role(key_id, _role_or_400(role)), _unreachable
        )
        telemetry.event("device role changed", key_id=key_id, role=role or "(none)")
        state.telemetry.count("kith.role.changed")
        return {"key_id": key_id, "role": role}

    @app.post("/v1/kith/{key_id}/name", dependencies=[admin])
    def set_device_name(key_id: str, name: str = Body(default="", embed=True)):
        """Let an administrator label a device (muster#29).

        WHY THIS EXISTS. `name` comes from the vouch, where an operator typed
        the model - and three devices vouched for as "Pixel 6a" made the wipe
        confirmation dialog show the same words for three different handsets,
        which is exactly the disambiguation `$('device-action-name')` was built
        to provide (muster#26). Nothing on the zippie side can fix this: leg
        names are deliberately uncorrelated with device identity (`LegName.kt`).

        WHY THIS IS NOT JUST `name`. That column is written by `record_issuance`
        on every renewal and follows the device's own report, so a rename
        stored there would be silently reverted the next time the device checks
        in - see `admin_name` in kith.py and the schema comment beside it. This
        writes the separate column that renewal never touches.

        AN EMPTY NAME IS A DELIBERATE CLEAR, the same shape as an empty role
        above: it removes the override and falls back to the device's own
        reported name, rather than setting an empty label.

        ADMINISTRATOR-ONLY, and for the sharpest possible reason: this exists
        so an administrator can tell devices apart before acting on one. A
        device that could rename itself could make that confirmation lie in
        exactly the way this endpoint exists to stop.
        """
        cleaned = name.strip()
        if len(cleaned) > 200:
            raise HTTPException(
                status_code=400,
                detail="a device name is shown in a confirmation dialog, not "
                       "stored as a document; 200 characters is the cap",
            )
        _changed_or_refused(
            lambda: state.kith.set_admin_name(key_id, cleaned or None), _unreachable
        )
        telemetry.event("device renamed", key_id=key_id, name=cleaned or "(cleared)")
        state.telemetry.count("kith.name.changed")
        return {"key_id": key_id, "admin_name": cleaned or None}

    @app.post("/v1/kith/{key_id}/wipe", dependencies=[admin])
    def set_device_wipe(key_id: str, wipe: bool = Body(default=True, embed=True)):
        """Ask for this device to be erased, WITHOUT refusing it first.

        WHY THIS IS A SEPARATE STATE AND NOT A FLAG ON /revoke (muster#15).
        `_proven_device` refuses a revoked key before anything is served, so a
        single call that sets both `wipe_pending_at` and `revoked_at` would
        remove the only channel the wipe instruction could travel down. This
        endpoint sets wipe-pending and clears revocation; the device fetches
        the wipe file, acknowledges it on /v1/device/wipe, and only then does
        it become revoked. Calling it off restores a revocation it lifted.

        `wipe: false` cancels a wipe request and restores the standing the
        device held before it was queued. An active device stays active, and
        a device whose revocation the erase lifted is revoked again, at its
        original time. It never readmits a device.
        """
        verb = standing.WIPE if wipe else standing.CALL_OFF_WIPE
        _refuse_unless_permitted(state, key_id, verb, _unreachable)
        _changed_or_refused(lambda: state.kith.set_wipe_pending(key_id, wipe), _unreachable)
        telemetry.event(
            "device wipe requested" if wipe else "device wipe cancelled",
            key_id=key_id,
        )
        state.telemetry.count(
            "kith.wipe_pending.changed", tags=[f"wipe:{str(wipe).lower()}"]
        )
        return {"key_id": key_id, "wipe_pending": wipe}

    @app.post("/v1/kith/{key_id}/reboot", dependencies=[admin])
    def set_device_reboot(key_id: str, reboot: bool = Body(default=True, embed=True)):
        """Ask this device to reboot itself at its next check-in (muster#58).

        WHY THIS EXISTS. A phone whose foreground service died mid-session, or
        that is otherwise stuck without having crashed outright, had no remote
        lever between "do nothing" and "erase it" - revoke and wipe are both
        far stronger than the problem calls for.

        NOT THE RIGHT TOOL FOR A LIVE SERVICE THAT DIED, and this belongs in
        docs/policy.md as plainly as it belongs here. Reboot fixes a crash
        loop or corrupted state; it does not obviously fix a foreground
        service Android killed for being backgrounded, because a phone with a
        lock screen may come back up unable to do anything requiring an
        unlocked keyguard - `CheckInSchedulePolicy.kt`'s own history is a
        phone that rebooted and could not announce itself again until someone
        physically unlocked it. Reaching for this on "the app went quiet"
        alone can turn a recoverable state into one that needs a physical tap
        anyway.

        REFUSES A REVOKED DEVICE OUTRIGHT WHEN ARMING, unlike wipe.
        `set_wipe_pending` clears `revoked_at` because wipe supersedes
        revocation (muster#15) - erasing is the stronger action, so
        readmitting to deliver it is correct. A reboot is the opposite: far
        weaker than revocation, and silently readmitting a device an
        administrator revoked on purpose just to reboot it would be a
        dangerous surprise rather than a convenience. `standing.permits` says
        so, and `_refuse_unless_permitted` does a plain read before the write
        rather than a database-level guard - accepted here because
        the race it leaves (revoking and reboot-arming the same device in the
        same instant, from two admin calls) leaves an inert flag on a device
        that already refuses every request, not a security property like
        wipe's ordering protects. It lives outside this route (Grug: this
        registrar was already over the complexity cap) rather than inline.

        `reboot: false` CANCELS AN UNDELIVERED INSTRUCTION, and is refused
        nothing - cancelling never touches `revoked_at` either way, so there
        is no surprise-readmission risk to guard against, and an operator
        clearing a stale request should never be blocked by the device's
        revocation state.

        ADMINISTRATOR-ONLY, for the same reason as wipe: a device that could
        reboot itself on request could be told to by whatever compromised it,
        at a moment of the attacker's choosing.
        """
        verb = standing.REBOOT if reboot else standing.CALL_OFF_REBOOT
        _refuse_unless_permitted(state, key_id, verb, _unreachable)
        _changed_or_refused(
            lambda: state.kith.set_reboot_requested(key_id, reboot), _unreachable
        )
        telemetry.event(
            "device reboot requested" if reboot else "device reboot cancelled",
            key_id=key_id,
        )
        state.telemetry.count(
            "kith.reboot_requested.changed", tags=[f"reboot:{str(reboot).lower()}"]
        )
        return {"key_id": key_id, "reboot_requested": reboot}

    @app.post("/v1/kith/{key_id}/revoke", dependencies=[admin])
    def set_device_revoked(key_id: str, revoked: bool = Body(default=True, embed=True)):
        """This device is no longer ours - or, with `revoked: false`, it is again.

        WHAT THIS DOES: muster stops answering the device. Every route a device
        can reach goes through `_proven_device`, which refuses a revoked key
        before anything is served, so configuration, assets and renewal all stop
        together and stay stopped.

        WHAT IT DOES NOT DO, and an administrator revoking a stolen device needs
        to know this in the same breath: it cannot reach into a device that has
        already cached a credential. A router that fetched its datapath key
        yesterday still holds it. Revocation stops the NEXT delivery; it does
        not retract the last one. Cutting a stolen device off from what it
        already has means rotating the credential at the other end too, and
        those are two actions rather than one.

        THE ROW IS THE RECORD; THE CRL AND OCSP RESPONDER ARE VIEWS OF IT.
        muster's own routes never consult either - `_proven_device` reads the
        row, so there is no staleness for a device asking muster. The artifacts
        (`revocation.py`, muster#23) exist for a relying party that is not
        muster, and lag this row by at most `FRESHNESS` (D28).

        REVERSIBLE, because an administrator can revoke the wrong key_id and the
        alternative to a way back is wiping a device to re-enroll it. It is the
        same argument the empty role makes next door.
        """
        # NOT a silent success, and here that matters more than anywhere else in
        # this file: an administrator who believes a stolen device is cut off
        # stops looking for it.
        verb = standing.REVOKE if revoked else standing.READMIT
        _refuse_unless_permitted(state, key_id, verb, _unreachable)
        _changed_or_refused(lambda: state.kith.set_revoked(key_id, revoked), _unreachable)
        telemetry.event(
            "device revoked" if revoked else "device readmitted", key_id=key_id
        )
        state.telemetry.count(
            "kith.revocation.changed", tags=[f"revoked:{str(revoked).lower()}"]
        )
        return {"key_id": key_id, "revoked": revoked}

    @app.get("/v1/kith/{key_id}", dependencies=[admin])
    def device(key_id: str):
        """One device and every certificate it has ever been issued.

        The certificate list is what makes renewal visible: a device that has
        renewed twice is ONE entry here with three certificates, not three
        devices. That is the property the whole table layout exists for, so it
        is worth being able to see it without a database client.
        """
        try:
            member = state.kith.member(key_id)
            if member is None:
                raise HTTPException(status_code=404, detail="no such device")
            history = state.kith.history(key_id)
            report = state.kith.report(key_id)
        except kith_store.Unreachable as exc:
            raise _unreachable(exc) from exc
        return {
            "device": _member(member, report),
            # WHAT IT LAST SAID IT DID (muster#146), or null if it never said.
            # Null and not an empty report: an empty one would read as every
            # step fine and nothing installed.
            "report": _report_view(report),
            # WHAT IT CARRIES AGAINST WHAT IT IS TOLD (muster#162), or null
            # when there is no report to compare.
            "drift": _drift(state, member.device, report),
            # WHERE WHAT IT IS TOLD DIFFERS FROM THE KITH'S INTENT (muster#181):
            # a role or device file overriding a kith-level install-apps line.
            # Unlike drift this does not need the device to have reported -
            # it is a property of the policy, not of the last check-in.
            "concerns": _policy_concerns(state, member.device),
            "certificates": [
                {
                    "serial": c.serial,
                    "not_before": c.not_before.isoformat(),
                    "not_after": c.not_after.isoformat(),
                    "issued_at": c.issued_at.isoformat(),
                    "collected_at": c.collected_at.isoformat() if c.collected_at else None,
                    "certificate_pem": c.certificate_pem,
                }
                for c in history
            ],
        }


def _unrecorded(state: State) -> list[dict]:
    """Each certificate the store does not hold, with the device it was signed for."""
    return [
        {
            "key_id": entry.device.key_id,
            "fingerprint": entry.device.fingerprint,
            "name": entry.device.name,
            "serial": entry.certificate.serial,
            "not_before": entry.certificate.not_before.isoformat(),
            "not_after": entry.certificate.not_after.isoformat(),
            "issued_at": entry.certificate.issued_at.isoformat(),
            # "deferred": still in the backlog, will be written when the store
            # answers. "dropped": nothing will write it until the device proves.
            "state": entry.state,
        }
        for entry in state.kith.unrecorded()
    ]


def _member(member: kith_store.Member, report: kith_store.Report | None = None) -> dict:
    """One device on the roll, as JSON.

    `certificates` is a COUNT and not a list on this shape deliberately: the
    roll is what a console renders for the whole estate, and inlining every PEM
    would make listing ten devices a megabyte.
    """
    return {
        "key_id": member.device.key_id,
        "fingerprint": member.device.fingerprint,
        "name": member.device.name,
        # WHAT AN ADMINISTRATOR CALLS IT (muster#29). null is the ordinary
        # case, meaning no override - a console decides what to DISPLAY, this
        # is not that decision made for it. Kept apart from `name` so the
        # console can still show what the device itself reports.
        "admin_name": member.device.admin_name,
        # WHETHER A REBOOT IS WAITING (muster#58). null is the ordinary case.
        # Same shape as wipe_pending_at below, one severity down.
        "reboot_requested_at": (
            member.device.reboot_requested_at.isoformat()
            if member.device.reboot_requested_at is not None
            else None
        ),
        # What the device reported, or null (muster#77).
        "check_in_interval_s": member.device.check_in_interval_s,
        "check_in_stale_after_periods": CHECK_IN_STALE_AFTER_PERIODS,
        # WHAT IT IS FOR (muster#70). Absent until now, so a console could show
        # a fleet of devices and not one of them said which policy it was on -
        # and the answer is the difference between a handset that carries a
        # write token and one that does not.
        "role": member.device.role,
        # WHETHER IT IS STILL OURS. null is the ordinary case. On the roll as
        # well as the single-device view, because the question a console is most
        # often opened to answer during an incident is "is that thing cut off",
        # and an answer only reachable one device at a time is one an operator
        # checks for the device they suspect and no other.
        "revoked_at": (
            member.device.revoked_at.isoformat()
            if member.device.revoked_at is not None
            else None
        ),
        "wipe_pending_at": (
            member.device.wipe_pending_at.isoformat()
            if member.device.wipe_pending_at is not None
            else None
        ),
        # WHAT AN ADMINISTRATOR MAY DO NEXT (muster#217), from `standing.offered`.
        # The console draws its buttons from this list rather than deciding
        # again, so the console and the server cannot rule differently.
        "offered": list(standing.offered(standing.Standing.of(member.device))),
        "first_seen": member.device.first_seen.isoformat(),
        "last_seen": member.device.last_seen.isoformat(),
        "certificates": member.certificates,
        "serial": member.current_serial,
        "not_after": member.not_after.isoformat() if member.not_after else None,
        "security_patch": report.security_patch if report is not None else None,
        "build_id": report.build_id if report is not None else None,
        "pending_update": report.pending_update if report is not None else None,
    }
