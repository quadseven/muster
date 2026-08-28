"""The enrollment exchange, and every way it says no.

These tests are the reason the state machine is separate from HTTP: each rule
here is about time or about a wrong answer, and both are miserable to exercise
through a web framework. The clock is injected, so every expiry rule is a
one-line move rather than a sleep.

The one to read first is `test_a_racer_who_guesses_the_code_still_needs_a_vouch`.
It is the attack the design exists to survive, and it is the reason `vouch()`
takes a fingerprint at all.

Then read `test_a_scanned_code_is_not_guessable_because_nothing_compares_it`,
which is the same attack against a device nobody is holding. There is no second
screen there, so the vouch cannot catch the racer - and the answer is that the
racer cannot reach the queue at all.
"""
from __future__ import annotations

import pytest

from muster.enroll import (
    MAX_ATTEMPTS,
    MAX_CODE_LENGTH,
    Enrollment,
    Outcome,
    Refused,
    Shape,
    fingerprint,
)

CSR = b"-----BEGIN CERTIFICATE REQUEST-----fake"
PUB = b"\x30\x59\x30\x13device-public-key"
OTHER_PUB = b"\x30\x59\x30\x13somebody-elses-key"


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


@pytest.fixture()
def enroll():
    return Enrollment(clock=Clock())


def _present(e, code, pub=PUB, name="pixel-6a"):
    return e.present(code, CSR, pub, name)


# ---- the happy path ------------------------------------------------------


def test_a_vouched_device_is_issued(enroll):
    code = enroll.mint()
    pending = _present(enroll, code)
    vouched = enroll.vouch(pending.request_id, pending.fingerprint)
    assert vouched.csr_der == CSR
    assert vouched.device_name == "pixel-6a"


def test_the_fingerprint_is_readable_aloud(enroll):
    """It exists to be compared BY EYE between a console and a phone. An
    unbroken 64-char hex run is the shape people skim instead of checking."""
    fp = fingerprint(PUB)
    assert fp.count(" ") == 3 and len(fp) == 19
    assert fp == fp.upper()


def test_the_same_key_always_fingerprints_the_same(enroll):
    assert fingerprint(PUB) == fingerprint(PUB)
    assert fingerprint(PUB) != fingerprint(OTHER_PUB)


# ---- THE attack ----------------------------------------------------------


def test_a_racer_who_guesses_the_code_still_needs_a_vouch(enroll):
    """The case the whole design is shaped around.

    Six digits is guessable. Assume the attacker wins the race and presents
    THEIR key against the administrator's freshly minted code. The
    administrator is holding their own phone, reading their own fingerprint off
    it. Vouching must fail, because the pending request carries a fingerprint
    that is not the one in their hand.
    """
    code = enroll.mint()
    attacker = _present(enroll, code, pub=OTHER_PUB, name="not-your-phone")

    honest_fingerprint_on_my_phone = fingerprint(PUB)
    with pytest.raises(Refused) as caught:
        enroll.vouch(attacker.request_id, honest_fingerprint_on_my_phone)
    assert caught.value.outcome is Outcome.FINGERPRINT_MISMATCH


def test_vouching_cannot_be_done_on_the_request_id_alone(enroll):
    """A vouch that took only an id would confirm "an enrollment is pending",
    which is exactly what the racer arranged. The signature requires the
    fingerprint, so this is a type-level guarantee rather than a habit."""
    import inspect

    params = inspect.signature(Enrollment.vouch).parameters
    assert "seen_fingerprint" in params
    assert params["seen_fingerprint"].default is inspect.Parameter.empty


def test_a_fingerprint_typed_with_odd_spacing_still_vouches(enroll):
    """The operator is typing or eyeballing this, not pasting it. Being strict
    about whitespace would train them to copy-paste, which defeats the point of
    comparing it by eye in the first place."""
    code = enroll.mint()
    pending = _present(enroll, code)
    messy = "  " + pending.fingerprint.replace(" ", "").lower() + "  "
    assert enroll.vouch(pending.request_id, messy).csr_der == CSR


# ---- the four ways a code is refused -------------------------------------


def test_an_unknown_code_is_refused(enroll):
    minted = enroll.mint()
    wrong = f"{(int(minted) + 1) % 10 ** 6:06d}"
    with pytest.raises(Refused) as caught:
        _present(enroll, wrong)
    assert caught.value.outcome is Outcome.NO_SUCH_CODE


def test_a_code_is_single_use(enroll):
    code = enroll.mint()
    _present(enroll, code)
    with pytest.raises(Refused) as caught:
        _present(enroll, code)
    assert caught.value.outcome is Outcome.CODE_USED


def test_a_code_expires(enroll):
    code = enroll.mint(ttl_s=300.0)
    enroll.clock.advance(300.0)
    with pytest.raises(Refused) as caught:
        _present(enroll, code)
    assert caught.value.outcome is Outcome.CODE_EXPIRED


def test_a_code_still_works_just_before_it_expires(enroll):
    code = enroll.mint(ttl_s=300.0)
    enroll.clock.advance(299.0)
    assert _present(enroll, code).device_name == "pixel-6a"


def test_guessing_burns_the_window(enroll):
    """MAX_ATTEMPTS is what turns "seconds to brute force" into "you get a
    handful of tries and then you are racing a human who has to re-mint"."""
    code = enroll.mint()
    for _ in range(MAX_ATTEMPTS):
        with pytest.raises(Refused):
            _present(enroll, "999999" if code != "999999" else "111111")
    with pytest.raises(Refused) as caught:
        _present(enroll, code)
    assert caught.value.outcome is Outcome.TOO_MANY_ATTEMPTS


def test_a_wrong_guess_does_not_burn_an_already_used_code(enroll):
    """Charging used codes would be pointless bookkeeping, and it would make
    CODE_USED report TOO_MANY_ATTEMPTS after enough noise - a confusing answer
    to "why did my enrollment fail"."""
    code = enroll.mint()
    _present(enroll, code)
    for _ in range(MAX_ATTEMPTS + 3):
        with pytest.raises(Refused):
            _present(enroll, "000001")
    with pytest.raises(Refused) as caught:
        _present(enroll, code)
    assert caught.value.outcome is Outcome.CODE_USED


# ---- vouching on nothing -------------------------------------------------


def test_vouching_for_an_unknown_request_is_refused(enroll):
    with pytest.raises(Refused) as caught:
        enroll.vouch("no-such-request", fingerprint(PUB))
    assert caught.value.outcome is Outcome.NOT_PENDING


def test_a_request_can_only_be_vouched_once(enroll):
    code = enroll.mint()
    pending = _present(enroll, code)
    enroll.vouch(pending.request_id, pending.fingerprint)
    with pytest.raises(Refused) as caught:
        enroll.vouch(pending.request_id, pending.fingerprint)
    assert caught.value.outcome is Outcome.NOT_PENDING


# ---- housekeeping --------------------------------------------------------


def test_sweep_drops_expired_and_used_codes(enroll):
    live = enroll.mint(ttl_s=300.0)
    spent = enroll.mint()
    _present(enroll, spent)
    enroll.clock.advance(10.0)

    assert enroll.sweep() == 1, "the used one goes, the live one stays"
    assert live in enroll.codes

    enroll.clock.advance(300.0)
    assert enroll.sweep() == 1
    assert enroll.codes == {}


# ---- the code nobody types -----------------------------------------------


def test_a_scanned_code_is_not_guessable_because_nothing_compares_it(enroll):
    """THE attack again, against a device nobody is holding.

    On the typed path a racer who guesses the six digits reaches the pending
    queue and is caught at the vouch, by a fingerprint the administrator is
    reading off the phone in their hand. Provisioning from a QR takes that hand
    away, so the catch is gone - and the answer is not to trust the code more,
    it is to make the guess impossible.

    192 bits from `secrets.token_urlsafe`. This asserts the width rather than
    the exact alphabet, because the width is the security property and the
    alphabet is an encoding choice.
    """
    code = enroll.mint(shape=Shape.SCANNED)
    assert not code.isdigit(), "six digits is the shape a human types, not a QR"
    assert len(code) >= 32, f"a code nobody types must not be short: {len(code)}"

    # Distinct every time, and from a CSPRNG. Two mints colliding would mean a
    # device provisioned from one QR could claim another's place in the queue.
    assert len({enroll.mint(shape=Shape.SCANNED) for _ in range(50)}) == 50


def test_a_scanned_code_is_single_use_like_any_other(enroll):
    """The QR is on a monitor for minutes and can be photographed. Spending the
    code on the first device that uses it is what bounds that to one device."""
    code = enroll.mint(shape=Shape.SCANNED)
    _present(enroll, code)
    with pytest.raises(Refused) as caught:
        _present(enroll, code, pub=OTHER_PUB)
    assert caught.value.outcome is Outcome.CODE_USED
    assert caught.value.shape is Shape.SCANNED


def test_a_scanned_code_expires_on_the_same_clock_as_a_typed_one(enroll):
    """A provisioning run has to survive download, install and the setup wizard
    inside this window, which is a real argument for a longer one - and it is
    refused. A code in a QR is a code on a screen in a room, and the window is
    the only thing bounding how long that screen is worth photographing."""
    code = enroll.mint(ttl_s=300.0, shape=Shape.SCANNED)
    enroll.clock.advance(300.0)
    with pytest.raises(Refused) as caught:
        _present(enroll, code)
    assert caught.value.outcome is Outcome.CODE_EXPIRED
    assert caught.value.shape is Shape.SCANNED


def test_stale_and_replayed_stay_two_different_answers(enroll):
    """Both are "that QR is no good" and they call for opposite responses. A
    stale one means mint another; a replayed one means a second device used the
    code, which is the answer that deserves somebody looking."""
    stale = enroll.mint(ttl_s=300.0, shape=Shape.SCANNED)
    spent = enroll.mint(ttl_s=300.0, shape=Shape.SCANNED)
    _present(enroll, spent)
    enroll.clock.advance(300.0)

    with pytest.raises(Refused) as first:
        _present(enroll, stale)
    with pytest.raises(Refused) as second:
        _present(enroll, spent)
    assert first.value.outcome is Outcome.CODE_EXPIRED
    assert second.value.outcome is Outcome.CODE_USED
    assert first.value.outcome is not second.value.outcome


def test_guessing_at_six_digits_cannot_burn_the_code_in_a_QR(enroll):
    """A DENIAL OF SERVICE ON A WIPED PHONE, in five requests, from anywhere.

    The attempt budget is charged against every live code so that MAX_ATTEMPTS
    bounds a guessing run at all. Left unqualified it also charges the scanned
    code sitting in a QR, so anyone who can POST five wrong six-digit codes
    kills a provisioning run already in flight - and the handset comes up wiped,
    owned by muster, and unable to enroll with nobody there to retry it.

    A 192-bit code is not what the budget was protecting, so it does not pay it.
    """
    scanned = enroll.mint(shape=Shape.SCANNED)
    typed = enroll.mint(shape=Shape.TYPED)

    for _ in range(MAX_ATTEMPTS * 3):
        with pytest.raises(Refused):
            _present(enroll, "000001")

    with pytest.raises(Refused) as burned:
        _present(enroll, typed)
    assert burned.value.outcome is Outcome.TOO_MANY_ATTEMPTS, (
        "the typed budget must still be spent, or guessing is unbounded"
    )
    assert _present(enroll, scanned).device_name == "pixel-6a"


def test_a_scanned_request_carries_its_shape_to_the_console(enroll):
    """The console has to be able to say which kind of vouch it is asking for.
    On a scanned request there is no second copy of the fingerprint anywhere, so
    drawing it identically to a typed one teaches a check that is theatre."""
    typed = _present(enroll, enroll.mint(shape=Shape.TYPED))
    scanned = _present(enroll, enroll.mint(shape=Shape.SCANNED), pub=OTHER_PUB)
    assert typed.shape is Shape.TYPED
    assert scanned.shape is Shape.SCANNED


def test_minting_a_scanned_code_is_the_vouch(enroll):
    """THE DECISION THIS MODULE DEFERRED, now made and pinned here.

    This test used to assert the opposite - that a scanned request still had to
    be vouched for - and the reversal is the point rather than a relaxation. A
    scanned code is minted by an authenticated administrator asking for exactly
    one device to be enrolled; that request IS the authorization. The second
    click added nothing, because on a scanned request the administrator reads
    the fingerprint off the same console page they are clicking on and so
    compares a value against itself.

    What still stands behind it is unchanged: 192 bits, single use, short lived.
    """
    code = enroll.mint(shape=Shape.SCANNED)
    pending = _present(enroll, code)
    assert pending.self_vouched
    # NOTHING PENDING, because nothing is. A row here is a console asking an
    # administrator to approve what they already approved - and clicking it is
    # what enrolled a second device.
    assert pending.request_id not in enroll.pending


def test_a_typed_device_still_has_to_be_vouched_for(enroll):
    """The conservative half, and it is untouched.

    Six digits is guessable BY DESIGN - the length is a usability number - so
    here the fingerprint really is a second copy, read off a handset somebody is
    holding. Everything the scanned path argues is false for this one.
    """
    code = enroll.mint(shape=Shape.TYPED)
    pending = _present(enroll, code)
    assert not pending.self_vouched
    assert pending.request_id in enroll.pending
    with pytest.raises(Refused) as caught:
        enroll.vouch(pending.request_id, fingerprint(OTHER_PUB))
    assert caught.value.outcome is Outcome.FINGERPRINT_MISMATCH
    assert enroll.vouch(pending.request_id, pending.fingerprint).csr_der == CSR


def test_a_scanned_request_cannot_be_vouched_a_second_time(enroll):
    """The duplicate-vouch bug, as a test.

    An operator watched a QR-provisioned phone enrol, then found a row still
    waiting in the console and clicked it - which minted a SECOND identity for
    one handset. There is now no row to click, and asking for one by id is
    refused rather than quietly issuing again.
    """
    pending = _present(enroll, enroll.mint(shape=Shape.SCANNED))
    with pytest.raises(Refused) as caught:
        enroll.vouch(pending.request_id, pending.fingerprint)
    assert caught.value.outcome is Outcome.NOT_PENDING


def test_a_code_muster_never_minted_names_no_shape(enroll):
    """`unknown`, not a guess. Classifying a refusal by the FORM of what was
    sent would let an attacker choose which bucket their traffic lands in, and
    "the QR path is failing" would then be answered from attacker input."""
    enroll.mint(shape=Shape.SCANNED)
    with pytest.raises(Refused) as caught:
        _present(enroll, "000000")
    assert caught.value.outcome is Outcome.NO_SUCH_CODE
    assert caught.value.shape is None


def test_a_non_ascii_code_is_a_wrong_guess_and_not_a_crash(enroll):
    """`hmac.compare_digest` raises TypeError on strings it cannot compare
    byte-for-byte, and this argument arrives straight off an unauthenticated
    endpoint - so without the guard one accented character answers 500 and puts
    a traceback in the log of the process holding the CA."""
    enroll.mint()
    with pytest.raises(Refused) as caught:
        # Escaped rather than pasted: this repository is ASCII, and a test whose
        # point is a non-ASCII byte is the one place that is easiest to get
        # wrong invisibly.
        _present(enroll, "12345\u00e9")
    assert caught.value.outcome is Outcome.NO_SUCH_CODE


def test_an_absurdly_long_code_is_refused_before_anything_is_compared(
    enroll, monkeypatch
):
    """The comparison loop costs one pass per live code, and `code` arrives in a
    JSON body from the open internet. Without a ceiling, one POST carrying a
    megabyte buys an attacker that work for free, over and over - and the loop
    grows with every code ever minted, because nothing sweeps them (muster#53).

    COUNTING THE COMPARISONS IS THE WHOLE TEST. The outcome is NO_SUCH_CODE
    either way - a long string matches nothing - so asserting the refusal would
    pass with the ceiling deleted and prove nothing at all. What the guard buys
    is that the expensive thing never runs, so that is what is measured.
    """
    import muster.enroll as module  # noqa: PLC0415

    compared = []
    real = module.hmac.compare_digest
    monkeypatch.setattr(
        module.hmac, "compare_digest",
        lambda a, b: compared.append(1) or real(a, b),
    )

    live = enroll.mint()
    with pytest.raises(Refused) as caught:
        _present(enroll, "x" * (MAX_CODE_LENGTH + 1))
    assert caught.value.outcome is Outcome.NO_SUCH_CODE
    assert compared == [], "the oversized code was compared against every live code"

    # A code of the permitted length still reaches the comparison, or the
    # ceiling would be turning legitimate traffic away rather than junk.
    with pytest.raises(Refused):
        _present(enroll, "x" * MAX_CODE_LENGTH)
    assert compared, "nothing at all is being compared any more"

    # Both are still wrong guesses, so both still cost the window an attempt - a
    # refusal that was free would be a way to probe without paying for it.
    assert enroll.codes[live].attempts == 2


def test_sweeping_does_not_disturb_pending_requests(enroll):
    """A device that has presented is waiting on a HUMAN, who may be asleep.
    Expiring the pairing code must not expire the request it created."""
    code = enroll.mint(ttl_s=300.0)
    pending = _present(enroll, code)
    enroll.clock.advance(10_000.0)
    enroll.sweep()
    assert enroll.vouch(pending.request_id, pending.fingerprint).csr_der == CSR


# ---- roles (muster#70) ---------------------------------------------------
#
# "make it a zippie android so it does zippie config". A role is chosen when the
# QR is minted - the one moment an administrator is deciding what a device is
# for - and has to survive all the way to issuance, because the device's key_id
# does not exist until then and policy is keyed on it.


def test_a_code_can_carry_a_role(enroll):
    code = enroll.mint(shape=Shape.SCANNED, role="zippie")
    assert _present(enroll, code).role == "zippie"


def test_no_role_is_the_ordinary_case(enroll):
    """A device with no role gets the kith's policy and nothing else. Empty
    rather than None so every consumer can compare strings."""
    assert _present(enroll, enroll.mint(shape=Shape.SCANNED)).role == ""


def test_a_role_survives_the_typed_path_too(enroll):
    """Nothing about a role is specific to scanning - it is what the device is
    for, not how it enrolled."""
    code = enroll.mint(shape=Shape.TYPED, role="kiosk")
    pending = _present(enroll, code)
    assert pending.role == "kiosk"
    assert enroll.vouch(pending.request_id, pending.fingerprint).role == "kiosk"


@pytest.mark.parametrize(
    "role",
    [
        "has space", "UPPER", "trailing-", "-leading", "has.dot",
        "has/slash", "a" * 32, "1starts-with-digit", "has_underscore",
    ],
)
def test_a_role_that_could_not_be_a_policy_scope_is_refused(enroll, role):
    """THE REASON THE CHARSET IS THIS NARROW. A role becomes half of a policy
    file name (`role-zippie.app-config`), and that name is a Kubernetes Secret
    key - which may hold only `[-._a-zA-Z0-9]`. A DOT is worse than illegal: the
    scope is split on the first one, so `has.dot` would silently address a
    different scope than the operator wrote.
    """
    with pytest.raises(ValueError):
        enroll.mint(shape=Shape.SCANNED, role=role)


def test_a_role_that_looks_like_a_key_id_is_refused(enroll):
    """64 hex characters is what a key_id is. A role that could be mistaken for
    one would let a QR address another device's policy scope."""
    with pytest.raises(ValueError):
        enroll.mint(shape=Shape.SCANNED, role="a" * 64)
