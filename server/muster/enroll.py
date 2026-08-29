"""The enrollment exchange: mint, present, vouch, issue.

This module is the whole trust decision, kept away from HTTP, storage and the
console so it can be tested as what it is - a state machine with four ways to
say no. See CONTEXT.md for the vocabulary; the words here mean exactly what they
mean there.

WHY THE PAIRING CODE IS NOT THE SECURITY. Six digits is 10^6. Against a public
endpoint that is guessable in seconds, and no amount of rate limiting makes a
six-digit code a credential. It is not trying to be one: it proves that a human
INTENDED an enrollment to happen around now, and nothing more.

The security is the vouch, and only if the vouch is made against the KEY. The
administrator sees the fingerprint of the public key in the CSR; the device
displays the same fingerprint. Approving means "yes, that is the fingerprint on
the screen in my hand". A racer who guesses the code lands in the pending queue
with a fingerprint the administrator is not looking at, and gets declined.

Vouching by code alone would mean the administrator confirming only "yes, I did
start an enrollment", which the racer has already assumed. That is why
`vouch()` takes a fingerprint and refuses to work without one.

WHAT CHANGES WHEN NOBODY IS HOLDING THE PHONE. Read the paragraph above again
and notice what every sentence of it rests on: a person looking at the device's
screen. Provisioning a wiped handset from a QR on a monitor removes that person,
and with them the second copy of the fingerprint - so the comparison that
catches the racer is simply not available.

The answer here is NOT to trust the code more. It is to make the racer
impossible. Six digits is a USABILITY number: it is short because somebody has
to read it off a console and type it on a phone. Take the typing away and
nothing constrains the length any more, so a code that rides in a QR is 192 bits
of url-safe text (`Shape.SCANNED`) rather than six digits (`Shape.TYPED`). The
stranger who guessed cannot exist against a scanned code, which is the whole of
what the fingerprint comparison was defending.

THE TRADE THIS MODULE DEFERRED HAS NOW BEEN MADE, and this paragraph is what it
used to say: that removing the vouch from a scanned request would make the
pairing code the entire security of the system, and that the choice belonged to
whoever runs the estate.

They made it, and the reasoning is better than "trust the code more". A SCANNED
CODE IS MINTED BY AN AUTHENTICATED ADMINISTRATOR WHO IS ASKING FOR EXACTLY ONE
DEVICE TO BE ENROLLED. That request is the authorization. The second click added
nothing to it: on a scanned request the administrator reads the fingerprint off
the same console page they are clicking, so they compare a value against itself
- which is not a check, it is a ritual. Asking the same person the same question
twice does not make the answer better, and it is why a QR-provisioned phone
still came up asking a human to go and approve it.

So the vouch MOVES rather than disappears. It happens at mint, where the
administrator has actually decided something, and `Shape.SCANNED` carries that
decision forward to issuance. What still stands behind it is unchanged: the code
is 192 bits, single use, and short lived, so the racer the fingerprint
comparison defended against cannot exist.

`Shape.TYPED` IS UNTOUCHED AND KEEPS ITS VOUCH. Six digits is guessable by
design, the human is standing at the device, and the fingerprint on its screen is
a real second copy. Everything the paragraph above says is false for a typed code.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from enum import Enum

# Six digits, because a human reads it off a screen and types it on a phone.
# The length is a usability choice and is ALLOWED to be weak - see the module
# docstring for why that is not where the security lives.
CODE_DIGITS = 6

# The width of a code NOBODY types. 24 bytes of url-safe base64 is 192 bits,
# which is not a stronger version of six digits - it is a different kind of
# thing. A typed code is allowed to be guessable because the vouch compares a
# fingerprint the guesser cannot produce; a scanned code has no such second
# check behind it, so it has to be the thing that cannot be guessed.
#
# url-safe base64 for the same reason provisioning.py encodes its checksum that
# way: this string travels inside a QR payload, through JSON, through an Android
# PersistableBundle, and `+` and `/` survive all of that and then get mangled by
# the first thing that treats the payload as URL-shaped.
SCANNED_CODE_BYTES = 24

# The longest string this will even look at as a code. UNAUTHENTICATED INPUT
# with no ceiling of its own: `code` arrives in a JSON body from the open
# internet, and every wrong guess costs one `compare_digest` pass per live code.
# Without this, one POST carrying a multi-megabyte string buys an attacker that
# work for free, repeatedly.
#
# 256 mirrors ProvisioningPolicy.MAX_PAIRING_CODE in the agent, which bounds the
# same value coming the other way out of a QR. Generous against the 32 a scanned
# code actually is, so lengthening SCANNED_CODE_BYTES cannot silently strand a
# fleet - and a code this long was never minted here, so refusing it turns
# nothing legitimate away.
# What a role may be called, and it is narrow on purpose.
#
# A ROLE BECOMES HALF OF A POLICY FILE NAME - `role-zippie.app-config` - and
# that name is a Kubernetes Secret key, which may hold only `[-._a-zA-Z0-9]`.
# Two of the exclusions below matter more than the charset:
#
#   A DOT IS WORSE THAN ILLEGAL. `policy.py` splits a scope from a file name on
#   the FIRST dot, so a role containing one would silently address a different
#   scope than the operator wrote - `role-a.b` reads as scope `role-a`, file
#   `b`, and `b` is not a managed file, so the policy would simply never arrive.
#
#   IT MUST NOT BE ABLE TO LOOK LIKE A key_id. A key_id is 64 lowercase hex
#   characters and is the OTHER kind of scope in that directory. A role that
#   could be mistaken for one would let whoever mints a QR address a specific
#   device's policy. The `role-` prefix already separates them; the length cap
#   means nothing has to rely on that alone.
#
# Lowercase only, because a Secret key is case-sensitive and `role-Zippie` beside
# `role-zippie` is a debugging session nobody needs.
# Ends alphanumeric as well as starting so: `zippie-` is legal as a Secret key
# and is almost always a typo, and the cost of a typo here is a policy scope
# that exists, is served to nothing, and looks exactly like one that works.
_ROLE = re.compile(r"^[a-z]([a-z0-9-]{0,29}[a-z0-9])?\Z")

MAX_CODE_LENGTH = 256

# A pairing code is alive for minutes, not hours. It bounds how long a guessing
# attack has a target to hit at all, and it matches the real gesture: an
# administrator generates a code because they are holding the device now.
DEFAULT_CODE_TTL_S = 300.0

# How many wrong guesses a single code tolerates before it is burned. Not the
# primary defense, but it turns "seconds to brute force" into "you get 5 tries
# and then this code is gone", which is the difference between a background
# attack and one that has to race a human.
MAX_ATTEMPTS = 5


class Shape(str, Enum):
    """Who reads a pairing code, which is the only thing that decides its length.

    Not a cosmetic label. It selects how the code is minted, whether a wrong
    guess elsewhere is allowed to burn it, and - once it is attached to a
    Pending - what the console can honestly tell an administrator they are
    approving. See the module docstring.
    """

    TYPED = "typed"
    SCANNED = "scanned"

    @property
    def self_vouching(self) -> bool:
        """Is minting this code the authorization, or does a human click later?

        A PROPERTY OF THE SHAPE, because the shape is the only thing that
        differs. A scanned code is minted by an authenticated administrator
        asking for one device to be enrolled and is never read by anybody; a
        typed code is read aloud to somebody holding the handset, whose screen
        carries a second copy of the fingerprint to compare. See the module
        docstring for why the second click on a scanned request compares a value
        against itself.
        """
        return self is Shape.SCANNED


class Outcome(str, Enum):
    """Why an enrollment step was refused. Every no is a distinct no.

    Collapsing these into one error would make the log useless: "wrong code"
    and "code expired" call for opposite responses from the operator, and
    "already used" is the one that means somebody may be replaying.
    """

    OK = "ok"
    NO_SUCH_CODE = "no-such-code"
    CODE_EXPIRED = "code-expired"
    CODE_USED = "code-used"
    TOO_MANY_ATTEMPTS = "too-many-attempts"
    NOT_PENDING = "not-pending"
    FINGERPRINT_MISMATCH = "fingerprint-mismatch"


class Refused(Exception):
    """A step said no. Carries the Outcome so callers can map it to a status.

    `shape` is which kind of code was refused, where that is knowable, so a
    caller can tag its telemetry with it. None means the code named nothing at
    all - there is no record to read a shape off, which is itself the honest
    answer and is exactly the NO_SUCH_CODE case.

    WHY THIS IS NOT INFERRED FROM THE STRING. Six digits is a shape a scanned
    code could never take, so a guess could be classified by its form - and
    then "the QR path is failing" would be answered from what an ATTACKER sent
    rather than from what muster minted. The shape is a property of the code
    that was issued, or it is unknown.
    """

    def __init__(
        self, outcome: Outcome, detail: str = "", shape: "Shape | None" = None
    ) -> None:
        super().__init__(detail or outcome.value)
        self.outcome = outcome
        self.shape = shape


# The longest name a device may present. 64 is not arbitrary: it is
# ub-common-name-length from X.509, and this string becomes a certificate's
# Common Name.
MAX_DEVICE_NAME = 64


def clean_device_name(name: str) -> str:
    """The name a device may be certified and recorded under. Raises ValueError.

    UNAUTHENTICATED INPUT that lands in two places which both care. It becomes
    the Common Name of a certificate, where 64 characters is the limit the
    standard sets and a control character is a well-worn way of making one
    string print as another. And it becomes a Postgres `text` value, which
    cannot hold a NUL byte at all.

    THE NUL IS THE EXPENSIVE ONE, and not because a row would be rejected. Kith
    writes are deferred and replayed in order (muster/kith.py), so a single
    undeliverable name sits at the head of the queue blocking every write behind
    it, while a perfectly healthy database is reported as unreachable. The store
    now recognizes that class of failure and drops the row, but a name nobody
    can read should never have got as far as being stored: refusing it at the
    door is both cheaper and the honest answer to the device.
    """
    cleaned = name.strip()
    if not cleaned:
        raise ValueError("a device must present a name")
    if len(cleaned) > MAX_DEVICE_NAME:
        raise ValueError(
            f"a device name may be at most {MAX_DEVICE_NAME} characters, "
            f"which is the limit a certificate's Common Name has"
        )
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in cleaned):
        raise ValueError("a device name may not contain control characters")
    return cleaned


def key_id(public_key_der: bytes) -> str:
    """The SHA-256 of a public key, whole, for a machine to compare.

    THE DEVICE'S IDENTITY. A device keeps the key it generated and renews the
    certificate over it, so this is the one value that is the same device before
    and after a renewal - which is why the kith is keyed on it rather than on a
    certificate serial (muster/kith.py, sql/0001_kith.sql).

    Untruncated, unlike `fingerprint` below. The truncation there is a
    concession to a human reading it aloud; a primary key has no such excuse,
    and 64 bits is a poor width to key a table on.
    """
    return hashlib.sha256(public_key_der).hexdigest()


def fingerprint(public_key_der: bytes) -> str:
    """The SHA-256 of a public key, grouped for a human to read aloud.

    Grouped deliberately. This string exists to be COMPARED BY EYE between a
    console and a phone screen, and an unbroken 64-character hex run is exactly
    the shape people skim instead of checking. Four groups of four from the
    leading bytes is enough: an attacker who can produce a key colliding on 64
    bits of SHA-256 is not being stopped by anything else here either.

    Derived from `key_id` rather than hashing again, so the short form is
    provably a rendering of the long one. Two separate calls to sha256 would
    both be correct today and are one edit away from describing different keys
    on the console and in the kith.
    """
    digest = key_id(public_key_der).upper()
    return " ".join(digest[i:i + 4] for i in range(0, 16, 4))


def _mint_code(shape: Shape) -> str:
    """A pairing code of the given shape.

    `secrets`, not `random`, for both - this is guessed at, not sampled. The
    typed one is six digits and is allowed to be weak; the scanned one is 192
    bits and is not, because nothing behind it compares a fingerprint.
    """
    if shape is Shape.SCANNED:
        return secrets.token_urlsafe(SCANNED_CODE_BYTES)
    return f"{secrets.randbelow(10 ** CODE_DIGITS):0{CODE_DIGITS}d}"


@dataclass
class PairingCode:
    code: str
    created_at: float
    ttl_s: float
    used: bool = False
    attempts: int = 0
    # Defaults to TYPED so that every existing construction keeps meaning what
    # it meant: a code somebody reads off a console and types on a phone.
    shape: Shape = Shape.TYPED
    # WHAT THE DEVICE IS FOR, chosen when this code was minted - the one moment
    # an administrator is deciding it. It rides the code because policy is keyed
    # on a key_id, and the device's key_id does not exist until issuance.
    role: str = ""

    def expired_at(self, now: float) -> bool:
        return now - self.created_at >= self.ttl_s


@dataclass
class Pending:
    """A device that has presented itself and is waiting to be vouched for."""

    request_id: str
    csr_der: bytes
    public_key_der: bytes
    device_name: str
    presented_at: float
    fingerprint: str = ""
    # WHICH KIND OF VOUCH THIS ONE IS. Carried through from the code that was
    # claimed, because it changes what an administrator can honestly say they
    # checked. On a TYPED request the fingerprint below is also on a screen in
    # their hand; on a SCANNED one there is no second copy of it anywhere, and a
    # console that draws the two the same way is telling them otherwise.
    shape: Shape = Shape.TYPED

    # Carried from the code that was claimed, and on to the kith at issuance.
    role: str = ""

    @property
    def self_vouched(self) -> bool:
        """Was this authorized when its code was minted?

        Read from the shape rather than stored, so there is no way to build a
        Pending that CLAIMS to be authorized and is not - the only thing that
        can answer yes is a code an administrator minted for a QR.
        """
        return self.shape.self_vouching

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = fingerprint(self.public_key_der)


@dataclass
class Enrollment:
    """The state machine. No HTTP, no disk, no clock of its own.

    `clock` is injected because every rule here is about time and a test that
    cannot move time can only assert the happy path.
    """

    clock: object
    codes: dict = field(default_factory=dict)
    pending: dict = field(default_factory=dict)

    def _now(self) -> float:
        return self.clock()  # type: ignore[operator]

    # ---- mint ------------------------------------------------------------

    def mint(
        self,
        ttl_s: float = DEFAULT_CODE_TTL_S,
        shape: Shape = Shape.TYPED,
        role: str = "",
    ) -> str:
        """An administrator asks for a pairing code.

        The TTL is the same either way and deliberately so. A scanned code has a
        whole provisioning run to survive - download, install, setup wizard -
        which is a real argument for a longer window, and it is refused here: a
        code in a QR is a code on a screen in a room, and the window is the only
        thing bounding how long that screen is worth photographing. A device
        that misses the window falls back to the typed path, which still works.
        """
        # REFUSED HERE, at the only door a role comes through, rather than
        # where it is used. By the time a role reaches `policy.py` it is half a
        # filename and a bad one has already been written into a Secret; by the
        # time it reaches the kith it is a row. This is the boundary.
        if role and not _ROLE.match(role):
            raise ValueError(
                f"'{role}' is not a role: lowercase letters, digits and dashes, "
                "starting with a letter, at most 31 characters. A role becomes "
                "half of a policy file name and a Kubernetes Secret key, and a "
                "dot in one would silently address a different scope."
            )
        code = _mint_code(shape)
        self.codes[code] = PairingCode(
            code=code, created_at=self._now(), ttl_s=ttl_s, shape=shape, role=role
        )
        return code

    # ---- present ---------------------------------------------------------

    def present(
        self, code: str, csr_der: bytes, public_key_der: bytes, device_name: str
    ) -> Pending:
        """A device offers its CSR and a pairing code.

        WHAT THIS GRANTS DEPENDS ON THE SHAPE OF THE CODE IT CLAIMED, and the
        module docstring is where that decision is argued.

        A TYPED code buys a place in the pending list and a fingerprint for a
        human to look at, and nothing else. That is what it always did.

        A SCANNED code was minted by an authenticated administrator asking for
        one device to be enrolled, so presenting it is the last step rather than
        the first: the returned Pending is `self_vouched` and the CALLER issues
        against it immediately. Such a request is deliberately NOT put in
        `self.pending` - there is nothing pending about it, and leaving it there
        would put a row in the console asking an administrator to approve
        something already approved. That row is exactly what a QR-provisioned
        phone produced before this, and clicking it enrolled a second device.
        """
        record = self._claimable(code)
        record.used = True

        request_id = secrets.token_urlsafe(12)
        entry = Pending(
            request_id=request_id,
            csr_der=csr_der,
            public_key_der=public_key_der,
            device_name=device_name,
            presented_at=self._now(),
            shape=record.shape,
            role=record.role,
        )
        if not entry.self_vouched:
            self.pending[request_id] = entry
        return entry

    def _claimable(self, code: str):
        """The four ways a code is refused, in the order they can be told apart.

        Compared with `hmac.compare_digest` rather than `==`. The timing signal
        on a six-digit code is not the weak point here, but a lookup that leaks
        how much of a code was right is the kind of thing that becomes the weak
        point later when someone lengthens the code and assumes it got stronger.

        NON-ASCII IS A WRONG GUESS, not a crash. `hmac.compare_digest` raises
        TypeError on strings it cannot compare byte-for-byte, and `code` arrives
        here straight off an UNAUTHENTICATED endpoint - so without this line a
        POST carrying one accented character answers 500 and puts a traceback in
        the log of the process that holds the CA. No minted code of either shape
        contains a non-ASCII character, so nothing legitimate is turned away.

        SO IS ANYTHING ABSURDLY LONG, and for the neighbouring reason: the loop
        below costs one comparison per live code, and an unauthenticated caller
        should not be able to buy that work by the megabyte. Both checks happen
        BEFORE the loop, so the expensive thing is what they guard.
        """
        record = None
        if code.isascii() and len(code) <= MAX_CODE_LENGTH:
            for candidate, held in self.codes.items():
                if hmac.compare_digest(candidate, code):
                    record = held
                    break
        if record is None:
            self._charge_attempts()
            raise Refused(Outcome.NO_SUCH_CODE)
        if record.used:
            raise Refused(Outcome.CODE_USED, shape=record.shape)
        if record.attempts >= MAX_ATTEMPTS:
            raise Refused(Outcome.TOO_MANY_ATTEMPTS, shape=record.shape)
        if record.expired_at(self._now()):
            raise Refused(Outcome.CODE_EXPIRED, shape=record.shape)
        return record

    def _charge_attempts(self) -> None:
        """A wrong guess costs every live TYPED code an attempt.

        Charging only the code that was guessed would be free, because a wrong
        guess names no code to charge. Spending the budget of the live codes is
        what makes MAX_ATTEMPTS bound a guessing run at all - and it is safe
        because a legitimate device types one code, once, correctly.

        SCANNED CODES ARE NOT CHARGED, and that is a security decision rather
        than an oversight. The budget exists to bound GUESSING, and 192 bits is
        not guessed - so charging a scanned code buys nothing and costs a
        handset: anyone who can POST five wrong six-digit codes would otherwise
        kill a provisioning run already in flight, and the phone comes up wiped,
        owned, and unable to enroll with nobody holding it. That is a denial of
        service against the whole point of the QR, available to the open
        internet, in five requests.
        """
        for held in self.codes.values():
            if not held.used and held.shape is Shape.TYPED:
                held.attempts += 1

    # ---- vouch -----------------------------------------------------------

    def vouch(self, request_id: str, seen_fingerprint: str) -> Pending:
        """An administrator approves a pending request, BY FINGERPRINT.

        `seen_fingerprint` is what the human is reading off the device in their
        hand. It is required, and it is compared, because a vouch that took only
        a request id would confirm nothing more than "an enrollment is pending",
        which is precisely what a racer who guessed the pairing code has
        arranged. Comparison is whitespace- and case-insensitive: the operator
        is typing or eyeballing this, not pasting it.

        ON A SCANNED REQUEST THERE IS NO DEVICE IN THEIR HAND, and this function
        cannot tell the difference - which is the honest reason it is unchanged.
        The comparison is only as good as where the second copy came from, and
        an operator reading the fingerprint off the same console page they are
        clicking on has compared nothing. What stops that being a hole is not
        anything here: it is that a scanned code cannot be guessed, so there is
        no second request to confuse this one with. `Pending.shape` is carried
        so the console can say which of the two an administrator is doing.
        """
        entry = self.pending.get(request_id)
        if entry is None:
            raise Refused(Outcome.NOT_PENDING)

        def canon(s: str) -> str:
            return "".join(s.split()).upper()

        if not hmac.compare_digest(canon(entry.fingerprint), canon(seen_fingerprint)):
            raise Refused(
                Outcome.FINGERPRINT_MISMATCH,
                "the fingerprint on the device does not match this request - "
                "somebody else may be enrolling against your pairing code",
            )
        return self.pending.pop(request_id)

    # ---- housekeeping ----------------------------------------------------

    def sweep(self) -> int:
        """Drop expired codes. Returns how many went.

        Used codes are dropped too: keeping them would let CODE_USED be reported
        forever, which reads as a replay attempt long after it is just an old
        code. Expiry is the honest answer once the window has passed.

        NOTHING IN muster/ CALLS THIS, and that is written down here rather than
        left to be rediscovered. `codes` therefore only grows, which matters more
        since muster#48 made minting page-view driven - every provisioning QR the
        console draws mints one. The two costs are `_claimable`'s comparison loop
        and `_charge_attempts`' full scan, both reachable unauthenticated.

        IT IS NOT WIRED HERE BECAUSE DOING IT NAIVELY LOSES A REFUSAL. Sweeping
        on mint would drop a code that was used SECONDS ago but is still inside
        its window, so a device replaying it would be told NO_SUCH_CODE instead
        of CODE_USED - and telling those two apart is exactly what muster#48 was
        asked to preserve. What this wants is a retention period longer than the
        TTL, which is a decision about how long a replay stays worth reporting.
        Tracked as muster#53.
        """
        now = self._now()
        dead = [c for c, held in self.codes.items()
                if held.used or held.expired_at(now)]
        for code in dead:
            del self.codes[code]
        return len(dead)
