"""Take a wiped Android device to Device Owner, or refuse and say why.

`adb shell dpm set-device-owner` is the one route to managing an Android device
that Google has not closed to us (docs/android-constraints.md). It is also
unforgiving: it works on a freshly wiped device and fails on almost anything
else, with messages that describe the symptom rather than the cause.

WHY THE PREFLIGHT IS THE POINT OF THIS MODULE. The provisioning command itself
is one line. What is worth writing down is everything that must be true first,
because each of these has the same failure shape - a device that is physically
in your hand, wiped, with a cable in it, refusing for a reason the error text
does not name:

  * an account on the device makes set-device-owner refuse outright
  * an existing Device Owner cannot be replaced, only factory reset away
  * a device already provisioned by somebody else looks identical to a fresh one
    until you ask

And the failure is expensive in a way a normal error is not: the recovery is
another factory reset, which on a phone that has been set up again means losing
whatever was done since. So this refuses early and loudly rather than trying.

THE SEAM. Every device interaction goes through an `Adb` object, so the whole
decision tree is testable with no phone attached. That is not a testing
convenience - it is the only way the refusal paths get exercised at all, because
reproducing them for real means wiping devices.
"""
from __future__ import annotations

import hashlib
import re
import shlex
import subprocess
from dataclasses import dataclass
from enum import Enum


class Verdict(str, Enum):
    """Whether this device can be provisioned, and if not, why not."""

    READY = "ready"
    NOT_CONNECTED = "not-connected"
    UNAUTHORIZED = "unauthorized"
    ALREADY_OWNED = "already-owned"
    HAS_ACCOUNTS = "has-accounts"
    API_TOO_OLD = "api-too-old"


# The DPC's own floor, from agent/android/app/build.gradle.kts. A device below
# this installs the APK and then fails at runtime, which is a worse place to
# find out than a preflight.
MIN_SDK = 29

ADMIN_COMPONENT = "app.muster.agent/.MusterDeviceAdminReceiver"

# WHERE THE AGENT READS ITS FILES, and it is not the obvious directory.
#
# Everything the agent needs at boot - the wallpaper, the server URL, its own
# certificate - lives in DEVICE-PROTECTED storage, because the agent runs before
# first unlock on an appliance that may sit in a cupboard for days and
# credential-protected storage is unreadable then.
#
# Those are two different directories on disk:
#
#     /data/user/0/<pkg>/files       credential-protected, the usual filesDir
#     /data/user_de/0/<pkg>/files    device-protected, what the agent reads
#
# Pushing to the first is the bug this constant exists to prevent: adb reports
# success, the file is genuinely there, and the agent never sees it. Nothing
# fails; the wallpaper simply never appears.
DEVICE_FILES = "/data/user_de/0/{package}/files"


@dataclass
class Preflight:
    verdict: Verdict
    detail: str = ""
    owner: str = ""
    accounts: tuple = ()
    sdk: int = 0

    @property
    def ok(self) -> bool:
        return self.verdict is Verdict.READY


class Adb:
    """The real adb. The only thing here that shells out, so tests replace one
    object.

    Two subprocess call sites rather than one: everything goes through `_run`,
    which is text mode, but `write_as` has to hand a PNG down stdin and text
    mode would try to decode it.
    """

    def __init__(self, binary: str = "adb") -> None:
        self.binary = binary

    def _run(self, args: list, timeout: float = 60.0) -> tuple:
        proc = subprocess.run(
            [self.binary, *args], capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, proc.stdout, proc.stderr

    def devices(self) -> dict:
        """serial -> state, from `adb devices`."""
        _rc, out, _err = self._run(["devices"])
        found = {}
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                found[parts[0]] = parts[1]
        return found

    def shell(self, serial: str, command: str, timeout: float = 60.0) -> str:
        _rc, out, _err = self._run(["-s", serial, "shell", command], timeout)
        return out

    def install(self, serial: str, apk_path: str) -> tuple:
        rc, out, err = self._run(["-s", serial, "install", "-r", apk_path], 300.0)
        return rc, out + err

    def shell_as(
        self, serial: str, package: str, command: str, timeout: float = 60.0
    ) -> str:
        """Run a command on the device AS THE APP, not as the shell user.

        Only stdout comes back, which is what makes this safe to parse: `run-as`
        puts its own refusals on stderr, so a caller reading this never mistakes
        "package not debuggable" for a file's contents.
        """
        return self.shell(serial, _run_as(package, command), timeout)

    def write_as(
        self, serial: str, package: str, remote: str, data: bytes,
        timeout: float = 300.0,
    ) -> tuple:
        """Stream bytes into a file the app owns. Returns (rc, everything said).

        The payload goes down stdin and never appears on a command line, so
        there is no quoting left to get wrong - which is the second bug in the
        code this replaced, where a server URL was written with `printf %s
        '<url>'` and anything shell-special in it would have been mangled or
        run.

        stdout and stderr are joined because the caller wants the device's
        words: `run-as` explains itself on stderr, and its explanation is the
        whole diagnosis when a write is refused.
        """
        command = _run_as(package, f"cat > {shlex.quote(remote)}")
        try:
            proc = subprocess.run(
                [self.binary, "-s", serial, "shell", command],
                input=data,
                capture_output=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            # EXIT CODES ARE THE INTERFACE (cli.py) and a traceback is none of
            # them. This is the only call that feeds megabytes down stdin, so a
            # phone that goes away mid-write hangs here and nowhere else.
            return 1, f"adb gave up writing {remote} after {timeout:.0f}s\n"
        said = (proc.stdout + proc.stderr).decode("utf-8", "replace")
        return proc.returncode, said


def _run_as(package: str, command: str) -> str:
    """Wrap a command so the device runs it under the app's own uid.

    Quoted rather than interpolated because the package and the path both come
    from the command line. Unquoted, a path with a space in it silently writes
    to the wrong file and anything with a `;` in it is a command.
    """
    return f"run-as {shlex.quote(package)} sh -c {shlex.quote(command)}"


def _parse_owner(dumpsys: str) -> str:
    """The Device Owner component, or "" if there is none.

    Parsed rather than pattern-matched on the word "Owner": `dumpsys
    device_policy` prints the header `Device Owner:` even when there is none,
    with the component on a following line. Matching the header alone reports
    every device as owned, which fails CLOSED and would make this tool refuse to
    provision anything - safe, but useless, and the kind of bug that gets
    "fixed" by deleting the check.
    """
    match = re.search(r"Device Owner:\s*\n?\s*admin=ComponentInfo\{([^}]+)\}", dumpsys)
    return match.group(1) if match else ""


def _parse_accounts(account_dump: str) -> tuple:
    """Account names from `dumpsys account`. Empty is what we need."""
    return tuple(sorted(set(re.findall(r"Account \{name=([^,]+),", account_dump))))


def preflight(adb: Adb, serial: str) -> Preflight:
    """Can this device be provisioned right now?

    Checked in the order the answers become knowable: a device that is not
    connected cannot be asked about accounts, and an unauthorized one answers
    every question with silence that looks like "no".
    """
    state = adb.devices().get(serial)
    if state is None:
        return Preflight(
            Verdict.NOT_CONNECTED,
            f"{serial} is not in `adb devices`. If it is on the far side of a "
            "router, the forward has to be up first.",
        )
    if state != "device":
        return Preflight(
            Verdict.UNAUTHORIZED,
            f"{serial} is in state '{state}'. An unauthorized device answers "
            "every probe with silence, which reads exactly like a clean phone - "
            "so this refuses rather than guessing. Accept the debugging prompt "
            "on the screen.",
        )

    sdk_raw = adb.shell(serial, "getprop ro.build.version.sdk").strip()
    sdk = int(sdk_raw) if sdk_raw.isdigit() else 0
    if sdk and sdk < MIN_SDK:
        return Preflight(
            Verdict.API_TOO_OLD,
            f"API {sdk} is below the agent's minSdk {MIN_SDK}; it would install "
            "and then fail at runtime.",
            sdk=sdk,
        )

    owner = _parse_owner(adb.shell(serial, "dumpsys device_policy"))
    if owner:
        return Preflight(
            Verdict.ALREADY_OWNED,
            f"this device is already managed by {owner}. Device Owner cannot be "
            "replaced in place - it needs a factory reset. Unenroll from THAT "
            "MDM's own console first.",
            owner=owner,
            sdk=sdk,
        )

    accounts = _parse_accounts(adb.shell(serial, "dumpsys account"))
    if accounts:
        return Preflight(
            Verdict.HAS_ACCOUNTS,
            "set-device-owner refuses on a device with accounts on it: "
            f"{', '.join(accounts)}. This is the most common reason a wiped "
            "phone still will not provision - finishing setup wizard while "
            "signed in is enough to do it.",
            accounts=accounts,
            sdk=sdk,
        )

    return Preflight(Verdict.READY, "wiped, unowned, no accounts", sdk=sdk)


def set_device_owner(adb: Adb, serial: str, component: str = ADMIN_COMPONENT) -> bool:
    """Make the DPC Device Owner, then ASK THE DEVICE whether it worked.

    `dpm set-device-owner` prints "Success" on stdout and also prints failures
    there, so its output is not a verdict. The only honest confirmation is the
    device's own policy state afterwards - the same rule the zippie deploy
    follows about the difference between what was installed and what is running.
    """
    adb.shell(serial, f"dpm set-device-owner {component}")
    owner = _parse_owner(adb.shell(serial, "dumpsys device_policy"))
    return owner.split("/")[0] == component.split("/")[0]


# ---- after ownership: what is actually on the device ---------------------


@dataclass
class Installed:
    """One package, as the DEVICE reports it - not as anything intended."""

    package: str
    version_name: str = ""
    version_code: str = ""

    @property
    def present(self) -> bool:
        return bool(self.version_name or self.version_code)


def installed_package(adb: Adb, serial: str, package: str) -> Installed:
    """What version of `package` is on this device, if any.

    `dumpsys package` rather than `pm list packages`: the list says whether a
    name is known, and the question that matters after an install is WHICH BUILD
    is there. An MDM's own record answers neither - it says what it meant to
    deliver. The device is the only witness.
    """
    dump = adb.shell(serial, f"dumpsys package {package}")
    version_name = ""
    version_code = ""
    for line in dump.splitlines():
        line = line.strip()
        if line.startswith("versionName=") and not version_name:
            version_name = line.split("=", 1)[1].strip()
        elif line.startswith("versionCode=") and not version_code:
            # `versionCode=107 minSdk=29 targetSdk=36` - take the first field.
            version_code = line.split("=", 1)[1].split()[0].strip()
    return Installed(package=package, version_name=version_name, version_code=version_code)


@dataclass
class DeviceState:
    """Everything worth asserting about a provisioned device."""

    serial: str
    owner: str
    packages: tuple
    sdk: int

    def owned_by(self, component: str) -> bool:
        return bool(self.owner) and self.owner.split("/")[0] == component.split("/")[0]


def device_state(adb: Adb, serial: str, packages: tuple = ()) -> DeviceState:
    """Read back what a device actually is, after provisioning it.

    This exists because 'the command returned zero' is not a state. Every step
    of provisioning has a way to look successful and leave the device wrong: an
    install that lands a different build, an ownership call the system swallowed,
    a wipe that did not clear an account. Reading the device afterwards is the
    only answer that cannot be stale.
    """
    sdk_raw = adb.shell(serial, "getprop ro.build.version.sdk").strip()
    return DeviceState(
        serial=serial,
        owner=_parse_owner(adb.shell(serial, "dumpsys device_policy")),
        packages=tuple(installed_package(adb, serial, p) for p in packages),
        sdk=int(sdk_raw) if sdk_raw.isdigit() else 0,
    )


# ---- putting a config file where the agent reads it ----------------------


@dataclass
class Placement:
    """Whether a config file is on the device, as the DEVICE reports it."""

    ok: bool
    detail: str


def _read_digest(adb: Adb, serial: str, package: str, target: str) -> str:
    """The sha256 the DEVICE computes over the file, or "" if it would not.

    A BYTE COUNT IS NOT ENOUGH, and the difference is not academic. An adb
    older than shell protocol v2 runs the remote command under a pty, and a
    pty's line discipline turns every CR arriving on stdin into an LF - a
    substitution that does not change the length. A PNG begins

        89 50 4E 47 0D 0A 1A 0A

    and that signature exists to catch exactly this transformation. Checked by
    length, the push reports success, the file on the device is corrupt, and
    the only thing that ever notices is the agent's BitmapFactory returning
    null at the next boot, in a log nobody is watching.

    A device with no `sha256sum` says nothing here, which reads as "cannot
    prove" rather than as a failed write. That is the honest answer to both.
    """
    try:
        out = adb.shell_as(serial, package, f"sha256sum {shlex.quote(target)}")
    except subprocess.TimeoutExpired:
        return ""
    fields = out.split()
    return fields[0] if fields else ""


# The shortest run of a payload that is treated as the payload coming back
# rather than as a coincidence, when matching across word boundaries.
_ECHO_RUN = 8

# The shortest WORD of a payload that a device's word is checked against. Three,
# not eight, because a value is not obliged to be long: `pin 4021` is four
# characters and every bit as much a credential as a token. Not one or two,
# because a payload word that short - "a", "to" - is a substring of half of
# English and would delete the device's whole message on every failure.
_ECHO_WORD = 3


def _their_words_only(words: str, payload: bytes) -> str:
    """`said` with everything the device merely repeated back removed.

    THE PTY IS THE LEAK. `place_file` streams the payload down stdin, and an
    adb that allocates a pty echoes every byte of it back on stdout - which
    `_explain` would then quote to the operator as "the device said". For a
    wallpaper that is mojibake; for an app configuration it is a write token on
    a terminal, in a scrollback, and in whatever CI log the command ran under.

    Two passes, because they fail differently.

    The first drops any word the device said that CONTAINS a word we sent.
    Containment rather than equality, because a device does not quote us
    cleanly: a shell that ends up reading the payload as commands answers
    `sh: 4021: not found`, and `4021:` is not `4021`. `_ECHO_WORD` is the floor
    on what counts. Between that and the floor being three rather than eight, a
    short value is caught and a genuine diagnostic still reads: `run-as:
    package not debuggable: app.muster.agent` contains no word of a config file.

    The second is the backstop, for an echo that came back mangled - a pty's
    line discipline rewrites bytes on the way through, which is why
    `_read_digest` exists at all - so nothing matches word for word. If any run
    of the payload survives the first pass, nothing is quoted. Half a
    credential in a log is not half a problem.

    Both passes read the WHOLE payload, comments and key names included, so an
    unlucky config file can cost a real diagnostic. That is the trade, and it is
    why the caller says only that the reply overlapped the payload rather than
    claiming the device echoed it.
    """
    text = payload.decode("utf-8", "replace")
    sent = {word for word in text.split() if len(word) >= _ECHO_WORD}
    kept = " ".join(
        word for word in words.split() if not any(ours in word for ours in sent)
    )
    runs = (text[i : i + _ECHO_RUN] for i in range(len(text) - _ECHO_RUN + 1))
    if any(run in kept for run in runs):
        return ""
    return kept


def _explain(rc: int, said: str, secret: bytes = b"") -> str:
    """The device's own words for a write that did not land, if it said any.

    Never the verdict, only the explanation, and this is the second thing that
    was wrong here. Lines starting `* ` are adb talking to itself on this
    machine - `* daemon not running; starting now at tcp:5037` - and an adb
    that allocates a pty echoes the entire payload back on stdout. Treating
    either as the phone refusing fails a write that worked; printing all of it
    buries the operator in a megabyte of mojibake.

    `secret` is the payload when the payload is one nobody may see - see
    `_their_words_only`. Passing it costs a diagnostic in the worst case and
    keeps a credential off a terminal in the common one.
    """
    words = " ".join(
        line for line in said.splitlines() if line.strip() and not line.startswith("* ")
    )
    if secret and words:
        words = _their_words_only(words, secret)
        if not words:
            # WHAT IS ACTUALLY KNOWN, which is that the reply overlapped the
            # payload - not that the device echoed it. The check draws its runs
            # from the whole file, key names and comments included, so an
            # unlucky config can trip it on a genuine error message. Naming a
            # cause that was never established would be worse than losing the
            # words, because this is the sentence an operator reads on the day
            # `run-as` stops working.
            return (
                ". The device's reply is not quoted here: what it said overlaps "
                "the payload, and this payload may hold a credential"
            )
    if len(words) > 200:
        words = words[:200] + " ..."
    if words:
        return f". The device said: {words}"
    if rc != 0:
        return f". adb exited {rc} and said nothing"
    return ""


def place_file(
    adb: Adb,
    serial: str,
    package: str,
    target: str,
    payload: bytes,
    secret: bool = False,
) -> Placement:
    """Write one config file into the agent's files directory, through the app.

    WRITTEN THROUGH THE APP, NOT AROUND IT, and this corrects a comment that
    used to claim the opposite. Staging in /data/local/tmp and `cp`-ing across
    cannot work: the agent's data directory is `drwx------` owned by the app's
    uid, so the shell (uid 2000) cannot write into it or even traverse it.
    Measured on <device-serial> on 2026-08-19 - the `cp` failed, `muster
    restrictions` said nothing was wrong, and the file was never there. The
    read-back below was the only thing that noticed.

    `run-as` NEEDS A DEBUGGABLE PACKAGE, so this stops working the day the
    release-signed agent ships (docs/signing-ceremony.md), and it says so:

        run-as: package not debuggable: app.muster.agent

    WHAT REPLACES IT NOW EXISTS (muster#46): an enrolled device fetches the
    same files from the control plane, authenticated by the certificate it
    holds - see muster/policy.py and `POST /v1/device/config`. So this is no
    longer the only route, and its expiry is a route ending rather than the
    route ending.

    IT STAYS, AND IT IS STILL NEEDED. A device that has not enrolled has no
    identity to fetch with, which is the case `muster provision --server-url`
    handles, and a cable is how the first device in an estate is set up.

    THE DEVICE IS THE WITNESS, and specifically the sha256 it computes over the
    file afterwards - not the exit code, which an older adb reports as 0
    whatever the phone did, and not the byte count, which a pty would preserve
    while corrupting every CR in the file. `_read_digest` has that in full.

    `secret=True` says this payload holds credentials, which the app-config
    file does: `announceToken` is a write token and `ddClientToken` is a
    telemetry one. It changes exactly one thing - the device is no longer
    quoted verbatim when it fails, because an adb with a pty answers a write by
    reading the whole payload back. The sha256 is still computed over the real
    bytes, so nothing about the verification is weakened. This is the same bet
    `telemetry.event` makes on the server: one place drops the secret, rather
    than a dozen call sites remembering to.
    """
    directory = target.rsplit("/", 1)[0]
    # As the app, because the shell cannot create a directory inside one it
    # cannot traverse. An agent that has never been launched has no files dir
    # yet, so this is the common case rather than a fallback. Deliberately
    # unchecked: `mkdir -p` says the same thing when the directory already
    # exists, and the write below fails loudly if it did not work.
    adb.shell_as(serial, package, f"mkdir -p {shlex.quote(directory)}")

    rc, said = adb.write_as(serial, package, target, payload)

    withheld = payload if secret else b""
    wanted = hashlib.sha256(payload).hexdigest()
    landed = _read_digest(adb, serial, package, target)
    if landed == wanted:
        return Placement(True, f"{target}, {len(payload)} bytes")
    if not landed:
        return Placement(
            False,
            f"cannot prove {target} is on the device: asked the device for its "
            f"sha256 and got nothing back{_explain(rc, said, withheld)}",
        )
    return Placement(
        False,
        f"{target} on the device is not what was sent: it holds sha256 "
        f"{landed}, and {wanted} was pushed{_explain(rc, said, withheld)}",
    )
