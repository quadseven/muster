"""What one device is told to be, and where that comes from.

WHY THIS EXISTS (muster#46). Until it did, every configuration muster could
apply traveled over a cable: `place_file` writes into the agent's own files
directory through `adb shell run-as`. So a device that provisioned by QR and
enrolled over the air came up owned, restricted by nothing, showing every app
it shipped with, and identical to a factory phone until somebody enabled
wireless debugging and pushed six files.

That route also has an expiry date on it. `run-as` needs a DEBUGGABLE package,
so it stops working the day the release-signed agent ships - which is the day
the project becomes real. `place_file` stays for the cable case and for a device
that has not enrolled yet. It is the bootstrap, not the mechanism.

THE FILES ARE THE INTERFACE, AND THEY ARE THE SAME FILES. What is served here
is the exact byte content the agent already reads out of its own device-
protected storage: `restrictions`, `visible-apps`, `app-config`. The agent
writes what it fetches into those paths and the existing stewards reconcile from
there, both ways, with their existing read-back guards. Building a second apply
path would mean two vocabularies, two sets of refusals, and one of them
untested on a handset.

WHERE IT COMES FROM: a directory, because the alternative is a table nothing
writes to. A console for editing policy is muster#36; until that exists, a
database schema here would be a mechanism with no operator, which is the
"configured but absent" failure this estate keeps rediscovering. A directory is
a Secret in the pod, and the same text an operator already writes for
`muster restrictions --file`.

    <root>/kith.restrictions              every device in the kith
    <root>/kith.visible-apps
    <root>/kith.wallpaper
    <root>/<key_id>.restrictions          this device only
    <root>/<key_id>.visible-apps
    <root>/<key_id>.wallpaper
    <root>/<key_id>.app-config
    <root>/<key_id>.wipe             this device only, and NEVER the kith or a role

FLAT, WITH A DOT, AND NOT NESTED DIRECTORIES. A Kubernetes Secret key may not
contain a slash (`[-._a-zA-Z0-9]+`), so a nested layout can only be produced by
enumerating every file in the volume's `items:` - which would make adding a
device an edit to the deployment manifest. Flat names are what
`kubectl create secret generic muster-policy --from-file=...` writes directly.

The split is on the FIRST dot and it cannot be ambiguous: a key_id is 64 hex
characters, so no scope contains a dot, and no managed file name does either.

`kith.app-config` IS NEVER READ, ON PURPOSE. `app-config` is the file that
carries credentials - `announceToken` is a write token, `ddClientToken` is a
telemetry one - and a credential under the shared scope is a credential handed
to every device in the estate. Refusing to serve it is loud; serving it widely
is silent, and silent is how a token ends up on a phone in a drawer that
somebody later sells.

WHAT IS NOT HERE, AND HOW THE WALLPAPER GETS AROUND IT. Anything that is not
text. A PNG inside this JSON body - a megabyte of base64 in a response that
already carries a device's write tokens - would be a decision made by accident,
so the bytes travel over their own route (`muster/assets.py`, muster#45) and
what travels HERE is a `wallpaper` file that NAMES one:

    image wall.png sha256 3f2a...
    surfaces system lock

That keeps this closed vocabulary the only thing deciding what a device acts on.
The device fetches the named asset, checks it against the digest it was given
here, and applies it - so a substituted asset is caught by a policy file the
device fetched over its own identity, rather than trusted because it arrived.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
from dataclasses import dataclass

# The closed vocabulary of file names that may travel to a device.
#
# A CLOSED SET RATHER THAN "WHATEVER IS IN THE DIRECTORY", because the device
# writes what it is served into its own files directory. An open set is a remote
# write primitive over the agent's private storage, and the first thing it would
# be pointed at is `server-url` - the file that decides which control plane the
# device answers to. It also keeps an editor backup out of a phone.
# The one managed file that is NEVER sourced from the shared or role scopes,
# and is not even read from the policy directory. It is synthesized from the
# kith's `wipe_pending_at` state, because the decision to erase a device must
# be a membership transition rather than a Secret edit. A wipe file one typo
# away from `kith` scope is a fleet-wide factory reset, so it is device scope
# by construction and has no file-name fallback.
WIPE_FILE = "wipe"
WIPE_COMMAND = "wipe\n"

MANAGED_FILES: tuple[str, ...] = (
    "restrictions",
    "visible-apps",
    "app-config",
    # NAMES an asset and the digest to expect; it is not the image. See the
    # module docstring. Text, like everything else here, which is what lets it
    # travel the route that already exists rather than needing a second one.
    "wallpaper",
    # NAMES applications, the assets carrying them and the digests to expect.
    # A reference like `wallpaper`, for the same reason: an APK is twelve
    # megabytes and does not travel in a JSON body.
    "install-apps",
    # The instruction to erase the device. It is in the closed vocabulary so
    # the agent writes it into device-protected storage and WipeSteward reads
    # it, but it is not read from the policy directory: `for_device` returns it
    # only when the kith says this device is wipe-pending.
    WIPE_FILE,
)

# The half of that vocabulary a device may inherit from the kith.
#
# `app-config` is deliberately not here. See the module docstring: it is the
# file that holds credentials, and the shared directory is read by every device.
# `wallpaper` IS here: it names an asset and a digest, neither of which is a
# secret, and one background for the whole kith is the ordinary case.
#
# `wipe` is NOT here, and never may be. A wipe file under the shared scope is
# a fleet-wide factory reset one typo away. It is synthesized from the kith's
# wipe-pending state and never read from this directory.
SHARED_FILES: tuple[str, ...] = (
    "restrictions",
    "visible-apps",
    "wallpaper",
    # HERE, unlike `app-config`: it names public artefacts and their digests,
    # none of which is a credential, and "every device carries the agent" is
    # the ordinary case rather than the exception.
    "install-apps",
)

# The scope every device in the kith reads from, when it has no file of its own.
# CONTEXT.md's word for "the set of devices muster recognizes", used here rather
# than "default" so the directory says which devices it applies to.
KITH_SCOPE = "kith"

# The scope a ROLE reads from, and the prefix is what keeps the three kinds of
# scope apart in one flat directory (muster#70). A role says what is DIFFERENT
# about a set of devices - "these are zippie androids" - and sits between the
# device and the kith:
#
#     <key_id>.restrictions        this device
#     role-zippie.restrictions     every device with this role
#     kith.restrictions            every device
#
# PREFIXED RATHER THAN BARE, so a role can never be mistaken for the other two.
# `kith` is a reserved word and a key_id is 64 hex characters; a bare role could
# collide with either, and the collision would be an operator addressing a
# device's policy by naming a role after it.
ROLE_SCOPE_PREFIX = "role-"

# Which files a role may carry, and it is ALL of them - including `app-config`,
# which the kith may not.
#
# THIS IS A SECURITY DECISION AND IT IS THE POINT OF ROLES. `kith.app-config` is
# never read because that file holds write tokens and the kith is every device
# in the estate. A role is narrower and is exactly what an operator means by
# "make it a zippie android so it does zippie config": the zippie token reaches
# the zippie androids and nothing else.
#
# It is still a credential shared by every device carrying the role. That is the
# trade, made deliberately - a role is a statement that these devices are
# interchangeable, and interchangeable devices share what they run.
#
# `wipe` is excluded even though roles may carry every other managed file. A
# role means "these devices are interchangeable", which is precisely the wrong
# scope for an instruction that erases ONE device. Wipe is device scope only,
# by construction, not by operator discipline.
ROLE_FILES: tuple[str, ...] = tuple(name for name in MANAGED_FILES if name != WIPE_FILE)

# Same shape as enroll._ROLE, and checked again here on purpose. By the time a
# role reaches this module it is about to become half of a path.
_ROLE = re.compile(r"^[a-z]([a-z0-9-]{0,29}[a-z0-9])?\Z")

# A key_id is `hashlib.sha256(...).hexdigest()` (muster/enroll.py), so nothing
# that reaches this module can contain a path separator. Checked anyway, at this
# module's own boundary rather than trusting the one caller it has today: the
# difference between a lookup and an arbitrary read of the pod's filesystem is
# not a property to leave resting on a function two files away.
_KEY_ID = re.compile(r"^[0-9a-f]{64}\Z")


class Unreadable(Exception):
    """A configured file exists and could not be read. NOT "there is none"."""


class NoSource(Exception):
    """muster cannot say what this device should be. NOT "it should be nothing".

    THE FAILURE THIS EXISTS TO STOP, and it is the one that would actually have
    happened. `muster-policy` is an OPTIONAL secret volume, and kubelet mounts an
    optional secret that does not exist as an EMPTY DIRECTORY. A secret that was
    deleted, misnamed, or never created therefore reads exactly like a policy
    directory nobody has put anything in - and an empty answer, served with a
    200, is an authoritative instruction to the whole fleet to delete every file
    muster manages. One typo in a secret name, and every device withdraws its
    configuration on its next boot.

    So an empty source is a REFUSAL, not an answer. Saying "assert nothing" is
    still possible and is still one file: an empty `kith.restrictions` withdraws
    every restriction, which is the vocabulary the agent already speaks
    (docs/policy.md - an absent file and an empty file mean different things).
    What is no longer possible is saying it by accident.
    """


@dataclass(frozen=True)
class Configuration:
    """What one device is told to be, ready to go on the wire.

    `__str__` IS OVERRIDDEN EVEN THOUGH THIS IS A DATACLASS, for the same reason
    `AppConfigPolicy` overrides it in the agent: the generated one prints every
    field, one of those fields is a write token, and this object is going to
    end up in an f-string in a log line the first time somebody debugs a fetch.
    Names and the revision are what a log is for.
    """

    key_id: str
    files: dict[str, str]
    revision: str
    role: str = ""

    def __str__(self) -> str:
        role = f" role={self.role}" if self.role else ""
        return f"revision={self.revision}{role} files={sorted(self.files)}"

    __repr__ = __str__


def _revision(files: dict[str, str]) -> str:
    """A name for exactly this configuration, stable across pods and restarts.

    STABLE, NOT MINTED PER READ. A random value regenerated on every fetch would
    have every device rewriting identical files and reporting a policy change
    that did not happen, and would make "are these two devices on the same
    policy" unanswerable. So it is a digest of the served content.

    THE DIGEST COVERS CREDENTIALS, AND THAT IS ACCEPTED RATHER THAN OVERLOOKED.
    A digest is a confirmation oracle for anybody who can already guess the
    whole payload byte for byte, and the people who see this value are the
    device that already holds the payload and whoever reads muster's logs. It is
    deliberately NOT a metric tag: that would be per-device cardinality as well
    as a wider audience.
    """
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:32]


def _read(path: pathlib.Path) -> str:
    """One file, or Unreadable. Never a silent empty string.

    An empty string is a real instruction here - an empty `restrictions` file
    means "withdraw everything" - so a read that fails must not be able to
    produce one. That is the whole reason this is not `path.read_text()` with a
    default.
    """
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise Unreadable(
            f"{path.name} is configured for this device and could not be read: {exc}"
        ) from exc


@dataclass
class Policies:
    """The directory, read on demand.

    READ ON DEMAND RATHER THAN CACHED AT STARTUP, because the point of a
    directory is that an operator can change it without a rollout. A ConfigMap
    update lands in the pod's filesystem within a minute or so; a copy taken at
    boot would mean every policy change needed a restart, which is a rollout
    wearing a different hat.

    `root=None` is a supported mode and the default, for the same reason
    `Telemetry` defaults to a disabled emitter and `Kith` to an in-memory one:
    every call site can then ask unconditionally, and there is no `if
    state.policies:` to forget on the one path nobody exercises.
    """

    root: pathlib.Path | None = None
    # Only for status(): the operator asked for a directory that is not there.
    # Kept as text so that "which path did it want" survives into /readyz.
    configured: str = ""

    def files_held(self) -> int:
        """How many files muster would serve from, across every device.

        COUNTED RATHER THAN ASSUMED, because "the volume is mounted" is not the
        question anybody has - an optional secret that does not exist mounts as
        an empty directory, so a mount point proves nothing. This is the number
        that tells a live policy source from a secret somebody deleted, and it
        is why `status()` reports it rather than a boolean.

        `iterdir` and not a recursive walk: the layout is flat by construction,
        and this runs on /readyz every ten seconds.
        """
        if self.root is None:
            return 0
        try:
            return sum(
                1
                for entry in self.root.iterdir()
                # By FILE NAME, not by scope: a role file is policy too, and a
                # directory holding only role files must not read as empty -
                # that count is what tells a live directory from a deleted
                # secret.
                if (
                    entry.is_file()
                    and entry.name.split(".", 1)[-1] in MANAGED_FILES
                    # Wipe is synthesized from the kith, never read from here.
                    # Counting a stray `kith.wipe` as policy would make a
                    # directory holding only that dangerous typo look like a
                    # live source and serve an empty configuration to devices.
                    and entry.name.split(".", 1)[-1] != WIPE_FILE
                )
            )
        except OSError:
            # A directory that cannot be listed is not an empty one. Reported as
            # zero here and refused by `for_device`, which is the same answer.
            return 0

    def status(self) -> dict:
        """Said out loud at boot and on /readyz.

        `files` IS THE FIELD THAT MATTERS. A policy directory that did not mount
        and a fleet nobody has configured yet answer every device identically,
        and `readable` alone cannot tell them apart - an optional secret volume
        that is absent still produces a readable, empty directory. A count can.
        """
        return {
            "directory": self.configured or (str(self.root) if self.root else ""),
            "readable": self.root is not None,
            "files": self.files_held(),
        }

    def for_device(
        self, key_id: str, role: str = "", wipe_pending: bool = False
    ) -> Configuration:
        """What this device is told to be, most specific scope first.

        THE ORDER IS device, then role, then kith, and it is a fallback per FILE
        rather than per device. A role says what is different about a set of
        devices; requiring it to restate the fleet's whole policy is how the two
        drift, and the drift is silent because both files look maintained.

        WIPE IS THE ONE FILE THAT DOES NOT COME FROM THIS DIRECTORY. It is
        synthesized from the kith's `wipe_pending_at` and returned before any
        policy read, so an absent policy secret or an unreadable file cannot
        stand between a wipe instruction and the device that must receive it.
        That is also why it cannot be authored as `kith.wipe` or `role-*.wipe`:
        the shared and role scopes are intentionally not consulted for this
        name.
        """
        if not _KEY_ID.match(key_id):
            raise ValueError(
                "a key_id is 64 lowercase hex characters; this is not one"
            )
        # THE SECOND DOOR. `enroll.mint` refuses a bad role at the first one,
        # and this module checks again because the difference between a lookup
        # and an arbitrary read of the pod's filesystem is not a property to
        # leave resting on a function two modules away.
        if role and not _ROLE.match(role):
            raise ValueError(
                f"'{role}' is not a role: lowercase letters, digits and dashes, "
                "starting with a letter. A role becomes half of a file name here."
            )

        # WIPE-PENDING DOES NOT NEED THE REST OF POLICY, and it must not wait
        # for it. The device is about to be erased; a broken policy volume is
        # not a reason to leave the wipe undelivered, and a shorter answer is
        # safe here because the next thing the device does is erase itself.
        if wipe_pending:
            files = {WIPE_FILE: WIPE_COMMAND}
            return Configuration(
                key_id=key_id,
                files=files,
                revision=_revision(files),
                role=role,
            )

        if self.root is None:
            raise NoSource(
                "this muster has no policy directory, so it cannot say what a "
                f"device should be (MUSTER_POLICY_DIR={self.configured or 'unset'})"
            )
        if self.files_held() == 0:
            # See NoSource. An empty directory is a deleted secret at least as
            # often as it is a deliberate instruction, and only one of those two
            # readings is recoverable.
            raise NoSource(
                f"the policy directory {self.root} holds nothing muster manages. "
                "An empty directory is not an instruction to withdraw policy - "
                "write an empty kith.restrictions to say that deliberately."
            )

        files: dict[str, str] = {}
        for name in MANAGED_FILES:
            # Wipe is not read here, even from `<key_id>.wipe`. It is the one
            # managed name whose source is membership state, not an operator
            # editing a Secret, because a wipe file must not be able to become
            # a shared file through a filename typo.
            if name == WIPE_FILE:
                continue
            mine = self.root / f"{key_id}.{name}"
            if mine.is_file():
                files[name] = _read(mine)
                continue
            # Then the role, if this device has one. Role files include
            # `app-config` where the kith's does not - see ROLE_FILES.
            if role and name in ROLE_FILES:
                ours = self.root / f"{ROLE_SCOPE_PREFIX}{role}.{name}"
                if ours.is_file():
                    files[name] = _read(ours)
                    continue
            # Falling through to the shared scope is what makes one edit reach a
            # fleet. `app-config` never gets here - see SHARED_FILES.
            theirs = self.root / f"{KITH_SCOPE}.{name}"
            if name in SHARED_FILES and theirs.is_file():
                files[name] = _read(theirs)
        return Configuration(
            key_id=key_id, files=files, revision=_revision(files), role=role
        )


def from_env() -> Policies:
    """Wire from the environment, and never refuse to start over it.

    A missing or unmountable policy directory must NOT crash the pod. The same
    argument as the kith store: a control plane that refuses to come up has
    stopped every device in the estate renewing, and lapse is a pairing code and
    a human holding the handset. What stops "optional" turning into "silently
    absent" is `status()`, which is reported at boot and on /readyz.
    """
    configured = os.environ.get("MUSTER_POLICY_DIR", "").strip()
    if not configured:
        return Policies()
    path = pathlib.Path(configured)
    if not path.is_dir():
        return Policies(root=None, configured=configured)
    return Policies(root=path, configured=configured)
