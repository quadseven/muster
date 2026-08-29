"""Operator files a device may fetch, and where they live.

WHY THIS EXISTS (muster#45). Every asset muster could apply used to travel over
a cable: `muster wallpaper` reads a PNG off the operator's laptop and pushes it
with `adb`. That works for one handset within cable reach and is unreachable for
a phone on somebody else's network - which, since QR provisioning landed, is
every device muster enrolls. The wallpaper on the open-source-MDM-managed Pixel comes
from a PNG in `/www` on a travel router, and a travel router is not a record of
what a fleet is supposed to have.

WHAT THIS IS NOT. It is not the whole of muster#45. An APK is the same route
with a bigger file behind it, and this store is a directory - which is a Secret
in the pod, capped at a megabyte. That is right-sized for a wallpaper and wrong
for an APK. The part meant to outlive the backing store is the ROUTE and its
contract: a name, a digest the device verifies, and `no-store`. Swapping the
directory for object storage later is a change to `fetch` and to nothing the
device knows about.

WHY A DIRECTORY, AGAIN. The same argument as `policy.Policies`: a table nothing
writes to is a mechanism with no operator, and a console for uploading assets is
muster#36. A directory is a Secret, and putting a file in it is one command an
operator already runs for policy.

    kubectl -n muster create secret generic muster-assets \\
      --from-file=wall.png=./zippie-wall.png

HOW A DEVICE LEARNS AN ASSET EXISTS is deliberately not here. It is told by a
managed policy file - `wallpaper` names an asset and the digest it expects - so
the closed vocabulary in `policy.MANAGED_FILES` stays the only thing that
decides what a device acts on. An endpoint that let a device enumerate the store
would be a wider answer than any device needs.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import os
import pathlib
import re
from dataclasses import dataclass

# The most bytes muster will read into memory to answer one request.
#
# A CAP RATHER THAN A STREAM, and the reason is this route's contract. The
# device verifies a digest, so the file has to be read through to serve it
# whatever happens; streaming would move where the memory goes rather than
# remove it. The pod's limit is 256Mi, so an uncapped read of a file an operator
# put in the wrong place is the pod being OOM-killed - which takes every other
# device's renewal down with it.
#
# RAISED FROM 8 MiB WHEN THE STORE MOVED OFF A SECRET (muster#75). The agent
# APK is ~12.7 MB, which is what the move was for - a Secret tops out near a
# megabyte, so the old ceiling was never the binding one and 8 MiB would have
# refused the first thing anybody wanted to serve. 32 MiB leaves room for an
# APK to grow without leaving room for a mistake.
MAX_BYTES = 32 * 1024 * 1024

# What an asset may be called. A CLOSED PATTERN, checked before the name is ever
# joined to a path.
#
# Refused BY NAME rather than by resolving and comparing against the root: a
# check that resolves first has already followed a symlink by the time it has
# something to compare. Both are done below - this one decides, and the symlink
# check catches a store somebody has pointed at something odd.
#
# No leading dot, so an editor backup or a `..` cannot be addressed. No slash or
# backslash, so nothing can leave the directory. No spaces, because a name that
# needs quoting in a shell is a name that will be mistyped in a policy file.
_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}\Z")

# What a device is told the bytes are. A CLOSED MAP with a boring default: an
# extension-to-type guess out of the standard library would let a file name
# decide a `Content-Type`, and `text/html` from muster's own origin is worth
# more to an attacker than the file is.
_MEDIA_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".apk": "application/vnd.android.package-archive",
}
_DEFAULT_MEDIA_TYPE = "application/octet-stream"


# How long muster will wait for the storage under it, per touch.
#
# THIS EXISTS BECAUSE OF WHAT THE UNAS DOES WHEN IT GOES AWAY. SMB
# unavailability BLOCKS rather than erroring: a measured 90-second host-level
# drop hung a plain `ls` for 106 SECONDS and then returned success. `soft` does
# not produce EIO, and a pod with a wedged write sat in D state for nineteen
# minutes.
#
# muster is a control plane. An unbounded touch is a request thread it never
# gets back, and enough of those stop enrollment and renewal - a device that
# cannot renew LAPSES, and lapse on a Device Owner phone means a wipe. So a
# wallpaper nobody can read must degrade to "no wallpaper", never to "no
# certificates".
STORAGE_TIMEOUT_S = 5.0

# How many storage touches may be in flight at once.
#
# A timeout STOPS WAITING; it cannot stop the thread, which stays blocked in the
# kernel until the mount recovers. Without a ceiling those accumulate one per
# request for as long as the NAS is away. The pool bounds them, and a request
# that cannot get a slot is refused immediately - which is the right answer,
# because it is the same answer the slot would have given it.
_STORAGE_WORKERS = 4
_storage = concurrent.futures.ThreadPoolExecutor(
    max_workers=_STORAGE_WORKERS, thread_name_prefix="muster-assets"
)


def _read_bytes(path: pathlib.Path) -> bytes:
    """Isolated so a test can make it hang, which is the only way to test this."""
    return path.read_bytes()


def _list_names(root: pathlib.Path) -> list[str]:
    """Isolated for the same reason as `_read_bytes`."""
    return sorted(
        entry.name
        for entry in root.iterdir()
        if _NAME.match(entry.name) and entry.is_file()
    )


def _bounded(work, *args):
    """Run one storage touch, or raise `Unavailable` rather than wait forever."""
    try:
        future = _storage.submit(work, *args)
    except RuntimeError as exc:  # interpreter shutting down
        raise Unavailable(f"muster is stopping: {exc}") from exc
    try:
        return future.result(timeout=STORAGE_TIMEOUT_S)
    except concurrent.futures.TimeoutError as slow:
        # NOT CANCELLED, because it cannot be: the thread is blocked in a
        # syscall the interpreter does not interrupt. It is abandoned, and
        # `_STORAGE_WORKERS` is what stops abandoning one per request from
        # growing without bound.
        raise Unavailable(
            f"the asset store did not answer within {STORAGE_TIMEOUT_S}s. The "
            "share is unreachable or wedged; muster is otherwise unaffected."
        ) from slow


class Unavailable(Exception):
    """The storage under the store did not answer. NOT "there is no asset".

    A SEPARATE FAILURE FROM `NoSource`, and the difference is where somebody
    goes to look. `NoSource` is a Secret that was never created - an operator
    fixes it. This is a share that stopped answering - it usually fixes itself,
    and the device should come back rather than conclude its policy was
    withdrawn.
    """


class Unknown(Exception):
    """No asset by that name. Also what an unusable name gets, deliberately.

    A caller asking for `../../etc/passwd` and a caller asking for a file that
    was never uploaded are told the same thing, because the difference is only
    ever useful to the first one.
    """


class Unreadable(Exception):
    """An asset is there and could not be read. NOT "there is none"."""


class TooLarge(Exception):
    """An asset is there and is bigger than muster will serve."""


class NoSource(Exception):
    """muster has no asset store. NOT "the store is empty".

    The same failure `policy.NoSource` exists for: an OPTIONAL secret volume
    that does not exist is mounted as an EMPTY DIRECTORY, so a secret that was
    deleted, misnamed or never created is indistinguishable from a store nobody
    has put anything in. Here that would mean answering "no such asset" for a
    wallpaper that is configured and present, and the device would report a
    missing asset rather than a missing store.
    """


@dataclass(frozen=True)
class Asset:
    """One file, read, with the digest of exactly the bytes in `content`.

    `__str__` IS OVERRIDDEN for the same reason `policy.Configuration` overrides
    it: this object ends up in an f-string in a log line the first time somebody
    debugs a fetch, and the generated `__repr__` prints every field. One of
    those fields is a megabyte of PNG, and the next one will be an APK.
    """

    name: str
    content: bytes
    digest: str

    @property
    def media_type(self) -> str:
        return _MEDIA_TYPES.get(
            pathlib.PurePosixPath(self.name).suffix.lower(), _DEFAULT_MEDIA_TYPE
        )

    def __str__(self) -> str:
        return f"{self.name} ({len(self.content)} bytes, sha256:{self.digest[:12]})"

    __repr__ = __str__


@dataclass
class Assets:
    """The store, read on demand.

    READ ON DEMAND for the same reason `policy.Policies` is: an operator
    replacing a wallpaper should not need a rollout, and a Secret update lands
    in the pod's filesystem within a minute or so.
    """

    root: pathlib.Path | None = None
    # Only for status(): the operator asked for a directory that is not there.
    configured: str = ""

    def names(self) -> list[str]:
        """What is actually in the store, by the same rules `fetch` applies.

        Not served to a device - see the module docstring - but the number is
        what tells a live store from a secret somebody deleted, and a name that
        `fetch` would refuse should not be counted as an asset.
        """
        if self.root is None:
            return []
        try:
            return _bounded(_list_names, self.root)
        except (OSError, Unavailable):
            # A directory that cannot be listed is not an empty one. Reported as
            # nothing here and refused by `fetch`, which is the same answer -
            # and `Unavailable` is caught alongside OSError on purpose, because
            # `status()` feeds /readyz and MUST answer. A readiness probe that
            # hangs on a wedged share gets the pod killed, and a restart cannot
            # unwedge a mount.
            return []

    def status(self) -> dict:
        """Said out loud at boot and on /readyz.

        `assets` IS THE FIELD THAT MATTERS, for the reason `policy.status`
        reports a count rather than a boolean: an absent optional secret volume
        still produces a readable, empty directory.
        """
        # ASKED ONCE, because on a wedged share each call costs the timeout and
        # this runs on /readyz every ten seconds.
        reachable = self.root is not None and self.reachable()
        return {
            "directory": self.configured or (str(self.root) if self.root else ""),
            # `readable` NOW MEANS "muster can actually read it", not "a path was
            # configured". On a Secret volume those were the same thing; on a
            # share that can stop answering they are not, and the whole point of
            # this field is to tell a live store from one that is gone.
            "readable": reachable,
            "assets": len(self.names()) if reachable else 0,
        }

    def reachable(self) -> bool:
        """Does the storage answer at all, within the bound?

        Separate from `names()` because "the share is gone" and "the share is
        empty" are different answers and only one of them is an operator's
        fault.
        """
        if self.root is None:
            return False
        try:
            _bounded(_list_names, self.root)
        except (OSError, Unavailable):
            return False
        return True

    def fetch(self, name: str) -> Asset:
        """One asset, or a refusal that says which kind of nothing this is."""
        if self.root is None:
            raise NoSource(
                "this muster has no asset store, so it cannot serve a file "
                f"(MUSTER_ASSET_DIR={self.configured or 'unset'})"
            )
        if not self.names():
            # See NoSource. An empty store is a deleted secret at least as often
            # as it is a store nobody has filled, and only one of those two
            # readings sends somebody to look at the right thing.
            raise NoSource(
                f"the asset store {self.root} holds nothing. An empty store is "
                "not the same as a missing asset - check the muster-assets secret."
            )
        if not _NAME.match(name or ""):
            raise Unknown(f"'{name}' is not a name an asset can have")

        # RESOLVED AND THEN CONTAINED, rather than "refuse every symlink".
        #
        # Refusing symlinks outright is what shipped first, and it refused the
        # only deployment this store actually has. A Kubernetes Secret volume
        # does not place files: it places a timestamped directory, a `..data`
        # symlink to it, and one symlink PER KEY pointing through `..data` -
        # which is how it swaps a whole Secret atomically. Every asset muster
        # serves is therefore a symlink, and the guard rejected all of them
        # while `/readyz` went on counting them (`is_file` follows a link and
        # `is_symlink` does not), so the store reported one asset and served
        # none.
        #
        # What that guard was actually for is a link pointing OUT of the store,
        # and containment is the check for that: resolve, then require the
        # result to still be inside the resolved root. `..data/wall.png`
        # resolves to a sibling of the root's own subdirectory and stays inside;
        # a link to /etc/muster/ca does not.
        try:
            root = self.root.resolve(strict=True)
            path = (root / name).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            # RuntimeError is a symlink loop. Both are "no such asset" to the
            # caller, for the reason `Unknown` gives.
            raise Unknown(f"no asset named '{name}': {exc}") from exc
        if not path.is_relative_to(root) or not path.is_file():
            raise Unknown(f"no asset named '{name}'")
        try:
            size = _bounded(lambda p: p.stat().st_size, path)
        except OSError as exc:
            raise Unreadable(f"'{name}' could not be measured: {exc}") from exc
        if size > MAX_BYTES:
            raise TooLarge(
                f"'{name}' is {size} bytes and muster serves at most {MAX_BYTES}"
            )
        try:
            content = _bounded(_read_bytes, path)
        except OSError as exc:
            raise Unreadable(f"'{name}' is in the store and could not be read: {exc}") from exc
        return Asset(name=name, content=content, digest=hashlib.sha256(content).hexdigest())


def from_env() -> Assets:
    """Wire from the environment, and never refuse to start over it.

    Same argument as `policy.from_env`: a control plane that will not come up
    has stopped every device in the estate renewing, and lapse is a pairing code
    and a human holding the handset. What stops "optional" turning into
    "silently absent" is `status()`, reported at boot and on /readyz.
    """
    configured = os.environ.get("MUSTER_ASSET_DIR", "").strip()
    if not configured:
        return Assets()
    path = pathlib.Path(configured)
    if not path.is_dir():
        return Assets(root=None, configured=configured)
    return Assets(root=path, configured=configured)
