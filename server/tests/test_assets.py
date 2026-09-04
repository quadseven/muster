"""Where an operator's files live, and what a device is allowed to fetch.

The store exists because everything muster could apply used to travel over a
cable (muster#45). A wallpaper is the smallest case and the one that proves the
route; an APK is the same route with a bigger file behind it.

The tests that matter most are `test_a_name_cannot_walk_out_of_the_directory` -
the endpoint takes a name from an unauthenticated-until-proven caller and turns
it into a path - and `test_an_empty_directory_is_refused_rather_than_answered`,
which is the same reasoning `policy.NoSource` exists for.
"""
# Spark-authored: deepseek-v4-flash-0731 on an on-prem DGX Spark, 2026-09-04; review pending
from __future__ import annotations

import hashlib
import pathlib

import pytest

from muster import assets


@pytest.fixture()
def store(tmp_path: pathlib.Path) -> assets.Assets:
    (tmp_path / "wall.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"pretend" * 10)
    return assets.Assets(root=tmp_path, configured=str(tmp_path))


def test_an_asset_comes_back_with_its_bytes_and_a_digest(store):
    asset = store.fetch("wall.png")
    assert asset.content.startswith(b"\x89PNG")
    assert asset.digest == hashlib.sha256(asset.content).hexdigest()


def test_the_digest_is_of_the_bytes_served_and_nothing_else(store, tmp_path):
    # Not of the name, not of the mtime. A device that re-applies because a
    # file was touched is the unconditional version wearing a disguise.
    first = store.fetch("wall.png").digest
    (tmp_path / "wall.png").touch()
    assert store.fetch("wall.png").digest == first


def test_a_changed_file_changes_the_digest(store, tmp_path):
    before = store.fetch("wall.png").digest
    (tmp_path / "wall.png").write_bytes(b"\x89PNG\r\n\x1a\ndifferent")
    assert store.fetch("wall.png").digest != before


@pytest.mark.parametrize(
    "name",
    [
        "../secret",
        "../../etc/passwd",
        "a/b.png",
        "/etc/passwd",
        "",
        ".",
        "..",
        ".hidden",
        "with space.png",
        "sub\\dir.png",
        "x" * 200,
    ],
)
def test_a_name_cannot_walk_out_of_the_directory(store, name):
    """The one input this module takes from outside, turned into a path.

    Refused by NAME rather than by resolving and comparing to the root: a
    check that resolves first has already followed a symlink by the time it
    compares.
    """
    with pytest.raises(assets.Unknown):
        store.fetch(name)


def test_a_symlink_out_of_the_directory_is_not_followed(tmp_path):
    root = tmp_path / "assets"
    root.mkdir()
    (tmp_path / "secret").write_bytes(b"the CA key")
    (root / "wall.png").symlink_to(tmp_path / "secret")
    store = assets.Assets(root=root, configured=str(root))
    with pytest.raises(assets.Unknown):
        store.fetch("wall.png")


def _as_kubernetes_mounts_a_secret(root: pathlib.Path, **files: bytes) -> None:
    """The layout a Secret volume actually has, which is not plain files.

    kubelet writes a timestamped directory, a `..data` symlink to it, and one
    symlink PER KEY pointing through `..data` - which is how a whole Secret is
    swapped atomically. Every asset muster serves is therefore a symlink.
    """
    data = root / "..2026_08_21_00_18_15.2564233962"
    data.mkdir(parents=True)
    for name, content in files.items():
        (data / name).write_bytes(content)
    (root / "..data").symlink_to(data.name)
    for name in files:
        (root / name).symlink_to(pathlib.Path("..data") / name)


def test_an_asset_mounted_the_way_kubernetes_mounts_one_is_served(tmp_path):
    """THE TEST THAT WAS MISSING, and it cost a deployment to find out.

    `tmp_path` fixtures write plain files; the only store muster has writes
    symlinks. A guard that refused every symlink passed every test here and
    refused every asset in production, while `/readyz` counted them - `is_file`
    follows a link and `is_symlink` does not - so the store reported one asset
    and served none.
    """
    root = tmp_path / "assets"
    root.mkdir()
    _as_kubernetes_mounts_a_secret(root, **{"wall.png": b"\x89PNG\r\n\x1a\nreal bytes"})
    store = assets.Assets(root=root, configured=str(root))

    asset = store.fetch("wall.png")
    assert asset.content.startswith(b"\x89PNG")
    assert asset.digest == hashlib.sha256(asset.content).hexdigest()


def test_readyz_and_fetch_agree_on_a_kubernetes_mount(tmp_path):
    """A count that disagrees with what can be fetched is worse than either
    number alone: it is what sent somebody to look at the policy file when the
    store was the problem."""
    root = tmp_path / "assets"
    root.mkdir()
    _as_kubernetes_mounts_a_secret(root, **{"wall.png": b"x", "other.png": b"y"})
    store = assets.Assets(root=root, configured=str(root))

    assert store.status()["assets"] == 2
    for name in ("wall.png", "other.png"):
        assert store.fetch(name).content


def test_the_secrets_own_dot_directories_are_not_assets(tmp_path):
    """`..data` and `..2026_...` are kubelet's, not an operator's."""
    root = tmp_path / "assets"
    root.mkdir()
    _as_kubernetes_mounts_a_secret(root, **{"wall.png": b"x"})
    store = assets.Assets(root=root, configured=str(root))

    assert store.names() == ["wall.png"]
    with pytest.raises(assets.Unknown):
        store.fetch("..data")


def test_an_asset_that_is_not_there_is_unknown(store):
    with pytest.raises(assets.Unknown):
        store.fetch("nothing.png")


def test_a_directory_is_not_an_asset(store, tmp_path):
    (tmp_path / "adir.png").mkdir()
    with pytest.raises(assets.Unknown):
        store.fetch("adir.png")


def test_an_asset_larger_than_the_cap_is_refused(tmp_path):
    """A 256Mi pod must not read an arbitrary file into memory to answer.

    Refused rather than streamed, because the digest this route's whole
    contract rests on cannot be computed without reading the file anyway.
    """
    (tmp_path / "big.png").write_bytes(b"\x00" * (assets.MAX_BYTES + 1))
    store = assets.Assets(root=tmp_path, configured=str(tmp_path))
    with pytest.raises(assets.TooLarge):
        store.fetch("big.png")


def test_no_directory_configured_is_refused_and_not_an_empty_answer():
    with pytest.raises(assets.NoSource):
        assets.Assets().fetch("wall.png")


def test_an_empty_directory_is_refused_rather_than_answered(tmp_path):
    """Same reasoning as policy.NoSource: an optional secret volume that does
    not exist mounts as an empty directory, and reads exactly like a store
    nobody has put anything in."""
    store = assets.Assets(root=tmp_path, configured=str(tmp_path))
    with pytest.raises(assets.NoSource):
        store.fetch("wall.png")


def test_status_counts_what_is_actually_there(store, tmp_path):
    assert store.status()["assets"] == 1
    (tmp_path / "second.png").write_bytes(b"\x89PNG\r\n\x1a\nx")
    assert store.status()["assets"] == 2


def test_status_of_an_unconfigured_store_says_so():
    status = assets.Assets().status()
    assert status["readable"] is False
    assert status["assets"] == 0


def test_a_media_type_is_decided_by_a_closed_map(store, tmp_path):
    assert store.fetch("wall.png").media_type == "image/png"
    (tmp_path / "app.apk").write_bytes(b"PK\x03\x04")
    assert store.fetch("app.apk").media_type == "application/vnd.android.package-archive"
    (tmp_path / "mystery.dat").write_bytes(b"?")
    assert store.fetch("mystery.dat").media_type == "application/octet-stream"


def test_an_asset_never_prints_its_own_bytes(store):
    """The same reason policy.Configuration overrides __str__: this object will
    end up in an f-string in a log line the first time somebody debugs a fetch,
    and a megabyte of PNG in a log is the good outcome - an APK is worse."""
    asset = store.fetch("wall.png")
    assert "PNG" not in str(asset)
    assert asset.name in str(asset)
    assert asset.digest[:12] in str(asset)


def test_from_env_never_refuses_to_start(monkeypatch, tmp_path):
    """A control plane that will not come up has stopped every device in the
    estate renewing. Same argument as policy.from_env."""
    monkeypatch.setenv("MUSTER_ASSET_DIR", str(tmp_path / "not-there"))
    store = assets.from_env()
    assert store.root is None
    assert store.configured.endswith("not-there")


def test_from_env_unset_is_a_store_that_holds_nothing(monkeypatch):
    monkeypatch.delenv("MUSTER_ASSET_DIR", raising=False)
    assert assets.from_env().root is None


# ---- a store that can hang (muster#75) -----------------------------------
#
# The asset store moves off a Secret volume and onto the UNAS over SMB, which
# is the only way an APK fits. That storage has a property a tmpfs does not:
# UNAVAILABILITY BLOCKS RATHER THAN ERRORING. A measured 90s host-level drop
# hung `ls` for 106 SECONDS and then returned success.
#
# muster is a control plane. If a filesystem touch can hang a request thread
# indefinitely, a NAS hiccup stops enrollment and renewal - and a device that
# cannot renew lapses, which on a Device Owner phone means a wipe. So every
# touch is bounded, and the bound is what these tests hold.


def _hanging(monkeypatch, target: str, seconds: float = 30.0) -> None:
    """Make one filesystem call take longer than muster is willing to wait."""
    import time as _time

    def _slow(*args, **kwargs):
        _time.sleep(seconds)

    monkeypatch.setattr(assets, target, _slow, raising=False)


def test_a_wedged_store_is_reported_rather_than_waited_on(tmp_path, monkeypatch):
    """THE TEST THIS SECTION EXISTS FOR. A read that never returns must become
    an answer, because the alternative is a request thread muster never gets
    back."""
    import time

    store = assets.Assets(root=tmp_path, configured=str(tmp_path))
    (tmp_path / "wall.png").write_bytes(b"\x89PNG")
    monkeypatch.setattr(assets, "STORAGE_TIMEOUT_S", 0.2)
    monkeypatch.setattr(
        assets, "_read_bytes", lambda p: time.sleep(30), raising=False
    )

    started = time.monotonic()
    with pytest.raises(assets.Unavailable):
        store.fetch("wall.png")
    assert time.monotonic() - started < 5, "muster waited on a wedged store"


def test_a_wedged_store_does_not_hang_readyz(tmp_path, monkeypatch):
    """`status()` is what /readyz publishes. If it can hang, a NAS hiccup makes
    the kubelet kill a pod whose restart cannot fix a wedged mount - so it
    answers, and says the store is unavailable."""
    import time

    store = assets.Assets(root=tmp_path, configured=str(tmp_path))
    monkeypatch.setattr(assets, "STORAGE_TIMEOUT_S", 0.2)
    monkeypatch.setattr(assets, "_list_names", lambda p: time.sleep(30), raising=False)

    started = time.monotonic()
    status = store.status()
    assert time.monotonic() - started < 5, "status() waited on a wedged store"
    assert status["readable"] is False
    assert status["assets"] == 0


# The readiness probe's own budget, from the Deployment manifest in the
# operator's ops repository.
#
# WHAT THIS IS A COPY OF, AND FROM WHERE. The real value lives in
# production/oke/manifests/muster/deployment.yaml (readinessProbe.timeoutSeconds),
# which this repo cannot see. It is written down here to hold muster's internal
# storage bound - `assets.STORAGE_TIMEOUT_S` - inside it, and the date is the
# day it was read off the live pod.
#
# THE INVARIANT IT CARRIES, IN WORDS: INTERNAL BOUND < PROBE TIMEOUT, WITH ROOM.
# STORAGE_TIMEOUT_S has to fit comfortably inside this budget, because if the two
# are equal a stalled share spends the whole budget deciding it is unreachable
# and the kubelet gives up at the same instant - the pod leaves the Service. The
# two tests below are what hold that. THIS COPY GOES STALE - and this constant
# stops meaning anything - the moment the manifest's timeoutSeconds is lowered,
# which is the one change nothing in this repo would otherwise notice.
READINESS_PROBE_TIMEOUT_S = 5.0  # kubectl, 2026-09-03


def test_storage_timeout_keeps_room_under_the_readiness_probe():
    """The RELATIONSHIP, with a margin - not a matched pair of literals.

    `STORAGE_TIMEOUT_S` is the internal bound and the probe's timeout is the
    budget it has to fit inside, because equal budgets mean a stalled share
    spends the whole probe deciding it is unreachable and the kubelet pulls the
    pod at the same instant. So this asserts the room between them, as a ratio,
    and survives EITHER number moving as long as the room stays. The probe
    timeout's real value lives in the ops repo's
    production/oke/manifests/muster/deployment.yaml (readinessProbe.timeoutSeconds),
    so when the two drift, that manifest is the source that wins and this copy
    in the constant above is what has gone stale.
    """
    assert assets.STORAGE_TIMEOUT_S < READINESS_PROBE_TIMEOUT_S * 0.6


def test_readyz_answers_while_the_asset_store_hangs(tmp_path, monkeypatch):
    """The bound has to fit INSIDE the probe, not merely exist.

    THE TEST ABOVE CANNOT CATCH THIS AND THAT IS WHY THIS ONE EXISTS. It sets
    `STORAGE_TIMEOUT_S` to 0.2 before hanging the store, so it proves the
    mechanism works while saying nothing about the number that ships. The
    number that shipped was 5.0 - exactly the probe's timeout - so a stalled
    share spent the entire budget deciding it was unreachable and the kubelet
    gave up at the same instant. The pod left the Service twice in 24 hours
    and `status()` was never once at fault: it answered, just never in time.

    So this one uses the REAL constant, and asserts against the probe's.
    """
    import time

    store = assets.Assets(root=tmp_path, configured=str(tmp_path))
    monkeypatch.setattr(assets, "_list_names", lambda p: time.sleep(30), raising=False)

    started = time.monotonic()
    status = store.status()
    took = time.monotonic() - started

    assert status["readable"] is False
    # Sixty percent of the budget, so a slow CI box has room and a change that
    # eats the whole probe still fails here.
    assert took < READINESS_PROBE_TIMEOUT_S * 0.6, (
        f"a hung asset store held /readyz for {took:.1f}s against a "
        f"{READINESS_PROBE_TIMEOUT_S}s readiness probe. The pod gets pulled "
        f"from the Service for a wallpaper share being slow, which is the "
        f"outcome readyz's own docstring says it exists to prevent. That probe "
        f"timeout's REAL value lives in the operator's ops repo, in "
        f"production/oke/manifests/muster/deployment.yaml "
        f"(readinessProbe.timeoutSeconds) - which this repo cannot see - and "
        f"{READINESS_PROBE_TIMEOUT_S}s here is only a recorded copy of it. "
        f"Lower assets.STORAGE_TIMEOUT_S."
    )


def test_a_healthy_store_is_not_slowed_down_by_the_bound(tmp_path):
    (tmp_path / "wall.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    store = assets.Assets(root=tmp_path, configured=str(tmp_path))
    assert store.fetch("wall.png").content.startswith(b"\x89PNG")
    assert store.status()["assets"] == 1


def test_an_apk_sized_asset_is_servable(tmp_path):
    """The whole reason this store is moving off a Secret. An agent APK is
    ~12.7 MB and a Secret tops out near 1 MB."""
    big = b"PK\x03\x04" + b"\x00" * (13 * 1024 * 1024)
    (tmp_path / "agent.apk").write_bytes(big)
    store = assets.Assets(root=tmp_path, configured=str(tmp_path))
    asset = store.fetch("agent.apk")
    assert len(asset.content) == len(big)
    assert asset.media_type == "application/vnd.android.package-archive"
