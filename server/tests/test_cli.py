"""What the exit codes say, on every command that writes to a device.

EXIT CODES ARE THE INTERFACE (`cli.py`), and until now nothing checked them.
That mattered here: `muster restrictions` spent two releases writing to a
directory the shell cannot enter, and the only thing standing between that and a
tool which silently does nothing was one read-back at the end of the command.
These tests are that guard, held from the outside.

The device is `RunAsAdb` from `test_provision.py` - a fake that refuses shell
writes into the app's directory because a real one does.
"""
from __future__ import annotations

import argparse

import pytest

from muster import cli
from muster.provision import DEVICE_FILES
from tests.test_provision import RunAsAdb

AGENT_FILES = DEVICE_FILES.format(package="app.muster.agent")


@pytest.fixture
def device(monkeypatch):
    """One device, handed to whatever the CLI builds."""
    adb = RunAsAdb()
    monkeypatch.setattr(cli, "Adb", lambda binary="adb": adb)
    return adb


def test_a_wallpaper_the_device_took_exits_zero(device, tmp_path):
    image = tmp_path / "kitchen.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\n")

    assert cli.main(["wallpaper", "fake-serial", "--image", str(image)]) == 0
    assert device.stored[f"{AGENT_FILES}/wallpaper.png"] == image.read_bytes()


def test_a_wallpaper_the_device_refused_exits_three(monkeypatch, tmp_path, capsys):
    """A release-signed agent is not debuggable, so this is the failure every
    one of these commands gets after the signing ceremony. It has to be an exit
    code a script notices and a sentence a human can act on."""
    refuser = RunAsAdb(debuggable=False)
    monkeypatch.setattr(cli, "Adb", lambda binary="adb": refuser)
    image = tmp_path / "kitchen.png"
    image.write_bytes(b"\x89PNG")

    assert cli.main(["wallpaper", "fake-serial", "--image", str(image)]) == 3
    assert "not debuggable" in capsys.readouterr().err


def test_restrictions_the_device_did_not_take_exit_three(monkeypatch, tmp_path, capsys):
    """The measured bug, from the outside. A device that holds no file must not
    leave the operator believing a policy is in force on it."""

    class Deaf(RunAsAdb):
        def write_as(self, serial, package, remote, data, timeout=300.0):
            return 0, ""

    monkeypatch.setattr(cli, "Adb", lambda binary="adb": Deaf())
    policy = tmp_path / "kitchen.restrictions"
    policy.write_text("DISALLOW_SAFE_BOOT\n")

    assert cli.main(["restrictions", "fake-serial", "--file", str(policy)]) == 3
    assert "cannot prove" in capsys.readouterr().err


def test_an_empty_restrictions_file_reaches_the_device(device, tmp_path):
    """Empty means "withdraw everything", and it is the only way to unlock a
    device muster locked down. Refusing to send it, or sending it and calling
    the zero-byte read-back a failure, both strand the operator."""
    policy = tmp_path / "unlocked.restrictions"
    policy.write_text("")

    assert cli.main(["restrictions", "fake-serial", "--file", str(policy)]) == 0
    assert device.stored[f"{AGENT_FILES}/restrictions"] == b""


def test_a_file_that_is_not_there_is_refused_before_the_device_is_touched(
    device, tmp_path
):
    """Exit 2 is "refused", not "tried and failed" - and nothing should have
    been said to the phone at all."""
    missing = str(tmp_path / "nope")
    assert cli.main(["restrictions", "fake-serial", "--file", missing]) == 2
    assert device.written == []
    assert device.as_calls == []


def test_a_visible_apps_allowlist_reaches_the_device(device, tmp_path):
    """The file the agent hides applications from. It goes to the same
    device-protected directory the shell cannot write to, through the app."""
    allowlist = tmp_path / "kitchen.visible-apps"
    allowlist.write_text("app.muster.agent\ncom.android.settings\n")

    assert cli.main(["visible-apps", "fake-serial", "--file", str(allowlist)]) == 0
    assert device.stored[f"{AGENT_FILES}/visible-apps"] == allowlist.read_bytes()


def test_an_empty_visible_apps_file_reaches_the_device(device, tmp_path):
    """Empty means "nothing stays visible", which is the strongest instruction
    this file can carry. Refusing to send it, or reading the zero-byte read-back
    as a failed write, would both leave the operator guessing."""
    allowlist = tmp_path / "bare.visible-apps"
    allowlist.write_text("")

    assert cli.main(["visible-apps", "fake-serial", "--file", str(allowlist)]) == 0
    assert device.stored[f"{AGENT_FILES}/visible-apps"] == b""


def test_a_visible_apps_file_the_device_did_not_take_exits_three(
    monkeypatch, tmp_path, capsys
):
    """An allowlist that never landed is worse than no allowlist: the operator
    walks away believing a phone has been stripped down and it has not."""

    class Deaf(RunAsAdb):
        def write_as(self, serial, package, remote, data, timeout=300.0):
            return 0, ""

    monkeypatch.setattr(cli, "Adb", lambda binary="adb": Deaf())
    allowlist = tmp_path / "kitchen.visible-apps"
    allowlist.write_text("app.muster.agent\n")

    assert cli.main(["visible-apps", "fake-serial", "--file", str(allowlist)]) == 3
    assert "cannot prove" in capsys.readouterr().err


def test_a_missing_visible_apps_file_is_refused_before_the_device_is_touched(
    device, tmp_path
):
    """Exit 2 is "refused", and nothing should have been said to the phone."""
    missing = str(tmp_path / "nope")
    assert cli.main(["visible-apps", "fake-serial", "--file", missing]) == 2
    assert device.written == []
    assert device.as_calls == []


def test_the_server_url_reaches_the_device_through_the_app(device, tmp_path):
    """`muster provision --server-url` is not named in #20 and had the same
    defect: `mkdir -p` and a `printf %s '<url>' >` redirect, both as the shell
    user, into a directory only the app can write to. It also interpolated an
    operator-supplied URL into a single-quoted shell string.

    Nothing exercised this command before. It is the third writer of a file the
    agent reads, so it goes the same way as the other two.
    """
    apk = tmp_path / "agent.apk"
    apk.write_bytes(b"not really an apk, and nothing here opens it")

    rc = cli.main([
        "provision", "fake-serial", "--apk", str(apk),
        "--server-url", "https://enroll.muster.example",
    ])

    assert rc == 0
    assert device.stored[f"{AGENT_FILES}/server-url"] == b"https://enroll.muster.example"


def test_a_server_url_the_device_did_not_take_fails_provisioning(monkeypatch, tmp_path):
    """A phone that is owned but has no address to enroll against is the state
    that looks provisioned and is not - recoverable only over the cable this
    step exists to finish with."""

    class Deaf(RunAsAdb):
        def write_as(self, serial, package, remote, data, timeout=300.0):
            return 0, ""

    monkeypatch.setattr(cli, "Adb", lambda binary="adb": Deaf())
    apk = tmp_path / "agent.apk"
    apk.write_bytes(b"not really an apk")

    rc = cli.main([
        "provision", "fake-serial", "--apk", str(apk),
        "--server-url", "https://enroll.muster.example",
    ])
    assert rc == 3


# ---- app configuration ---------------------------------------------------

# A write token, which is the whole point of the file: it is the credential a
# person used to have to type into a phone by hand. Invented for this test and
# never valid anywhere - and it has to LOOK like a credential, because these
# tests assert that a thing shaped like this never reaches a terminal.
TOKEN = "zk_live_7f3a91c4e08b46d2a5"  # noqa: S105 - fixture, not a real secret
APP_CONFIG = (
    "# the kitchen leg\n"
    f"set app.zippie.companion announceToken {TOKEN}\n"
    "set-bool app.zippie.companion autoStartRelay true\n"
    "grant app.zippie.companion android.permission.POST_NOTIFICATIONS\n"
)


def test_an_app_configuration_reaches_the_device_through_the_app(device, tmp_path):
    """The fourth file the agent reads, going the same way as the other three:
    written as the app, verified by the sha256 the device computes."""
    config = tmp_path / "kitchen.appconfig"
    config.write_text(APP_CONFIG)

    assert cli.main(["app-config", "fake-serial", "--file", str(config)]) == 0
    assert device.stored[f"{AGENT_FILES}/app-config"] == APP_CONFIG.encode()


def test_an_app_configuration_the_device_did_not_take_exits_three(monkeypatch, tmp_path):
    """A device that holds no file must not leave the operator believing an app
    on it has been configured - which here means believing a phone is about to
    start relaying when nothing told it to."""

    class Deaf(RunAsAdb):
        def write_as(self, serial, package, remote, data, timeout=300.0):
            return 0, ""

    monkeypatch.setattr(cli, "Adb", lambda binary="adb": Deaf())
    config = tmp_path / "kitchen.appconfig"
    config.write_text(APP_CONFIG)

    assert cli.main(["app-config", "fake-serial", "--file", str(config)]) == 3


def test_a_token_never_reaches_the_operators_terminal(monkeypatch, tmp_path, capsys):
    """THE test this feature has to pass, held from the outside.

    An adb without shell protocol v2 runs the remote command under a pty, and a
    pty echoes stdin back on stdout - so the device's answer to this write is
    the write token. Everything about that is ordinary except that the command
    then quotes it, and a credential printed to a terminal is in a scrollback
    and in a CI log forever.
    """

    class Parrot(RunAsAdb):
        def write_as(self, serial, package, remote, data, timeout=300.0):
            return 0, data.decode() + "run-as: package not debuggable: x\n"

    monkeypatch.setattr(cli, "Adb", lambda binary="adb": Parrot())
    config = tmp_path / "kitchen.appconfig"
    config.write_text(APP_CONFIG)

    assert cli.main(["app-config", "fake-serial", "--file", str(config)]) == 3
    said = capsys.readouterr()
    assert TOKEN not in said.out + said.err
    assert "announceToken" not in said.out + said.err


def test_a_missing_app_configuration_is_refused_before_the_device_is_touched(
    device, tmp_path
):
    """Exit 2 is "refused", not "tried and failed"."""
    missing = str(tmp_path / "nope")
    assert cli.main(["app-config", "fake-serial", "--file", missing]) == 2
    assert device.written == []
    assert device.as_calls == []


# --------------------------------------------------------------------------
# `muster asset` (muster#45)


def _asset_output(capsys, tmp_path, **kwargs) -> str:
    import hashlib

    from muster import cli

    image = tmp_path / "wall.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * 100)
    args = argparse.Namespace(
        image=str(image), name="", scope="kith", surfaces=["system", "lock"], **kwargs
    )
    assert cli.cmd_asset(args) == 0
    out = capsys.readouterr().out
    assert hashlib.sha256(image.read_bytes()).hexdigest() in out
    return out


def test_asset_prints_a_publish_command_that_actually_works(capsys, tmp_path):
    """THE TEST THIS EXISTS FOR, and it cost a failed deploy to learn.

    A client-side `kubectl apply` stores the whole object in a
    `last-applied-configuration` annotation, and annotations stop at 262144
    bytes - so an asset over roughly 190KB of real bytes is refused with
    "metadata.annotations: Too long", which names the annotation and not the
    file. A wallpaper is bigger than that, so the FIRST asset anybody publishes
    hits it. Printing a command that fails is worse than printing none.
    """
    out = _asset_output(capsys, tmp_path)
    assert "--server-side" in out
    assert "kubectl apply -f -" not in out


def test_asset_prints_the_policy_stanza_the_device_will_read(capsys, tmp_path):
    out = _asset_output(capsys, tmp_path)
    assert "image wall.png sha256 " in out
    assert "surfaces system lock" in out
    assert "kith.wallpaper" in out


def test_asset_refuses_a_name_no_asset_can_have(tmp_path):
    from muster import cli

    image = tmp_path / "wall.png"
    image.write_bytes(b"\x89PNG")
    args = argparse.Namespace(
        image=str(image), name="../../etc/passwd", scope="kith", surfaces=["system"]
    )
    assert cli.cmd_asset(args) == 2


def test_asset_refuses_a_file_that_is_not_there(tmp_path):
    from muster import cli

    args = argparse.Namespace(
        image=str(tmp_path / "nope.png"), name="", scope="kith", surfaces=["system"]
    )
    assert cli.cmd_asset(args) == 2
