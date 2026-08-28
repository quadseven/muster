"""Every reason a wiped phone still will not provision.

These paths are unreachable in practice without wiping a device per test, which
is why the whole decision tree goes through an injected `Adb`. The refusals
matter more than the happy path: `dpm set-device-owner` failing is recoverable
only by another factory reset, so a tool that tries and fails costs the operator
the setup they just did.

`test_the_owner_header_alone_is_not_an_owner` is the one to read. `dumpsys
device_policy` prints "Device Owner:" on every device, owned or not, and
matching that header reports everything as owned - which fails closed, refuses
to provision anything, and looks like an over-cautious tool rather than a bug.
"""
from __future__ import annotations

import hashlib

import pytest

from muster.provision import (
    ADMIN_COMPONENT,
    MIN_SDK,
    Verdict,
    preflight,
    set_device_owner,
)

# Real shapes, taken from the two Pixel 6a on 2026-08-18.
OWNED_BY_OSS_MDM = """
  Device Owner:
    admin=ComponentInfo{com.example.ossmdm.launcher/com.example.ossmdm.launcher.AdminReceiver}
    Device Owner Type: 0
"""
OWNED_BY_COMMERCIAL_MDM = """
  Device Owner:
    admin=ComponentInfo{com.google.android.apps.work.clouddpc/com.google.android.apps.work.clouddpc.receivers.CloudDeviceAdminReceiver}
"""
# THE trap: the header with nothing under it. This is an UNOWNED device.
UNOWNED = """
  Device Owner:
  Enabled Device Admins (User 0, provisioningState: 0):
"""
OWNED_BY_MUSTER = """
  Device Owner:
    admin=ComponentInfo{app.muster.agent/app.muster.agent.MusterDeviceAdminReceiver}
"""

WITH_ACCOUNT = 'Account {name=operator@example.com, type=com.google}'
NO_ACCOUNTS = "Accounts: 0"


class FakeAdb:
    def __init__(self, *, state="device", sdk="34", policy=UNOWNED,
                 accounts=NO_ACCOUNTS, serial="fake-serial"):
        self.serial = serial
        self._state = state
        self._sdk = sdk
        self._policy = policy
        self._accounts = accounts
        self.shell_calls = []

    def devices(self):
        return {} if self._state is None else {self.serial: self._state}

    def shell(self, serial, command, timeout=60.0):
        self.shell_calls.append(command)
        if "ro.build.version.sdk" in command:
            return self._sdk + "\n"
        if command.startswith("dumpsys device_policy"):
            return self._policy
        if command.startswith("dumpsys account"):
            return self._accounts
        if command.startswith("dpm set-device-owner"):
            self._policy = OWNED_BY_MUSTER
            return "Success: Device owner set\n"
        return ""


# ---- ready ---------------------------------------------------------------


def test_a_wiped_unowned_device_is_ready():
    adb = FakeAdb()
    result = preflight(adb, "fake-serial")
    assert result.verdict is Verdict.READY
    assert result.ok
    assert result.sdk == 34


def test_the_owner_header_alone_is_not_an_owner():
    """THE parsing trap. Every device prints "Device Owner:"; only an owned one
    prints a component under it. Matching the header would refuse every device
    and read as caution rather than as a bug."""
    adb = FakeAdb(policy=UNOWNED)
    assert preflight(adb, "fake-serial").verdict is Verdict.READY


# ---- refusals ------------------------------------------------------------


def test_a_device_that_is_not_connected_is_refused():
    adb = FakeAdb(state=None)
    result = preflight(adb, "fake-serial")
    assert result.verdict is Verdict.NOT_CONNECTED
    assert "adb devices" in result.detail


def test_an_unauthorized_device_is_refused_rather_than_probed():
    """An unauthorized device answers every probe with an empty string, which
    parses as "no owner, no accounts" - i.e. exactly like a clean phone. Guessing
    here would run set-device-owner against something unknown."""
    adb = FakeAdb(state="unauthorized")
    result = preflight(adb, "fake-serial")
    assert result.verdict is Verdict.UNAUTHORIZED
    assert "silence" in result.detail


@pytest.mark.parametrize(
    "policy,expected",
    [(OWNED_BY_OSS_MDM, "com.example.ossmdm.launcher"),
     (OWNED_BY_COMMERCIAL_MDM, "com.google.android.apps.work.clouddpc")],
)
def test_an_already_managed_device_is_refused_and_names_its_owner(policy, expected):
    """Naming the incumbent matters: the fix differs. Each MDM is unenrolled its
    own way, and "already owned" alone tells the operator to go and find out
    which."""
    adb = FakeAdb(policy=policy)
    result = preflight(adb, "fake-serial")
    assert result.verdict is Verdict.ALREADY_OWNED
    assert expected in result.owner
    assert "factory reset" in result.detail


def test_a_device_with_an_account_is_refused_with_the_reason():
    """The most common real failure: the phone was wiped, then setup wizard was
    completed while signed in. set-device-owner then refuses, and its message
    does not mention accounts."""
    adb = FakeAdb(accounts=WITH_ACCOUNT)
    result = preflight(adb, "fake-serial")
    assert result.verdict is Verdict.HAS_ACCOUNTS
    assert result.accounts == ("operator@example.com",)
    assert "setup wizard" in result.detail


def test_a_device_below_min_sdk_is_refused_before_installing():
    adb = FakeAdb(sdk=str(MIN_SDK - 1))
    result = preflight(adb, "fake-serial")
    assert result.verdict is Verdict.API_TOO_OLD
    assert result.sdk == MIN_SDK - 1


def test_ownership_is_checked_before_accounts():
    """Both can be true at once, and "already owned" is the more actionable
    answer - clearing accounts on a managed device changes nothing."""
    adb = FakeAdb(policy=OWNED_BY_OSS_MDM, accounts=WITH_ACCOUNT)
    assert preflight(adb, "fake-serial").verdict is Verdict.ALREADY_OWNED


# ---- setting ownership ---------------------------------------------------


def test_ownership_is_confirmed_by_asking_the_device():
    """`dpm set-device-owner` prints failures on stdout too, so its output is
    not a verdict. The device's own policy state is."""
    adb = FakeAdb()
    assert set_device_owner(adb, "fake-serial") is True
    assert any(c.startswith("dpm set-device-owner") for c in adb.shell_calls)
    assert adb.shell_calls[-1].startswith("dumpsys device_policy"), (
        "the last thing it does must be to ask, not to assume"
    )


def test_a_silent_failure_to_take_ownership_is_reported_as_failure():
    """A device that swallowed the command and stayed unowned must not be
    reported as provisioned - that is the state that looks fine until the first
    policy call throws SecurityException."""

    class Stubborn(FakeAdb):
        def shell(self, serial, command, timeout=60.0):
            if command.startswith("dpm set-device-owner"):
                self.shell_calls.append(command)
                return "java.lang.IllegalStateException: Not allowed\n"
            return super().shell(serial, command, timeout)

    assert set_device_owner(Stubborn(), "fake-serial") is False


def test_the_component_matches_the_shipped_manifest():
    """This string is an interface with the Android APK. If the receiver is
    renamed there and not here, provisioning fails on a wiped phone with a cable
    in hand - the most expensive place to find out."""
    from pathlib import Path

    manifest = (
        Path(__file__).resolve().parents[2]
        / "agent/android/app/src/main/AndroidManifest.xml"
    )
    package, receiver = ADMIN_COMPONENT.split("/")
    assert receiver.lstrip(".") in manifest.read_text()
    gradle = (
        Path(__file__).resolve().parents[2]
        / "agent/android/app/build.gradle.kts"
    )
    assert f'applicationId = "{package}"' in gradle.read_text()


# ---- reading the device back ---------------------------------------------

PACKAGE_DUMP = """
Packages:
  Package [app.zippie.companion] (a1b2c3):
    versionCode=107 minSdk=29 targetSdk=36
    versionName=0.1.0-107-6f97848
    firstInstallTime=2026-08-11 22:48:16
"""
NO_SUCH_PACKAGE = "Unable to find package: app.zippie.companion\n"


class PackageAdb(FakeAdb):
    def __init__(self, package_dump=PACKAGE_DUMP, **kw):
        super().__init__(**kw)
        self._package_dump = package_dump

    def shell(self, serial, command, timeout=60.0):
        if command.startswith("dumpsys package"):
            self.shell_calls.append(command)
            return self._package_dump
        return super().shell(serial, command, timeout)


def test_an_installed_package_reports_the_build_the_device_holds():
    """`pm list packages` says whether a NAME is known; after an install the
    question is which BUILD is there. Only the device can answer that."""
    from muster.provision import installed_package

    found = installed_package(PackageAdb(), "fake-serial", "app.zippie.companion")
    assert found.present
    assert found.version_name == "0.1.0-107-6f97848"
    assert found.version_code == "107", "versionCode line carries trailing fields"


def test_an_absent_package_is_reported_absent_rather_than_blank():
    from muster.provision import installed_package

    found = installed_package(
        PackageAdb(package_dump=NO_SUCH_PACKAGE), "fake-serial", "app.zippie.companion"
    )
    assert not found.present


def test_device_state_reports_the_owner_and_the_packages_together():
    from muster.provision import device_state

    state = device_state(
        PackageAdb(policy=OWNED_BY_MUSTER), "fake-serial", ("app.zippie.companion",)
    )
    assert state.owned_by(ADMIN_COMPONENT)
    assert state.packages[0].version_name == "0.1.0-107-6f97848"
    assert state.sdk == 34


def test_a_device_owned_by_somebody_else_does_not_pass_verification():
    """The live case tonight: both Pixels are owned, neither by us."""
    from muster.provision import device_state

    state = device_state(PackageAdb(policy=OWNED_BY_OSS_MDM), "fake-serial")
    assert not state.owned_by(ADMIN_COMPONENT)
    assert "ossmdm" in state.owner


def test_an_unowned_device_does_not_pass_verification_either():
    """Provisioning that silently did nothing must not read as success."""
    from muster.provision import device_state

    state = device_state(PackageAdb(policy=UNOWNED), "fake-serial")
    assert not state.owned_by(ADMIN_COMPONENT)
    assert state.owner == ""


# ---- the two directories that look the same ------------------------------


def test_the_agent_files_path_is_device_protected_storage():
    """THE bug this constant exists to prevent.

    /data/user/0/<pkg>/files and /data/user_de/0/<pkg>/files are different
    directories. Pushing to the first one succeeds - adb reports success, the
    file is genuinely there - and the agent, which reads device-protected
    storage so it works before first unlock, never sees it. Nothing fails; the
    wallpaper simply never appears.
    """
    from muster.provision import DEVICE_FILES

    path = DEVICE_FILES.format(package="app.muster.agent")
    assert path.startswith("/data/user_de/"), (
        f"{path} is credential-protected storage; the agent cannot read it at boot"
    )
    assert path.endswith("/files")


def test_the_agent_actually_reads_device_protected_storage():
    """The Python side is only correct if the Kotlin side still agrees. Someone
    dropping createDeviceProtectedStorageContext for a plain filesDir would move
    the agent to the other directory and this constant would silently be wrong."""
    from pathlib import Path

    agent = Path(__file__).resolve().parents[2] / "agent/android/app/src/main/java/app/muster/agent"
    for name in (
        "WallpaperSteward.kt",
        "FileIdentityStore.kt",
        "EnrollActivity.kt",
        "RestrictionSteward.kt",
    ):
        source = (agent / name).read_text()
        assert "createDeviceProtectedStorageContext" in source, (
            f"{name} no longer reads device-protected storage, so the path "
            "muster pushes to is wrong for it"
        )


def test_the_wallpaper_and_server_url_land_in_the_same_place_the_agent_looks():
    """Both files are read by the agent from its device-protected files dir."""
    from muster.provision import DEVICE_FILES
    from pathlib import Path

    files = DEVICE_FILES.format(package="app.muster.agent")
    agent = Path(__file__).resolve().parents[2] / "agent/android/app/src/main/java/app/muster/agent"

    # The agent names these files; the CLI writes them. Both sides, one test.
    assert '"wallpaper.png"' in (agent / "WallpaperSteward.kt").read_text()
    assert '"server-url"' in (agent / "EnrollActivity.kt").read_text()
    cli = (Path(__file__).resolve().parents[1] / "muster/cli.py").read_text()
    assert "wallpaper.png" in cli and "server-url" in cli
    assert files in cli or "DEVICE_FILES" in cli


def test_the_restrictions_file_is_named_the_same_on_both_sides():
    """The CLI writes a filename and the agent reads one. Nothing else checks.

    A rename on either side is not a build failure, an exception, or a log line.
    The push succeeds, the file is genuinely on the device, and the agent finds
    no config - which it correctly reports as "nothing configured, leave the
    device alone". The phone then comes up with no restrictions and a
    restrictions file sitting on it, which is the most confusing possible way to
    fail.
    """
    from pathlib import Path

    agent = Path(__file__).resolve().parents[2] / "agent/android/app/src/main/java/app/muster/agent"
    steward = (agent / "RestrictionSteward.kt").read_text()
    cli = (Path(__file__).resolve().parents[1] / "muster/cli.py").read_text()

    assert '"restrictions"' in steward, "the agent no longer reads a file called 'restrictions'"
    assert '/restrictions"' in cli, "the CLI no longer pushes a file called 'restrictions'"


def test_restrictions_are_reconciled_at_boot():
    """Guards the bug this whole feature was written to fix.

    A steward that exists and is never called is what the agent already had:
    WallpaperSteward.lock() was written, documented and unit-tested, and no code
    path could reach it, so the device enforced nothing while the suite was
    green. The Kotlin side has its own test for this; this one exists because
    the Python suite is what runs on every change to either half.
    """
    from pathlib import Path

    agent = Path(__file__).resolve().parents[2] / "agent/android/app/src/main/java/app/muster/agent"
    plan = (agent / "BootPlan.kt").read_text()
    assert "RestrictionSteward" in plan, "restrictions are no longer reconciled at boot"
    assert "WallpaperSteward" in plan, "the wallpaper is no longer reconciled at boot"


def test_the_agent_can_answer_the_provisioning_flow():
    """The manifest gap that factory-reset a handset on 2026-08-19.

    A QR-provisioned Pixel downloaded the agent successfully - 12,606,023 bytes,
    HTTP 200, logged server-side - and then failed with "Something went wrong"
    and a Reset button. Nothing was wrong with the QR, the checksum, the
    download or Play Protect. The agent declared no activity for either intent
    the platform sends during provisioning, so it could not answer, and AOSP
    `DevicePolicyManager` says what happens next:

        "admin apps must implement activities with intent filters for the
         ACTION_GET_PROVISIONING_MODE and ACTION_ADMIN_POLICY_COMPLIANCE intent
         actions ... will cause the provisioning to fail"

        "If provisioning fails, the device is factory reset."

    This test costs nothing and the failure it guards costs a wipe, a rebuild
    and a redeploy - and reports itself on the handset as a sentence that names
    no cause.
    """
    from pathlib import Path

    manifest = (
        Path(__file__).resolve().parents[2]
        / "agent/android/app/src/main/AndroidManifest.xml"
    ).read_text()

    for action in (
        "android.app.action.GET_PROVISIONING_MODE",
        "android.app.action.ADMIN_POLICY_COMPLIANCE",
    ):
        assert action in manifest, (
            f"{action} is not declared; a QR-provisioned device will download "
            "the agent, fail, and factory reset itself"
        )

    # Guarded by a permission only the system holds. Exported without it, any
    # app on the device could drive the activities that decide provisioning.
    assert manifest.count("android.permission.BIND_DEVICE_ADMIN") >= 3, (
        "the provisioning activities must be guarded by BIND_DEVICE_ADMIN, "
        "alongside the device admin receiver"
    )


def test_the_qr_server_url_extra_has_a_reader():
    """The QR has always carried the server address; nothing used to read it.

    `provisioning.py` puts `muster.server_url` into the admin extras bundle of
    every provisioning QR. Until PolicyComplianceActivity existed there was no
    code in the agent that referenced the extras bundle at all, so a
    QR-provisioned phone came up owned, healthy, and with no address to enroll
    against - recoverable only over the adb cable the QR exists to avoid.

    Both halves are asserted here because they are in different languages and
    nothing else compares them.
    """
    from pathlib import Path

    agent = Path(__file__).resolve().parents[2] / "agent/android/app/src/main/java/app/muster/agent"
    server = Path(__file__).resolve().parents[1] / "muster/provisioning.py"

    assert "muster.server_url" in server.read_text(), (
        "the server no longer puts its address in the provisioning QR"
    )
    policy = (agent / "ProvisioningPolicy.kt").read_text()
    assert "muster.server_url" in policy, (
        "the agent no longer looks for the address the QR carries"
    )
    compliance = (agent / "PolicyComplianceActivity.kt").read_text()
    assert "EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE" in compliance
    assert '"server-url"' in compliance, (
        "the adopted address must land in the file the enrollment screen reads"
    )


# ---- writing a config file the shell is not allowed to touch --------------


class RunAsAdb(FakeAdb):
    """A device that enforces what a real one enforces: the app's data
    directory belongs to the app.

    Nothing written as the shell user arrives, because on hardware nothing
    written as the shell user arrives - the directory is `drwx------` owned by
    the app's uid. A fake that quietly accepted those writes would let the
    broken code pass, which is how it stayed in the tree until a phone was in
    front of it.

    `shell_as` here deliberately does NOT route through `shell`, which is what
    makes `test_the_shell_user_never_touches_the_agents_directory` mean
    something: `shell_calls` stays empty unless the code under test talks to
    the device as uid 2000.
    """

    def __init__(self, *, debuggable=True, installed=True, reports_status=True, **kw):
        super().__init__(**kw)
        self.stored = {}
        self.written = []
        self.as_calls = []
        self._debuggable = debuggable
        self._installed = installed
        # An adb older than shell protocol v2 does not forward the remote exit
        # status and answers 0 for a command the phone refused outright.
        self._reports_status = reports_status

    def _refusal(self, package):
        if not self._installed:
            return f"run-as: unknown package: {package}"
        if not self._debuggable:
            return f"run-as: package not debuggable: {package}"
        return ""

    def write_as(self, serial, package, remote, data, timeout=300.0):
        refusal = self._refusal(package)
        if refusal:
            return (1 if self._reports_status else 0), refusal + "\n"
        self.written.append((package, remote, data))
        self.stored[remote] = data
        return 0, ""

    def shell_as(self, serial, package, command, timeout=60.0):
        self.as_calls.append(command)
        if self._refusal(package):
            # `run-as` explains itself on stderr, and `Adb.shell` returns only
            # stdout. A caller that reads this sees silence, not a reason.
            return ""
        if command.startswith("sha256sum "):
            path = command.split(None, 1)[1].strip().strip("'")
            held = self.stored.get(path)
            if held is None:
                return ""
            return f"{hashlib.sha256(held).hexdigest()}  {path}\n"
        return ""

    def install(self, serial, apk_path):
        return 0, "Success\n"


AGENT_FILES = "/data/user_de/0/app.muster.agent/files"


def test_a_config_file_is_written_as_the_app_and_confirmed_by_the_device():
    """The whole fix in one test: the bytes go in under the app's own uid, and
    what says so is the device reading the file back, not adb returning zero."""
    from muster.provision import place_file

    adb = RunAsAdb()
    placed = place_file(
        adb, "fake-serial", "app.muster.agent",
        f"{AGENT_FILES}/restrictions", b"DISALLOW_SAFE_BOOT\n",
    )
    assert placed.ok, placed.detail
    assert adb.written == [
        ("app.muster.agent", f"{AGENT_FILES}/restrictions", b"DISALLOW_SAFE_BOOT\n")
    ]
    assert "19 bytes" in placed.detail


def test_the_shell_user_never_touches_the_agents_directory():
    """THE defect. `mkdir`, the write and the read-back all have to go through
    the app; a single one of them left on the plain shell fails with a
    permission error on hardware and nowhere else."""
    from muster.provision import place_file

    adb = RunAsAdb()
    place_file(
        adb, "fake-serial", "app.muster.agent", f"{AGENT_FILES}/wallpaper.png", b"PNG"
    )

    assert any(c.startswith("mkdir -p") for c in adb.as_calls), (
        "the files directory must be created as the app - an agent that has "
        "never been launched has no files dir, and the shell cannot make one"
    )
    assert not any(AGENT_FILES in c for c in adb.shell_calls), (
        "something is still talking to the agent's directory as uid 2000"
    )


def test_a_release_signed_agent_refuses_and_says_so():
    """The expiry date on this route, and it has to be readable when it lands.

    `run-as` needs a debuggable package. The moment the signing ceremony
    happens and a release APK ships, every one of these commands stops working
    - so the device's own words have to reach the operator rather than a
    generic failure that reads like a broken cable.
    """
    from muster.provision import place_file

    placed = place_file(
        RunAsAdb(debuggable=False), "fake-serial", "app.muster.agent",
        f"{AGENT_FILES}/restrictions", b"DISALLOW_SAFE_BOOT\n",
    )
    assert not placed.ok
    assert "not debuggable" in placed.detail


def test_an_agent_that_is_not_installed_is_not_a_silent_no_op():
    from muster.provision import place_file

    placed = place_file(
        RunAsAdb(installed=False), "fake-serial", "app.muster.agent",
        f"{AGENT_FILES}/restrictions", b"",
    )
    assert not placed.ok
    assert "unknown package" in placed.detail


def test_a_write_that_reported_success_and_landed_nothing_is_a_failure():
    """The shape the old code had, and the reason the read-back is not optional.

    `adb shell` only forwards the remote exit status on shell protocol v2, so an
    older adb answers 0 for a command the phone refused outright. A device that
    says "fine" and holds no file must not read as configured.
    """
    from muster.provision import place_file

    class Liar(RunAsAdb):
        def write_as(self, serial, package, remote, data, timeout=300.0):
            return 0, ""

    placed = place_file(
        Liar(), "fake-serial", "app.muster.agent", f"{AGENT_FILES}/restrictions", b"x"
    )
    assert not placed.ok
    assert "cannot prove" in placed.detail


def test_a_truncated_write_is_not_reported_as_success():
    """A restrictions file that arrived half-written is a device that enforces
    half a policy, and the agent has no way to know it was given an offcut."""
    from muster.provision import place_file

    class HalfWay(RunAsAdb):
        def write_as(self, serial, package, remote, data, timeout=300.0):
            super().write_as(serial, package, remote, data[: len(data) // 2])
            return 0, ""

    placed = place_file(
        HalfWay(), "fake-serial", "app.muster.agent",
        f"{AGENT_FILES}/restrictions", b"DISALLOW_SAFE_BOOT\n",
    )
    assert not placed.ok
    assert "is not what was sent" in placed.detail


def test_an_empty_file_is_a_placement_and_not_a_failure():
    """AN EMPTY RESTRICTIONS FILE IS A VALID INSTRUCTION - it means "withdraw
    everything muster set" (docs/policy.md). A verification that treats zero
    bytes as nothing-landed would make the one way to unlock a device the one
    way this command cannot work."""
    from muster.provision import place_file

    adb = RunAsAdb()
    placed = place_file(
        adb, "fake-serial", "app.muster.agent", f"{AGENT_FILES}/restrictions", b""
    )
    assert placed.ok, placed.detail
    assert adb.stored[f"{AGENT_FILES}/restrictions"] == b""


def test_a_package_or_a_path_cannot_become_a_command():
    """Both come off the command line, and both end up inside a shell string on
    the device. Unquoted, a path with a space in it writes somewhere else and a
    `;` runs as the app."""
    from muster.provision import _run_as

    assert _run_as("app.muster.agent", "cat > /data/x") == (
        "run-as app.muster.agent sh -c 'cat > /data/x'"
    )
    hostile = _run_as("app.muster.agent; rm -rf /", "cat > /data/x")
    assert "'app.muster.agent; rm -rf /'" in hostile


def test_the_cli_no_longer_stages_config_in_a_directory_it_cannot_copy_out_of():
    """The route this replaced, guarded so it cannot come back by resemblance.

    Pushing to /data/local/tmp and `cp`-ing across is the obvious thing to write
    and it cannot work: the agent's directory is `drwx------` owned by the app.
    `printf %s '<url>' >` is the same mistake with a quoting bug on top.
    """
    from pathlib import Path

    cli = (Path(__file__).resolve().parents[1] / "muster/cli.py").read_text()

    assert "/data/local/tmp" not in cli, (
        "config is being staged in the shell's directory again; nothing can "
        "copy it from there into a directory owned by the app"
    )
    assert "printf %s" not in cli, (
        "the server URL is being written through a shell command line again"
    )
    assert cli.count("place_file(") == 5, (
        "all five files the agent reads - wallpaper, restrictions, visible-apps, "
        "app config, server URL - go to the device the same way, or the ones "
        "that do not are broken"
    )


def test_an_old_adb_that_answers_zero_does_not_hide_a_refusal():
    """`adb shell` only forwards the remote exit status on shell protocol v2.
    An older one reports 0 for a command the phone would not run, so the exit
    code alone would report a release-signed agent as configured."""
    from muster.provision import place_file

    placed = place_file(
        RunAsAdb(debuggable=False, reports_status=False), "fake-serial",
        "app.muster.agent", f"{AGENT_FILES}/restrictions", b"DISALLOW_SAFE_BOOT\n",
    )
    assert not placed.ok
    assert "not debuggable" in placed.detail


def test_adbs_own_chatter_is_not_mistaken_for_the_devices_answer():
    """`* daemon not running; starting now at tcp:5037` arrives on stderr the
    first time adb runs after a reboot. It is adb talking to itself on this
    machine, and reading it as a refusal fails a perfectly good write once a
    day for a reason that is not on the phone at all."""
    from muster.provision import place_file

    class NoisyDaemon(RunAsAdb):
        def write_as(self, serial, package, remote, data, timeout=300.0):
            super().write_as(serial, package, remote, data)
            return 0, (
                "* daemon not running; starting now at tcp:5037\n"
                "* daemon started successfully\n"
            )

    placed = place_file(
        NoisyDaemon(), "fake-serial", "app.muster.agent",
        f"{AGENT_FILES}/restrictions", b"DISALLOW_SAFE_BOOT\n",
    )
    assert placed.ok, placed.detail


def test_a_corruption_that_keeps_the_length_is_still_caught():
    """WHY THE READ-BACK IS A DIGEST AND NOT A BYTE COUNT.

    An adb older than shell protocol v2 runs the remote command under a pty,
    whose line discipline turns every CR arriving on stdin into an LF. The file
    is the same length afterwards and every byte of it may be wrong. A PNG
    starts `89 50 4E 47 0D 0A 1A 0A` precisely so this is detectable - and a
    length check would call it placed, exit 0, and leave the agent to fail
    silently at the next boot with a null bitmap in a log nobody reads.
    """
    from muster.provision import place_file

    class Pty(RunAsAdb):
        def write_as(self, serial, package, remote, data, timeout=300.0):
            return super().write_as(
                serial, package, remote, data.replace(b"\r", b"\n")
            )

    png = b"\x89PNG\r\n\x1a\n"
    adb = Pty()
    placed = place_file(
        adb, "fake-serial", "app.muster.agent", f"{AGENT_FILES}/wallpaper.png", png
    )
    stored = adb.stored[f"{AGENT_FILES}/wallpaper.png"]
    assert len(stored) == len(png), "the corruption this guards is length-preserving"
    assert not placed.ok, "a byte count would have passed this"
    assert "is not what was sent" in placed.detail


def test_the_write_hands_adb_a_quoted_path_and_the_payload_on_stdin(monkeypatch):
    """The one piece of this that really shells out, and it is where the
    quoting is load-bearing: `--package` comes off the command line and lands
    inside a `sh -c` string on the device. Unquoted, a path with a space in it
    writes to the wrong file and a `;` in it runs as the app.

    The payload is asserted to be on stdin because a command line is where the
    old `printf %s '<url>'` went wrong, and a PNG on one would be worse.
    """
    from muster import provision

    seen = {}

    class Finished:
        returncode = 0
        stdout = b""
        stderr = b""

    def fake_run(args, **kwargs):
        seen["args"] = args
        seen["input"] = kwargs.get("input")
        return Finished()

    monkeypatch.setattr(provision.subprocess, "run", fake_run)
    provision.Adb("adb").write_as(
        "fake-serial", "app.muster.agent", "/data/user_de/0/x/files/wall paper.png",
        b"\x89PNG\r\n",
    )

    assert seen["input"] == b"\x89PNG\r\n", "the payload must never touch a command line"
    assert seen["args"][:4] == ["adb", "-s", "fake-serial", "shell"]
    assert "cat > /data/user_de/0/x/files/wall paper.png" not in seen["args"][4], (
        "the path went in unquoted, so the write lands at .../wall and "
        "'paper.png' is a second argument"
    )


def test_a_write_that_never_finishes_is_an_exit_code_and_not_a_traceback(monkeypatch):
    """EXIT CODES ARE THE INTERFACE (cli.py), and this runs from scripts. A
    phone that goes away mid-write leaves adb hanging on the only call that
    feeds it megabytes; ending that in `subprocess.TimeoutExpired` is none of
    0, 2 or 3."""
    from muster import provision

    def never(args, **kwargs):
        raise provision.subprocess.TimeoutExpired(args, 300.0)

    monkeypatch.setattr(provision.subprocess, "run", never)
    rc, said = provision.Adb("adb").write_as(
        "fake-serial", "app.muster.agent", "/data/x", b"payload"
    )

    assert rc != 0
    assert "gave up" in said and "/data/x" in said


# ---- a payload nobody may see -------------------------------------------

# Shaped like the thing this whole path exists to deliver: a write token that
# used to have to be typed into a phone by hand.
APP_CONFIG = (
    b"set app.zippie.companion announceToken zk_live_7f3a91c4e08b46d2a5\n"
    b"set-bool app.zippie.companion autoStartRelay true\n"
)
# Invented for this test and never valid anywhere. It has to LOOK like a
# credential, because what these tests assert is that a thing shaped like this
# never reaches a terminal.
TOKEN = "zk_live_7f3a91c4e08b46d2a5"  # noqa: S105 - fixture, not a real secret


class Parrot(RunAsAdb):
    """An adb that allocates a pty, which is a real one and not a hypothetical.

    Without shell protocol v2 the remote command runs under a pty, and a pty
    echoes stdin back on stdout - so the answer to a write is the payload. The
    file also never lands, because this one refuses the write; both halves are
    what an old adb against a release-signed agent actually does.
    """

    def write_as(self, serial, package, remote, data, timeout=300.0):
        return 0, data.decode() + "run-as: package not debuggable: app.muster.agent\n"


def test_a_secret_payload_is_never_quoted_back_off_the_device():
    """THE leak, and it is in the diagnostic rather than in the write.

    `place_file` ends by quoting what the device said, which for a pty is
    everything it was sent. For a wallpaper that is mojibake. For an app
    configuration it is a write token on a terminal, in a scrollback, and in
    whatever CI log the command ran under - and a credential printed once is
    printed forever.
    """
    from muster.provision import place_file

    placed = place_file(
        Parrot(), "fake-serial", "app.muster.agent",
        f"{AGENT_FILES}/app-config", APP_CONFIG, secret=True,
    )
    assert not placed.ok
    assert TOKEN not in placed.detail
    assert "announceToken" not in placed.detail


def test_the_devices_own_refusal_still_reaches_the_operator():
    """Suppressing the echo must not suppress the diagnosis. `run-as: package
    not debuggable` is the failure every one of these commands gets the day the
    signing ceremony happens, and it has to be readable when it lands."""
    from muster.provision import place_file

    placed = place_file(
        Parrot(), "fake-serial", "app.muster.agent",
        f"{AGENT_FILES}/app-config", APP_CONFIG, secret=True,
    )
    assert "not debuggable" in placed.detail, placed.detail


def test_a_mangled_echo_costs_the_whole_quote_rather_than_leaking():
    """The backstop, and the reason there are two passes rather than one.

    Dropping whole words the device repeated handles a clean echo. A mangled
    one does not match word for word - a pty's line discipline rewrites bytes
    on the way through, which is precisely why `_read_digest` exists - and a
    token that arrives back with one character changed is still a token. So if
    any run of the payload survives the first pass, nothing is quoted at all.
    Half a credential in a log is not half a problem.
    """
    from muster.provision import place_file

    class Mangler(RunAsAdb):
        def write_as(self, serial, package, remote, data, timeout=300.0):
            # Underscores to hyphens: no word matches what was sent, and every
            # recognizable run of the token is still there.
            return 0, data.decode().replace("_", "-")

    placed = place_file(
        Mangler(), "fake-serial", "app.muster.agent",
        f"{AGENT_FILES}/app-config", APP_CONFIG, secret=True,
    )
    assert "7f3a91c4e08b46d2a5" not in placed.detail
    assert "not quoted here" in placed.detail


def test_a_payload_that_is_not_secret_is_still_quoted_as_before():
    """The wallpaper, the restrictions and the server URL are not credentials,
    and their diagnostics must not get quieter because this option exists."""
    from muster.provision import place_file

    class Refuser(RunAsAdb):
        def write_as(self, serial, package, remote, data, timeout=300.0):
            return 1, "run-as: unknown package: app.muster.agent\n"

    placed = place_file(
        Refuser(), "fake-serial", "app.muster.agent",
        f"{AGENT_FILES}/restrictions", b"DISALLOW_SAFE_BOOT\n",
    )
    assert "unknown package" in placed.detail


def test_a_short_value_quoted_on_its_own_is_dropped_too():
    """The run-length backstop has a floor and a credential does not.

    The shape: the payload comes back one WORD at a time rather than verbatim,
    so no eight-character run of the file survives anywhere to be recognized. A
    shell that ends up reading the payload as commands does exactly this -
    `sh: 4021: not found`, one line per word - and a short value then sails out
    on stderr surrounded by the device's own words rather than by ours.

    So an EXACT word match counts at any length: a word coming back exactly as
    it went out is an echo whatever its length, and only that rule has no floor.
    """
    from muster.provision import place_file

    class Interpreter(RunAsAdb):
        def write_as(self, serial, package, remote, data, timeout=300.0):
            said = "".join(
                f"sh: {word}: not found\n" for word in data.decode().split()
            )
            return 1, said

    placed = place_file(
        Interpreter(), "fake-serial", "app.muster.agent",
        f"{AGENT_FILES}/app-config",
        b"set app.example.thing pin 4021\n",
        secret=True,
    )
    assert not placed.ok
    assert "4021" not in placed.detail, placed.detail
    # And the device's own words still get through - it is only ours that go.
    assert "not found" in placed.detail, placed.detail
