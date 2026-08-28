"""What the agent's manifest must keep saying, whoever edits it next.

Separate from test_provision.py because the manifest is edited for reasons that
have nothing to do with provisioning - an icon, a label, a new activity - and
those are exactly the edits most likely to cost one of the properties below
without anybody connecting the two.
"""
from __future__ import annotations

from pathlib import Path

MANIFEST = (
    Path(__file__).resolve().parents[2]
    / "agent/android/app/src/main/AndroidManifest.xml"
)


def test_the_permission_profile_is_exactly_four():
    """The Play Protect bet, expressed as a test.

    A QR-provisioned Pixel 6a cleared Google's approved-DPC heuristic on
    2026-08-19 with this profile and no others. `provisioning.py` says why that
    is thought to be the reason: reports describe the check behaving like a
    harmful-app heuristic rather than a strict list, and developers clearing it
    by dropping permissions that read as dangerous.

    Nobody can prove which permission would tip it back. That is the point - the
    cost of finding out is a wiped handset that fails with "App blocked to
    protect your device", so a new permission must be a decision somebody argues
    for, not a line that arrives with a feature.
    """
    manifest = MANIFEST.read_text()
    declared = {
        line.split('android:name="')[1].split('"')[0]
        for line in manifest.splitlines()
        if "<uses-permission" in line
    }
    assert declared == {
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.SET_WALLPAPER",
        "android.permission.INTERNET",
        # ARGUED FOR ON 2026-08-23, which is what this test asks of a fourth.
        #
        # WHY IT IS NEEDED. JobScheduler refuses a job carrying a connectivity
        # constraint from an app that does not hold this, and it THROWS rather
        # than returning false. `CheckInJob.scheduleCatchUp` sets
        # NETWORK_TYPE_ANY - waiting for a network IS that job's purpose - so
        # without this the catch-up cannot exist. It was written without the
        # permission and threw every time it ran, which on a JobService worker
        # meant a crash loop; a handset showed "Muster keeps stopping" to an
        # operator mid-enrolment.
        #
        # WHY NOT AVOID IT. There is no connectivity-aware recovery without it:
        # a ConnectivityManager callback needs the same permission. The only
        # alternative is deleting the catch-up entirely and letting a device
        # whose router just came back wait out the full quarter-hour interval -
        # which on a bonded uplink is a leg down for fifteen minutes because a
        # fetch failed once.
        #
        # WHY IT IS THOUGHT SAFE FOR THE PLAY PROTECT BET. It is
        # protectionLevel="normal": granted at install, never prompted, and it
        # reveals whether there is a network rather than anything about its
        # contents or the user. It is among the most commonly declared
        # permissions on Android, present in most apps that touch a socket, so a
        # heuristic that scored it as harmful would score most of the store.
        # That is a judgement, not a proof - the docstring above is right that
        # nobody can prove which permission tips it - and the next
        # QR provisioning run is where it gets tested.
        "android.permission.ACCESS_NETWORK_STATE",
    }, f"the agent's permission profile changed: {sorted(declared)}"

    # The fourth is on the receiver rather than the application, and it is what
    # stops any app on the device driving the components that own it.
    assert "android.permission.BIND_DEVICE_ADMIN" in manifest


def test_the_agent_can_see_other_apps_without_asking_for_a_permission():
    """The other half of the Play Protect bet, and the one that looks harmless.

    From targetSdk 30 an app cannot enumerate other packages, and being Device
    Owner does not exempt it - `AppsFilterBase.shouldFilterApplication` in AOSP
    has no device owner case at all. The two ways out are QUERY_ALL_PACKAGES,
    which is a fifth permission and would put the test above at risk, and a
    `<queries>` element, which is not a permission.

    Pinned because dropping the block breaks NOTHING VISIBLY. The build stays
    green, the APK installs, and `AppVisibilitySteward` comes up able to see only
    itself - so the allowlist reconciles a device of one application and hides
    nothing, on a handset nobody is holding.
    """
    manifest = MANIFEST.read_text()
    assert manifest.count("<queries>") == 1, "the queries block is the only route"
    block = manifest.split("<queries>", 1)[1].split("</queries>", 1)[0]

    for intent in (
        # The set the allowlist manages: anything with an icon.
        "android.intent.category.LAUNCHER",
        # The home screen and the setup wizard, which must never be hidden and
        # are recognized by what they answer rather than by what they are called.
        "android.intent.category.HOME",
        "android.intent.category.SETUP_WIZARD",
        # Settings, the last local way back into a device.
        "android.settings.SETTINGS",
    ):
        assert intent in block, f"{intent} is not in the queries block"

    # Scoped to what is DECLARED rather than to the whole file: the comment
    # above the block names QUERY_ALL_PACKAGES because rejecting it is the whole
    # reason the block is there, and a test that forbids the words makes the
    # reasoning unwritable.
    declared = "\n".join(
        line for line in manifest.splitlines() if "<uses-permission" in line
    )
    assert "QUERY_ALL_PACKAGES" not in declared, (
        "the permission route was taken after all, which puts the four-permission "
        "profile - and with it the Play Protect result - back in play"
    )


def test_the_provisioning_activities_stay_guarded():
    """Exported, because the system starts them; guarded, because everything
    else can see them too. Dropping the permission would leave the activities
    that decide provisioning mode reachable by any installed app."""
    manifest = MANIFEST.read_text()
    for action in (
        "android.app.action.GET_PROVISIONING_MODE",
        "android.app.action.ADMIN_POLICY_COMPLIANCE",
    ):
        assert action in manifest, f"{action} is not declared"
    # Receiver plus both provisioning activities.
    assert manifest.count("android.permission.BIND_DEVICE_ADMIN") >= 3


def test_the_launcher_icon_is_declared():
    """An app with no icon gets a grey Android silhouette, which on a Device
    Owner is the only thing a person sees representing whatever owns their
    phone."""
    manifest = MANIFEST.read_text()
    assert 'android:icon="@mipmap/ic_launcher"' in manifest
    assert 'android:roundIcon="@mipmap/ic_launcher_round"' in manifest

    res = MANIFEST.parent / "res"
    for density in ("mdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi"):
        assert (res / f"mipmap-{density}/ic_launcher.png").is_file(), density
        assert (res / f"mipmap-{density}/ic_launcher_foreground.png").is_file(), density
    assert (res / "mipmap-anydpi-v26/ic_launcher.xml").is_file()
    assert (res / "values/ic_launcher_background.xml").is_file()
