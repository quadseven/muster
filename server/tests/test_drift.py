"""What a device reported, held against what its policy tells it to carry (muster#162).

Pure: the expected versions are the served `install-apps` text and the reported
ones are the stored report, so every state here is reachable without a device.
"""
from __future__ import annotations

from muster import drift
from muster.kith import PackageReport

DIGEST = "0" * 64


def _line(package: str, version: str) -> str:
    return f"install {package} {package}.apk sha256 {DIGEST} version {version}"


def _states(install_apps: str | None, reported: tuple[PackageReport, ...] | None):
    return {
        entry.package: entry.state
        for entry in drift.compare(drift.expected_versions(install_apps), reported)
    }


def test_a_version_behind_the_policy_is_drift():
    entries = drift.compare(
        drift.expected_versions(_line("app.example.companion", "80") + "\n"),
        (PackageReport(package="app.example.companion", version_code=78),),
    )

    assert entries == [
        drift.Entry(
            package="app.example.companion",
            expected_version_code=80,
            reported_version_code=78,
            state=drift.BEHIND,
        )
    ]
    assert drift.drifted(entries) == 1


def test_at_or_past_the_policy_is_current_and_not_drift():
    """Past it is what a hand-installed build looks like, and the agent leaves
    it alone (AppInstallPolicy.plan), so calling it drift would be a remedy
    nobody can apply."""
    text = _line("app.example.at", "80") + "\n" + _line("app.example.past", "80")
    reported = (
        PackageReport(package="app.example.at", version_code=80),
        PackageReport(package="app.example.past", version_code=91),
    )

    entries = drift.compare(drift.expected_versions(text), reported)

    assert {e.package: e.state for e in entries} == {
        "app.example.at": drift.CURRENT,
        "app.example.past": drift.CURRENT,
    }
    assert drift.drifted(entries) == 0


def test_reported_as_not_installed_is_drift():
    """A null versionCode is the device saying it looked and the app is not there."""
    states = _states(
        _line("app.example.companion", "80"),
        (PackageReport(package="app.example.companion", version_code=None),),
    )

    assert states == {"app.example.companion": drift.MISSING}


def test_a_package_the_report_does_not_mention_is_unreported_not_missing():
    """The report predates the policy line, or the device never reported at all.
    Reading that as "not installed" would invent an answer the device never gave."""
    text = _line("app.example.companion", "80")

    assert _states(text, ()) == {"app.example.companion": drift.UNREPORTED}
    assert _states(text, None) == {"app.example.companion": drift.UNREPORTED}
    assert drift.drifted(
        drift.compare(drift.expected_versions(text), None)
    ) == 0


def test_a_reported_package_no_policy_names_is_unmanaged():
    """muster cannot push what no `install-apps` line names - including anything
    Play installed. Shown so the reader knows it is out of reach, not current."""
    states = _states(
        _line("app.example.companion", "80"),
        (
            PackageReport(package="app.example.companion", version_code=80),
            PackageReport(package="app.example.dropped", version_code=3),
        ),
    )

    assert states == {
        "app.example.companion": drift.CURRENT,
        "app.example.dropped": drift.UNMANAGED,
    }


def test_a_line_whose_version_cannot_be_read_is_unreadable_not_current():
    """The agent refuses such a line, so nothing will be installed for it; a
    guess at the version would hide that."""
    text = (
        f"install app.example.short app.apk sha256 {DIGEST}\n"
        f"install app.example.word app.apk sha256 {DIGEST} version seventy\n"
    )
    reported = (PackageReport(package="app.example.short", version_code=1),)

    entries = drift.compare(drift.expected_versions(text), reported)

    assert [(e.package, e.expected_version_code, e.state) for e in entries] == [
        ("app.example.short", None, drift.UNREADABLE),
        ("app.example.word", None, drift.UNREADABLE),
    ]
    assert drift.drifted(entries) == 0


def test_no_install_file_expects_nothing():
    assert drift.expected_versions(None) == {}
    assert drift.expected_versions("") == {}
    assert _states(None, (PackageReport(package="app.example.x", version_code=1),)) == {
        "app.example.x": drift.UNMANAGED,
    }


def test_comments_and_other_lines_name_no_package():
    text = "# the companion app\n\n" + _line("app.example.companion", "80") + "\n"

    assert drift.expected_versions(text) == {"app.example.companion": 80}


def test_the_install_keyword_is_case_insensitive_like_the_agent_reads_it():
    assert drift.expected_versions(_line("app.example.x", "5").replace("install", "INSTALL")) == {
        "app.example.x": 5,
    }


def test_policy_order_first_then_what_only_the_report_names():
    text = _line("app.example.b", "1") + "\n" + _line("app.example.a", "1")
    reported = (
        PackageReport(package="app.example.z", version_code=1),
        PackageReport(package="app.example.a", version_code=1),
    )

    assert [e.package for e in drift.compare(drift.expected_versions(text), reported)] == [
        "app.example.b",
        "app.example.a",
        "app.example.z",
    ]


def test_a_package_reported_twice_is_one_entry():
    reported = (
        PackageReport(package="app.example.z", version_code=1),
        PackageReport(package="app.example.z", version_code=2),
    )

    assert len(drift.compare({}, reported)) == 1
