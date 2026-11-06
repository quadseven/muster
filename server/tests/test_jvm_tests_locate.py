"""agent/tools/jvm-tests.sh finds its Gradle cache and JDK on a lane machine.

A lane runs the validation contract with HOME pointed at an empty directory,
so a cache path built from $HOME alone, or a JDK path pinned to one machine,
parks every lane change under agent/android/ (muster#208). These tests drive
the script's `--locate` mode with fake caches and fake JDKs, so they need no
real JDK and no real Gradle cache.
"""

import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "agent" / "tools" / "jvm-tests.sh"


def _cache(base: Path) -> Path:
    files = base / "caches" / "modules-2" / "files-2.1"
    files.mkdir(parents=True)
    return files


def _jdk(base: Path, works: bool) -> Path:
    """A JDK home whose `java -version` runs, or fails like a wrong-arch binary."""
    java = base / "bin" / "java"
    java.parent.mkdir(parents=True)
    java.write_text("#!/bin/sh\nexit 0\n" if works else "#!/bin/sh\necho 'bad CPU type' >&2\nexit 126\n")
    java.chmod(java.stat().st_mode | stat.S_IXUSR)
    return base


def _locate(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    full = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **env}
    return subprocess.run(
        ["bash", str(SCRIPT), "--locate"], env=full, capture_output=True, text=True, timeout=60
    )


def test_gradle_user_home_wins_over_an_empty_home(tmp_path):
    files = _cache(tmp_path / "guh")
    jdk = _jdk(tmp_path / "jdk", works=True)
    empty = tmp_path / "empty-home"
    empty.mkdir()
    run = _locate({"HOME": str(empty), "GRADLE_USER_HOME": str(tmp_path / "guh"), "MUSTER_JDK": str(jdk)})
    assert run.returncode == 0, run.stderr
    assert f"gradle cache: {files}" in run.stdout
    assert f"jdk: {jdk}" in run.stdout


def test_a_gradle_user_home_without_files_falls_back_to_home(tmp_path):
    (tmp_path / "guh").mkdir()
    files = _cache(tmp_path / "home" / ".gradle")
    jdk = _jdk(tmp_path / "jdk", works=True)
    run = _locate(
        {"HOME": str(tmp_path / "home"), "GRADLE_USER_HOME": str(tmp_path / "guh"), "MUSTER_JDK": str(jdk)}
    )
    assert run.returncode == 0, run.stderr
    assert f"gradle cache: {files}" in run.stdout


def test_a_jdk_that_cannot_run_is_never_chosen(tmp_path):
    _cache(tmp_path / "guh")
    broken = _jdk(tmp_path / "x86-jdk", works=False)
    empty = tmp_path / "empty-home"
    empty.mkdir()
    run = _locate({"HOME": str(empty), "GRADLE_USER_HOME": str(tmp_path / "guh"), "MUSTER_JDK": str(broken)})
    assert f"jdk: {broken}\n" not in run.stdout
    if run.returncode != 0:
        # No other JDK on this machine: the refusal names what it tried.
        assert str(broken) in run.stderr
