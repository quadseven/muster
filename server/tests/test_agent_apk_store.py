"""The server image must still build after the agent artifact expires (muster#123).

build.server-image.yml bakes the APK from the newest successful agent build on
main, and that run's artifact is kept 14 days. An agent that went quiet for two
weeks used to block every server release. The fix keeps signing push-only and
stores each push-to-main APK as a release asset that never expires; the image
job falls back to that stored copy when the artifact is gone.

These tests pin the shape of that fix, since the failure only shows up on a
day nobody is looking:

- the store job runs only for a push to main, after the build and its pin
  check succeeded, on a GitHub-hosted runner, and is the ONLY job in the
  agent workflow that can write repository contents;
- the image job downloads the artifact only when it is present, falls back to
  the stored release asset otherwise, and still fails with a "missing or
  expired" message naming the run when neither exists;
- both workflows name the same release tag and asset.

Note: PyYAML parses the GitHub Actions `on:` key as boolean True.
"""
from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github/workflows"
AGENT = WORKFLOWS / "check.agent-android.yml"
IMAGE = WORKFLOWS / "build.server-image.yml"

RELEASE_TAG = "agent-apk"
ASSET = "muster-agent.tar"


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def _store_job(workflow: dict) -> dict:
    jobs = [
        job
        for job in workflow["jobs"].values()
        if any(RELEASE_TAG in str(step.get("run", "")) for step in job.get("steps", []))
    ]
    assert len(jobs) == 1, "check.agent-android.yml must have exactly one job that stores the APK"
    return jobs[0]


def _step(job: dict, name_part: str) -> dict:
    steps = [s for s in job["steps"] if name_part in str(s.get("name", ""))]
    assert len(steps) == 1, f"expected exactly one step named like {name_part!r}"
    return steps[0]


def test_the_store_job_runs_only_after_a_push_to_main_build() -> None:
    job = _store_job(_load(AGENT))
    assert job.get("needs") in ("assemble", ["assemble"])
    condition = " ".join(str(job.get("if", "")).split())
    assert "github.event_name == 'push'" in condition
    assert "github.ref == 'refs/heads/main'" in condition


def test_the_store_job_runs_on_a_hosted_runner() -> None:
    # The mac mini is a persistent runner that executes candidate code; a
    # token that can rewrite the repository must never be handed to it.
    job = _store_job(_load(AGENT))
    runs_on = job["runs-on"]
    assert isinstance(runs_on, str) and runs_on.startswith("ubuntu-"), runs_on


def test_only_the_store_job_can_write_contents() -> None:
    workflow = _load(AGENT)
    assert workflow["permissions"] == {"contents": "read"}
    store = _store_job(workflow)
    assert store.get("permissions") == {"contents": "write"}
    for job in workflow["jobs"].values():
        if job is store:
            continue
        assert "write" not in str(job.get("permissions", {})), job.get("name")


def test_the_store_job_publishes_one_asset_to_the_shared_tag() -> None:
    script = "\n".join(str(s.get("run", "")) for s in _store_job(_load(AGENT))["steps"])
    assert ASSET in script
    assert f"gh release upload {RELEASE_TAG}" in script.replace('"', "")


def test_the_image_downloads_the_artifact_only_when_it_is_present() -> None:
    job = _load(IMAGE)["jobs"]["build"]
    downloads = [s for s in job["steps"] if "actions/download-artifact" in str(s.get("uses", ""))]
    assert len(downloads) == 1
    assert "steps.apk.outputs.source == 'artifact'" in str(downloads[0].get("if", ""))


def test_the_image_falls_back_to_the_stored_release_apk() -> None:
    job = _load(IMAGE)["jobs"]["build"]
    fallback = _step(job, "stored release APK")
    assert "steps.apk.outputs.source == 'release'" in str(fallback.get("if", ""))
    script = str(fallback["run"])
    assert f"releases/tags/{RELEASE_TAG}" in script
    assert ASSET in script
    assert "--max-time" in script


def test_the_lookup_no_longer_fails_on_an_expired_artifact_alone() -> None:
    job = _load(IMAGE)["jobs"]["build"]
    lookup = str(_step(job, "Find the newest agent APK")["run"])
    assert "source=artifact" in lookup
    assert "source=release" in lookup
    assert "missing or expired for run $run_id" in lookup
