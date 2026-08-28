"""What one device is told to be, and what it must never be told.

The two tests that carry the security are
`a_credential_is_never_read_from_the_shared_scope` and
`one_devices_configuration_never_reaches_another`. The one that carries the
availability is `a_file_that_cannot_be_read_refuses_the_whole_answer`: a
half-answer here is indistinguishable from an operator having deleted a policy,
and the device acts on that difference by withdrawing what it was enforcing.
"""
from __future__ import annotations

import pytest

from muster import policy

A = "a" * 64
B = "b" * 64


@pytest.fixture()
def root(tmp_path):
    return tmp_path


def _shared(root, name: str):
    return root / f"{policy.KITH_SCOPE}.{name}"


def _own(root, key_id: str, name: str):
    return root / f"{key_id}.{name}"


# ---- the two that carry the security -------------------------------------


def test_a_credential_is_never_read_from_the_shared_scope(root):
    """`app-config` is the file that holds tokens, so it is never fleet-wide.

    An operator who writes `kith.app-config` has written a token every device
    in the estate would be handed, and nothing about the file name would have
    told them so. muster refuses to serve it at all rather than serving it
    widely, because the second is silent and the first is not.
    """
    _shared(root, "app-config").write_text(
        "set app.zippie.companion announceToken zk_live_7f3a91c4e08b46d2a5\n"
    )
    served = policy.Policies(root=root).for_device(A)

    assert "app-config" not in served.files
    assert "zk_live_7f3a91c4e08b46d2a5" not in repr(served.files)


def test_one_devices_configuration_never_reaches_another(root):
    """The whole point of authenticating the fetch with the certificate."""
    _own(root, A, "app-config").write_text(
        "set app.zippie.companion announceToken kitchen-token\n"
    )
    _own(root, B, "app-config").write_text(
        "set app.zippie.companion announceToken hallway-token\n"
    )
    policies = policy.Policies(root=root)

    assert "kitchen-token" in policies.for_device(A).files["app-config"]
    assert "hallway-token" not in repr(policies.for_device(A).files)
    assert "kitchen-token" not in repr(policies.for_device(B).files)


def test_a_file_that_cannot_be_read_refuses_the_whole_answer(root):
    """A HALF-ANSWER IS A POLICY WITHDRAWAL, which is why this raises.

    The agent treats a file absent from a successful fetch as "this device has
    no such policy" and takes what it was enforcing back off. So serving three
    files when four were configured, because one of them held a byte that is not
    UTF-8, would withdraw a restriction set because a file got corrupted. Same
    reasoning as the kith answering 503 rather than an empty roll.
    """
    _shared(root, "restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    _shared(root, "visible-apps").write_bytes(b"app.muster.agent\n\xff\xfe")

    with pytest.raises(policy.Unreadable):
        policy.Policies(root=root).for_device(A)


# ---- what is served, and from where --------------------------------------


def test_an_empty_policy_directory_is_refused_and_not_served_as_nothing(root):
    """THE ONE THAT WOULD ACTUALLY HAVE HAPPENED.

    `muster-policy` is an OPTIONAL secret volume, and kubelet mounts an optional
    secret that does not exist as an EMPTY DIRECTORY. So a secret that was
    deleted, misnamed or never created is indistinguishable from a policy
    directory nobody has put anything in - and an empty answer is an
    authoritative instruction to every device in the estate to delete every file
    muster manages. One typo in a secret name would have withdrawn the fleet's
    configuration on its next boot.
    """
    with pytest.raises(policy.NoSource):
        policy.Policies(root=root).for_device(A)


def test_no_policy_directory_at_all_is_refused_too(tmp_path):
    """A muster that was never given a policy directory does not manage
    configuration. Saying "you have no policy" is a claim it cannot support, and
    the device acts on that claim by withdrawing."""
    with pytest.raises(policy.NoSource):
        policy.Policies(root=None).for_device(A)


def test_a_directory_of_only_unmanaged_files_is_refused(root):
    """A volume that mounted something is not a volume that mounted THIS. An
    editor backup or a stray README is not a policy, and counting it would put
    the empty-directory hole back with an extra step."""
    (root / "README").write_text("policy lives in the muster-policy secret")
    (root / "kith.restrictions.swp").write_text("junk")

    with pytest.raises(policy.NoSource):
        policy.Policies(root=root).for_device(A)


def test_one_empty_managed_file_is_a_source_and_withdraws_deliberately(root):
    """HOW AN OPERATOR SAYS "ASSERT NOTHING" ON PURPOSE, now that saying it by
    accident is refused. It is the vocabulary the agent already speaks: an
    absent file leaves the device alone, an empty one withdraws."""
    _shared(root, "restrictions").write_text("")

    served = policy.Policies(root=root).for_device(A)
    assert served.files == {"restrictions": ""}


def test_the_shared_scope_reaches_a_device_with_no_file_of_its_own(root):
    """This is what makes a policy change reach a fleet without a person."""
    _shared(root, "restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    served = policy.Policies(root=root).for_device(A)
    assert served.files["restrictions"] == "DISALLOW_SAFE_BOOT\n"


def test_a_devices_own_file_replaces_the_shared_one_rather_than_merging(root):
    """MERGING WOULD BE A SECOND VOCABULARY NOBODY ASKED FOR.

    Two restriction files combined by muster means a device carrying a
    restriction that appears in neither file the operator was looking at, and
    no way to take it off with the device's own file. Replacement is the rule
    the agent's own reconcilers already follow.
    """
    _shared(root, "restrictions").write_text("DISALLOW_SAFE_BOOT\nDISALLOW_ADD_USER\n")
    _own(root, A, "restrictions").write_text("DISALLOW_ADD_USER\n")

    served = policy.Policies(root=root).for_device(A)
    assert served.files["restrictions"] == "DISALLOW_ADD_USER\n"


def test_an_empty_file_is_served_as_empty_and_not_as_absent(root):
    """THE DISTINCTION THE WHOLE AGENT IS BUILT ON. An empty restrictions file
    means "withdraw everything"; no file at all means "nobody has configured
    this device". Collapsing them here would make it impossible to unlock one
    device that the kith-wide file restricts."""
    _shared(root, "restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    _own(root, A, "restrictions").write_text("")

    served = policy.Policies(root=root).for_device(A)
    assert served.files["restrictions"] == ""
    assert "restrictions" in served.files


def test_a_file_muster_does_not_manage_is_not_served(root):
    """The device writes what it is served into its own files directory, so the
    set of names that can travel is a closed vocabulary rather than whatever is
    in the policy directory. A stray editor backup must not become a file on a phone,
    and neither must a name somebody hoped the agent would grow."""
    # A real file too, or the source is empty and this refuses before it gets
    # as far as ignoring anything - see NoSource.
    _shared(root, "restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    _shared(root, "restrictions.swp").write_text("junk")
    _shared(root, "server-url").write_text("https://elsewhere.example")
    _own(root, A, "wallpaper.png").write_text("not a png either")

    served = policy.Policies(root=root).for_device(A)
    assert set(served.files) == {"restrictions"}


def test_a_key_id_that_is_not_one_is_refused_rather_than_looked_up(root):
    """`key_id` is a SHA-256 hexdigest by construction, so nothing that reaches
    this can contain a path separator. Checked anyway, at this module's own
    boundary: the day something else calls it, the guard is the difference
    between a lookup and an arbitrary read of the pod's filesystem."""
    for bad in ("../../etc", "", "A" * 64, "abc", "/" + "a" * 63):
        with pytest.raises(ValueError):
            policy.Policies(root=root).for_device(bad)


# ---- the revision --------------------------------------------------------


def test_the_revision_changes_when_the_content_does(root):
    _shared(root, "restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    before = policy.Policies(root=root).for_device(A).revision

    _shared(root, "restrictions").write_text("DISALLOW_SAFE_BOOT\nDISALLOW_ADD_USER\n")
    after = policy.Policies(root=root).for_device(A).revision

    assert before != after


def test_the_revision_is_the_same_for_the_same_content(root):
    """So a device can tell "policy changed" from "the pod restarted". A
    revision minted per read would have every device rewriting its own files on
    every boot and reporting a change that did not happen."""
    _shared(root, "restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    assert (
        policy.Policies(root=root).for_device(A).revision
        == policy.Policies(root=root).for_device(A).revision
    )


def test_two_devices_with_the_same_content_share_a_revision(root):
    """A revision describes the CONFIGURATION, not the device. Mixing the
    key_id in would make "are these two devices on the same policy" a question
    nobody can answer by looking."""
    _shared(root, "restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    policies = policy.Policies(root=root)
    assert policies.for_device(A).revision == policies.for_device(B).revision


def test_the_revision_is_not_the_configuration(root):
    """It is written to logs, and the configuration is not."""
    _own(root, A, "app-config").write_text(
        "set app.zippie.companion announceToken zk_live_7f3a91c4e08b46d2a5\n"
    )
    served = policy.Policies(root=root).for_device(A)
    assert "zk_live_7f3a91c4e08b46d2a5" not in served.revision


def test_the_configuration_never_prints_itself(root):
    """`Configuration` is logged, returned and put in an f-string by whatever
    handles it next. A data class prints every field, and one of those fields
    is a write token."""
    _own(root, A, "app-config").write_text(
        "set app.zippie.companion announceToken zk_live_7f3a91c4e08b46d2a5\n"
    )
    served = policy.Policies(root=root).for_device(A)

    for rendered in (str(served), repr(served), f"{served}"):
        assert "zk_live_7f3a91c4e08b46d2a5" not in rendered
    assert "app-config" in str(served), "the NAMES are what the log is for"


# ---- wiring --------------------------------------------------------------


def test_from_env_with_nothing_set_still_starts(monkeypatch):
    """A muster with no policy directory must COME UP - it just cannot answer a
    device about configuration. Refusing to start would stop every device in the
    estate renewing over a feature none of them had yesterday."""
    monkeypatch.delenv("MUSTER_POLICY_DIR", raising=False)
    source = policy.from_env()
    assert source.status()["readable"] is False
    with pytest.raises(policy.NoSource):
        source.for_device(A)


def test_from_env_pointed_at_a_directory_that_is_not_there_is_not_a_crash(
    monkeypatch, tmp_path
):
    """Same decision as the kith store: report it, do not refuse to start."""
    monkeypatch.setenv("MUSTER_POLICY_DIR", str(tmp_path / "nope"))
    source = policy.from_env()
    assert "nope" in source.status()["directory"]
    assert source.status()["readable"] is False
    with pytest.raises(policy.NoSource):
        source.for_device(A)


def test_status_counts_the_files_because_readable_cannot_tell_the_story(root):
    """`readable` IS TRUE FOR AN ABSENT OPTIONAL SECRET, because kubelet mounts
    one as an empty directory. The count is the field that distinguishes a live
    policy source from a secret somebody deleted, which is the whole reason
    /readyz reports this at all."""
    empty = policy.Policies(root=root).status()
    assert empty["readable"] is True, "a mount point exists, which proves nothing"
    assert empty["files"] == 0, "and this is what says so"

    _shared(root, "restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    _own(root, A, "app-config").write_text("set app.example.thing k v\n")
    (root / "README").write_text("not policy")

    status = policy.Policies(root=root).status()
    assert status["files"] == 2, "only names muster manages are counted"
    assert status["directory"].endswith(str(root))


# ---- role scopes (muster#70) ---------------------------------------------
#
# "make it a zippie android so it does zippie config". A role sits between the
# device and the kith: one edit reaches every device with that role, and no
# others.


def _role(root, role, name):
    return root / f"role-{role}.{name}"


def test_a_role_file_reaches_a_device_with_that_role(tmp_path):
    _shared(tmp_path, "restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    _role(tmp_path, "zippie", "restrictions").write_text("DISALLOW_ADD_USER\n")
    served = policy.Policies(root=tmp_path).for_device(A, role="zippie")
    assert served.files["restrictions"] == "DISALLOW_ADD_USER\n"


def test_a_device_with_no_role_never_sees_a_role_file(tmp_path):
    _shared(tmp_path, "restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    _role(tmp_path, "zippie", "restrictions").write_text("DISALLOW_ADD_USER\n")
    served = policy.Policies(root=tmp_path).for_device(A)
    assert served.files["restrictions"] == "DISALLOW_SAFE_BOOT\n"


def test_a_role_falls_back_to_the_kith_for_what_it_does_not_name(tmp_path):
    """A role says what is DIFFERENT about these devices, not everything about
    them. Requiring a role to restate the fleet's policy is how the two drift."""
    _shared(tmp_path, "restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    _shared(tmp_path, "visible-apps").write_text("app.muster.agent\n")
    _role(tmp_path, "zippie", "restrictions").write_text("DISALLOW_ADD_USER\n")
    served = policy.Policies(root=tmp_path).for_device(A, role="zippie")
    assert served.files["restrictions"] == "DISALLOW_ADD_USER\n"
    assert served.files["visible-apps"] == "app.muster.agent\n"


def test_a_device_of_its_own_still_beats_its_role(tmp_path):
    """Most specific wins, and the device is the most specific thing there is."""
    _shared(tmp_path, "restrictions").write_text("kith\n")
    _role(tmp_path, "zippie", "restrictions").write_text("role\n")
    _own(tmp_path, A, "restrictions").write_text("device\n")
    assert policy.Policies(root=tmp_path).for_device(A, role="zippie").files[
        "restrictions"
    ] == "device\n"


def test_a_role_MAY_carry_app_config_although_the_kith_may_not(tmp_path):
    """THE WHOLE POINT OF ROLES, and a security decision worth stating.

    `kith.app-config` is never read because that file holds write tokens and the
    kith is every device in the estate. A ROLE is narrower and is exactly the
    operator's intent: "make it a zippie android so it does zippie config"
    means the zippie token reaches the zippie androids.

    It is still a credential shared by every device carrying the role. That is
    the trade, made deliberately, and it is what a role is FOR.
    """
    _role(tmp_path, "zippie", "app-config").write_text(
        "set app.zippie.companion announceToken abc\n"
    )
    served = policy.Policies(root=tmp_path).for_device(A, role="zippie")
    assert "announceToken" in served.files["app-config"]


def test_the_kith_still_may_not_carry_app_config_even_beside_a_role(tmp_path):
    _shared(tmp_path, "app-config").write_text("set app.x y z\n")
    _role(tmp_path, "zippie", "restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    served = policy.Policies(root=tmp_path).for_device(A, role="zippie")
    assert "app-config" not in served.files


def test_two_roles_do_not_see_each_other(tmp_path):
    _role(tmp_path, "zippie", "restrictions").write_text("zippie\n")
    _role(tmp_path, "kiosk", "restrictions").write_text("kiosk\n")
    policies = policy.Policies(root=tmp_path)
    assert policies.for_device(A, role="zippie").files["restrictions"] == "zippie\n"
    assert policies.for_device(A, role="kiosk").files["restrictions"] == "kiosk\n"


def test_a_role_changes_the_revision(tmp_path):
    """Two devices on different policy are not on the same revision, and the
    revision is what an operator compares to answer "are these two the same"."""
    _shared(tmp_path, "restrictions").write_text("kith\n")
    _role(tmp_path, "zippie", "restrictions").write_text("zippie\n")
    policies = policy.Policies(root=tmp_path)
    assert policies.for_device(A).revision != policies.for_device(A, role="zippie").revision


def test_a_role_that_is_not_a_role_is_refused_rather_than_joined_to_a_path(tmp_path):
    """`policy.py` is the second door, not the first - enroll.mint refuses these
    too. Checked again here because the difference between a lookup and an
    arbitrary read of the pod's filesystem is not a property to leave resting on
    a function two modules away."""
    _shared(tmp_path, "restrictions").write_text("kith\n")
    policies = policy.Policies(root=tmp_path)
    for bad in ("../../etc", "has.dot", "has/slash", "UPPER", "trailing-"):
        with pytest.raises(ValueError):
            policies.for_device(A, role=bad)
    # Empty is NOT a bad role - it is the ordinary case, meaning "no role".
    assert policies.for_device(A, role="").files["restrictions"] == "kith\n"


def test_role_files_are_counted_as_policy(tmp_path):
    """`files_held` is what tells a live policy directory from a deleted secret,
    so a directory holding only role files must not read as empty."""
    _role(tmp_path, "zippie", "restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    assert policy.Policies(root=tmp_path).files_held() == 1


def test_the_two_role_patterns_cannot_drift(tmp_path):
    """`enroll` and `policy` each refuse a bad role at their own door, which is
    this codebase's convention - `_KEY_ID` is duplicated here for the same
    reason, with the same comment.

    Duplication is the right call at a boundary and the wrong one to leave
    unguarded: if `mint` grew looser than this module, an operator would get a
    QR minted happily and a 500 from the pod holding the CA when the device
    fetched. If it grew tighter, a role already in the kith would stop
    resolving. Neither shows up until a handset is involved.
    """
    from muster import enroll

    assert policy._ROLE.pattern == enroll._ROLE.pattern
