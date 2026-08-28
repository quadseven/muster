"""`muster` on the command line.

Thin on purpose. Every decision lives in enroll.py or provision.py where it can
be tested without a device or a network; this file turns arguments into calls
and verdicts into exit codes.

EXIT CODES ARE THE INTERFACE. This gets run from scripts and from CI, where a
human is not reading the prose:

    0  it worked, or the device is ready
    2  refused - the device cannot be provisioned, and the reason is on stderr
    3  it tried and the device did not end up owned
"""
from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys

from muster import assets
from muster.provision import (
    ADMIN_COMPONENT,
    DEVICE_FILES,
    Adb,
    device_state,
    place_file,
    preflight,
    set_device_owner,
)


def cmd_preflight(args) -> int:
    result = preflight(Adb(args.adb), args.serial)
    print(f"{args.serial}: {result.verdict.value}")
    if result.owner:
        print(f"  owner: {result.owner}")
    if result.accounts:
        print(f"  accounts: {', '.join(result.accounts)}")
    if result.detail:
        print(f"  {result.detail}", file=sys.stdout if result.ok else sys.stderr)
    return 0 if result.ok else 2


def cmd_provision(args) -> int:
    """Preflight, install, own, and confirm - refusing before it acts.

    The preflight is NOT optional and there is deliberately no --force. The
    failure it prevents costs a factory reset to recover from, and a flag that
    skips it would be used exactly once, at 1am, on the wrong device.
    """
    adb = Adb(args.adb)

    result = preflight(adb, args.serial)
    if not result.ok:
        print(f"refusing: {result.verdict.value}", file=sys.stderr)
        print(f"  {result.detail}", file=sys.stderr)
        return 2
    print(f"{args.serial}: {result.detail} (API {result.sdk})")

    print(f"installing {args.apk}")
    rc, out = adb.install(args.serial, args.apk)
    if rc != 0:
        print(f"install failed:\n{out}", file=sys.stderr)
        return 3

    print(f"setting device owner to {args.component}")
    if not set_device_owner(adb, args.serial, args.component):
        print(
            "the device did not end up owned. It installed, so the APK is fine - "
            "the usual cause is an account or a leftover profile that the "
            "preflight could not see. `adb shell dumpsys device_policy` says "
            "what the device thinks.",
            file=sys.stderr,
        )
        return 3

    # Anything else the operator wants on the phone, installed while the cable
    # is still attached. A device provisioned this way is NOT enrolled in
    # managed Google Play, so nothing reconciles the app set and deletes these
    # afterwards - which is the whole reason this route is worth taking.
    for extra in args.also_install or []:
        print(f"installing {extra}")
        rc, out = adb.install(args.serial, extra)
        if rc != 0:
            print(f"install of {extra} failed:\n{out}", file=sys.stderr)
            return 3

    if args.server_url:
        # Written to the device rather than compiled in: a hostname baked into a
        # Device Owner APK cannot change without a release, and a release there
        # eventually costs a factory reset.
        package = args.component.split("/")[0]
        files = DEVICE_FILES.format(package=package)
        placed = place_file(
            adb, args.serial, package, f"{files}/server-url", args.server_url.encode()
        )
        if not placed.ok:
            print(f"the server URL did not land: {placed.detail}", file=sys.stderr)
            return 3
        print(f"server url: {args.server_url}")

    print("device owner set and confirmed by the device")
    return cmd_verify(args)


def cmd_verify(args) -> int:
    """Read the device back and say what it actually is.

    Separate from provisioning so it can be run at any time - a week later, on a
    phone somebody else touched - and so provisioning ends by proving its own
    work rather than by reporting that its last command returned zero.
    """
    state = device_state(Adb(args.adb), args.serial, tuple(args.package or []))

    print(f"{args.serial}: API {state.sdk}")
    print(f"  owner: {state.owner or '(none)'}")
    for pkg in state.packages:
        if pkg.present:
            print(f"  {pkg.package}: {pkg.version_name} (code {pkg.version_code})")
        else:
            print(f"  {pkg.package}: NOT INSTALLED")

    problems = []
    if not state.owned_by(args.component):
        problems.append(f"expected owner {args.component}, found {state.owner or 'none'}")
    problems += [f"{p.package} is not installed" for p in state.packages if not p.present]

    for problem in problems:
        print(f"  problem: {problem}", file=sys.stderr)
    return 0 if not problems else 3


def cmd_asset(args) -> int:
    """Prepare an image for the asset store, and say exactly how to put it there.

    WHY THIS PRINTS A COMMAND RATHER THAN UPLOADING (muster#45). The store is a
    Secret, and there is no upload endpoint yet - a console for that is
    muster#36. Inventing one here would be a second way to write policy that no
    operator asked for and no test covers on a handset. What an operator
    actually needs is the two things they cannot work out by hand: the digest
    the device will check, and the exact policy stanza that names it.

    THE DIGEST IS COMPUTED FROM THE FILE ON DISK, which is the whole point.
    Typing a digest by hand into a policy file is how a wallpaper never applies
    and nothing says why.
    """
    source = pathlib.Path(args.image)
    if not source.is_file():
        print(f"no image at {source}", file=sys.stderr)
        return 2

    name = args.name or source.name
    if not assets._NAME.match(name):
        print(
            f"'{name}' is not a name an asset can have: letters, digits, dot, "
            "dash and underscore, starting with a letter or digit, and no "
            "longer than 64 characters. Use --name to give it one.",
            file=sys.stderr,
        )
        return 2

    body = source.read_bytes()
    if len(body) > assets.MAX_BYTES:
        print(
            f"{source} is {len(body)} bytes; muster serves at most "
            f"{assets.MAX_BYTES}",
            file=sys.stderr,
        )
        return 2

    digest = hashlib.sha256(body).hexdigest()
    surfaces = " ".join(args.surfaces)
    print(f"{name}  {len(body)} bytes  sha256 {digest}")
    print()
    print("Put the bytes in the store:")
    print()
    print("  kubectl -n muster create secret generic muster-assets \\")
    print(f"    --from-file={name}={source} \\")
    # `--server-side`, AND IT IS NOT A STYLE CHOICE. A client-side `kubectl
    # apply` stores the ENTIRE object in a
    # `kubectl.kubernetes.io/last-applied-configuration` annotation, and
    # annotations are capped at 262144 bytes. An asset is base64 in the Secret,
    # so anything over about 190KB of real bytes is refused with
    # "metadata.annotations: Too long" - which names the annotation and not the
    # file, and says nothing about what to do instead. A 247KB wallpaper hits
    # this, so the FIRST asset anybody publishes hits it.
    print("    --dry-run=client -o yaml | kubectl apply --server-side --force-conflicts -f -")
    print()
    print(
        "  (--server-side is required, not tidiness: a client-side apply keeps a"
    )
    print(
        "   copy of the whole object in an annotation, and annotations stop at"
    )
    print(
        "   262144 bytes - which a wallpaper-sized asset exceeds once base64ed.)"
    )
    print()
    print(f"Then write this as the '{args.scope}.wallpaper' policy file:")
    print()
    print(f"  image {name} sha256 {digest}")
    print(f"  surfaces {surfaces}")
    print()
    # NAMED OUT LOUD, because a Secret update reaches a running pod's filesystem
    # on kubelet's schedule and an operator who does not know that concludes the
    # feature is broken about ninety seconds too early.
    print(
        "A Secret change reaches the pod's filesystem within a minute or so; "
        "the device applies it at its next check-in."
    )
    return 0


def cmd_wallpaper(args) -> int:
    """Push an image to the agent's device-protected files directory.

    Not baked into the APK on purpose: this app is Device Owner, so changing a
    bundled asset would mean a rebuild, a reinstall, and eventually a factory
    reset when the signing key moves. A file is the difference between changing
    the wallpaper and shipping a release.

    The agent applies it at the next boot, once, keyed on the image's hash - so
    running this twice with the same picture does nothing the second time.
    """
    adb = Adb(args.adb)
    source = pathlib.Path(args.image)
    if not source.is_file():
        print(f"no image at {source}", file=sys.stderr)
        return 2

    # `place_file` and not `adb push`: the agent's directory belongs to the app
    # and the shell cannot write into it, so a push here lands nowhere and reads
    # like a broken cable. What it does instead has an expiry date on it, and
    # says so where it is written.
    files = DEVICE_FILES.format(package=args.package)
    placed = place_file(
        adb, args.serial, args.package, f"{files}/wallpaper.png", source.read_bytes()
    )
    if not placed.ok:
        print(placed.detail, file=sys.stderr)
        return 3
    print(f"placed: {placed.detail}")
    print("the agent applies it at the next boot")
    return 0


def cmd_restrictions(args) -> int:
    """Push the restrictions file the agent reconciles against at boot.

    Same shape as the wallpaper beside it, for the same reason: this app is
    Device Owner, so anything baked into the APK can only be changed by a
    release, and a release eventually costs a factory reset when the signing key
    moves.

    AN EMPTY FILE IS A VALID INSTRUCTION and means "no restrictions" - the agent
    withdraws everything it previously set. Not pushing a file at all means
    something different: the device is left exactly as it is. That distinction is
    the difference between a device nobody has configured yet and one somebody
    deliberately unlocked.

    NOT VALIDATED HERE, DELIBERATELY. The vocabulary of restriction names lives
    in the agent, in RestrictionPolicy, and a second copy in this file would be
    free to drift from it - at which point the CLI would confidently accept a
    name the device refuses, or refuse one it accepts. The agent names every
    line it will not act on:

        adb logcat -s muster

    Restrictions are reconciled at boot, so this takes effect on the next one.
    """
    adb = Adb(args.adb)
    source = pathlib.Path(args.file)
    if not source.is_file():
        print(f"no restrictions file at {source}", file=sys.stderr)
        return 2

    files = DEVICE_FILES.format(package=args.package)
    placed = place_file(
        adb, args.serial, args.package, f"{files}/restrictions", source.read_bytes()
    )
    if not placed.ok:
        print(placed.detail, file=sys.stderr)
        return 3
    print(f"placed: {placed.detail}")
    print("the agent reconciles at the next boot; anything refused is named in")
    print("  adb logcat -s muster")
    return 0


def cmd_visible_apps(args) -> int:
    """Push the allowlist of applications the agent leaves on the launcher.

    Same shape as the restrictions file beside it, for the same reason: this app
    is Device Owner, so anything baked into the APK can only be changed by a
    release, and a release eventually costs a factory reset when the signing key
    moves.

    AN EMPTY FILE IS A VALID INSTRUCTION and means "nothing stays" - every
    application with an icon goes except the handful the agent will never hide.
    Not pushing a file at all means something different: the device's launcher is
    left exactly as it is. That distinction is the difference between a device
    nobody has configured yet and one somebody deliberately stripped.

    NOT VALIDATED HERE, DELIBERATELY. Which packages exist is a question only the
    handset can answer, and which packages are load-bearing lives in the agent,
    in AppVisibilityPolicy. A second copy of either in this file would be free to
    drift from it. The agent names every line it will not act on, and every
    package it keeps visible against the file's wishes:

        adb logcat -s muster

    The allowlist is reconciled at boot, so this takes effect on the next one.
    """
    adb = Adb(args.adb)
    source = pathlib.Path(args.file)
    if not source.is_file():
        print(f"no visible-apps file at {source}", file=sys.stderr)
        return 2

    files = DEVICE_FILES.format(package=args.package)
    placed = place_file(
        adb, args.serial, args.package, f"{files}/visible-apps", source.read_bytes()
    )
    if not placed.ok:
        print(placed.detail, file=sys.stderr)
        return 3
    print(f"placed: {placed.detail}")
    # WHAT THIS COMMAND KNOWS AND WHAT IT DOES NOT. The sha256 above is the
    # device's own, so the file is on it. Nothing here has asked whether the
    # agent will act on the file: it goes inert if this device is not owned by
    # muster, if the APK shipped without its package queries, or if the file
    # names things it will not act on - and none of that is visible from a
    # laptop. Saying "the agent reconciles at the next boot" flatly would be
    # asserting the one half this command cannot see, which is the habit
    # `provision.py` exists to break.
    print("that is the file on the device, and all this command can prove.")
    print("whether the agent acts on it - and anything refused, withheld, or")
    print("kept visible against it - is only visible on the device:")
    print("  adb logcat -s muster")
    return 0


def cmd_app_config(args) -> int:
    """Push the managed configuration the agent applies to other apps at boot.

    THIS IS THE STEP THAT TURNS AN INSTALLED APP INTO A CONTRIBUTING ONE. A
    Device Owner can set application restrictions, which an app reads through
    `RestrictionsManager` - so the credential a person used to have to type into
    the phone becomes a line in a file. Measured on <device-serial> on
    2026-08-19: app.zippie.companion was installed, running, and absent from its
    bond, because nothing could give it a write token.

    Same shape as `restrictions` beside it, and NOT VALIDATED HERE for the same
    reason: the vocabulary lives in the agent, in `AppConfigPolicy`, and a
    second copy in this file would be free to drift from it. The agent names
    every line it will not act on, by line number:

        adb logcat -s muster

    THE FILE HOLDS CREDENTIALS, which is what makes this command different from
    every other one here. Nothing prints its contents, and `place_file` is told
    the payload is secret so that a failing device is not quoted back verbatim -
    an adb that allocates a pty answers a write by echoing the whole payload.
    """
    adb = Adb(args.adb)
    source = pathlib.Path(args.file)
    if not source.is_file():
        print(f"no app configuration file at {source}", file=sys.stderr)
        return 2

    files = DEVICE_FILES.format(package=args.package)
    placed = place_file(
        adb,
        args.serial,
        args.package,
        f"{files}/app-config",
        source.read_bytes(),
        secret=True,
    )
    if not placed.ok:
        print(placed.detail, file=sys.stderr)
        return 3
    print(f"placed: {placed.detail}")
    # Same honesty as `visible-apps` above, and it bites harder here: this
    # command cannot see whether the device is owned by muster, whether the
    # configured app is even installed, or whether it read the bundle. The
    # thing that settles all three is the configured app doing its job.
    print("that is the file on the device, and all this command can prove.")
    print("whether the agent applies it - and anything refused, by line")
    print("number - is only visible on the device:")
    print("  adb logcat -s muster")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="muster")
    parser.add_argument("--adb", default="adb", help="path to the adb binary")
    sub = parser.add_subparsers(dest="command", required=True)

    pf = sub.add_parser(
        "preflight", help="can this device be provisioned? changes nothing"
    )
    pf.add_argument("serial")
    pf.set_defaults(func=cmd_preflight)

    pv = sub.add_parser("provision", help="install the agent and take ownership")
    pv.add_argument("serial")
    pv.add_argument("--apk", required=True, help="path to the agent APK")
    pv.add_argument("--component", default=ADMIN_COMPONENT)
    pv.add_argument(
        "--also-install",
        action="append",
        metavar="APK",
        help="another APK to install once ownership is taken; repeatable",
    )
    pv.add_argument(
        "--package",
        action="append",
        help="package to assert is present afterwards; repeatable",
    )
    pv.add_argument(
        "--server-url",
        help="base URL of the muster control plane, written to the device",
    )
    pv.set_defaults(func=cmd_provision)

    vf = sub.add_parser("verify", help="read a device back and say what it is")
    vf.add_argument("serial")
    vf.add_argument("--component", default=ADMIN_COMPONENT)
    vf.add_argument(
        "--package",
        action="append",
        help="package to assert is present; repeatable",
    )
    vf.set_defaults(func=cmd_verify)

    wp = sub.add_parser("wallpaper", help="push a wallpaper for the agent to apply")
    wp.add_argument("serial")
    wp.add_argument("--image", required=True, help="path to a PNG")
    wp.add_argument("--package", default="app.muster.agent")
    wp.set_defaults(func=cmd_wallpaper)

    at = sub.add_parser(
        "asset",
        help="prepare an image for the asset store and print how to publish it",
    )
    at.add_argument("image", help="path to the file to publish")
    at.add_argument(
        "--name",
        default="",
        help="what devices will call it (default: the file's own name)",
    )
    at.add_argument(
        "--scope",
        default="kith",
        help="'kith' for every device, or a 64-character key_id for one",
    )
    at.add_argument(
        "--surfaces",
        nargs="+",
        default=["system", "lock"],
        choices=["system", "lock"],
        help="which screens the wallpaper goes on (default: both)",
    )
    at.set_defaults(func=cmd_asset)

    rs = sub.add_parser(
        "restrictions", help="push the restrictions the agent should enforce"
    )
    rs.add_argument("serial")
    rs.add_argument(
        "--file",
        required=True,
        help="restrictions file: one name per line, # comments, empty means none",
    )
    rs.add_argument("--package", default="app.muster.agent")
    rs.set_defaults(func=cmd_restrictions)

    va = sub.add_parser(
        "visible-apps",
        help="push the allowlist of applications that stay on the launcher",
    )
    va.add_argument("serial")
    va.add_argument(
        "--file",
        required=True,
        help=(
            "allowlist: one package name per line, # comments, empty means "
            "nothing stays visible"
        ),
    )
    va.add_argument("--package", default="app.muster.agent")
    va.set_defaults(func=cmd_visible_apps)

    ac = sub.add_parser(
        "app-config", help="push the configuration the agent gives other apps"
    )
    ac.add_argument("serial")
    ac.add_argument(
        "--file",
        required=True,
        help=(
            "app configuration: 'set <package> <key> <value>', "
            "'set-bool <package> <key> true|false', 'grant <package> <permission>'"
        ),
    )
    ac.add_argument(
        "--package",
        default="app.muster.agent",
        help=(
            "the AGENT's package, which is where the file is written. The apps "
            "being configured are named on every line inside it"
        ),
    )
    ac.set_defaults(func=cmd_app_config)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
