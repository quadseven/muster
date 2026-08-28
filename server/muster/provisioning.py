"""The QR that turns a wiped phone into a managed one, with no cable.

Six taps on the setup wizard's welcome screen opens a scanner. What it scans is
this payload: where to fetch the agent, how to know the download is genuine, and
anything the agent should know on first boot.

THE CHECKSUM IS OF THE SIGNING CERTIFICATE, NOT THE APK. This is the single
most common way to get this wrong, and it fails as "can't set up device" with
nothing naming the cause:

  PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM   SHA-256 of the SIGNING CERT
  PROVISIONING_DEVICE_ADMIN_PACKAGE_CHECKSUM     SHA-256 of the APK file

The second is deprecated and, worse, ties the QR to one exact build - reprint it
on every release or provisioning breaks. The certificate checksum is stable for
the life of the signing key, so one printed QR keeps working across releases,
which is the entire point of using it.

Base64 is URL-SAFE and the padding is stripped. Standard base64 puts `+` and `/`
in the string; both survive a QR fine and then get mangled the moment anyone
pastes the payload through anything URL-shaped. Android accepts either, so the
safe encoding costs nothing.

WHY THIS MIGHT NOT WORK, stated so nobody rediscovers it: Google gates
enterprise provisioning behind a Play Protect allowlist of approved DPCs, and an
unapproved one can fail with "App blocked to protect your device". Reports
indicate the check behaves like a harmful-app heuristic rather than a strict
list - devices sometimes offer a "continue", and developers have cleared it by
dropping permissions that read as dangerous. This agent asks for four:
RECEIVE_BOOT_COMPLETED, SET_WALLPAPER, INTERNET, BIND_DEVICE_ADMIN. No SMS, no
notification listener, no accessibility. That is a clean profile, and whether it
clears the heuristic is an EMPIRICAL question - one wipe of a device that
carries nothing answers it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import zipfile

from cryptography.hazmat.primitives.serialization import pkcs7

# The extras Android reads out of a provisioning QR. Named rather than inlined:
# a typo in one of these is not a validation error, it is a field the platform
# silently ignores, and the failure surfaces as a device that provisions into
# the wrong state.
COMPONENT = "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME"
DOWNLOAD = "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION"
SIGNATURE_CHECKSUM = "android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM"
SKIP_ENCRYPTION = "android.app.extra.PROVISIONING_SKIP_ENCRYPTION"
LEAVE_SYSTEM_APPS = "android.app.extra.PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED"
WIFI_SSID = "android.app.extra.PROVISIONING_WIFI_SSID"
WIFI_PASSWORD = "android.app.extra.PROVISIONING_WIFI_PASSWORD"  # noqa: S105 - an Android extra KEY name, not a password
WIFI_SECURITY = "android.app.extra.PROVISIONING_WIFI_SECURITY_TYPE"
ADMIN_EXTRAS = "android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE"

# What muster itself puts INSIDE the admin extras bundle. These two are not
# Android's names, they are ours - the platform hands the bundle to the DPC
# verbatim and never looks inside it - so they are an interface with the agent
# and with nothing else. `ProvisioningPolicy` in the agent mirrors both, and a
# rename on one side is a device that provisions healthy and then knows nothing.
EXTRA_SERVER_URL = "muster.server_url"
EXTRA_PAIRING_CODE = "muster.pairing_code"  # noqa: S105 - a bundle KEY name, not a code

# The agent's admin component. Mirrors provision.py's ADMIN_COMPONENT and the
# manifest; a mismatch provisions a device into a state where nothing owns it.
ADMIN_COMPONENT_DEFAULT = "app.muster.agent/.MusterDeviceAdminReceiver"


class NotSigned(Exception):
    """The APK carries no signing certificate this can read."""


def signing_certificate_der(apk_path: str | pathlib.Path) -> bytes:
    """The DER of the certificate an APK was signed with.

    Read out of the v1 (JAR) signature block in META-INF. An APK signed ONLY
    with v2/v3 has no such block, and this raises rather than guessing - a
    checksum computed from the wrong thing produces a QR that fails on the
    handset with no diagnosis, which is the worst place to find out.
    """
    with zipfile.ZipFile(apk_path) as apk:
        blocks = [
            n for n in apk.namelist()
            if n.upper().startswith("META-INF/")
            and n.upper().endswith((".RSA", ".DSA", ".EC"))
        ]
        if not blocks:
            raise NotSigned(
                f"{apk_path} has no META-INF signature block: it is unsigned, or "
                "signed only with v2/v3, which this cannot read"
            )
        certificates = pkcs7.load_der_pkcs7_certificates(apk.read(blocks[0]))
    if not certificates:
        raise NotSigned(f"{apk_path}'s signature block contains no certificate")
    from cryptography.hazmat.primitives.serialization import Encoding

    return certificates[0].public_bytes(Encoding.DER)


def signature_checksum(apk_path: str | pathlib.Path) -> str:
    """The value Android wants in PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM.

    SHA-256 of the signing certificate, url-safe base64, padding stripped.
    """
    digest = hashlib.sha256(signing_certificate_der(apk_path)).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def payload(
    *,
    component: str,
    download_url: str,
    checksum: str,
    server_url: str = "",
    pairing_code: str = "",
    wifi_ssid: str = "",
    wifi_password: str = "",
    wifi_security: str = "WPA",
    leave_system_apps: bool = True,
) -> dict:
    """The provisioning payload, ready to be encoded as a QR.

    `server_url` rides in the admin extras bundle, which the platform hands to
    the DPC on first run. That is what makes this a no-cable path end to end:
    the device comes up already knowing where to enroll, so nobody types a URL
    on a phone keyboard.

    `pairing_code` rides the same way, and it is what takes the last person off
    the handset: a device that arrives holding one presents itself without
    anybody typing six digits into it. It is OPTIONAL, and a payload without one
    is exactly the payload this function produced before - the device provisions
    and waits to be enrolled by hand. See enroll.Shape for why a code nobody
    types is 192 bits rather than six digits.

    A CODE MAKES THIS PAYLOAD PERISHABLE, which the rest of it is not. The whole
    argument for the certificate checksum above is that one printed QR keeps
    working across releases; a pairing code expires in minutes, so a printed QR
    carrying one is a QR whose hands-free half is always dead. It degrades to
    the typed path rather than failing, but a QR meant to be printed should be
    minted without a code.

    LEAVE_ALL_SYSTEM_APPS_ENABLED defaults true. False strips system apps the
    DPC does not explicitly enable, which on a Pixel means losing the launcher,
    the camera and Settings - a very managed device that nobody can use.
    """
    data: dict = {
        COMPONENT: component,
        DOWNLOAD: download_url,
        SIGNATURE_CHECKSUM: checksum,
        LEAVE_SYSTEM_APPS: leave_system_apps,
        # Encryption is on by default on modern devices and skipping it is
        # ignored there; setting it false is the honest declaration of intent.
        SKIP_ENCRYPTION: False,
    }
    if wifi_ssid:
        # The device has no network before provisioning and needs one to fetch
        # the agent. Without this the operator joins wifi by hand first, which
        # is fine but is a step, and steps are where this goes wrong.
        data[WIFI_SSID] = wifi_ssid
        data[WIFI_SECURITY] = wifi_security
        if wifi_password:
            data[WIFI_PASSWORD] = wifi_password
    # Built as ONE bundle rather than assigned twice. The platform passes
    # whatever sits under ADMIN_EXTRAS through untouched and does not merge, so
    # a second assignment here would silently drop the first key - and the
    # symptom is a phone that provisions healthy and then has an address with no
    # code, or a code with nowhere to send it.
    extras: dict = {}
    if server_url:
        extras[EXTRA_SERVER_URL] = server_url.rstrip("/")
    if pairing_code:
        extras[EXTRA_PAIRING_CODE] = pairing_code
    if extras:
        data[ADMIN_EXTRAS] = extras
    return data


def encode(data: dict) -> str:
    """Compact JSON, which is what the scanner expects."""
    return json.dumps(data, separators=(",", ":"), sort_keys=True)
