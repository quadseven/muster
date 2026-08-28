package app.muster.agent

/**
 * The two answers a DPC must be able to give while a phone is being provisioned.
 *
 * WHY THIS EXISTS, and what it cost to find out. A QR-provisioned device
 * downloaded this agent successfully - 12,606,023 bytes, HTTP 200, logged
 * server-side - and then failed with "Something went wrong" and a Reset button.
 * Nothing was wrong with the download, the checksum or Play Protect. The agent
 * simply could not answer the questions the platform asks during provisioning,
 * because it had no activity for either of them.
 *
 * AOSP `DevicePolicyManager.java` is explicit:
 *
 *   "to support [Android S] and later, admin apps must implement activities
 *    with intent filters for the ACTION_GET_PROVISIONING_MODE and
 *    ACTION_ADMIN_POLICY_COMPLIANCE intent actions ... will cause the
 *    provisioning to fail"
 *
 *   "If provisioning fails, the device is factory reset."
 *
 * That last line is why the failure is expensive and why the decision lives in
 * a plain object with tests around it: getting this wrong does not throw, it
 * wipes a handset and shows a screen that names no cause.
 *
 * Values checked against AOSP core/java/android/app/admin/DevicePolicyManager.java
 * on 2026-08-19.
 */
object ProvisioningPolicy {

    /** `DevicePolicyManager.PROVISIONING_MODE_FULLY_MANAGED_DEVICE`. */
    const val FULLY_MANAGED_DEVICE = 1

    /** `DevicePolicyManager.PROVISIONING_MODE_MANAGED_PROFILE`. */
    const val MANAGED_PROFILE = 2

    /**
     * The key muster puts its address under in the QR's admin extras bundle.
     *
     * Mirrors `ADMIN_EXTRAS` in the server's provisioning.py. Until the policy
     * compliance activity existed, this travelled in every provisioning QR and
     * nothing on the device ever read it - so a QR-provisioned phone came up
     * with no server address and nowhere to enroll.
     */
    const val SERVER_URL_KEY = "muster.server_url"

    /**
     * The key muster puts a PAIRING CODE under in the same bundle.
     *
     * Mirrors `EXTRA_PAIRING_CODE` in the server's provisioning.py, and a server
     * test asserts this file still spells it the same way - a rename on one side
     * is a phone that provisions healthy and then waits to be typed at, with
     * nothing on the handset saying why.
     *
     * OPTIONAL, always. A QR minted to be printed carries no code, because the
     * rest of that payload is stable for the life of the signing key and a code
     * expires in minutes. A device that arrives without one is enrolled by hand,
     * which is exactly what every device did before this key existed.
     */
    const val PAIRING_CODE_KEY = "muster.pairing_code"

    /**
     * How long a pairing code may be. Six digits at the short end, and a scanned
     * one is 24 bytes of url-safe base64 (32 characters) at the other.
     *
     * The ceiling is not a validation nicety. This string is written to a file
     * in device-protected storage and then POSTed by a phone nobody is holding,
     * so an extras bundle carrying a megabyte of junk would otherwise be
     * faithfully stored and faithfully sent. Generous enough that lengthening
     * the server's code does not silently strand a fleet.
     */
    const val MAX_PAIRING_CODE = 256

    sealed interface Mode {
        /** Take the whole device. */
        data class FullyManaged(val reason: String) : Mode
        /** Do not provision at all, and say why. */
        data class Refuse(val why: String) : Mode
    }

    /**
     * Which provisioning mode to ask for, given what the platform offered.
     *
     * MUSTER ONLY DOES FULLY MANAGED, and refusing is the honest answer to
     * anything else. A work profile cannot hold Device Owner, and Device Owner
     * is not a preference here - the wallpaper, the restrictions and the silent
     * installs all require it. Provisioning into a work profile would produce a
     * device that enrolls, reports healthy, and cannot carry out a single
     * policy.
     *
     * An EMPTY list is treated as "fully managed". The extra is only populated
     * when the platform is offering a choice; older flows send nothing at all,
     * and refusing there would break provisioning on exactly the devices that
     * never had a decision to make.
     */
    fun chooseMode(allowed: List<Int>): Mode = when {
        allowed.isEmpty() ->
            Mode.FullyManaged("no choice was offered, which is the single-mode flow")
        FULLY_MANAGED_DEVICE in allowed ->
            Mode.FullyManaged("fully managed was among the offered modes")
        else ->
            Mode.Refuse(
                "the platform offered only $allowed; muster needs Device Owner, " +
                    "which a work profile cannot hold"
            )
    }

    /**
     * The server address out of the admin extras, or null if there is not one.
     *
     * Validated rather than trusted. This string becomes the address a freshly
     * wiped phone enrolls against, written to the same file the enrollment
     * screen reads, so a malformed value is not a display bug - it is a device
     * that either cannot enroll or tries to enroll somewhere unintended.
     *
     * The trailing slash is trimmed because the server states its own base URL
     * without one (`state.base_url.rstrip('/')`), and a device that disagreed
     * would build every path with a doubled separator.
     */
    fun serverUrl(raw: String?): String? {
        val url = raw?.trim().orEmpty()
        if (url.isEmpty()) return null
        val scheme = when {
            url.startsWith("https://") -> "https://"
            // http is accepted for a control plane on a LAN during development.
            // It is not rejected outright because refusing it here would fail a
            // provisioning run for a reason nothing on the phone could explain.
            url.startsWith("http://") -> "http://"
            else -> return null
        }
        if (url.removePrefix(scheme).isBlank()) return null
        return url.trimEnd('/')
    }

    /**
     * The pairing code out of the admin extras, or null if there is not a usable one.
     *
     * Validated rather than trusted, for the same reason `serverUrl` is: this
     * value is written to a file a wiped phone reads at boot and then POSTed
     * without anybody looking at the result. A malformed one is not a display
     * bug, it is a device burning attempts against the server with a string
     * nobody minted - and on the typed path five of those kill every live code.
     *
     * PRINTABLE ASCII WITH NO WHITESPACE, which is what both shapes of code
     * actually are: six digits, or url-safe base64. Refusing the rest is not
     * about the alphabet - it is that a control character or a newline that
     * survives into the POST body produces a refusal the operator cannot read,
     * on a device nobody is holding, with the real cause invisible.
     *
     * Trimmed first, deliberately. `PersistableBundle` values arrive exactly as
     * the QR encoded them and a stray leading space is not something anybody
     * could see in a QR to correct.
     */
    fun pairingCode(raw: String?): String? {
        val code = raw?.trim().orEmpty()
        if (code.isEmpty() || code.length > MAX_PAIRING_CODE) return null
        if (code.any { it.code <= 0x20 || it.code >= 0x7F }) return null
        return code
    }
}
