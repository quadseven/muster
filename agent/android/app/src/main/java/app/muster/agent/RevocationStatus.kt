package app.muster.agent

/**
 * Whether muster's last authoritative answer says this device is revoked.
 *
 * DURABLE BECAUSE CHECK-INS USUALLY HAPPEN IN THE BACKGROUND. Keeping this only
 * in StatusActivity's last report would mean a periodic check-in learns the
 * truth, logs it, and the screen still says "Managed and current". The status
 * survives process death so the next person holding the phone sees it.
 *
 * ONLY TWO ANSWERS MAY CHANGE IT. An explicit [ConfigurationClient.Fetched.Revoked]
 * sets it; a real configuration clears it after an administrator readmits the
 * device. A timeout, malformed reply, or other refusal preserves the last
 * authoritative answer. Otherwise a transport failure could invent or erase a
 * revocation, making hotel wifi indistinguishable from an administrator's act.
 */
object RevocationStatus {
    fun next(
        current: Boolean,
        fetched: ConfigurationClient.Fetched,
    ): Boolean = when (fetched) {
        is ConfigurationClient.Fetched.Configuration -> false
        is ConfigurationClient.Fetched.Revoked -> true
        is ConfigurationClient.Fetched.NotEnrolled -> current
        is ConfigurationClient.Fetched.Unrecognized -> current
        is ConfigurationClient.Fetched.Unreachable -> current
        is ConfigurationClient.Fetched.Refused -> current
        is ConfigurationClient.Fetched.DeviceCannotAsk -> current
    }
}
