package app.muster.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The per-device wifi policy (muster#195): read the served `wifi` file, decide
 * whether the network needs adding, and never print the passphrase.
 *
 * WHAT THIS DOES NOT COVER. Whether `WifiManager` accepts the configuration a
 * Device Owner hands it, and whether a handset that forgot the network rejoins
 * it, need a handset. WifiSteward makes those calls; this proves the decision
 * it acts on and every string it can log or report.
 */
class WifiPolicyTest {

    private val passphrase = "correct horse battery staple"
    private val served = "ssid relay-net\nsecurity WPA\npassphrase $passphrase\n"

    /** A device in memory: what the steward's platform half would do. */
    private class FakeTarget(
        override val isDeviceOwner: Boolean = true,
        var networks: MutableSet<String> = mutableSetOf(),
        var presenceKnown: Boolean = true,
        var accepts: Boolean = true,
    ) : WifiPolicy.Target {
        val saved = mutableListOf<WifiPolicy.Network>()
        override fun onDevice(ssid: String): Boolean? = if (presenceKnown) ssid in networks else null
        override fun save(network: WifiPolicy.Network): Boolean {
            saved.add(network)
            if (accepts) networks.add(network.ssid)
            return accepts
        }
    }

    private class FakeLedger(var digest: String? = null) : WifiPolicy.Ledger {
        override fun lastApplied(): String? = digest
        override fun record(digest: String) {
            this.digest = digest
        }
    }

    private val logged = mutableListOf<String>()
    private val log: (String) -> Unit = { logged.add(it) }

    // ---- the format, the same as server/muster/policy.py WifiNetwork ----

    @Test
    fun theServedFileIsReadInTheServersFormat() {
        val read = WifiPolicy.parse(served) as WifiPolicy.Parsed
        assertEquals("relay-net", read.network.ssid)
        assertEquals("WPA", read.network.security)
        assertEquals(passphrase, read.network.passphrase)
    }

    @Test
    fun securityDefaultsToWpaAsTheQrDoes() {
        val read = WifiPolicy.parse("ssid relay-net\npassphrase $passphrase") as WifiPolicy.Parsed
        assertEquals("WPA", read.network.security)
    }

    @Test
    fun anOpenNetworkNeedsNoPassphrase() {
        val read = WifiPolicy.parse("# open\nssid cafe\nsecurity NONE\n") as WifiPolicy.Parsed
        assertEquals("NONE", read.network.security)
        assertEquals("", read.network.passphrase)
    }

    @Test
    fun aFileTheServerWouldRefuseIsRefusedHereToo() {
        for (bad in listOf(
            "ssid relay-net\nsecurity WPA",
            "security WPA\npassphrase x",
            "ssid ${"a".repeat(33)}\npassphrase x",
            "ssid relay-net\nsecurity WPA3\npassphrase x",
            "ssid relay-net\nssid other\npassphrase x",
            "ssid relay-net\nhidden yes\npassphrase x",
        )) {
            assertTrue(bad, WifiPolicy.parse(bad) is WifiPolicy.Refused)
        }
    }

    @Test
    fun anAbsentFileIsNotAnEmptyOne() {
        assertEquals(WifiPolicy.Absent, WifiPolicy.parse(null))
        assertTrue(WifiPolicy.parse("") is WifiPolicy.Refused)
    }

    // ---- box 2: adds, changes nothing, leaves alone ----

    @Test
    fun aServedFileAddsTheNetwork() {
        val target = FakeTarget()
        val ledger = FakeLedger()
        val outcome = WifiPolicy.reconcile(served, ledger, target, log)

        assertEquals(listOf("relay-net"), target.saved.map { it.ssid })
        assertEquals(WifiPolicy.Kind.ADD, (outcome.plan as WifiPolicy.Apply).kind)
        assertEquals(true, outcome.saved)
        assertEquals(WifiPolicy.digest(target.saved.single()), ledger.digest)
        assertTrue(outcome.concerns().isEmpty())
    }

    @Test
    fun anIdenticalFileOnTheNextFetchChangesNothing() {
        val target = FakeTarget()
        val ledger = FakeLedger()
        WifiPolicy.reconcile(served, ledger, target, log)
        target.saved.clear()

        val outcome = WifiPolicy.reconcile(served, ledger, target, log)

        assertTrue("an identical file must not touch the platform", target.saved.isEmpty())
        assertTrue(outcome.plan is WifiPolicy.Unchanged)
        assertTrue(outcome.concerns().isEmpty())
    }

    @Test
    fun anAbsentFileLeavesExistingNetworksAlone() {
        val target = FakeTarget(networks = mutableSetOf("home", "relay-net"))
        val ledger = FakeLedger("an earlier digest")

        val outcome = WifiPolicy.reconcile(null, ledger, target, log)

        assertEquals(WifiPolicy.LeaveAlone, outcome.plan)
        assertTrue(target.saved.isEmpty())
        assertEquals(setOf("home", "relay-net"), target.networks)
        assertEquals("an earlier digest", ledger.digest)
        assertTrue(outcome.concerns().isEmpty())
    }

    @Test
    fun aChangedFileUpdatesTheNetwork() {
        val target = FakeTarget()
        val ledger = FakeLedger()
        WifiPolicy.reconcile(served, ledger, target, log)
        val first = ledger.digest

        val outcome = WifiPolicy.reconcile(served.replace(passphrase, "a new one"), ledger, target, log)

        assertEquals(WifiPolicy.Kind.UPDATE, (outcome.plan as WifiPolicy.Apply).kind)
        assertNotEquals(first, ledger.digest)
    }

    @Test
    fun aNetworkTheDeviceForgotIsAddedBackEvenFromAnIdenticalFile() {
        // The point of the ticket: the record says "applied", the device says
        // the network is gone, and the device wins.
        val target = FakeTarget()
        val ledger = FakeLedger()
        WifiPolicy.reconcile(served, ledger, target, log)
        target.networks.clear()
        target.saved.clear()

        val outcome = WifiPolicy.reconcile(served, ledger, target, log)

        assertEquals(WifiPolicy.Kind.ADD, (outcome.plan as WifiPolicy.Apply).kind)
        assertEquals(listOf("relay-net"), target.saved.map { it.ssid })
    }

    @Test
    fun aDeviceThatCannotSayWhatItHoldsIsToldAgain() {
        val target = FakeTarget(presenceKnown = false)
        val ledger = FakeLedger()
        WifiPolicy.reconcile(served, ledger, target, log)
        target.saved.clear()

        val outcome = WifiPolicy.reconcile(served, ledger, target, log)

        assertEquals(WifiPolicy.Kind.REASSERT, (outcome.plan as WifiPolicy.Apply).kind)
        assertEquals(1, target.saved.size)
    }

    @Test
    fun aRefusedSaveIsAConcernAndIsNotRecordedAsApplied() {
        val target = FakeTarget(accepts = false)
        val ledger = FakeLedger()

        val outcome = WifiPolicy.reconcile(served, ledger, target, log)

        assertEquals(false, outcome.saved)
        assertEquals(null, ledger.digest)
        assertEquals(1, outcome.concerns().size)
    }

    @Test
    fun aDeviceThatIsNotOwnerChangesNothingAndSaysSo() {
        val target = FakeTarget(isDeviceOwner = false)
        val outcome = WifiPolicy.reconcile(served, FakeLedger(), target, log)
        assertTrue(target.saved.isEmpty())
        assertEquals(1, outcome.concerns().size)
    }

    @Test
    fun aRefusedFileIsAConcernAndTouchesNothing() {
        val target = FakeTarget()
        val outcome = WifiPolicy.reconcile("ssid relay-net\nsecurity WPA", FakeLedger(), target, log)
        assertTrue(outcome.plan is WifiPolicy.Refused)
        assertTrue(target.saved.isEmpty())
        assertEquals(1, outcome.concerns().size)
    }

    // ---- box 4: no log line or report carries the passphrase ----

    @Test
    fun noLogLineOrReportCarriesThePassphrase() {
        val strings = mutableListOf<String>()
        val scenarios = listOf(
            FakeTarget() to FakeLedger(),
            FakeTarget(accepts = false) to FakeLedger(),
            FakeTarget(isDeviceOwner = false) to FakeLedger(),
            FakeTarget(presenceKnown = false) to FakeLedger(),
        )
        for ((target, ledger) in scenarios) {
            repeat(2) {
                val outcome = WifiPolicy.reconcile(served, ledger, target, log)
                strings += outcome.toString()
                strings += outcome.concerns()
                strings += WifiPolicy.describe(outcome.plan)
                strings += outcome.plan.toString()
            }
        }
        // A file that names the passphrase on a line the parser refuses.
        val refused = WifiPolicy.reconcile("ssid relay-net\nsecret $passphrase", FakeLedger(), FakeTarget(), log)
        strings += refused.toString()
        strings += refused.concerns()
        strings += (WifiPolicy.parse(served) as WifiPolicy.Parsed).network.toString()
        strings += logged
        strings += SyncReport.of(listOf(SyncReport.Step("wifi", refused))).toString()

        assertTrue(logged.isNotEmpty())
        for (s in strings) {
            assertFalse("the passphrase reached: $s", s.contains(passphrase))
            assertFalse("a passphrase fragment reached: $s", s.contains("horse"))
        }
    }

    @Test
    fun theDigestIsNotReportedEither() {
        // A bare sha256 of a short passphrase is an offline guessing oracle,
        // so the record stays on the device and out of every string.
        val target = FakeTarget()
        val ledger = FakeLedger()
        val outcome = WifiPolicy.reconcile(served, ledger, target, log)
        val digest = ledger.digest!!
        for (s in logged + outcome.toString() + outcome.concerns()) {
            assertFalse(s.contains(digest))
        }
    }

    // ---- what the platform is handed ----

    @Test
    fun theSsidAndAPassphraseAreQuotedForTheConfiguration() {
        assertEquals("\"relay-net\"", WifiPolicy.quoted("relay-net"))
    }

    @Test
    fun aHexWepKeyIsHandedOverUnquoted() {
        assertEquals("0123456789", WifiPolicy.wepKey("0123456789"))
        assertEquals("\"abcde\"", WifiPolicy.wepKey("abcde"))
    }
}
