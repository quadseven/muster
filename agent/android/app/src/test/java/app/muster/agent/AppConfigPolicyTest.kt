package app.muster.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What an app is configured with, what muster refuses to configure, and what
 * never leaves this object.
 *
 * The three that matter most:
 *
 *  - `noValueEverReachesAnythingThatCanBeLogged` - the config file is where a
 *    write token lives, and `BootReceiver` logs the outcome of every boot step.
 *    A data class prints all of its fields unless somebody stops it.
 *  - `aBlankValueIsRefusedRatherThanPushed` - the receiving app cannot tell a
 *    blank value from an absent key, so a blank reads to the operator as
 *    "clear this" and does nothing at all.
 *  - `aKeyDeletedFromTheFileLeavesTheBundle` - the reconcile goes both ways,
 *    and what happens next is the receiving app's business, not muster's.
 */
class AppConfigPolicyTest {

    /** A value shaped like the thing this whole feature exists to deliver. */
    private val token = "zk_live_7f3a91c4e08b46d2a5"

    private fun read(text: String?) = AppConfigPolicy.read(text)

    private fun app(text: String) = read(text).apps.single()

    // ---- reading ---------------------------------------------------------

    @Test
    fun nothingConfiguredAsksForNothing() {
        assertTrue(read(null).apps.isEmpty())
        assertTrue(read("").apps.isEmpty())
        assertTrue(read("  \n\n  ").apps.isEmpty())
        assertTrue(read(null).refused.isEmpty())
    }

    @Test
    fun aStringValueIsCarriedThroughExactly() {
        val configured = app("set app.zippie.companion announceToken $token")
        assertEquals("app.zippie.companion", configured.packageName)
        assertEquals(mapOf("announceToken" to token), configured.values)
    }

    @Test
    fun theKeysAreTheAppsKeysSpeltTheAppsWay() {
        // muster has no vocabulary of its own here and must not invent one:
        // these are read verbatim out of the receiving app's
        // res/xml/app_restrictions.xml, camel case and all. A management plane
        // that normalizes a key configures nothing and reports success.
        val configured = app(
            """
            set app.zippie.companion announceToken   $token
            set app.zippie.companion consoleLanHost  192.168.1.10:8080
            set app.zippie.companion consoleUrl      https://console.example
            set app.zippie.companion homeHost        192.168.1.11
            set app.zippie.companion homePort        51999
            set app.zippie.companion listenPort      51998
            set app.zippie.companion ddClientToken   pub_deadbeef
            set app.zippie.companion ddSite          datadoghq.eu
            set-bool app.zippie.companion autoStartRelay true
            set-bool app.zippie.companion homeScreenMode false
            """.trimIndent()
        )
        assertEquals(
            listOf(
                "announceToken", "consoleLanHost", "consoleUrl", "homeHost",
                "homePort", "listenPort", "ddClientToken", "ddSite",
                "autoStartRelay", "homeScreenMode",
            ),
            configured.values.keys.toList(),
        )
        assertEquals(true, configured.values["autoStartRelay"])
        assertEquals(false, configured.values["homeScreenMode"])
        assertEquals("51999", configured.values["homePort"])
    }

    @Test
    fun aPortStaysAStringRatherThanBeingGuessedIntoANumber() {
        // NOT an inferred type. A token of digits is a string, and an inferred
        // Int would be read by `(managed[key] as? String)` as absent - a
        // credential that silently does not apply, on a device nobody is
        // holding. `set-bool` exists because the receiving contract declares
        // that one key a bool; nothing else is guessed.
        val configured = app("set app.zippie.companion announceToken 8675309")
        assertEquals("8675309", configured.values["announceToken"])
        assertTrue(configured.values["announceToken"] is String)
    }

    @Test
    fun aValueKeepsItsHashRatherThanBeingTruncatedAtOne() {
        // The restrictions file beside this one strips trailing comments. This
        // one must not: a token cut off at a '#' is a device authenticating
        // with something almost right, which looks like a server problem.
        val secret = "abc#def#ghi"
        val configured = app("set app.zippie.companion announceToken $secret")
        assertEquals(secret, configured.values["announceToken"])
    }

    @Test
    fun aWholeLineCommentAndBlankLinesAreIgnored() {
        val configured = app(
            """
            # a LAN-local relay leg

              set app.zippie.companion homeHost 192.168.1.11
            """.trimIndent()
        )
        assertEquals(mapOf("homeHost" to "192.168.1.11"), configured.values)
    }

    @Test
    fun aPermissionIsGrantedToTheAppThatNeedsIt() {
        val configured = app("grant app.zippie.companion android.permission.POST_NOTIFICATIONS")
        assertEquals(listOf("android.permission.POST_NOTIFICATIONS"), configured.grants)
        assertTrue(configured.values.isEmpty())
    }

    @Test
    fun eachAppAppearsOnceWithEverythingItWasGiven() {
        val desired = read(
            """
            set app.zippie.companion homeHost 192.168.1.11
            grant app.zippie.companion android.permission.POST_NOTIFICATIONS
            set app.other.thing theme dark
            set app.zippie.companion homePort 51999
            """.trimIndent()
        )
        assertEquals(
            listOf("app.zippie.companion", "app.other.thing"),
            desired.apps.map { it.packageName },
        )
        val zippie = desired.apps.first()
        assertEquals(listOf("homeHost", "homePort"), zippie.values.keys.toList())
        assertEquals(listOf("android.permission.POST_NOTIFICATIONS"), zippie.grants)
    }

    // ---- refusals --------------------------------------------------------

    @Test
    fun aBlankValueIsRefusedRatherThanPushed() {
        // THE refusal that encodes the receiving contract. A key present and
        // blank means the same as a key absent to the app: it leaves what it
        // has stored alone. So a blank line looks like an instruction to clear
        // a setting and is not one, and pushing it would make muster complicit.
        val desired = read("set app.zippie.companion announceToken")
        assertTrue(desired.apps.isEmpty())
        val why = desired.refused.single().why
        assertTrue(why.contains("blank"))
        assertTrue(why.contains("Delete the line"))
        // And the third word is not named, because on a three-word line it is
        // not provably a key - see aKeyEqualsValueLineNeverShowsItsThirdWord.
        assertFalse(why.contains("announceToken"))
        assertEquals("line 1: set app.zippie.companion", desired.refused.single().line)
    }

    @Test
    fun anUnknownVerbIsRefusedRatherThanSkipped() {
        val desired = read("configure app.zippie.companion announceToken $token")
        assertTrue(desired.apps.isEmpty())
        assertEquals(1, desired.refused.size)
        assertFalse(desired.refused.single().line.contains(token))
    }

    @Test
    fun somethingThatIsNotAPackageNameIsRefused() {
        val desired = read("set zippie announceToken $token")
        assertTrue(desired.apps.isEmpty())
        val refusal = desired.refused.single()
        assertTrue(refusal.why.contains("not a package name"))
        // The bad word is not quoted back. A line whose second column is not a
        // package is a line whose columns are unknown, so the third one is not
        // provably a key name - and the column after that is where tokens go.
        assertFalse(refusal.line.contains("zippie"))
        assertFalse(refusal.why.contains("zippie"))
    }

    @Test
    fun aKeySetTwiceIsRefusedRatherThanSilentlyResolved() {
        // Two lines setting one key means the file disagrees with itself, and
        // whichever one loses is invisible - including to the person who is
        // sure they changed the token.
        val desired = read(
            """
            set app.zippie.companion homeHost 192.168.1.11
            set app.zippie.companion homeHost 192.168.1.12
            """.trimIndent()
        )
        assertEquals(mapOf("homeHost" to "192.168.1.11"), desired.apps.single().values)
        assertTrue(desired.refused.single().why.contains("already set"))
    }

    @Test
    fun aBooleanThatIsNotTrueOrFalseIsRefused() {
        val desired = read("set-bool app.zippie.companion autoStartRelay yes")
        assertTrue(desired.apps.isEmpty())
        assertTrue(desired.refused.single().why.contains("'true' or 'false'"))
    }

    @Test
    fun aGrantWithSomethingExtraOnTheLineIsRefused() {
        val desired = read("grant app.zippie.companion android.permission.CAMERA and.another")
        assertTrue(desired.apps.isEmpty())
        assertEquals(1, desired.refused.size)
    }

    @Test
    fun theSamePermissionTwiceIsAskedForOnce() {
        val configured = app(
            """
            grant app.zippie.companion android.permission.POST_NOTIFICATIONS
            grant app.zippie.companion android.permission.POST_NOTIFICATIONS
            """.trimIndent()
        )
        assertEquals(listOf("android.permission.POST_NOTIFICATIONS"), configured.grants)
    }

    // ---- secrets ---------------------------------------------------------

    @Test
    fun noValueEverReachesAnythingThatCanBeLogged() {
        // THE test. `BootReceiver` logs "boot (ACTION): <name> <outcome>" for
        // every step, and a Kotlin data class prints every field it holds. The
        // toString overrides in AppConfigPolicy are the only thing between a
        // write token and logcat, and they are one careless `data class` away
        // from being deleted as redundant.
        val desired = read(
            """
            set app.zippie.companion announceToken $token
            set app.zippie.companion ddClientToken pub_$token
            set-bool app.zippie.companion autoStartRelay true
            """.trimIndent()
        )
        val plan = AppConfigPolicy.plan(desired, emptyMap(), emptySet())

        for (printed in listOf(desired.toString(), plan.toString(), plan.writes.single().toString())) {
            assertFalse("a value reached a string that is logged: $printed", printed.contains(token))
        }
        // And the key names DO survive, or the log says nothing useful at all.
        assertTrue(plan.toString().contains("announceToken"))
    }

    @Test
    fun aRefusalNamesTheKeyAndNeverTheValue() {
        val desired = read("set-bool app.zippie.companion autoStartRelay $token")
        val refusal = desired.refused.single()
        assertFalse(refusal.line.contains(token))
        assertFalse(refusal.why.contains(token))
        assertTrue(refusal.line.contains("autoStartRelay"))
        assertEquals(
            "line 1: set-bool app.zippie.companion autoStartRelay ${AppConfigPolicy.REDACTED}",
            refusal.line,
        )
    }

    @Test
    fun aKeyEqualsValueLineNeverShowsItsThirdWord() {
        // THE leak this file exists to prevent, and the shape it actually
        // arrives in. `key=value` is what every other config format on earth
        // uses, so it is the most likely thing an operator types here - and on
        // a three-word line the third word is not provably a key. It is either
        // a key with its value missing or a value with its key missing, and
        // nothing can tell which, so it is not quoted at all.
        for (line in listOf(
            "set app.zippie.companion announceToken=$token",
            "set app.zippie.companion announceToken:$token",
            "set app.zippie.companion $token",
        )) {
            val refusal = read(line).refused.single()
            assertFalse("leaked in line: ${refusal.line}", refusal.line.contains(token))
            assertFalse("leaked in why: ${refusal.why}", refusal.why.contains(token))
        }
    }

    @Test
    fun aFourthWordIsWhatMakesTheThirdOneNameable() {
        // With a fourth word the columns are unambiguous, so the key - or on a
        // `grant`, the permission - is named and only the value is withheld.
        // That is the whole rule: position is provable or it is not.
        val named = read(
            """
            set app.zippie.companion homeHost 192.168.1.11
            set app.zippie.companion homeHost 192.168.1.12
            """.trimIndent()
        ).refused.single()
        assertEquals(
            "line 2: set app.zippie.companion homeHost ${AppConfigPolicy.REDACTED}",
            named.line,
        )

        val grant = read("grant app.zippie.companion android.permission.CAMERA extra").refused.single()
        assertTrue(grant.line.contains("android.permission.CAMERA"))
    }

    @Test
    fun aMalformedLineIsNotEchoedBackInCaseItIsABareCredential() {
        // Somebody pastes the token on a line of its own. Refusing it is right;
        // quoting the whole line to explain the refusal is not.
        val desired = read(token)
        assertEquals(1, desired.refused.size)
        assertFalse(desired.refused.single().line.contains(token))
        // Identified by where it is, not by what it says.
        assertEquals("line 1", desired.refused.single().line)
    }

    // ---- planning --------------------------------------------------------

    @Test
    fun anUnconfiguredAppIsGivenEverything() {
        val desired = read(
            """
            set app.zippie.companion homeHost 192.168.1.11
            set-bool app.zippie.companion autoStartRelay true
            """.trimIndent()
        )
        val plan = AppConfigPolicy.plan(desired, emptyMap(), emptySet())
        val write = plan.writes.single()
        assertEquals("app.zippie.companion", write.packageName)
        assertEquals(listOf("homeHost", "autoStartRelay"), write.setKeys)
        assertEquals(mapOf("homeHost" to "192.168.1.11", "autoStartRelay" to true), write.values)
    }

    @Test
    fun reconcilingTwiceChangesNothingTheSecondTime() {
        val desired = read(
            """
            set app.zippie.companion homeHost 192.168.1.11
            set-bool app.zippie.companion autoStartRelay true
            """.trimIndent()
        )
        val plan = AppConfigPolicy.plan(
            desired,
            mapOf(
                "app.zippie.companion" to mapOf(
                    "homeHost" to "192.168.1.11",
                    "autoStartRelay" to true,
                )
            ),
            emptySet(),
        )
        assertTrue(plan.changesNothing)
    }

    @Test
    fun aChangedValueRewritesTheWholeBundle() {
        // setApplicationRestrictions replaces rather than merges, so a write
        // that carried only the changed key would silently drop the rest.
        val desired = read(
            """
            set app.zippie.companion homeHost 192.168.1.12
            set app.zippie.companion homePort 51999
            """.trimIndent()
        )
        val plan = AppConfigPolicy.plan(
            desired,
            mapOf(
                "app.zippie.companion" to mapOf(
                    "homeHost" to "192.168.1.11",
                    "homePort" to "51999",
                )
            ),
            emptySet(),
        )
        val write = plan.writes.single()
        assertEquals(listOf("homeHost"), write.setKeys)
        assertEquals(
            mapOf("homeHost" to "192.168.1.12", "homePort" to "51999"),
            write.values,
        )
    }

    @Test
    fun aKeyDeletedFromTheFileLeavesTheBundle() {
        // Reconciling goes both ways here as it does for restrictions. What
        // the app then does about it is the app's business: under the
        // receiving contract an absent key means "keep what you have stored",
        // so muster stops pushing a value rather than blanking one.
        val desired = read("set app.zippie.companion homeHost 192.168.1.11")
        val plan = AppConfigPolicy.plan(
            desired,
            mapOf(
                "app.zippie.companion" to mapOf(
                    "homeHost" to "192.168.1.11",
                    "announceToken" to token,
                )
            ),
            emptySet(),
        )
        val write = plan.writes.single()
        assertEquals(listOf("announceToken"), write.droppedKeys)
        assertEquals(mapOf("homeHost" to "192.168.1.11"), write.values)
    }

    @Test
    fun anAppNamedOnlyToGrantItAPermissionKeepsItsBundle() {
        // Otherwise a one-line `grant` would write an empty bundle over
        // whatever the app was configured with, which is a configuration wipe
        // dressed up as a permission change.
        val desired = read("grant app.zippie.companion android.permission.POST_NOTIFICATIONS")
        val plan = AppConfigPolicy.plan(
            desired,
            mapOf("app.zippie.companion" to mapOf("announceToken" to token)),
            emptySet(),
        )
        assertTrue(plan.writes.isEmpty())
        assertEquals(
            listOf(AppConfigPolicy.Grant(
                "app.zippie.companion", "android.permission.POST_NOTIFICATIONS"
            )),
            plan.grants,
        )
    }

    @Test
    fun anAppTheFileNoLongerMentionsIsLeftAlone() {
        // The other half of the rule above, and the reason it has to be that
        // way round: an app dropped from the file entirely keeps its bundle,
        // so an app kept in the file for a permission must keep its bundle too.
        // Anything else makes deleting one line more destructive than deleting
        // two.
        val desired = read("set app.zippie.companion homeHost 192.168.1.11")
        val plan = AppConfigPolicy.plan(
            desired,
            mapOf(
                "app.zippie.companion" to mapOf("homeHost" to "192.168.1.11"),
                "app.other.thing" to mapOf("theme" to "dark"),
            ),
            emptySet(),
        )
        assertTrue(plan.changesNothing)
    }

    @Test
    fun aPermissionAlreadyInForceIsNotAskedForAgain() {
        val desired = read("grant app.zippie.companion android.permission.POST_NOTIFICATIONS")
        val plan = AppConfigPolicy.plan(
            desired,
            emptyMap(),
            setOf(
                AppConfigPolicy.Grant(
                    "app.zippie.companion", "android.permission.POST_NOTIFICATIONS"
                )
            ),
        )
        assertTrue(plan.changesNothing)
    }

    @Test
    fun aBundleThatWasClearedOutFromUnderUsIsPutBack() {
        // Every boot re-asserts rather than remembers having asserted. A
        // bundle the platform quietly dropped otherwise reads as applied
        // forever, which is how a phone stays absent from a bond for a week.
        val desired = read("set app.zippie.companion homeHost 192.168.1.11")
        val plan = AppConfigPolicy.plan(desired, mapOf("app.zippie.companion" to emptyMap()), emptySet())
        assertEquals(listOf("homeHost"), plan.writes.single().setKeys)
    }

    @Test
    fun anEmptyFileWithdrawsNothing() {
        // DELIBERATELY NOT SYMMETRIC with the restrictions file beside this
        // one, where an empty file means "withdraw everything muster set". The
        // difference is what withdrawal buys: taking a restriction off changes
        // what a device may do, and taking a bundle off changes nothing an app
        // can observe, because it falls straight back to what it has stored.
        val plan = AppConfigPolicy.plan(
            read(""),
            mapOf("app.zippie.companion" to mapOf("announceToken" to token)),
            emptySet(),
        )
        assertTrue(plan.changesNothing)
    }

    @Test
    fun refusalsSurviveIntoThePlanSoTheyGetLogged() {
        val desired = read("set app.zippie.companion announceToken")
        val plan = AppConfigPolicy.plan(desired, emptyMap(), emptySet())
        assertTrue(plan.changesNothing)
        assertEquals(1, plan.refused.size)
    }

    // ---- battery exemption, reported (muster#79) --------------------------

    @Test
    fun anAppMusterConfiguredButAndroidMayFreezeIsAConcern() {
        // WHY MUSTER REPORTS SOMETHING IT CANNOT CHANGE. There is no public
        // Device Owner API to allowlist an app from battery optimization -
        // checked against android-36's own DevicePolicyManager, which contains
        // nothing matching "exempt". Only the app can ask, with a dialog.
        //
        // But `PowerManager.isIgnoringBatteryOptimizations` is READABLE by
        // anyone, and that is the difference between "the leg went quiet, we
        // think Android froze it" and muster saying so. A zippie leg spent a
        // week in exactly that state: socket bound, nothing servicing it, and
        // the only way to tell was probing the port from the router.
        //
        // "asked" and "granted" are the two states that were indistinguishable.
        // A prompt in the app proves the first. Only this proves the second.
        val decided = AppConfigPolicy.batteryConcerns(
            mapOf("app.zippie.companion" to false)
        )
        assertEquals(1, decided.size)
        assertTrue(decided[0], decided[0].contains("app.zippie.companion"))
        assertTrue(decided[0], decided[0].contains("battery"))
    }

    @Test
    fun anExemptAppIsNotAConcern() {
        assertTrue(
            AppConfigPolicy.batteryConcerns(mapOf("app.zippie.companion" to true)).isEmpty()
        )
    }

    @Test
    fun anAppWhoseExemptionCouldNotBeReadIsNotGuessedAt() {
        // A device that could not answer must not be reported as either exempt
        // or frozen. Silence beats a fabricated state - the whole point is that
        // this line is trusted.
        assertTrue(AppConfigPolicy.batteryConcerns(emptyMap()).isEmpty())
    }

    // ---- waking an app that was just configured (muster#82) ---------------
    //
    // WHY THIS EXISTS. muster installed zippie, configured it, and zippie never
    // started - because a freshly installed app that has never been launched
    // sits in Android's STOPPED state and receives no broadcasts, so its own
    // boot receiver never fires. An MDM-provisioned phone could not begin
    // relaying without a human tapping a button, which is the whole thing this
    // project exists to avoid.
    //
    // An EXPLICIT intent carrying FLAG_INCLUDE_STOPPED_PACKAGES reaches a
    // stopped app and takes it out of that state. The component is named in
    // POLICY rather than guessed, because it is a contract with the other app
    // and a guess would break silently on a rename.

    @Test
    fun aWakeLineNamesAComponentAndAnAction() {
        val read = AppConfigPolicy.read(
            "wake app.zippie.companion app.zippie.companion/.WakeReceiver " +
                "app.zippie.companion.action.WAKE"
        )
        assertEquals(1, read.wakes.size)
        val w = read.wakes[0]
        assertEquals("app.zippie.companion", w.packageName)
        assertEquals("app.zippie.companion/.WakeReceiver", w.component)
        assertEquals("app.zippie.companion.action.WAKE", w.action)
        assertTrue(read.refused.toString(), read.refused.isEmpty())
    }

    @Test
    fun aWakeLineMissingItsActionIsRefused() {
        val read = AppConfigPolicy.read("wake app.zippie.companion app.zippie.companion/.W")
        assertTrue(read.wakes.isEmpty())
        assertEquals(1, read.refused.size)
    }

    @Test
    fun aComponentThatIsNotOneIsRefused() {
        // No slash means no component, and `ComponentName.unflattenFromString`
        // returns null rather than throwing - so an unrefused typo here is a
        // wake that silently never happens.
        val read = AppConfigPolicy.read(
            "wake app.zippie.companion NotAComponent app.zippie.companion.action.WAKE"
        )
        assertTrue(read.wakes.isEmpty())
        assertEquals(1, read.refused.size)
    }

    @Test
    fun aWakeForOneAppCannotNameAnotherAppsComponent() {
        // The package is stated separately from the component so muster can
        // decide WHEN to wake - after configuring THAT package. A line whose
        // component belongs to a different package would wake something the
        // operator did not name.
        val read = AppConfigPolicy.read(
            "wake app.zippie.companion com.example.other/.R app.zippie.companion.action.WAKE"
        )
        assertTrue(read.wakes.isEmpty())
        assertEquals(1, read.refused.size)
    }

    @Test
    fun `a record from an earlier boot attests to nothing`() {
        // THE POINT OF THE STAMP. A reboot stops every app, so "this app has
        // been told" stops being true the moment the device comes back - while
        // the record itself survives in storage. An app that fails to start
        // itself on boot would otherwise never be woken again, because its
        // configuration has not changed and the ledger says it was told.
        val stored = AppConfigPolicy.ledgerValue(bootCount = 41, fingerprint = "abc123")
        assertEquals("abc123", AppConfigPolicy.ledgerFingerprint(stored, bootCount = 41))
        assertNull(
            "a record written before this boot must not count",
            AppConfigPolicy.ledgerFingerprint(stored, bootCount = 42),
        )
    }

    @Test
    fun `both boot broadcasts in one boot do not re-wake`() {
        // The receiver runs for LOCKED_BOOT_COMPLETED and again for
        // BOOT_COMPLETED. Clearing the ledger on each would have woken every
        // managed app twice per boot; a shared boot count means the second pass
        // reads the first pass's record.
        val stored = AppConfigPolicy.ledgerValue(bootCount = 7, fingerprint = "f")
        assertEquals("f", AppConfigPolicy.ledgerFingerprint(stored, bootCount = 7))
    }

    @Test
    fun `a malformed or absent ledger entry attests to nothing`() {
        assertNull(AppConfigPolicy.ledgerFingerprint(null, bootCount = 1))
        assertNull(AppConfigPolicy.ledgerFingerprint("", bootCount = 1))
        assertNull(AppConfigPolicy.ledgerFingerprint("nocolon", bootCount = 1))
        assertNull(AppConfigPolicy.ledgerFingerprint(":abc", bootCount = 1))
        assertNull(AppConfigPolicy.ledgerFingerprint("notanumber:abc", bootCount = 1))
        assertNull("an entry with no fingerprint is not a fingerprint",
            AppConfigPolicy.ledgerFingerprint("1:", bootCount = 1))
    }

    @Test
    fun `a fingerprint containing a colon survives the round trip`() {
        // The value is split on the FIRST colon, so a fingerprint that contains
        // one must come back whole rather than truncated - a truncated
        // fingerprint would never match and the app would be woken forever.
        val fp = "aa:bb:cc"
        assertEquals(fp, AppConfigPolicy.ledgerFingerprint(
            AppConfigPolicy.ledgerValue(3, fp), bootCount = 3))
    }

    @Test
    fun `an installed package that has not been told is woken`() {
        assertTrue(
            AppConfigPolicy.shouldWake(
                AppConfigPolicy.Wake("app.zippie.companion", "app.zippie.companion/.W", "a.WAKE"),
                installed = setOf("app.zippie.companion"),
                wokenFor = null,
                fingerprint = "abc123",
            ),
        )
    }

    @Test
    fun `a package already told about this configuration is left alone`() {
        // NOT ON EVERY CHECK-IN. A wake every fifteen minutes forever is
        // battery spent telling an app something it already knows - the other
        // side debounces, but relying on somebody else's debounce for our own
        // restraint is not a design.
        assertFalse(
            AppConfigPolicy.shouldWake(
                AppConfigPolicy.Wake("app.zippie.companion", "app.zippie.companion/.W", "a.WAKE"),
                installed = setOf("app.zippie.companion"),
                wokenFor = "abc123",
                fingerprint = "abc123",
            ),
        )
    }

    @Test
    fun `a changed configuration wakes a package that was told the old one`() {
        assertTrue(
            AppConfigPolicy.shouldWake(
                AppConfigPolicy.Wake("app.zippie.companion", "app.zippie.companion/.W", "a.WAKE"),
                installed = setOf("app.zippie.companion"),
                wokenFor = "abc123",
                fingerprint = "def456",
            ),
        )
    }

    @Test
    fun `one app's edit does not re-wake a different app`() {
        val wakeA = AppConfigPolicy.Wake("app.a", "app.a/.W", "a.WAKE")
        val wakeB = AppConfigPolicy.Wake("app.b", "app.b/.W", "b.WAKE")
        fun desired(aValue: String) = AppConfigPolicy.Desired(
            apps = listOf(
                AppConfigPolicy.AppConfig("app.a", mapOf("k" to aValue), emptyList()),
                AppConfigPolicy.AppConfig("app.b", mapOf("k" to "unchanged"), emptyList()),
            ),
            refused = emptyList(),
            wakes = listOf(wakeA, wakeB),
        )
        val before = desired("one")
        val after = desired("two")
        assertNotEquals(
            "app.a changed, so its fingerprint must change",
            AppConfigPolicy.fingerprintFor(wakeA, before),
            AppConfigPolicy.fingerprintFor(wakeA, after),
        )
        assertEquals(
            "app.b did not change and must not be re-woken",
            AppConfigPolicy.fingerprintFor(wakeB, before),
            AppConfigPolicy.fingerprintFor(wakeB, after),
        )
    }

    @Test
    fun `two wake targets on one package are tracked apart`() {
        // A PACKAGE-KEYED LEDGER let a send to one component mark the other as
        // told - and in the failure interleaving, a FAILED first wake plus a
        // successful second one records the failed one as delivered, so it is
        // never retried. Distinct fingerprints per target are what make a
        // component-keyed ledger meaningful.
        val relay = AppConfigPolicy.Wake("app.a", "app.a/.Relay", "a.WAKE")
        val config = AppConfigPolicy.Wake("app.a", "app.a/.Config", "a.CONFIG")
        val desired = AppConfigPolicy.Desired(
            apps = listOf(AppConfigPolicy.AppConfig("app.a", mapOf("k" to "v"), emptyList())),
            refused = emptyList(),
            wakes = listOf(relay, config),
        )
        assertNotEquals(
            AppConfigPolicy.fingerprintFor(relay, desired),
            AppConfigPolicy.fingerprintFor(config, desired),
        )
    }

    @Test
    fun `the fingerprint does not move once the configuration is applied`() {
        // DERIVED FROM Desired, NOT Plan. `plan()` is a DELTA - it drops an app
        // whose values already match and filters out grants already in force -
        // so a fingerprint taken from the plan is one value on the pass that
        // writes and another on every steady-state pass after it. That would
        // wake the app every fifteen minutes forever, restarting a working
        // relay to tell it something it already knows.
        val wake = AppConfigPolicy.Wake("app.a", "app.a/.W", "a.WAKE")
        val desired = AppConfigPolicy.Desired(
            apps = listOf(AppConfigPolicy.AppConfig("app.a", mapOf("k" to "v"), listOf("P"))),
            refused = emptyList(),
            wakes = listOf(wake),
        )
        // The pass that writes, and a steady-state pass, see the same Desired.
        assertEquals(
            AppConfigPolicy.fingerprintFor(wake, desired),
            AppConfigPolicy.fingerprintFor(wake, desired),
        )
        // And it is genuinely sensitive to the thing it describes.
        val edited = desired.copy(
            apps = listOf(AppConfigPolicy.AppConfig("app.a", mapOf("k" to "w"), listOf("P"))),
        )
        assertNotEquals(
            AppConfigPolicy.fingerprintFor(wake, desired),
            AppConfigPolicy.fingerprintFor(wake, edited),
        )
    }

    @Test
    fun `values containing the separators cannot collide`() {
        val wake = AppConfigPolicy.Wake("app.a", "app.a/.W", "a.WAKE")
        fun desiredOf(values: Map<String, Any>) = AppConfigPolicy.Desired(
            apps = listOf(AppConfigPolicy.AppConfig("app.a", values, emptyList())),
            refused = emptyList(),
            wakes = listOf(wake),
        )
        assertNotEquals(
            AppConfigPolicy.fingerprintFor(wake, desiredOf(mapOf("x" to "y", "z" to "w"))),
            AppConfigPolicy.fingerprintFor(wake, desiredOf(mapOf("x" to "y,z=w"))),
        )
    }

    @Test
    fun `an install that lands after the wake is retried on the next pass`() {
        // THE REGRESSION THE LEDGER EXISTS FOR. The install step COMMITS a
        // PackageInstaller session and returns; the installation finishes
        // asynchronously. So on the pass that installs an app, the wake can be
        // aimed at a package that does not exist yet - and Android neither
        // queues that broadcast nor reports the miss.
        //
        // Gating on "did this pass change anything" made that permanent: the
        // next pass found the configuration identical and never tried again. A
        // freshly enrolled handset sat exactly there on 2026-08-23 - installed,
        // correctly configured, process alive, relay never started, and nothing
        // that would ever retry.
        val fingerprint = "abc123"
        assertFalse(
            "nothing should be woken while the install is still landing",
            AppConfigPolicy.shouldWake(
                AppConfigPolicy.Wake("app.zippie.companion", "app.zippie.companion/.W", "a.WAKE"), installed = emptySet(), wokenFor = null, fingerprint = fingerprint,
            ),
        )
        // Nothing was sent, so the steward records nothing - which is what lets
        // the next pass try again even though the configuration has NOT changed.
        assertTrue(
            "the same unchanged configuration must wake it once the package exists",
            AppConfigPolicy.shouldWake(
                AppConfigPolicy.Wake("app.zippie.companion", "app.zippie.companion/.W", "a.WAKE"),
                installed = setOf("app.zippie.companion"),
                wokenFor = null,
                fingerprint = fingerprint,
            ),
        )
    }

}
