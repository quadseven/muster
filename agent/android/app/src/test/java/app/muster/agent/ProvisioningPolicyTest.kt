package app.muster.agent

import app.muster.agent.ProvisioningPolicy.Mode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The answers that decide whether a wiped phone provisions or resets itself.
 *
 * Every case here is one a device cannot be asked to demonstrate cheaply: a
 * wrong answer does not throw, it factory-resets the handset and shows
 * "Something went wrong" with no cause named. That already happened once, which
 * is why the decision is a plain function rather than a line inside an Activity.
 */
class ProvisioningPolicyTest {

    @Test
    fun noOfferedChoiceStillProvisions() {
        // The extra is only populated when the platform offers a choice.
        // Refusing on an empty list would break provisioning on exactly the
        // flows that never had a decision to make.
        val mode = ProvisioningPolicy.chooseMode(emptyList())
        assertTrue(mode is Mode.FullyManaged)
    }

    @Test
    fun fullyManagedIsTakenWhenOffered() {
        assertTrue(ProvisioningPolicy.chooseMode(listOf(1)) is Mode.FullyManaged)
        assertTrue(ProvisioningPolicy.chooseMode(listOf(1, 2)) is Mode.FullyManaged)
    }

    @Test
    fun aWorkProfileOnlyOfferIsRefused() {
        // A work profile cannot hold Device Owner, and Device Owner is not a
        // preference here - the wallpaper, the restrictions and the silent
        // installs all need it. Provisioning into a profile would produce a
        // device that enrolls, looks healthy, and can carry out no policy.
        val mode = ProvisioningPolicy.chooseMode(listOf(ProvisioningPolicy.MANAGED_PROFILE))
        assertTrue(mode is Mode.Refuse)
        assertTrue((mode as Mode.Refuse).why.contains("Device Owner"))
    }

    @Test
    fun theModeConstantsMatchThePlatform() {
        // Checked against AOSP DevicePolicyManager.java on 2026-08-19. These are
        // ints on the wire; a wrong one is not a type error, it is a device
        // provisioned into the wrong shape.
        assertEquals(1, ProvisioningPolicy.FULLY_MANAGED_DEVICE)
        assertEquals(2, ProvisioningPolicy.MANAGED_PROFILE)
    }

    // ---- the server address out of the QR --------------------------------

    @Test
    fun anAbsentServerAddressIsNull() {
        assertNull(ProvisioningPolicy.serverUrl(null))
        assertNull(ProvisioningPolicy.serverUrl(""))
        assertNull(ProvisioningPolicy.serverUrl("   "))
    }

    @Test
    fun aRealAddressSurvivesIntact() {
        assertEquals(
            "https://enroll.muster.example",
            ProvisioningPolicy.serverUrl("https://enroll.muster.example"),
        )
    }

    @Test
    fun surroundingSpaceAndATrailingSlashAreTrimmed() {
        // The server states its own base URL without a trailing slash, so a
        // device that kept one would build every path with a doubled separator.
        assertEquals(
            "https://enroll.muster.example",
            ProvisioningPolicy.serverUrl("  https://enroll.muster.example/  "),
        )
    }

    @Test
    fun aLanAddressOverPlainHttpIsAccepted() {
        // Refused outright, a development control plane would fail provisioning
        // for a reason nothing on the phone could explain.
        assertEquals("http://10.0.0.5:8000", ProvisioningPolicy.serverUrl("http://10.0.0.5:8000"))
    }

    @Test
    fun somethingThatIsNotAnHttpUrlIsRefused() {
        assertNull(ProvisioningPolicy.serverUrl("ftp://enroll.muster.example"))
        assertNull(ProvisioningPolicy.serverUrl("enroll.muster.example"))
        assertNull(ProvisioningPolicy.serverUrl("javascript:alert(1)"))
    }

    @Test
    fun aSchemeWithNothingAfterItIsRefused() {
        // This is the shape a truncated or half-substituted config produces, and
        // it would otherwise be written to the file a wiped phone enrolls from.
        assertNull(ProvisioningPolicy.serverUrl("https://"))
        assertNull(ProvisioningPolicy.serverUrl("https://   "))
    }

    // ---- the pairing code out of the QR ----------------------------------

    @Test
    fun aQrWithNoPairingCodeIsNotAFault() {
        // A QR minted to be PRINTED carries no code on purpose: the rest of that
        // payload is stable for the life of the signing key and a code expires
        // in minutes. Null means "this device is enrolled by hand", which is a
        // supported outcome and not an error.
        assertNull(ProvisioningPolicy.pairingCode(null))
        assertNull(ProvisioningPolicy.pairingCode(""))
        assertNull(ProvisioningPolicy.pairingCode("   "))
    }

    @Test
    fun bothShapesOfCodeSurviveIntact() {
        // Six digits when a person typed it; url-safe base64 when nobody did.
        // See enroll.py: the long one is long precisely because nothing reads it
        // aloud, and truncating it here would be silent.
        assertEquals("482913", ProvisioningPolicy.pairingCode("482913"))
        val scanned = "kM7-xQ2fPl9aB3cD4eF5gH6iJ7kL8mN0oPqRsTuVwXy"
        assertEquals(scanned, ProvisioningPolicy.pairingCode(scanned))
    }

    @Test
    fun surroundingSpaceIsTrimmedFromACode() {
        // PersistableBundle hands back exactly what the QR encoded, and a stray
        // leading space is not something anybody can see in a QR to correct. It
        // would otherwise be POSTed verbatim and refused as an unknown code -
        // on the typed path, that also spends an attempt against every live one.
        assertEquals("482913", ProvisioningPolicy.pairingCode("  482913\n"))
    }

    @Test
    fun aCodeWithWhitespaceOrControlCharactersInsideIsRefused() {
        // Not about the alphabet. A newline or a control character that survives
        // into the POST body produces a refusal nobody can read, on a device
        // nobody is holding, with the real cause invisible from either end.
        assertNull(ProvisioningPolicy.pairingCode("482 913"))
        assertNull(ProvisioningPolicy.pairingCode("4829 13"))
        assertNull(ProvisioningPolicy.pairingCode("48\n2913"))
    }

    @Test
    fun anAbsurdlyLongCodeIsRefusedRatherThanStored() {
        // This string is written to a file in device-protected storage and then
        // POSTed by a phone nobody is holding. Without a ceiling, an extras
        // bundle carrying a megabyte of junk is faithfully kept and faithfully
        // sent, forever, at every boot.
        assertNull(ProvisioningPolicy.pairingCode("x".repeat(ProvisioningPolicy.MAX_PAIRING_CODE + 1)))
        assertEquals(
            ProvisioningPolicy.MAX_PAIRING_CODE,
            ProvisioningPolicy.pairingCode("x".repeat(ProvisioningPolicy.MAX_PAIRING_CODE))?.length,
        )
    }
}
