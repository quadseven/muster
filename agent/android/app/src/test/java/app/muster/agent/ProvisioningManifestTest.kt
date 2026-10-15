package app.muster.agent

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.w3c.dom.Element

/**
 * The manifest must answer both questions the platform asks during provisioning.
 *
 * Losing either activity does not throw anywhere: the phone downloads the agent,
 * shows "Something went wrong" and factory-resets itself. Nothing but reading the
 * manifest can notice, because the activities are only ever started by the
 * system, so this is the test that dies when someone tidies one away.
 */
class ProvisioningManifestTest {

    private val android = "http://schemas.android.com/apk/res/android"
    private val guard = "android.permission.BIND_DEVICE_ADMIN"

    // Gradle runs unit tests with the module directory as the working directory.
    private val manifest = DocumentBuilderFactory.newInstance()
        .apply { isNamespaceAware = true }
        .newDocumentBuilder()
        .parse(File("src/main/AndroidManifest.xml"))
        .documentElement

    private fun activityAnswering(action: String): Element? {
        val activities = manifest.getElementsByTagName("activity")
        return (0 until activities.length)
            .map { activities.item(it) as Element }
            .firstOrNull { activity ->
                val actions = activity.getElementsByTagName("action")
                (0 until actions.length).any {
                    (actions.item(it) as Element).getAttributeNS(android, "name") == action
                }
            }
    }

    private fun assertAnswered(action: String, by: String) {
        val activity = activityAnswering(action)
        assertNotNull("no activity in the manifest answers $action", activity)
        assertEquals(".$by", activity!!.getAttributeNS(android, "name"))
        assertEquals("true", activity.getAttributeNS(android, "exported"))
        assertEquals(guard, activity.getAttributeNS(android, "permission"))
    }

    @Test
    fun theProvisioningModeQuestionIsAnswered() {
        assertAnswered("android.app.action.GET_PROVISIONING_MODE", "ProvisioningModeActivity")
    }

    @Test
    fun thePolicyComplianceQuestionIsAnswered() {
        assertAnswered("android.app.action.ADMIN_POLICY_COMPLIANCE", "PolicyComplianceActivity")
    }

    @Test
    fun noPermissionWasAddedToAnswerThem() {
        val declared = manifest.getElementsByTagName("uses-permission")
        val names = (0 until declared.length)
            .map { (declared.item(it) as Element).getAttributeNS(android, "name") }
            .toSet()
        // Play Protect's heuristic reads this list, and docs/android-constraints.md
        // says a new entry is a decision, not a free change. Extend this set
        // deliberately or not at all.
        assertEquals(
            setOf(
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.SET_WALLPAPER",
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE",
            ),
            names,
        )
    }
}
