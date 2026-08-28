plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// The release signing key, taken from the environment and never from the repo.
//
// A keystore checked into the tree is one that leaks with the tree, so the path
// is supplied at build time and a path INSIDE the checkout is refused outright -
// CI writes the decoded keystore outside the workspace for the same reason.
// Bare `File`, not `java.io.File`: in a Gradle Kotlin DSL script `java` in
// expression position resolves to the Java plugin extension and shadows the
// package, so the qualified form fails to compile with "Unresolved reference: io".
val musterKeystoreFile: File? =
    System.getenv("MUSTER_KEYSTORE_PATH")?.takeIf { it.isNotBlank() }?.let { path ->
        val resolved = File(path).canonicalFile
        if (!resolved.isFile) {
            throw GradleException("MUSTER_KEYSTORE_PATH points at $resolved, which is not a file")
        }
        // REFUSE A KEYSTORE INSIDE THE CHECKOUT rather than trusting .gitignore
        // to catch it. A .gitignore entry is one `git add -f` or one renamed
        // file away from being wrong, and a signing key committed once is
        // committed forever. Compared by path COMPONENT (kotlin.io startsWith),
        // not string prefix, so a sibling directory whose name merely begins
        // with the repo's is not mistaken for being inside it.
        if (resolved.startsWith(rootDir.canonicalFile)) {
            throw GradleException(
                "MUSTER_KEYSTORE_PATH is inside the checkout ($resolved). Keep the " +
                    "keystore outside the repository so it cannot be committed."
            )
        }
        resolved
    }

fun requiredEnv(name: String): String =
    System.getenv(name)?.takeIf { it.isNotBlank() }
        ?: throw GradleException(
            "$name is not set, but MUSTER_KEYSTORE_PATH is - the signing secrets " +
                "are half-seeded, which would produce an APK signed by something " +
                "other than what you think."
        )

android {
    namespace = "app.muster.agent"
    compileSdk = 36

    defaultConfig {
        applicationId = "app.muster.agent"
        // 29 to match the zippie companion, which is the app this DPC exists to
        // install. A DPC that could not run on a device the payload supports
        // would be a strange constraint to invent.
        minSdk = 29
        targetSdk = 36
        versionCode = (System.getenv("MUSTER_VERSION_CODE") ?: "1").toInt()
        versionName = "0.1.0" + (System.getenv("MUSTER_VERSION_LABEL")?.let { "-$it" } ?: "")
    }

    // V1 (JAR) SIGNING STAYS ON, alongside v2/v3.
    //
    // minSdk 29 does not need it to install - v2 has been sufficient since 24 -
    // so AGP would happily drop it. It is kept because the PROVISIONING QR needs
    // the SHA-256 of the signing CERTIFICATE, and with v1 that certificate is a
    // PKCS#7 block inside META-INF that any zip reader can pull out. Without it
    // the certificate lives in the APK Signing Block, which needs either
    // apksigner or a hand-rolled binary parser to reach - a tool dependency on
    // the one value that decides whether a phone provisions or fails with
    // "can't set up device" and no explanation.
    signingConfigs {
        getByName("debug") {
            enableV1Signing = true
            enableV2Signing = true
        }
        if (musterKeystoreFile != null) {
            create("release") {
                storeFile = musterKeystoreFile
                storePassword = requiredEnv("MUSTER_KEYSTORE_PASSWORD")
                keyAlias = requiredEnv("MUSTER_KEY_ALIAS")
                keyPassword = requiredEnv("MUSTER_KEY_PASSWORD")
                // V1 PINNED ON, and this is where muster diverges from the
                // zippie companion, which deliberately leaves the choice to
                // apksigner. apksigner picks by minSdk, and at 29 it signs
                // v2/v3 and SKIPS the v1 JAR signature - which for this app
                // would be silent breakage, because the provisioning QR carries
                // the SHA-256 of the signing certificate and muster reads that
                // certificate out of the META-INF PKCS#7 block that only v1
                // produces. Without it the release APK cannot be provisioned at
                // all, and the build would still be green.
                enableV1Signing = true
                enableV2Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (musterKeystoreFile != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }


    packaging {
        resources {
            // The three BouncyCastle jars each carry the same OSGi manifest
            // under META-INF/versions/9, and the Android packager refuses to
            // choose between identical files. Excluded rather than picked with
            // pickFirst: this is build metadata for a module system Android
            // does not use, so dropping it entirely is honest, where
            // pickFirst would silently keep one arbitrary copy of something
            // that might one day differ.
            excludes += setOf(
                "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")

    // PKCS#10 is not in the platform. Android ships an ancient trimmed
    // BouncyCastle under the same package names, so the full artifacts are
    // pulled in explicitly rather than hoped for - the platform copy has no
    // PKCS10CertificationRequestBuilder at all, and the failure is a
    // NoClassDefFoundError at enrollment time on a device.
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")

    // JVM unit tests. The renewal decision and the CSR shape are pure logic and
    // must be provable without a device: the states that matter - expired while
    // in a drawer, clock behind its own certificate - are ones nobody can stage
    // on real hardware on demand.
    testImplementation("junit:junit:4.13.2")
    // org.json is part of Android but is a stub on the JVM - every method
    // throws. Without the real implementation on the test classpath, tests that
    // touch JSON fail with an unhelpful RuntimeException rather than a
    // meaningful assertion.
    testImplementation("org.json:json:20240303")
}

// AN UNSIGNED RELEASE APK IS NOT A FAILURE TO AGP - IT IS AN OUTPUT.
// With no signing config, `assembleRelease` succeeds and writes
// app-release-unsigned.apk, which no phone will install and whose certificate
// muster cannot read. That is a green build producing a thing that cannot be
// used, so make it a red build instead.
//
// The hook is on the packaging tasks rather than at configuration time on
// purpose: a configuration-time throw would break `testDebugUnitTest` too, and
// the unit-test job must keep working with no keystore anywhere near it.
tasks.matching { it.name == "packageRelease" || it.name == "bundleRelease" }.configureEach {
    doFirst {
        if (musterKeystoreFile == null) {
            throw GradleException(
                "release packaging needs a signing key: set MUSTER_KEYSTORE_PATH, " +
                    "MUSTER_KEYSTORE_PASSWORD, MUSTER_KEY_ALIAS and MUSTER_KEY_PASSWORD. " +
                    "docs/signing-ceremony.md has the ceremony for a real key."
            )
        }
    }
}
