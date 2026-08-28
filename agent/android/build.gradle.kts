// Versions pinned to match quadseven/zippie's companion-android, deliberately.
// Both apps are built by the same self-hosted mac mini runner, and a toolchain
// that differs between them means the runner holds two Gradle distributions and
// two AGP downloads for no benefit - and the first mysterious build failure
// costs more than the pinning ever saves.
plugins {
    id("com.android.application") version "8.11.1" apply false
    id("org.jetbrains.kotlin.android") version "2.1.20" apply false
}
