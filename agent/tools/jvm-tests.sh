#!/bin/bash
# Compile and run the agent's JVM unit tests with no Android SDK installed.
#
# WHY THIS EXISTS. The only machine with an Android SDK is the self-hosted
# runner, so without this the feedback loop on a Kotlin change is a push, a
# queue and a CI round trip - minutes, for a typo. Everything here is already on
# the workstation: the Kotlin compiler, JUnit and BouncyCastle come out of the
# Gradle cache that the wrapper populated.
#
# WHAT IT COVERS, AND WHAT IT DOES NOT. Only the sources with no `android.*`
# import - which under the house pattern is where the deciding happens, because
# a `*Policy` object holds the logic and the `*Steward` beside it only makes
# platform calls. Anything touching the platform is CI's job, and a pass here
# is not a claim about CI. A failure here is a real failure.
#
# PROVE IT HAS TEETH before trusting a pass - `--selftest` feeds it a deliberate
# type error and fails if the compiler does not object. A harness that silently
# accepts anything looks exactly like a clean build.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SRC="$ROOT/agent/android/app/src/main/java/app/muster/agent"
TST="$ROOT/agent/android/app/src/test/java/app/muster/agent"
OUT="${TMPDIR:-/tmp}/muster-jvm-tests"

# Found rather than pinned: the cache path carries a content hash that changes
# with every dependency bump, and a stale pin here fails as "file not found" on
# a machine where the jar is present, which reads as a broken workstation.
G="$HOME/.gradle/caches/modules-2/files-2.1"
# `return`, NOT `exit`. An `exit` here would end the command substitution's
# subshell outright, so a `|| fallback` written on the calling line would never
# run and the variable would be assigned an empty string - a missing jar would
# then surface hundreds of lines later as "unresolved reference", naming the
# symbol and never the jar.
jar() {
  local found
  found="$(find "$G/$1" -name "$2-*.jar" ! -name "*-sources.jar" \
    ! -name "*-javadoc.jar" 2>/dev/null | sort -V | tail -1)"
  [ -n "$found" ] || return 1
  echo "$found"
}
# The `||` sits on the ASSIGNMENT, outside the substitution, which is the only
# place it is reached.
need() {
  local found
  found="$(jar "$1" "$2")" || {
    echo "missing jar: $1:$2 - run agent/android/gradlew once to populate the cache" >&2
    exit 1
  }
  echo "$found"
}
KS="$(need org.jetbrains.kotlin kotlin-stdlib)" || exit 1
CP="$(need org.jetbrains.kotlin kotlin-compiler-embeddable)" || exit 1
# The stdlib goes on the COMPILER's classpath as well as the compilation's:
# K2JVMCompiler is itself written in Kotlin, and without it the entry point dies
# on NoClassDefFoundError kotlin/jvm/internal/Intrinsics before reading a single
# source file.
CP="$CP:$KS"
for a in "org.jetbrains.kotlin kotlin-reflect" "org.jetbrains.intellij.deps trove4j" \
         "org.jetbrains.kotlinx kotlinx-coroutines-core-jvm" \
         "org.jetbrains.kotlin kotlin-daemon-embeddable" "org.jetbrains annotations"; do
  extra="$(need $a)" || exit 1
  CP="$CP:$extra"
done
JUNIT="$(need junit junit)" || exit 1
HAM="$(need org.hamcrest hamcrest-core)" || exit 1
# org.json is an Android platform class, so plain-JVM code needs a real
# implementation on the classpath (see AppConfigPolicyTest and friends).
# build.gradle.kts already pulls org.json:json as a testImplementation
# dependency for the identical reason on the Gradle/AGP side, so this is
# resolved from the same Gradle module cache as every other dependency above
# rather than a jar vendored into the repo: org.json's license carries a
# non-standard "shall be used for Good, not Evil" clause that is not
# OSI-approved, and committing the compiled jar as source would redistribute
# it under that license. Resolving it at build time sidesteps that; running
# `agent/android/gradlew` once (same precondition as every `need` call above)
# populates the cache entry.
JSON="$(need org.json json)" || exit 1
# BouncyCastle: a real dependency, and CertificateRequestTest verifies a CSR
# signature with it rather than trusting the bytes it just produced.
BC=""
for a in "org.bouncycastle bcpkix-jdk18on" "org.bouncycastle bcprov-jdk18on" \
         "org.bouncycastle bcutil-jdk18on"; do
  found="$(need $a)" || exit 1
  BC="$BC:$found"
done

# Kotlin 2.x's bundled IntelliJ JavaVersion.parse throws on "26.0.2", so the
# default JDK cannot run the compiler. Named explicitly rather than left to
# JAVA_HOME, because the failure is an IllegalArgumentException with a version
# string and no other context.
JH="${MUSTER_JDK:-/Library/Java/JavaVirtualMachines/jdk-20.jdk/Contents/Home}"
[ -x "$JH/bin/java" ] || { echo "need a JDK 17-21 at $JH (set MUSTER_JDK)" >&2; exit 1; }

rm -rf "$OUT"; mkdir -p "$OUT"

# THE PURE SET, DISCOVERED RATHER THAN LISTED: every main source with no
# `android.*` import. That is the house pattern rather than an accident - the
# decision logic lives in `*Policy` objects and the stewards below them only
# make platform calls - so this covers where the thinking happens. A hand-kept
# list is how a new policy file quietly stops being checked.
PURE=()
while IFS= read -r f; do PURE+=("$f"); done < <(
  grep -L "^import android\." "$SRC"/*.kt | sort)
[ ${#PURE[@]} -gt 0 ] || { echo "no pure sources found under $SRC" >&2; exit 1; }
echo "typechecking ${#PURE[@]} pure sources"

# The matching tests: a test whose subject imports android.* cannot be built
# here, and BootPlanTest reads sources off disk rather than calling them.
TESTS=()
for f in "${PURE[@]}"; do
  t="$TST/$(basename "${f%.kt}")Test.kt"
  [ -f "$t" ] && TESTS+=("$t")
done
[ ${#TESTS[@]} -gt 0 ] || { echo "no matching tests found" >&2; exit 1; }

# A TEST FILE WHOSE SUBJECT IS PURE AND WHICH IS NOT IN THAT LIST HAS BEEN
# SILENTLY SKIPPED, and that is a worse outcome than a compile error: the
# suite goes green and the tests never ran. It happened while writing
# muster#67 - `AppInstallPolicyTest.kt` existed for several minutes before
# `AppInstallPolicy.kt` did, and the harness reported OK the whole time.
#
# Only tests whose subject imports `android.*` are legitimately skipped here;
# CI runs those. Anything else with no source at all is a typo in a filename.
for t in "$TST"/*Test.kt; do
  [ -e "$t" ] || continue
  subject="$SRC/$(basename "${t%Test.kt}").kt"
  for chosen in "${TESTS[@]}"; do
    [ "$chosen" = "$t" ] && continue 2
  done
  if [ ! -f "$subject" ]; then
    echo "::error::$(basename "$t") has no subject at $(basename "$subject") - it is not being run by anything" >&2
    exit 1
  fi
done

echo "running ${#TESTS[@]} test files"
EXTRA=()
if [ "${1:-}" = "--selftest" ]; then
  mkdir -p "$OUT/selftest"
  echo 'package app.muster.agent
object HarnessSelfTest { val n: Int = "deliberately not an Int" }' > "$OUT/selftest/SelfTest.kt"
  EXTRA=("$OUT/selftest")
fi

"$JH/bin/java" -cp "$CP" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
  -nowarn -no-stdlib -no-reflect -jvm-target 17 \
  -cp "$KS:$JUNIT:$HAM:$JSON$BC" -d "$OUT/classes" \
  "${PURE[@]}" "${TESTS[@]}" "${EXTRA[@]+"${EXTRA[@]}"}" > "$OUT/compile.log" 2>&1
rc=$?
grep -v "^warning:" "$OUT/compile.log"

if [ "${1:-}" = "--selftest" ]; then
  # A NON-ZERO EXIT IS NOT ENOUGH, and the first run of this selftest is why:
  # the compiler died on a missing class before reading any source, exited
  # non-zero, and the check reported that the harness had teeth. A harness that
  # passes its own teeth-check by crashing is worse than one with no check.
  # Only a real diagnostic about the deliberate error counts.
  if grep -q "error:.*[Tt]ype mismatch" "$OUT/compile.log"; then
    echo "SELFTEST OK: the compiler ran and rejected a deliberate type error."
    exit 0
  fi
  echo "SELFTEST FAILED: no type-mismatch diagnostic. Do not trust a pass." >&2
  echo "  (exit $rc; see $OUT/compile.log)" >&2
  exit 1
fi
[ "$rc" -eq 0 ] || { echo "COMPILE FAILED ($rc)"; exit 1; }

# Every compiled *Test class, so a test file added without touching this script
# still runs. A hand-kept list is how a test stops being run without anybody
# noticing it stopped.
CLASSES=$(cd "$OUT/classes" && find . -name "*Test.class" ! -name "*\$*" \
  | sed 's|^\./||; s|\.class$||; s|/|.|g' | sort)
[ -n "$CLASSES" ] || { echo "no test classes compiled" >&2; exit 1; }
echo "running: $(echo "$CLASSES" | wc -l | tr -d ' ') test classes"
"$JH/bin/java" -cp "$OUT/classes:$KS:$JUNIT:$HAM:$JSON$BC" org.junit.runner.JUnitCore $CLASSES
