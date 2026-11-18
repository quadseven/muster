#!/bin/bash
# The sandbox hides the workstation's Gradle cache and blocks Gradle's daemon.
# Stage locked jars in the directory layout the standalone JVM harness reads.
set -euo pipefail

tools="$(cd "$(dirname "$0")" && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/muster-jvm-lane.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
cache="$scratch/caches/modules-2/files-2.1"
central=https://repo.maven.apache.org/maven2
mkdir -p "$cache"

while read -r digest coordinate; do
  if ! [[ "$digest" =~ ^[0-9a-f]{64}$ && "$coordinate" =~ ^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*:[A-Za-z0-9_-]+:[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    echo "invalid JVM dependency lock entry" >&2
    exit 1
  fi
  IFS=: read -r group artifact version <<< "$coordinate"
  jar="$artifact-$version.jar"
  destination="$cache/$group/$artifact/$version/$digest"
  mkdir -p "$destination"
  curl --fail --silent --show-error --retry 2 --max-time 90 \
    -o "$destination/$jar" "$central/${group//.//}/$artifact/$version/$jar"
  (cd "$destination" && printf '%s  %s\n' "$digest" "$jar" | shasum -a 256 -c)
done < "$tools/jvm-dependencies.lock"

cd "$tools/../android/app"
GRADLE_USER_HOME="$scratch" TMPDIR="$scratch" bash "$tools/jvm-tests.sh"
