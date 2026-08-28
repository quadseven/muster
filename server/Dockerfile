# muster's control plane.
#
# WHY A REAL IMAGE, when zippie-home ships its Python in a ConfigMap: this needs
# fastapi and cryptography, which are not in a stock python image, and a
# container that pip installs at start is one that fails to come up when the
# index is unreachable - on the service every device phones home to.
#
# PINNED BY DIGEST, not by tag. `python:3.12-alpine` is a moving target, and an
# image whose base changes under it cannot have a stable digest of its own.
# Resolved from the registry on 2026-08-19, not typed from memory.
FROM python:3.12-alpine@sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31

WORKDIR /app

# NO `apk add libpq` HERE, AND THAT IS THE FIX RATHER THAN AN OMISSION.
# psycopg[binary] carries its own libpq (musllinux_1_2 wheels exist, which is
# what this got wrong first time round - see server/pyproject.toml). Installing
# alpine's libpq beside it did NOT work: the pure-Python driver finds the
# library with ctypes.util.find_library, which shells out to `ldconfig -p`, and
# musl's ldconfig has no -p. The library was present, the image built clean, and
# `import psycopg` still failed with "libpq library not found".
#
# uv from PyPI rather than a COPY --from of its image: one less base to pin and
# to keep current, for a tool used once at build time.
RUN pip install --no-cache-dir uv==0.5.11

COPY pyproject.toml uv.lock ./
# --frozen: install exactly what the committed lock resolved, never re-resolve.
# A container that resolves at build time is one whose dependencies differ from
# the ones CI tested, discovered in production.
RUN uv sync --frozen --no-dev --no-install-project

COPY muster ./muster

# The agent this server hands to provisioning devices. COPY of a missing path
# FAILS the build, which is the gate: an image published without an APK is a
# server whose provisioning QR sends a freshly wiped phone to a 404.
COPY agent/muster-agent.apk /app/agent/muster-agent.apk
# The versionCode the APK beside it actually carries, read out of that APK by
# the agent build and written by the same step that verified it - so it cannot
# describe a different build. Without this muster can serve an agent and not
# know which one, and a device cannot be told whether it is behind.
COPY agent/agent-version.txt /app/agent/agent-version.txt

ENV PATH="/app/.venv/bin:$PATH"

# Non-root. This process holds the CA private key; there is no reason for it to
# be able to write anywhere it was not explicitly given.
RUN adduser -D -u 10001 muster && chown -R muster:muster /app
USER muster

EXPOSE 8000

# --factory, because app_from_env REFUSES TO START without MUSTER_ADMIN_TOKEN.
# That refusal has to happen at startup, where the pod goes CrashLoopBackOff and
# somebody notices - not at first request, quietly serving an open console.
CMD ["uvicorn", "--factory", "muster.api:app_from_env", "--host", "0.0.0.0", "--port", "8000"]
