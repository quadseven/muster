"""The fourth audience: public revocation artifacts, on their own hostnames.

Split out of api.py by audience (muster#218). The CRL and the OCSP responder
are Starlette Host routes, so the hostname from MUSTER_CRL_URL /
MUSTER_OCSP_URL decides which surface answers and every other hostname falls
through to the console. `register` inserts them AHEAD of every other route,
which is what lets the intended hostname win over the console's `/`.
"""
from __future__ import annotations

import base64
import urllib.parse
from email.utils import format_datetime
from typing import TYPE_CHECKING

from fastapi import FastAPI, Request, Response
from starlette.routing import Host, Route, Router

from muster import kith as kith_store
from muster import revocation, telemetry

if TYPE_CHECKING:
    from muster.api import State


def _cache_headers(artifact: revocation.Artifact) -> dict[str, str]:
    """Make HTTP freshness end at the signed artifact's nextUpdate.

    THE HEADER AND THE SIGNED TIME ARE ONE CONTRACT. Letting a proxy cache past
    nextUpdate would extend the revocation window beyond the value a relying
    party can see and verify. Making max-age shorter would multiply store reads
    without improving the signed answer. Unsuccessful OCSP responses have no
    nextUpdate and are never cached.

    MEASURED FROM WHEN IT WAS SIGNED, NOT FROM thisUpdate (muster#230).
    thisUpdate is backdated for relying-party clock skew, so a max-age from it
    would let a cache keep the artifact past its signed nextUpdate by exactly
    the backdate.
    """
    if artifact.next_update is None or artifact.produced_at is None:
        return {"Cache-Control": "no-store"}
    max_age = int((artifact.next_update - artifact.produced_at).total_seconds())
    return {
        "Cache-Control": f"public, max-age={max_age}, must-revalidate",
        "Expires": format_datetime(artifact.next_update, usegmt=True),
    }


def register(app: FastAPI, state: State) -> None:
    """The fourth audience: public, unauthenticated, and cacheable.

    HOST ROUTES, NOT ORDINARY PATH ROUTES. All three public names reach one pod
    and both standards conventionally use `/`. Registering plain GET and POST
    handlers there would serve a CRL from the console hostname and make the
    route-audience table unable to say which surface it described. The Host
    route keeps identical paths separate and is inserted ahead of FastAPI's
    console `/` route so the intended hostname wins.
    """
    responder = revocation.Responder(
        state.authority, state.kith, clock=state.kith.now
    )

    async def crl(_request: Request) -> Response:
        try:
            artifact = responder.crl()
        except kith_store.Unreachable as exc:
            # AN EMPTY CRL IS AN AUTHORITATIVE LIE. During a store outage the
            # only safe answer is no artifact, so a cache cannot replace a
            # previously complete list with a freshly signed empty one.
            #
            # THE REASON GOES TO THE LOG, NOT DOWN THE WIRE, and this endpoint
            # is the reason the distinction matters. Every OTHER route that
            # returns `str(unreachable)` in its detail is behind an
            # administrator session or a device proof; this one is open to the
            # internet. `Unreachable` wraps the driver's error, which carries
            # the DSN host, port and database name - so the helpful detail that
            # is right for an operator is internal topology for a stranger.
            telemetry.event(
                "the CRL could not be built", error=str(exc), surface="crl"
            )
            state.telemetry.count("revocation.crl.unreachable")
            return Response(
                content="the revocation list is temporarily unavailable\n",
                status_code=503,
                media_type="text/plain",
                headers={"Cache-Control": "no-store"},
            )
        return Response(
            content=artifact.content,
            media_type="application/pkix-crl",
            headers={
                **_cache_headers(artifact),
                "Content-Disposition": 'attachment; filename="muster.crl"',
            },
        )

    async def ocsp_post(request: Request) -> Response:
        return await _ocsp_response(request, responder, await request.body())

    async def ocsp_get(request: Request) -> Response:
        # RFC 5019 puts the RFC 4648 base64 request in the final path segment.
        # It is percent-decoded before base64, because `/`, `+` and `=` all have
        # meanings in a URL and a client is required to escape them.
        encoded = urllib.parse.unquote(request.path_params["request_b64"])
        try:
            request_der = base64.b64decode(encoded, validate=True)
        except ValueError:
            request_der = b""
        return await _ocsp_response(request, responder, request_der)

    # PLAIN HTTP, REQUIRED, and until 2026-09-01 this check required the
    # opposite. A relying party checking a certificate against these URLs is
    # in the middle of deciding whether to trust this CA; fetching the CRL
    # over TLS would first need a verified certificate for the CRL host,
    # which is the question it was trying to answer. So RFC 5280 clients and
    # the CA/Browser Forum baseline put distribution points and OCSP
    # responders on http, the response is trusted because it is SIGNED by
    # the issuer (revocation.py), not because of the transport, and the
    # verifiers that follow these URIs - OpenSSL, curl, the platform stores -
    # do not follow an https one. An https URL here is therefore not extra
    # safety; it is a revocation check that silently never happens. The pod
    # refuses at startup, where the misconfiguration is one log line, rather
    # than stamping it into certificates that live for ninety days.
    crl_url = urllib.parse.urlsplit(state.authority.crl_url)
    ocsp_url = urllib.parse.urlsplit(state.authority.ocsp_url)
    for label, configured in (("CRL", crl_url), ("OCSP", ocsp_url)):
        if configured.scheme != "http" or not configured.hostname:
            raise ValueError(
                f"{label} URL must be an absolute plain http URL with a "
                f"hostname - relying parties do not fetch revocation data "
                f"over https - got {configured.geturl()!r}"
            )

    crl_router = Router(
        routes=[Route(crl_url.path or "/", crl, methods=["GET"])]
    )
    ocsp_router = Router(
        routes=[
            Route(ocsp_url.path or "/", ocsp_post, methods=["POST"]),
            Route(
                (ocsp_url.path.rstrip("/") or "") + "/{request_b64:path}",
                ocsp_get,
                methods=["GET"],
            ),
        ]
    )
    app.router.routes[0:0] = [
        Host(crl_url.hostname, crl_router, name="public-crl"),
        Host(ocsp_url.hostname, ocsp_router, name="public-ocsp"),
    ]


async def _ocsp_response(
    _request: Request,
    responder: revocation.Responder,
    request_der: bytes,
) -> Response:
    # A normal request is under 100 bytes. The bound is not a parsing policy;
    # it keeps an unauthenticated endpoint from handing an arbitrary body to a
    # DER parser in the process that holds the CA key.
    if len(request_der) > 16 * 1024:
        request_der = b""
    try:
        artifact = responder.ocsp(request_der)
    except kith_store.Unreachable:
        # RFC 6960 has a signed-protocol answer for this exact condition. It is
        # deliberately not cached: the store may recover before the next poll.
        artifact = revocation.try_later()
    return Response(
        content=artifact.content,
        media_type="application/ocsp-response",
        headers=_cache_headers(artifact),
    )
