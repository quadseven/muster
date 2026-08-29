# Signing in to the console

Written 2026-08-19, when the console stopped being a token box. Updated
2026-08-27: the shared bootstrap token that had survived, demoted, as a
fallback way in has been removed entirely. Administrator sign-in (below) is
now the only way in, and `app_from_env` refuses to start without it.

Before this, the console asked for `MUSTER_ADMIN_TOKEN`, held it in the tab and
forgot it on reload. One shared string, no accounts, no sessions, no sign-out,
and no way to tell who did anything - on the surface that mints pairing codes
and vouches for devices.

Now an administrator signs in at the identity provider the estate already runs,
and muster verifies a signed token. muster never sees a password.

## What is actually deployed, as of 2026-08-21

Wired and live. `/v1/session` reports `sign_in_configured: true` and the boot
line reports one administrator.

**muster has its OWN pool, and the first attempt did not.** It was first
pointed at an existing pool belonging to another application in this
operator's estate, because "log in the same way" was read as "the same
directory". That other application has open self-registration and no MFA, so
that made the identity source for a control plane holding a CA and owning
Device Owner on phones a directory strangers could add themselves to. Nobody
could administer muster without being in `MUSTER_ADMIN_SUBJECTS`, and that
allowlist was the only control there was.

    pool         muster's own, admin-create only, MFA-capable
    app client   a confidential client, authorization-code flow
    hosted UI    a Cognito-hosted sign-in page, muster's own domain
    callback     https://enroll.muster.example/auth/callback
    admins       one Cognito `sub`, in MUSTER_ADMIN_SUBJECTS

**No pool in this operator's estate had a hosted UI until muster needed one.**
The other application signs in with SRP straight from its own front end, so
`MUSTER_OIDC_AUTHORIZE_URL` had nowhere to point - which is why this feature
was built, tested and unreachable for as long as it was.

The pool is declared in a separate identity-management Pulumi project, not
alongside the application it was separated from, and not clicked into a
console. A different project on purpose: declaring muster's identity beside
an unrelated application would mean a `pulumi up` for that application is a
`pulumi up` for the phone fleet's front door.

**ADMINS ARE LISTED BY `sub`, NEVER BY EMAIL.** A subject is stable; an email
address is not - it can be changed by whoever holds the account, so an
allowlist keyed on one is an allowlist that can be joined. The pool has other
real people in it who are deliberately not administrators of muster.

The client secret lives in SSM at `/muster/prod/oidc-client-secret`; the
`muster-oidc` Secret in the cluster is a copy of it, and a cluster is not a
backup. It is created with `--from-literal` and not `--from-file`: a file adds
a trailing newline, the server then expects a secret nobody can produce, and
the failure is a 401 that never explains itself.

Verified end to end at deploy time: `/auth/signin` answers 303 to the hosted
UI's `/oauth2/authorize` endpoint carrying `response_type=code`,
`code_challenge_method=S256` and the right `redirect_uri`; the hosted endpoint
answers that request rather than 404ing.

## What an operator must apply, by hand

Nothing here creates cloud resources. muster reads five URLs and a list of
subjects from its environment; somebody with access to the estate's identity
provider has to produce them. This estate's rule is that infrastructure is IaC,
and none of muster's is yet (`docs/what-is-deployed.md` is the interim record) -
so this is written down rather than automated, and it moves into Pulumi with the
rest.

**1. An application client for muster, in the pool the estate already runs.**
muster is another client of the existing pool, not a second identity story.

    grant                 authorization code, with PKCE
    scopes                openid, email
    callback URL          https://enroll.muster.example/auth/callback
    sign-out URL          https://enroll.muster.example/

The callback URL must match **exactly**, including the scheme and no trailing
slash. muster builds it from `MUSTER_BASE_URL` rather than from the request's
Host header, for the reason that variable exists at all: behind a tunnel the
Host is whatever the proxy says, and a redirect URL taken from a header is one
that anybody who can set a header can aim somewhere else.

A client secret is supported and optional. With one, muster authenticates the
token exchange with it; without one, PKCE alone carries the flow. PKCE is sent
either way.

**2. The four URLs.** All four are in the provider's OIDC discovery document, so
there is no need to type any of them from memory. **If
`authorization_endpoint` is missing from that document, the pool has never had
its browser sign-in surface turned on, and that is the one thing to enable** -
muster sends the browser there, which is the whole reason it never handles a
password.

    curl -s "$ISSUER/.well-known/openid-configuration" | jq '{jwks_uri, authorization_endpoint, token_endpoint, end_session_endpoint}'

They are configured explicitly rather than discovered at boot on purpose. A
service that fetches its own configuration at startup is one that cannot start
when the provider is having a bad morning - on the process that signs
certificates for every device in the estate.

**3. The subjects allowed to administer muster.** The pool is shared with the
estate's other services, so *having an account there* is not *may vouch for
devices*. `MUSTER_ADMIN_SUBJECTS` is the allowlist, and muster refuses to start
with a provider configured and the list empty.

It allows by the token's `sub` claim and never by email. An email address can be
changed, released and registered by somebody else; a subject cannot. To find
yours, sign in once - the refusal page names the exact subject it did not
recognize, which is the string to put in the list.

**4. The environment.** In the cluster these arrive as a secret named
`muster-sign-in`, which `deploy/oke/muster.yaml` already reads as **optional**:
until it exists the pod comes up token-only rather than crash-looping, and
creating it plus a restart is the whole cutover.

    MUSTER_OIDC_ISSUER            what the token's `iss` claim must equal
    MUSTER_OIDC_JWKS_URL          where the signing keys are published
    MUSTER_OIDC_AUTHORIZE_URL     where the browser is sent
    MUSTER_OIDC_TOKEN_URL         where the code is exchanged
    MUSTER_OIDC_CLIENT_ID         the client created above
    MUSTER_OIDC_CLIENT_SECRET     optional
    MUSTER_OIDC_END_SESSION_URL   optional, and worth setting - see below
    MUSTER_ADMIN_SUBJECTS         comma separated `sub` claims

    kubectl -n muster create secret generic muster-sign-in \
      --from-literal=MUSTER_OIDC_ISSUER=... \
      --from-literal=MUSTER_OIDC_JWKS_URL=... \
      --from-literal=MUSTER_OIDC_AUTHORIZE_URL=... \
      --from-literal=MUSTER_OIDC_TOKEN_URL=... \
      --from-literal=MUSTER_OIDC_CLIENT_ID=... \
      --from-literal=MUSTER_ADMIN_SUBJECTS=...
    kubectl -n muster rollout restart deploy/muster

Watch for the trailing newline that `docs/what-is-deployed.md` records against
the admin token: `--from-literal` does not add one, `--from-file` fed by
`print()` does, and a client id with a newline on the end fails an exchange with
a message about the client id being wrong.

**Setting `MUSTER_OIDC_END_SESSION_URL` is worth the extra field.** Without it,
signing out of muster clears muster's own session and leaves the provider's
cookie alone, so the next sign-in is one click and no password. On a shared
machine that is not a sign-out.

## How it works, in the order it happens

    GET  /auth/signin     muster records a flow, puts its `state` in a
                          short-lived cookie, and sends the browser to the
                          provider with `state`, `nonce` and a PKCE challenge
    (the provider does the part with the password in it)
    GET  /auth/callback   muster checks the returned `state` against BOTH the
                          flow it started and that cookie, exchanges the code
                          with the verifier that never left this process,
                          verifies the token, checks the subject against the
                          allowlist, and sets the session cookies
    POST /auth/signout    clears the session cookies and says where to end the
                          session at the provider too

**Both halves of that state check are needed.** The flow store is one dict for
the whole process, so a returned `state` proves that *some* browser started a
sign-in here - not that it was this one. An attacker who starts a sign-in, keeps
the state and hands the operator a link to `/auth/callback` carrying an
authorization code for their own account would otherwise sign the operator in as
themselves, on the console that vouches for devices. The cookie is what makes
the browser that comes back the browser that left.

That cookie is `SameSite=Lax` rather than `Strict` deliberately: the callback is
a top-level GET navigation *from* the provider, which is cross-site, and Strict
withholds cookies on exactly that navigation. Every sign-in would fail with a
message about not having started in this browser.

The session cookies are `HttpOnly`, `Secure` and `SameSite=Lax`. HttpOnly is the
point:
a script on the page cannot read the session, which the old token in a variable
could not claim. SameSite=Lax is also the CSRF control - a browser does not
attach these to a cross-site POST, so a page on another origin cannot make an
administrator vouch for a device. **That holds only while every state-changing
route stays a POST.** A GET that changes something is reachable cross-site with
the cookie attached.

The session token expires in an hour or so; muster renews it in place with the
second cookie rather than bouncing the operator to the provider in the middle of
comparing a fingerprint. Neither cookie carries a lifetime of its own, so both
die with the browser: renewal is there to get somebody through a long afternoon,
not to say a closed browser is still signed in to the service holding the CA.

## What sign-in must never touch

`/v1/enroll/*` and the proof-of-possession endpoints stay reachable by a caller
with no credential at all, and that is not an oversight to tidy up later. **A
device that has not enrolled has nothing to sign in with and no way to be given
it** - that is the problem enrollment exists to solve. Putting a human's session
in front of those paths would brick every enrollment and every renewal in the
estate, and the only symptom would be a 401 on a phone nobody is looking at.

Two things enforce it rather than hoping:

- Authorization is a dependency on each administrator route, not a rule that
  matches paths. It cannot be otherwise: `POST /v1/enroll/requests` is a
  device's way in and `GET /v1/enroll/requests` is the administrator's pending
  list, so no prefix can tell them apart.
- `test_api.py` holds the whole route table and asserts that every route in the
  app is deliberately on one side of it, that every administrator route refuses
  a caller with nothing, and that **no open route ever answers 401**. Add an
  admin dependency to the device path and those tests say so by name.

## What gets recorded

Two pieces of middleware, and the order between them is load-bearing:

    outer   AdministratorMiddleware   works out who is acting
    inner   ActionRecordMiddleware    writes down what they did

The second reads what the first stamped. Swap them and nothing errors: every
record just says `anonymous`, which is a log that looks healthy and answers no
question anybody will ever ask it. That failure is why the order is asserted at
composition time - a reorder crash-loops the pod at startup instead of shipping
a silently worthless audit trail.

Only requests that change something are recorded, and only from a caller with a
name. The console polls the pending list every two seconds; a record per poll
buries the one line that matters.

The record carries the **route template**, never the request path.
`/v1/enroll/requests/{request_id}/vouch` contains a request id, and that id is
all a device needs to collect its certificate - a log stream is the one place a
secret cannot be deleted from afterwards.

## What the page may load

The console carries a `Content-Security-Policy` that starts at `default-src
'none'` and permits one nonced style block, one nonced script and images from
this origin. `docs/observability.md` records why this page in particular takes
no third-party script: it is the administrator's surface on the service that
holds the CA. A promise in a document is not a control, so the header enumerates
what may run and a test asserts the header.
