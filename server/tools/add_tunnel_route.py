"""Add a hostname to a shared Cloudflare tunnel, without losing the others.

THE HAZARD THIS IS SHAPED AROUND. If this tunnel is shared with other
services (it is, in this operator's deployment), its ingress lives in
Cloudflare and the API takes a WHOLE-CONFIG PUT. There is no "add one rule"
call. Get the read-modify-write wrong and every other hostname on the tunnel
comes off the internet at the same instant, from a command that looked like
it was adding something.

So it reads first, refuses if the hostname is already routed, inserts before the
catch-all (Cloudflare matches in order and the catch-all matches everything, so
anything after it is unreachable), and then reads back and asserts that every
rule which existed still does.

    MUSTER_CF_TOKEN_PARAM=<ssm name> MUSTER_CF_ACCOUNT_PARAM=<ssm name> \
    MUSTER_CF_TUNNEL_PARAM=<ssm name> \
    uv run python tools/add_tunnel_route.py <hostname> <service-url>

The three variables name the SSM parameters (in your own account) that hold
the Cloudflare API token, the account id and the tunnel id. The parameter
names are configuration, not code: they are your deployment's, not this
repo's (muster#225).
"""
import json, os, subprocess, sys, urllib.error, urllib.request

PARAMS = ("MUSTER_CF_TOKEN_PARAM", "MUSTER_CF_ACCOUNT_PARAM", "MUSTER_CF_TUNNEL_PARAM")

# Arguments and configuration are checked BEFORE any secret is fetched, so a
# typo never leaves a decrypted token in this process for nothing.
if len(sys.argv) != 3:
    print(f"usage: {sys.argv[0]} <hostname> <service-url>", file=sys.stderr)
    raise SystemExit(2)
missing = [name for name in PARAMS if not os.environ.get(name)]
if missing:
    print("set " + ", ".join(missing) + " to the SSM parameter names", file=sys.stderr)
    raise SystemExit(2)
HOSTNAME, SERVICE = sys.argv[1], sys.argv[2]

def ssm(name, decrypt=False):
    cmd = ["aws","ssm","get-parameter","--name",name,"--query","Parameter.Value","--output","text"]
    if decrypt: cmd.insert(3,"--with-decryption")
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()

TOKEN = ssm(os.environ["MUSTER_CF_TOKEN_PARAM"], decrypt=True)
ACCT  = ssm(os.environ["MUSTER_CF_ACCOUNT_PARAM"])
TUN   = ssm(os.environ["MUSTER_CF_TUNNEL_PARAM"])
BASE  = f"https://api.cloudflare.com/client/v4/accounts/{ACCT}/cfd_tunnel/{TUN}/configurations"

API = "https://api.cloudflare.com/"

def call(method, url, body=None):
    # Only ever the Cloudflare API over https. The account and tunnel ids come
    # from SSM, so refuse anything that would make urlopen reach another
    # scheme or host.
    if not url.startswith(API):
        raise SystemExit(f"refusing to call a URL outside {API}")
    req = urllib.request.Request(url, method=method,  # noqa: S310 - checked above
        data=json.dumps(body).encode() if body else None,
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:  # noqa: S310 - https Cloudflare API only, checked above
            return json.load(r)
    except urllib.error.HTTPError as error:
        # Status only. The body can echo request details, and a traceback
        # would print it.
        print(f"{method} failed: HTTP {error.code}", file=sys.stderr)
        raise SystemExit(1) from None

current = call("GET", BASE)["result"]["config"]
before = list(current.get("ingress", []))

if any(r.get("hostname") == HOSTNAME for r in before):
    print(f"{HOSTNAME} is already routed; nothing to do")
    sys.exit(0)

# Insert BEFORE the catch-all. Cloudflare matches in order and the catch-all
# matches everything, so anything after it is unreachable.
catch_all = [r for r in before if "hostname" not in r]
rules = [r for r in before if "hostname" in r]
new = rules + [{"hostname": HOSTNAME, "service": SERVICE}] + catch_all

current["ingress"] = new
call("PUT", BASE, {"config": current})

after = call("GET", BASE)["result"]["config"]["ingress"]
# Every rule that existed must still exist. A PUT replaces the whole config, so
# a mistake here takes every other service sharing this tunnel off the internet.
missing = [r for r in before if r not in after]
if missing:
    print("LOST RULES:", json.dumps(missing, indent=2)); sys.exit(1)
print(f"ingress rules: {len(before)} -> {len(after)}, none lost")
for r in after:
    print(f"  {r.get('hostname','(catch-all)'):<38} -> {r.get('service')}")
