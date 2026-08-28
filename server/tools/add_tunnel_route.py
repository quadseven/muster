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

    uv run --with boto3 python tools/add_tunnel_route.py <hostname> <service-url>

Needs SSM parameters /infra/cloudflare/api_token, /infra/cloudflare/account_id,
and /infra/cloudflare/tunnel_id for this deployment's tunnel.
"""
import json, subprocess, sys, urllib.request

def ssm(name, decrypt=False):
    cmd = ["aws","ssm","get-parameter","--name",name,"--query","Parameter.Value","--output","text"]
    if decrypt: cmd.insert(3,"--with-decryption")
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()

TOKEN = ssm("/infra/cloudflare/api_token", decrypt=True)
ACCT  = ssm("/infra/cloudflare/account_id")
TUN   = ssm("/infra/cloudflare/tunnel_id")
BASE  = f"https://api.cloudflare.com/client/v4/accounts/{ACCT}/cfd_tunnel/{TUN}/configurations"

if len(sys.argv) != 3:
    print(f"usage: {sys.argv[0]} <hostname> <service-url>", file=sys.stderr)
    raise SystemExit(2)
HOSTNAME, SERVICE = sys.argv[1], sys.argv[2]

def call(method, url, body=None):
    req = urllib.request.Request(url, method=method,
        data=json.dumps(body).encode() if body else None,
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.load(r)

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
