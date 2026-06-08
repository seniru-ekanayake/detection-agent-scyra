import urllib.request
import urllib.error
import json
import subprocess
import os
import sys
import dns.resolver
from datetime import datetime

domain = "testfire.net"
workspace_dir = r"C:\Scybers\Detection Agent"
bin_dir = os.path.join(workspace_dir, "tests", "e2e", "fixtures", "bin")
ground_truth_path = os.path.join(workspace_dir, "tests", "e2e", "fixtures", "ground_truth.json")

# Ensure directories exist
os.makedirs(os.path.dirname(ground_truth_path), exist_ok=True)

# Executables
subfinder_path = os.path.join(bin_dir, "subfinder.exe") if os.path.exists(os.path.join(bin_dir, "subfinder.exe")) else "subfinder"
amass_path = os.path.join(bin_dir, "amass.exe") if os.path.exists(os.path.join(bin_dir, "amass.exe")) else "amass"

print(f"Using subfinder path: {subfinder_path}")
print(f"Using amass path: {amass_path}")

# Helper for HTTP requests
def fetch_json(url):
    req = urllib.request.Request(
        url,
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode('utf-8'))
    except Exception as e:
        print(f"Error fetching JSON from {url}: {e}")
        return []

def fetch_text(url):
    req = urllib.request.Request(
        url,
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode('utf-8')
    except Exception as e:
        print(f"Error fetching text from {url}: {e}")
        return ""

# 1. Query crt.sh
print("Querying crt.sh...")
crtsh_hosts = set()
crtsh_data = fetch_json(f"https://crt.sh/?q=%.{domain}&output=json")
for item in crtsh_data:
    if "name_value" in item and item["name_value"]:
        for line in item["name_value"].split("\n"):
            line = line.strip().lower()
            if line.startswith("*."):
                line = line[2:]
            if line and not line.startswith("*") and not line.startswith("."):
                crtsh_hosts.add(line)

# 2. Run Subfinder
print("Running Subfinder...")
subfinder_hosts = set()
try:
    cmd = [subfinder_path, "-d", domain, "-all", "-silent"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    for line in res.stdout.splitlines():
        line = line.strip().lower()
        if line.startswith("*."):
            line = line[2:]
        if line and not line.startswith("*") and not line.startswith("."):
            subfinder_hosts.add(line)
except Exception as e:
    print(f"Error running subfinder: {e}")

# 3. Run Amass
print("Running Amass...")
amass_hosts = set()
try:
    cmd = [amass_path, "enum", "-passive", "-d", domain]
    # Amass can sometimes take a while, let's run with a reasonable timeout or check
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    for line in res.stdout.splitlines():
        line = line.strip().lower()
        # Parse output: amass can return IP/metadata, but passive enum typically returns hostnames
        parts = line.split()
        if parts:
            host = parts[0].strip().lower()
            if host.startswith("*."):
                host = host[2:]
            if host and not host.startswith("*") and not host.startswith("."):
                amass_hosts.add(host)
except Exception as e:
    print(f"Error running amass: {e}")

# 4. Query HackerTarget
print("Querying HackerTarget...")
hackertarget_hosts = set()
ht_data = fetch_text(f"https://api.hackertarget.com/hostsearch/?q={domain}")
for line in ht_data.splitlines():
    line = line.strip().lower()
    if "," in line:
        parts = line.split(",")
        host = parts[0].strip()
        if host.startswith("*."):
            host = host[2:]
        if host and not host.startswith("*") and not host.startswith("."):
            hackertarget_hosts.add(host)

# 5. Merge, Deduplicate, DNS Resolve
print("Merging and resolving hostnames...")
all_hosts = crtsh_hosts.union(subfinder_hosts).union(amass_hosts).union(hackertarget_hosts)
resolved_hosts = []

resolver = dns.resolver.Resolver()
resolver.timeout = 2.0
resolver.lifetime = 2.0

for host in sorted(all_hosts):
    # Discard any entry containing * or starting with .
    if "*" in host or host.startswith("."):
        continue
    # Keep only hostnames that return at least one A record
    try:
        answers = resolver.resolve(host, 'A')
        if len(answers) > 0:
            resolved_hosts.append(host)
    except Exception:
        # Fails resolution, skip
        pass

# 6. Save Ground Truth
ground_truth = {
    domain: {
        "known_subdomains": resolved_hosts,
        "source": "automated_preflight",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "generation_method": "crtsh+subfinder+amass+hackertarget+dns_verified",
        "counts": {
            "crtsh": len(crtsh_hosts),
            "subfinder": len(subfinder_hosts),
            "amass": len(amass_hosts),
            "hackertarget": len(hackertarget_hosts),
            "after_dedup_and_dns": len(resolved_hosts)
        }
    }
}

with open(ground_truth_path, "w") as f:
    json.dump(ground_truth, f, indent=2)

# 7. Print Console Output
print("---------------------------------")
print("GROUND TRUTH GENERATION COMPLETE")
print(f"Domain:          {domain}")
print(f"crt.sh:          {len(crtsh_hosts)} hostnames")
print(f"Subfinder:       {len(subfinder_hosts)} hostnames")
print(f"Amass:           {len(amass_hosts)} hostnames")
print(f"HackerTarget:    {len(hackertarget_hosts)} hostnames")
print(f"After dedup+DNS: {len(resolved_hosts)} hostnames")
print(f"Saved to: tests/e2e/fixtures/ground_truth.json")
print("---------------------------------")

if len(resolved_hosts) == 0:
    print("Error: after_dedup_and_dns count is zero! Resolve at least one subdomain before proceeding.")
    sys.exit(1)
