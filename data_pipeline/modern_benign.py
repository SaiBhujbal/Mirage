"""Modern representative benign traffic generator.

The CSIC-2010 corpus is narrow, 2010-era web-app traffic. A model trained only on it treats
anything modern (JSON APIs, REST paths, SPAs, JWTs, markdown, base64 avatars) as out-of-
distribution and false-positives on it — which is exactly why ML enforcement blocked 100% of the
harness's modern benign. This generates a large, DIVERSE, RANDOMIZED benign corpus across the
shapes real production traffic actually takes, so the model can learn the modern benign manifold.

IMPORTANT (no leakage): this is a TRAINING aid. It is generated with randomized values and is
NOT the frozen harness eval corpus — the harness (held-out) still validates that the model
GENERALIZED to modern benign rather than memorizing specific records.

    from data_pipeline.modern_benign import generate
    records = generate(3000, seed=7)   # list of (method, path, query, body)
"""
from __future__ import annotations

import base64
import random
from typing import List, Tuple

Record = Tuple[str, str, str, str]

_WORDS = ("shoes running blue laptop phone camera desk chair coffee book novel garden tool "
          "wireless bluetooth organic cotton leather steel ceramic guide review price size "
          "color small large medium red green black white today weather news sports music").split()
_NAMES = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy"]
_PATHS = ["/", "/home", "/search", "/products", "/api/v1/users", "/api/v2/orders", "/account",
          "/dashboard", "/blog/post", "/checkout", "/cart", "/profile/settings", "/help/faq",
          "/catalog/items", "/reports/monthly", "/media/upload", "/oauth/callback", "/graphql"]
_CATS = ["books", "electronics", "clothing", "home", "toys", "sports", "beauty", "grocery"]
_SORTS = ["price", "name", "date", "rating", "popularity"]
_DOMAINS = ["example.com", "app.example.com", "google.com", "myapp.io", "shop.example.org"]


def _rand_word(r, n=1):
    return " ".join(r.choice(_WORDS) for _ in range(n))


def _jwt(r):
    def seg(d):
        return base64.urlsafe_b64encode(str(d).encode()).decode().rstrip("=")
    return f"{seg({'alg':'HS256'})}.{seg({'sub':r.randint(1,9999)})}.{''.join(r.choice('abcdef0123456789') for _ in range(20))}"


def _gens(r) -> List[Record]:
    """One randomized benign record from each shape family."""
    out: List[Record] = []
    uid = r.randint(1, 99999)
    # search
    out.append(("GET", "/search", f"q={_rand_word(r, r.randint(1,4))}&sort={r.choice(_SORTS)}&page={r.randint(1,20)}", ""))
    # rest api list w/ filters
    out.append(("GET", r.choice(_PATHS), f"category={r.choice(_CATS)}&limit={r.choice([10,20,50])}&offset={r.randint(0,500)}", ""))
    # id lookup
    out.append(("GET", f"/api/v2/items/{uid}", f"fields=name,price,stock", ""))
    # json post (nested)
    out.append(("POST", "/api/v1/orders", "", '{"user":"%s","items":[{"id":%d,"qty":%d}],"total":%d}'
                % (r.choice(_NAMES), uid, r.randint(1,5), r.randint(10,999))))
    # json login
    out.append(("POST", "/login", "", '{"user":"%s","pass":"%s%d!"}' % (r.choice(_NAMES), _rand_word(r), r.randint(100,999))))
    # form comment
    out.append(("POST", "/comment", "", f"comment={_rand_word(r, r.randint(3,8))}&rating={r.randint(1,5)}"))
    # graphql
    out.append(("POST", "/graphql", "", '{"query":"{ user(id:%d){ name email orders { id total } } }"}' % uid))
    # markdown content
    out.append(("POST", "/blog", "", f"content=# {_rand_word(r,2).title()}\\n\\n{_rand_word(r,10)} and a [link](https://{r.choice(_DOMAINS)}/page)."))
    # date range report
    out.append(("GET", "/reports", f"from=2024-{r.randint(1,12):02d}-01&to=2024-{r.randint(1,12):02d}-28", ""))
    # file path param
    out.append(("GET", "/files", f"path=/home/user/docs/{_rand_word(r)}_{uid}.pdf", ""))
    # callback / redirect url (benign absolute)
    out.append(("GET", "/oauth/callback", f"code={''.join(r.choice('abcdef0123456789') for _ in range(24))}&state={uid}", ""))
    # base64 avatar upload
    blob = base64.b64encode(bytes(r.getrandbits(8) for _ in range(r.randint(20, 60)))).decode()
    out.append(("POST", "/avatar", "", f"image={blob}"))
    # pagination / api key-ish query
    out.append(("GET", "/api/v1/products", f"q={_rand_word(r,2)}&in_stock=true&min_price={r.randint(1,50)}", ""))
    # profile update json
    out.append(("PUT", "/profile", "", '{"name":"%s","bio":"%s","theme":"%s"}'
                % (r.choice(_NAMES).title(), _rand_word(r, 6), r.choice(["dark","light"]))))
    return out


def generate(n: int = 3000, seed: int = 7) -> List[Record]:
    """Generate ~n diverse benign records (randomized values; distinct from the eval corpus)."""
    r = random.Random(seed)
    out: List[Record] = []
    while len(out) < n:
        out.extend(_gens(r))
    return out[:n]


if __name__ == "__main__":
    recs = generate(20, seed=1)
    for m, p, q, b in recs:
        print(f"{m:5s} {p:24s} q={q[:40]!r} b={b[:40]!r}")
