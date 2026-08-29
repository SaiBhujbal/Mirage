"""
NovaBank — the demo website the WAF protects (intentionally VULNERABLE, real-looking).

This is the UPSTREAM app. Run it on :8000, then front it with the standalone WAF:
    python demo/novabank.py                      # vulnerable site on :8000 (no WAF)
    UPSTREAM_URL=http://127.0.0.1:8000 WAF_MODE=block python -m waf.server   # WAF on :8080

Browse :8000 directly = unprotected (attacks work). Browse :8080 = through the WAF (blocked).
Real SQLite backend so SQL injection actually exfiltrates data. DO NOT deploy.
"""
import os, sqlite3
from flask import Flask, request, Response, redirect

DB = os.path.join(os.path.dirname(__file__), "novabank.db")
app = Flask(__name__)

CSS = """
:root{--nb:#0b4f8a;--nb2:#0a6cc9;--ink:#12212e;--mut:#5b6b7a;--line:#dce4ec;--bg:#eef3f8;--ok:#1e8e5a}
*{box-sizing:border-box}body{margin:0;font-family:'Segoe UI',system-ui,Arial,sans-serif;color:var(--ink);background:var(--bg)}
a{color:var(--nb2);text-decoration:none}
.top{background:linear-gradient(100deg,var(--nb),var(--nb2));color:#fff;padding:0 24px;display:flex;align-items:center;gap:22px;height:60px}
.top .logo{font-weight:800;font-size:20px;letter-spacing:.5px}.top .logo span{opacity:.85;font-weight:400}
.top nav{display:flex;gap:18px;margin-left:auto;font-size:14px}.top nav a{color:#fff;opacity:.92}
.wrap{max-width:1040px;margin:0 auto;padding:26px 20px 60px}
.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:22px;box-shadow:0 1px 2px rgba(10,40,70,.05)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
h1{font-size:26px;margin:.2em 0}h2{font-size:18px;margin:.1em 0 .6em}.mut{color:var(--mut)}
label{display:block;font-size:13px;color:var(--mut);margin:10px 0 4px}
input,select{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:8px;font-size:14px}
.btn{background:var(--nb2);color:#fff;border:0;border-radius:8px;padding:11px 18px;font-size:15px;cursor:pointer;margin-top:14px}
.hero{background:linear-gradient(120deg,#0b4f8a,#0a6cc9);color:#fff;border-radius:14px;padding:34px;margin-bottom:20px}
.hero h1{font-size:30px}.hero p{opacity:.9;max-width:52ch}
.prod{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:8px}
.prod .p{border:1px solid var(--line);border-radius:10px;padding:14px;background:#fbfdff}
.bal{font-size:34px;font-weight:800;color:var(--nb)}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{padding:9px 8px;border-bottom:1px solid var(--line);text-align:left}
.foot{color:var(--mut);font-size:12px;text-align:center;margin-top:30px}
.badge{display:inline-block;background:#e7f4ee;color:var(--ok);border-radius:20px;padding:3px 10px;font-size:12px}
"""

def page(title, body):
    return Response(f"""<!doctype html><html><head><meta charset="utf-8"><title>{title} · NovaBank</title>
<meta name="viewport" content="width=device-width,initial-scale=1"><style>{CSS}</style></head><body>
<div class="top"><div class="logo">Nova<span>Bank</span></div>
<nav><a href="/">Home</a><a href="/search?q=savings">Products</a><a href="/dashboard">Dashboard</a>
<a href="/transfer">Transfer</a><a href="/login">Sign in</a></nav></div>
<div class="wrap">{body}</div>
<div class="foot">NovaBank demo · not a real bank · intentionally vulnerable target for WAF demonstration</div>
</body></html>""", mimetype="text/html")


def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c


def init_db():
    if os.path.exists(DB): os.remove(DB)
    c = db()
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY,username TEXT,password TEXT,ssn TEXT,balance INTEGER)")
    c.executemany("INSERT INTO users(username,password,ssn,balance) VALUES(?,?,?,?)", [
        ("john.doe","hunter2","512-90-1234",4200),
        ("jane.smith","correcthorse","441-22-8765",91500),
        ("admin","S3cr3t_R00t_2026","000-00-0001",999999)])
    c.commit(); c.close()


@app.route("/")
def home():
    return page("Home", """
    <div class="hero"><h1>Banking that moves with you</h1>
    <p>Open an account in minutes. Send money, track spending, and grow your savings — all in one place.</p></div>
    <div class="grid">
      <div class="card"><h2>Sign in to online banking</h2>
        <form method="post" action="/login">
          <label>Username</label><input name="username" placeholder="john.doe" autocomplete="off">
          <label>Password</label><input name="password" type="password" placeholder="••••••••">
          <button class="btn">Sign in</button></form></div>
      <div class="card"><h2>Featured products</h2>
        <div class="prod">
          <div class="p"><b>High-yield savings</b><div class="mut">4.30% APY</div></div>
          <div class="p"><b>Everyday checking</b><div class="mut">No fees</div></div>
          <div class="p"><b>Travel card</b><div class="mut">3% back</div></div>
        </div><p class="mut" style="margin-top:12px">Search our products above.</p></div>
    </div>""")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return page("Sign in", """<div class="card" style="max-width:420px;margin:auto">
          <h2>Sign in</h2><form method="post" action="/login">
          <label>Username</label><input name="username" autocomplete="off">
          <label>Password</label><input name="password" type="password">
          <button class="btn">Sign in</button></form></div>""")
    u = request.form.get("username", ""); p = request.form.get("password", "")
    q = f"SELECT id,username,balance,ssn FROM users WHERE username='{u}' AND password='{p}'"  # VULNERABLE
    conn = db()
    try:
        rows = conn.execute(q).fetchall()
    except Exception as e:
        conn.close(); return page("Sign in", f'<div class="card"><h2>Login error</h2><p class="mut">{e}</p><pre>{q}</pre></div>')
    conn.close()
    if rows:
        r = rows[0]
        acc = "".join(f"<tr><td>{x['username']}</td><td>${x['balance']:,}</td><td>{x['ssn']}</td></tr>" for x in rows)
        return page("Dashboard", f"""<h1>Welcome back, {r['username']} <span class="badge">signed in</span></h1>
          <div class="grid"><div class="card"><h2>Available balance</h2><div class="bal">${r['balance']:,}</div>
          <p class="mut">Account •••• {r['id']}12</p></div>
          <div class="card"><h2>Accounts returned</h2><table><tr><th>User</th><th>Balance</th><th>SSN</th></tr>{acc}</table></div></div>
          <p class="mut" style="margin-top:10px">query: <code>{q}</code></p>""")
    return page("Sign in", f'<div class="card"><h2>Invalid credentials</h2><p class="mut">Try again.</p><p class="mut">query: <code>{q}</code></p></div>')


@app.route("/dashboard")
def dashboard():
    return page("Dashboard", """<h1>Dashboard</h1><div class="card"><p class="mut">Please
      <a href="/login">sign in</a> to view your accounts.</p></div>""")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULNERABLE: reflects unsanitized -> XSS
    return page("Products", f"""<h1>Search results</h1>
      <div class="card"><p class="mut">You searched for: <b>{q}</b></p>
      <div class="prod"><div class="p"><b>High-yield savings</b><div class="mut">4.30% APY</div></div>
      <div class="p"><b>Everyday checking</b><div class="mut">No fees</div></div></div></div>""")


@app.route("/transfer")
def transfer():
    to = request.args.get("to", ""); amt = request.args.get("amt", ""); note = request.args.get("note", "")
    done = f'<div class="card"><h2>Transfer submitted <span class="badge">ok</span></h2><p>Sent <b>${amt}</b> to <b>{to}</b>.</p><p class="mut">Note: {note}</p></div>' if to else ""
    return page("Transfer", f"""<h1>Send money</h1>{done}
      <div class="card" style="max-width:460px"><form method="get" action="/transfer">
      <label>Recipient</label><input name="to" placeholder="jane.smith">
      <label>Amount</label><input name="amt" placeholder="100">
      <label>Note</label><input name="note" placeholder="rent">
      <button class="btn">Send</button></form></div>""")


@app.route("/account")
def account():
    uid = request.args.get("id", "0")
    q = f"SELECT id,username,balance FROM users WHERE id={uid}"  # VULNERABLE
    conn = db()
    try:
        rows = conn.execute(q).fetchall()
    except Exception as e:
        conn.close(); return page("Account", f'<div class="card"><p class="mut">{e}</p><pre>{q}</pre></div>')
    conn.close()
    body = "".join(f"<tr><td>{r['id']}</td><td>{r['username']}</td><td>${r['balance']:,}</td></tr>" for r in rows)
    return page("Account", f'<h1>Account</h1><div class="card"><table><tr><th>ID</th><th>User</th><th>Balance</th></tr>{body}</table><p class="mut">query: <code>{q}</code></p></div>')


@app.route("/download")
def download():
    fn = request.args.get("file", "statement.txt")
    try:
        with open(os.path.join(os.path.dirname(__file__), fn), "r", errors="ignore") as f:
            return Response(f.read()[:2000], mimetype="text/plain")   # VULNERABLE: path traversal
    except Exception as e:
        return Response(f"error: {e}", mimetype="text/plain")


@app.route("/health")
def health():
    return {"status": "ok", "app": "NovaBank"}


def _refuse_unsafe_start() -> None:
    """
    This app is DELIBERATELY VULNERABLE (SQL injection, XSS, path traversal, over a real
    SQLite backend holding fake PII). It exists to demonstrate what the WAF stops. Running
    it anywhere reachable is a breach, not a demo -- so make that hard to do by accident.

    Two guards, both REFUSING rather than warning:
      1. it binds loopback only; a non-loopback bind must be opted into explicitly
      2. any production-looking environment is refused outright

    Override only for a genuinely isolated lab (a throwaway container or VM, never a shared
    or internet-reachable host):
        NOVABANK_I_UNDERSTAND_THIS_IS_VULNERABLE=yes
    """
    ack = os.environ.get("NOVABANK_I_UNDERSTAND_THIS_IS_VULNERABLE", "").strip().lower()
    acked = ack in ("1", "true", "yes", "on")
    host = os.environ.get("HOST", "127.0.0.1").strip()
    env = os.environ.get("ENV", "").strip().lower()
    loopback = ("127.0.0.1", "localhost", "::1")

    if env in ("prod", "production", "staging") and not acked:
        print("[NovaBank] REFUSING TO START: ENV=" + repr(env))
        print("  This app is intentionally vulnerable and must never run in a deployed")
        print("  environment. It is a demo target for the WAF, not an application.")
        raise SystemExit(2)

    if host not in loopback and not acked:
        print("[NovaBank] REFUSING TO START: HOST=" + repr(host) + " is not loopback.")
        print("  Binding this deliberately vulnerable app to a reachable interface exposes")
        print("  SQL injection, XSS and path traversal to anyone who can route to it.")
        print("  If this really is an isolated lab, set:")
        print("    NOVABANK_I_UNDERSTAND_THIS_IS_VULNERABLE=yes")
        raise SystemExit(2)

    if acked and host not in loopback:
        print("[NovaBank] WARNING: bound to " + host + " with the vulnerability acknowledgement")
        print("  set. Ensure this host is isolated and NOT internet-reachable.")


if __name__ == "__main__":
    _refuse_unsafe_start()
    init_db()
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"[NovaBank] vulnerable demo site -> http://{host}:{port}  (front it with the WAF on :8080)")
    app.run(host=host, port=port, threaded=True)
