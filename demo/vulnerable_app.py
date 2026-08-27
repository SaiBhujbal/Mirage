"""
NovaBank — an intentionally VULNERABLE demo banking/e-commerce app.

Purpose: show real exploitation succeeding with the WAF OFF, and the exact
same attack being blocked with the WAF ON — with a real SQLite backend so
SQL injection actually exfiltrates data (not a mock).

  WAF toggled by env var:  WAF=on  or  WAF=off   (default off)
  Run:  WAF=off python demo/vulnerable_app.py   ->  http://127.0.0.1:8000

Endpoints (deliberately insecure):
  GET  /                         home
  POST /login       (SQLi)       string-concatenated auth query
  GET  /search?q=   (XSS)        reflects q unsanitized
  GET  /download?file=  (LFI)    reads path unsanitized
  GET  /transfer?to=&amt=&note=  (stored/query injection surface)
  GET  /api/user?id=  (SQLi)     numeric-ish concat
  GET  /health

Do NOT deploy this. It is a target dummy.
"""
import os, sqlite3, html, time
from flask import Flask, request, jsonify, Response, g

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from demo.waf_gate import evaluate

WAF_ENABLED = os.environ.get("WAF", "off").lower() in ("on", "1", "true")
DB_PATH = os.path.join(os.path.dirname(__file__), "novabank.db")

app = Flask(__name__)


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = db()
    c = conn.cursor()
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, ssn TEXT, balance INTEGER)")
    c.executemany("INSERT INTO users (username,password,ssn,balance) VALUES (?,?,?,?)", [
        ("john.doe", "hunter2", "512-90-1234", 4200),
        ("jane.smith", "correcthorse", "441-22-8765", 91500),
        ("admin", "S3cr3t_R00t_2026", "000-00-0001", 999999),
    ])
    conn.commit()
    conn.close()


# ---- WAF middleware ---------------------------------------------------------
@app.before_request
def waf_layer():
    g.waf_latency = 0.0
    if not WAF_ENABLED:
        return None
    body = request.get_data(as_text=True) or ""
    d = evaluate(request.method, request.path, request.query_string.decode("utf-8", "ignore"),
                 body, dict(request.headers))
    g.waf_latency = d.latency_ms
    if d.blocked:
        return Response(
            f'{{"error":"Request blocked by WAF","category":"{d.category}",'
            f'"severity":{d.severity},"layer":"{d.layer}"}}',
            status=403, mimetype="application/json",
            headers={"X-WAF": "DECEPTICON", "X-WAF-Block": d.category,
                     "X-WAF-Latency-ms": str(d.latency_ms)})
    return None


@app.after_request
def waf_header(resp):
    resp.headers["X-WAF-Mode"] = "on" if WAF_ENABLED else "off"
    try:
        resp.headers["X-WAF-Latency-ms"] = str(round(g.get("waf_latency", 0.0), 4))
    except Exception:
        pass
    return resp


# ---- Vulnerable endpoints ---------------------------------------------------
@app.route("/")
def home():
    return jsonify({"app": "NovaBank", "waf": "on" if WAF_ENABLED else "off",
                    "endpoints": ["/login", "/search", "/download", "/api/user", "/transfer"]})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or request.form
    user = data.get("username", "")
    pw = data.get("password", "")
    # VULNERABLE: string concatenation
    q = f"SELECT id,username,balance,ssn FROM users WHERE username='{user}' AND password='{pw}'"
    conn = db()
    try:
        rows = conn.execute(q).fetchall()
    except Exception as e:
        conn.close()
        return jsonify({"ok": False, "error": str(e), "query": q}), 200
    conn.close()
    if rows:
        return jsonify({"ok": True, "authenticated": True, "query": q,
                        "accounts": [dict(r) for r in rows]}), 200
    return jsonify({"ok": False, "authenticated": False, "query": q}), 200


@app.route("/api/user")
def api_user():
    uid = request.args.get("id", "0")
    q = f"SELECT id,username,balance FROM users WHERE id={uid}"  # VULNERABLE
    conn = db()
    try:
        rows = conn.execute(q).fetchall()
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e), "query": q}), 200
    conn.close()
    return jsonify({"query": q, "results": [dict(r) for r in rows]}), 200


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULNERABLE: reflects unsanitized -> XSS
    return Response(f"<html><body><h2>Results for: {q}</h2><p>No products found.</p></body></html>",
                    mimetype="text/html")


@app.route("/download")
def download():
    fname = request.args.get("file", "readme.txt")
    # VULNERABLE: path traversal
    try:
        base = os.path.dirname(__file__)
        with open(os.path.join(base, fname), "r", errors="ignore") as f:
            content = f.read()[:2000]
        return Response(content, mimetype="text/plain")
    except Exception as e:
        return jsonify({"error": str(e), "requested": fname}), 200


@app.route("/transfer")
def transfer():
    to = request.args.get("to", "")
    amt = request.args.get("amt", "0")
    note = request.args.get("note", "")
    # reflects note (XSS surface) + shows params
    return Response(f"<html><body>Transfer ${amt} to {to}. Note: {note}</body></html>",
                    mimetype="text/html")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "waf": "on" if WAF_ENABLED else "off"})


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "8000"))
    print(f"[NovaBank] WAF={'ON' if WAF_ENABLED else 'OFF'}  ->  http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, threaded=True)
