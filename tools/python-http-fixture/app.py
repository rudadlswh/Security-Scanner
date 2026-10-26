"""Intentionally vulnerable, loopback-only SAST/DAST training fixture.

Python 3.10+, standard library only. All records and credentials are synthetic.
"""

import argparse
import html
import json
import secrets
import sqlite3
import tempfile
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit


LAB_ID = "intentional-security-lab-v1"


def seed(root):
    (root / "public").mkdir()
    (root / "private").mkdir()
    (root / "public" / "hello.txt").write_text("PUBLIC-LAB-FILE", encoding="utf-8")
    (root / "private" / "backup.txt").write_text(
        "PRIVATE-LAB-BACKUP: synthetic data only", encoding="utf-8"
    )
    with closing(sqlite3.connect(root / "lab.sqlite3")) as db:
        db.executescript("""
            CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, visible INTEGER);
            INSERT INTO products VALUES (1, 'Public notebook', 1);
            INSERT INTO products VALUES (2, 'INTERNAL-LAB-PRODUCT', 0);
            CREATE TABLE invoices (id INTEGER PRIMARY KEY, owner TEXT, amount INTEGER);
            INSERT INTO invoices VALUES (1, 'alice', 100);
            INSERT INTO invoices VALUES (2, 'bob', 900);
        """)


class LabServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, root, port=8000):
        self.root = root.resolve()
        seed(self.root)
        # Fixture identities, deliberately available via /lab/sessions.
        # They model already-authenticated callers; they are not a login system.
        self.sessions = {name: secrets.token_urlsafe(24) for name in ("alice", "bob")}
        super().__init__(("127.0.0.1", port), Handler)


class Handler(BaseHTTPRequestHandler):
    server_version = "SecurityTrainingLab/1.0"

    def log_message(self, format, *args):
        # Do not log attack strings or query parameters to the terminal.
        pass

    def send_body(self, status, body, content_type="text/plain", improved=False):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        if improved:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            )
        self.end_headers()
        self.wfile.write(raw)

    def send_json(self, status, value, improved=False):
        self.send_body(status, json.dumps(value), "application/json", improved)

    def do_GET(self):
        port = self.server.server_port
        allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if self.headers.get("Host", "").lower() not in allowed:
            self.send_json(403, {"error": "Use the loopback address"})
            return
        origin = self.headers.get("Origin")
        if origin and origin not in {"http://" + host for host in allowed}:
            self.send_json(403, {"error": "Foreign origins are blocked"})
            return
        if len(self.path) > 8192:
            self.send_json(414, {"error": "Request target too long"})
            return
        try:
            self.dispatch()
        except sqlite3.Error:
            self.send_json(400, {"error": "Invalid SQL input"})
        except (ValueError, OSError):
            self.send_json(400, {"error": "Invalid lab input"})

    def dispatch(self):
        url = urlsplit(self.path)
        params = parse_qs(url.query, keep_blank_values=True)
        value = lambda key, default="": params.get(key, [default])[0]
        improved = url.path.startswith("/safe/")

        if url.path == "/health":
            self.send_json(200, {"lab": LAB_ID})
        elif url.path == "/lab/sessions":
            self.send_json(200, self.server.sessions)
        elif url.path == "/":
            self.index()
        elif url.path in ("/vulnerable/search", "/safe/search"):
            self.search(value("q"), improved)
        elif url.path in ("/vulnerable/reflect", "/safe/reflect"):
            # CWE-79: the vulnerable response embeds attacker-controlled HTML.
            message = html.escape(value("message"), quote=True) if improved else value("message")
            self.send_body(200, f"<!doctype html><meta charset='utf-8'><p>{message}</p>",
                           "text/html", improved)
        elif url.path in ("/vulnerable/invoice", "/safe/invoice"):
            self.invoice(value("id", "1"), improved)
        elif url.path in ("/vulnerable/download", "/safe/download"):
            self.download(value("name", "hello.txt"), improved)
        else:
            self.send_json(404, {"error": "Not found"})

    def search(self, term, improved):
        with closing(sqlite3.connect(self.server.root / "lab.sqlite3")) as db:
            if improved:
                rows = db.execute(
                    "SELECT id, name FROM products WHERE visible = 1 AND name LIKE ?",
                    ("%" + term + "%",),
                ).fetchall()
            else:
                # CWE-89: user input changes SQL syntax and bypasses visibility.
                query = f"SELECT id, name FROM products WHERE visible = 1 AND name LIKE '%{term}%'"
                rows = db.execute(query).fetchall()
        self.send_json(200, [{"id": row[0], "name": row[1]} for row in rows], improved)

    def invoice(self, invoice_id, improved):
        token = self.headers.get("X-Lab-Session", "")
        caller = next((name for name, known in self.server.sessions.items() if token == known), None)
        if caller is None:
            self.send_json(401, {"error": "Supply a fixture X-Lab-Session token"}, improved)
            return
        with closing(sqlite3.connect(self.server.root / "lab.sqlite3")) as db:
            row = db.execute("SELECT id, owner, amount FROM invoices WHERE id = ?",
                             (invoice_id,)).fetchone()
        if row is None:
            self.send_json(404, {"error": "Invoice not found"}, improved)
            return
        # CWE-639 / CWE-862: authentication alone does not authorize this object.
        if improved and row[1] != caller:
            self.send_json(403, {"error": "Invoice belongs to another user"}, improved)
            return
        self.send_json(200, {"id": row[0], "owner": row[1], "amount": row[2]}, improved)

    def download(self, name, improved):
        public = self.server.root / "public"
        target = (public / name).resolve()
        # Containment for the training environment: neither route can read host files.
        # The vulnerable route still crosses the public/private authorization boundary.
        if not target.is_relative_to(self.server.root):
            self.send_json(403, {"error": "Outside the synthetic lab data"}, improved)
            return
        # CWE-22: missing this narrower check exposes ../private/backup.txt.
        if improved and not target.is_relative_to(public):
            self.send_json(403, {"error": "Outside the public directory"}, improved)
            return
        if not target.is_file():
            self.send_json(404, {"error": "File not found"}, improved)
            return
        self.send_body(200, target.read_text(encoding="utf-8"), improved=improved)

    def index(self):
        links = []
        examples = {
            "search": {"q": "notebook"},
            "reflect": {"message": "hello"},
            "invoice": {"id": "1"},
            "download": {"name": "hello.txt"},
        }
        for mode in ("vulnerable", "safe"):
            for route, params in examples.items():
                path = f"/{mode}/{route}"
                href = html.escape(path + "?" + urlencode(params), quote=True)
                links.append(f'<li><a href="{href}">{path}</a></li>')
        forms = "".join(
            f'<form action="/{mode}/{route}" method="get">'
            f'<label>{mode}/{route}: <input name="{field}" value="hello"></label>'
            '<button>Send</button></form>'
            for mode in ("vulnerable", "safe")
            for route, field in (("search", "q"), ("reflect", "message"), ("download", "name"))
        )
        self.send_body(200,
            '<!doctype html><html lang="en"><meta charset="utf-8">'
            '<title>Intentional Security Lab</title><h1>Intentional Security Lab</h1>'
            '<p>Synthetic data. Local training only. The safe routes improve individual flaws; '
            'this server is not a production application.</p>'
            '<p>Invoice tests: obtain fixture tokens from <a href="/lab/sessions">/lab/sessions</a> '
            'and send the X-Lab-Session header. See README.md for attack inputs.</p>'
            '<ul>' + "".join(links) + '</ul>' + forms + '</html>', "text/html")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="security-lab-") as directory:
        with LabServer(Path(directory), args.port) as server:
            print(f"Intentional security lab: http://127.0.0.1:{server.server_port}", flush=True)
            print("Synthetic data resets on restart. Ctrl+C to stop.", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass


if __name__ == "__main__":
    main()
