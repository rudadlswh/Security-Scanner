"""사용자 테스트용 루프백 HTTP/SQLite 예제. 안전/의도적 취약 DELETE를 구분한다.
실제 프로젝트·실제 사용자 데이터와 무관한 메모리 DB만 사용한다. 테스트 목적으로만 실행한다.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sqlite3
import threading

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.execute("create table items (id text primary key, owner text not null)")
LOCK = threading.Lock()
ITEM = "lcr-disposable-001"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def actor(self):
        header = self.headers.get("Authorization", "")
        return {"Bearer fixture-owner": "owner", "Bearer fixture-non-owner": "non_owner", "Bearer fixture-observer": "observer"}.get(header)

    def reply(self, status, body=None):
        raw = json.dumps(body or {}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path != "/test/fixtures/item/state":
            return self.reply(404)
        if self.actor() != "observer":
            return self.reply(403)
        with LOCK:
            exists = DB.execute("select 1 from items where id=?", (ITEM,)).fetchone() is not None
        self.reply(200, {"exists": exists})

    def do_POST(self):
        if self.path != "/test/fixtures/item" or self.actor() != "observer":
            return self.reply(403)
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 4096:
            return self.reply(400)
        try:
            body = json.loads(self.rfile.read(length))
            if body.get("id") != ITEM or body.get("owner") != "owner":
                return self.reply(400)
        except (ValueError, AttributeError):
            return self.reply(400)
        with LOCK:
            DB.execute("insert or replace into items(id,owner) values(?,?)", (ITEM, "owner"))
            DB.commit()
        self.reply(201)

    def do_DELETE(self):
        actor = self.actor()
        if self.path == "/test/fixtures/item":
            if actor != "observer":
                return self.reply(403)
        elif self.path in {"/api/items/" + ITEM, "/api/unsafe/items/" + ITEM}:
            if actor is None:
                return self.reply(401)
            with LOCK:
                row = DB.execute("select owner from items where id=?", (ITEM,)).fetchone()
            if row is None:
                return self.reply(404)
            # The unsafe route intentionally omits this owner check, for the test harness demonstration.
            if not self.path.startswith("/api/unsafe/") and actor != row[0]:
                return self.reply(403)
        else:
            return self.reply(404)
        with LOCK:
            DB.execute("delete from items where id=?", (ITEM,))
            DB.commit()
        self.reply(204)


if __name__ == "__main__":
    print("Disposable HTTP fixture: http://127.0.0.1:18080 (memory SQLite; Ctrl+C to stop)")
    server = ThreadingHTTPServer(("127.0.0.1", 18080), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        DB.close()
