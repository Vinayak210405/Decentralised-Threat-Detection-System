"""Consortium dashboard.

    python -m dtds.demo          # saves .nodes/demo/snapshot.json
    python -m dtds.dashboard     # then open http://127.0.0.1:8050

For a live view, run `npx hardhat node` in another terminal before the demo.

Live mode reads the running chain (deployments/localhost.json) plus the company
folders in .nodes/demo/. With no chain running it shows the snapshot the demo
saved (.nodes/demo/snapshot.json).

    python -m dtds.dashboard --export dashboard.html    # one self-contained HTML file

The server binds to 127.0.0.1 only: the company views show private data.
"""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Dict

from dtds.dashboard.collect import build_state
from dtds.paths import NODES_DIR, ROOT

STATIC = Path(__file__).resolve().parent / "static" / "index.html"


def make_state_fn(nodes_dir: Path, deployment: Path, snapshot: Path) -> Callable[[], Dict]:
    def state():
        try:
            from dtds.sharing.chain import Registry
            reg = Registry(deployment) if deployment.exists() else None
        except Exception:
            reg = None
        if reg is not None:
            return build_state(reg, nodes_dir)
        if snapshot.exists():
            return build_state(snapshot=json.loads(snapshot.read_text(encoding="utf-8")))
        return build_state(None, nodes_dir)
    return state


def export_html(state: Dict, out: Path) -> Path:
    html = STATIC.read_text(encoding="utf-8")
    # "</" is escaped so no string in the data can close the <script> element.
    blob = json.dumps(state).replace("</", "<\\/")
    html = html.replace("<script>\n", f"<script>\nwindow.__STATE__ = {blob};\n", 1)
    out.write_text(html, encoding="utf-8")
    return out


def make_handler(state_fn: Callable[[], Dict]):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, body: bytes, ctype: str):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                             "connect-src 'self'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                self._send(200, STATIC.read_bytes(), "text/html; charset=utf-8")
            elif path == "/api/state":
                self._send(200, json.dumps(state_fn()).encode(), "application/json")
            else:
                self._send(404, b"not found", "text/plain")

        def do_HEAD(self):
            self.do_GET()

        def log_message(self, *args):
            pass
    return Handler


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8050)
    ap.add_argument("--nodes-dir", type=Path, default=NODES_DIR / "demo")
    ap.add_argument("--deployment", type=Path, default=ROOT / "deployments" / "localhost.json")
    ap.add_argument("--snapshot", type=Path, default=None)
    ap.add_argument("--export", type=Path, default=None, help="write a self-contained HTML file and exit")
    args = ap.parse_args(argv)
    snapshot = args.snapshot or args.nodes_dir / "snapshot.json"
    state_fn = make_state_fn(args.nodes_dir, args.deployment, snapshot)
    if args.export:
        print(f"Wrote {export_html(state_fn(), args.export)}")
        return
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(state_fn))
    print(f"Dashboard on http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
