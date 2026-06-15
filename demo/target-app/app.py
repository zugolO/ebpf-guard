#!/usr/bin/env python3
"""
Vulnerable web app for ebpf-guard demo testing.
Intentionally insecure — DO NOT deploy in production.
"""

import subprocess
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

PORT = 8080


class VulnerableHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[target-app] {self.address_string()} - {fmt % args}")

    def send_text(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        # /ping?host=<value>  — command injection via ping
        if parsed.path == "/ping":
            host = params.get("host", ["127.0.0.1"])[0]
            try:
                out = subprocess.check_output(f"ping -c 1 {host}", shell=True,
                                              stderr=subprocess.STDOUT, timeout=5)
                self.send_text(200, out.decode(errors="replace"))
            except Exception as e:
                self.send_text(500, str(e))

        # /read?file=<path>   — arbitrary file read
        elif parsed.path == "/read":
            path = params.get("file", ["/etc/hostname"])[0]
            try:
                with open(path) as f:
                    self.send_text(200, f.read())
            except Exception as e:
                self.send_text(403, str(e))

        # /exec?cmd=<command> — direct RCE
        elif parsed.path == "/exec":
            cmd = params.get("cmd", ["id"])[0]
            try:
                out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
                self.send_text(200, out.decode(errors="replace"))
            except Exception as e:
                self.send_text(500, str(e))

        # /env                — dump environment variables
        elif parsed.path == "/env":
            self.send_text(200, "\n".join(f"{k}={v}" for k, v in os.environ.items()))

        elif parsed.path == "/health":
            self.send_text(200, "ok")

        else:
            menu = (
                "=== Vulnerable App (ebpf-guard demo target) ===\n\n"
                "Endpoints:\n"
                "  GET /ping?host=<value>      command injection via ping\n"
                "  GET /read?file=<path>       arbitrary file read\n"
                "  GET /exec?cmd=<command>     direct RCE\n"
                "  GET /env                    dump environment\n"
                "  GET /health                 health check\n"
            )
            self.send_text(200, menu)


if __name__ == "__main__":
    print(f"[target-app] Listening on :{PORT}")
    print("[target-app] WARNING: intentionally vulnerable — for testing only!")
    HTTPServer(("0.0.0.0", PORT), VulnerableHandler).serve_forever()
