#!/usr/bin/env python3
"""
VPS Security Dashboard - Lightweight Web Server
Serves the dashboard HTML and handles refresh requests.
Runs on port 8088 (Tailscale only).
No caching - always serves fresh files.
"""

import http.server
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

PORT = 8088
DASHBOARD_DIR = Path("/opt/security-dashboard")
COLLECTOR_SCRIPT = DASHBOARD_DIR / "scripts" / "collect_data.py"


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DASHBOARD_DIR), **kwargs)

    def end_headers(self):
        # Disable ALL caching so pages always load fresh
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == '/api/refresh':
            self.handle_refresh()
        else:
            self.send_error(404)

    def handle_refresh(self):
        """Run the data collector and return fresh data."""
        try:
            result = subprocess.run(
                ["sudo", "python3", str(COLLECTOR_SCRIPT)],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok"}).encode())
            else:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": result.stderr[:200]}).encode())
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())

    def log_message(self, format, *args):
        if '/api/' in str(args[0]) or '.html' in str(args[0]):
            sys.stderr.write(f"[Dashboard] {args[0]}\n")


if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", PORT), DashboardHandler)
    print(f"Security Dashboard running on http://0.0.0.0:{PORT}")
    print(f"Access via Tailscale: http://YOUR_TAILSCALE_IP:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()
