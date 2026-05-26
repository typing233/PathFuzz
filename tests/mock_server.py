#!/usr/bin/env python3
"""Simple mock server that returns 5xx for certain inputs to test PathFuzz."""
import http.server
import json

class MockHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if "/pets/" in self.path and "AAAA" in self.path:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Internal Server Error"}).encode())
        elif self.path == "/api/v1/pets/":
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "missing pet id"}).encode())
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"data": []}).encode())

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        if body == b"null" or body == b"":
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid body"}).encode())
        else:
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"id": 1}).encode())

    def do_PUT(self):
        self.do_POST()

    def do_DELETE(self):
        if "AAAA" in self.path:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "crash"}).encode())
        else:
            self.send_response(204)
            self.end_headers()

    def do_PATCH(self):
        self.do_POST()

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    server = http.server.HTTPServer(("127.0.0.1", 8080), MockHandler)
    print("Mock server running on http://127.0.0.1:8080")
    server.serve_forever()
