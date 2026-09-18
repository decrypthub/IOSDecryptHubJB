#!/usr/bin/env python3
"""IOSDecryptHub 网络抓包矩阵的本地回显服务器 (仅标准库)。

用法:
    python3 tests/net_echo_server.py --port 8099            # 明文 HTTP (+ws 路径)
    python3 tests/net_echo_server.py --port 8099 --ws       # 同时启用最小 WebSocket echo
    python3 tests/net_echo_server.py --tls --port 8443      # HTTPS (自签名证书, 客户端需信任)

端点:
    /echo            回显 method/path/query/headers/body(最多 4KB 明文)
    /redirect        302 跳到 /echo?from=redirect (测重定向链)
    /status/404|500  指定状态码
    /delay?ms=N      睡 N 毫秒再回显 (测超时/错误路径)
    /big             1MB 响应体 (测下载/响应截断)
    /ws              WebSocket echo (需 --ws, 文本帧原文返回, 首条后 5 秒关)
"""

import argparse
import base64
import hashlib
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class Handler(BaseHTTPRequestHandler):
    server_version = "DHEcho/1.0"

    def log_message(self, *args):
        pass

    def _read_body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0:
            return b""
        # 流式 body 可能没有 Content-Length: 读到对端半关 (最多 1MB)
        data = b""
        self.connection.settimeout(2)
        try:
            while len(data) < min(n, 1024 * 1024):
                chunk = self.rfile.read(min(n - len(data), 65536))
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, ConnectionError):
            pass
        return data

    def _echo(self):
        body = self._read_body()
        try:
            body_text = body.decode("utf-8")[:4096]
        except UnicodeDecodeError:
            body_text = f"<binary {len(body)} bytes>"
        parsed = urllib.parse.urlparse(self.path)
        resp = {
            "method": self.command,
            "path": parsed.path,
            "query": urllib.parse.parse_qs(parsed.query),
            "headers": {k: v for k, v in self.headers.items()},
            "body_len": len(body),
            "body": body_text,
        }
        data = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Echo-Case", parsed.path)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle_ws(self):
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode()).digest()
        ).decode()
        raw = self.connection
        raw.sendall(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
            ).encode()
        )
        raw.settimeout(6)
        try:
            # 只回显首条文本帧, 然后发 close
            opcode, payload = self._ws_read_frame(raw)
            if opcode == 0x1 and payload is not None:
                self._ws_send(raw, 0x1, payload)
            self._ws_send(raw, 0x8, b"")
        except (socket.timeout, ConnectionError, ValueError):
            pass

    @staticmethod
    def _ws_read_frame(raw):
        hdr = raw.recv(2)
        if len(hdr) < 2:
            raise ValueError("short frame")
        b1, b2 = hdr[0], hdr[1]
        opcode = b1 & 0x0F
        masked = (b2 & 0x80) != 0
        length = b2 & 0x7F
        if length == 126:
            length = int.from_bytes(raw.recv(2), "big")
        elif length == 127:
            length = int.from_bytes(raw.recv(8), "big")
        mask = raw.recv(4) if masked else b"\x00\x00\x00\x00"
        payload = b""
        while len(payload) < length:
            chunk = raw.recv(length - len(payload))
            if not chunk:
                break
            payload += chunk
        if masked:
            payload = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
        return opcode, payload

    @staticmethod
    def _ws_send(raw, opcode, payload):
        hdr = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            hdr += bytes([n])
        elif n < 65536:
            hdr += bytes([126]) + n.to_bytes(2, "big")
        else:
            hdr += bytes([127]) + n.to_bytes(8, "big")
        raw.sendall(hdr + payload)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/ws" and self.server.enable_ws:
            if self.headers.get("Upgrade", "").lower() == "websocket":
                self._handle_ws()
                return
        if parsed.path == "/events":
            payload = b"data: DH_WK_SSE_001\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            self.wfile.flush()
            return
        if parsed.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/echo?from=redirect")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if parsed.path.startswith("/status/"):
            try:
                code = int(parsed.path.rsplit("/", 1)[-1])
            except ValueError:
                code = 200
            body = json.dumps({"status": code}).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/delay":
            qs = urllib.parse.parse_qs(parsed.query)
            try:
                ms = int(qs.get("ms", ["1000"])[0])
            except ValueError:
                ms = 1000
            time.sleep(ms / 1000.0)
            self._echo()
            return
        if parsed.path == "/big":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(1024 * 1024))
            self.end_headers()
            chunk = b"B" * 65536
            for _ in range(16):
                self.wfile.write(chunk)
            return
        self._echo()

    do_POST = _echo
    do_PUT = _echo
    do_DELETE = _echo
    do_PATCH = _echo
    do_OPTIONS = _echo

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("X-Echo-Case", "head")
        self.send_header("Content-Length", "0")
        self.end_headers()


def ensure_cert(path):
    if os.path.exists(path + ".crt") and os.path.exists(path + ".key"):
        return
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", path + ".key", "-out", path + ".crt",
            "-days", "2", "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--ws", action="store_true")
    ap.add_argument("--tls", action="store_true")
    args = ap.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    server.enable_ws = args.ws
    scheme = "http"
    if args.tls:
        cert_base = os.path.join(tempfile.gettempdir(), "dhecho")
        ensure_cert(cert_base)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_base + ".crt", cert_base + ".key")
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    print(f"[echo] {scheme}://127.0.0.1:{args.port} ws={args.ws}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
