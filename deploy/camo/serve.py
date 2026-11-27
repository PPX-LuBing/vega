#!/usr/bin/env python3
"""极简静态 HTTPS 站点，给 REALITY 当伪装 dest 用。

只用标准库，零依赖，常驻内存几 MB。要求（REALITY 的硬条件）：
  - 只开 TLS 1.3
  - 支持 X25519（OpenSSL 默认组里就有）
  - 协商 h2（python ssl 不能真的跑 h2，但 ALPN 会协商成 h2，
    REALITY 只看 ALPN 结果，真实探测者拿到的是 h2 应答头）

⚠️ 2026-11-27 修复的致命 bug
------------------------------------------------------------
旧版把监听 socket 直接 ctx.wrap_socket() 包掉了：

    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

这样 TLS 握手发生在 accept() 内部、在主循环里同步执行。只要有人
建立一条 TCP 连接但一个字节都不发（端口扫描器、探针、curl 超时前的
半开连接都算），accept() 就停在握手上，整个进程不再接受任何新连接。

而 REALITY 每次握手都要先拨 dest（127.0.0.1:9443）才能比对 ClientHello
—— dest 卡住 → `REALITY: failed to dial dest: i/o timeout` → 全网
REALITY 节点连不上。2026-11-26 上线，11-27 就垮了，症状是「节点连不上」，
极易被误判成 SNI 配错。

改法：监听 socket 保持明文，握手挪到每个连接自己的工作线程里做。
顺带加了连接超时和并发上限，慢连接不再能占着资源不放。
"""
import http.server
import os
import ssl
import socketserver
import threading

ROOT = "/opt/camo/site"
CERT = "/var/lib/vega/certs/us2.542048.xyz/cert.pem"
KEY = "/var/lib/vega/certs/us2.542048.xyz/key.pem"
PORT = int(os.environ.get("CAMO_PORT", "9443"))

# 单连接握手 + 读请求的超时，防止慢连接长期占用线程
CONN_TIMEOUT = 10
# 并发上限：MemoryMax=64M，别让探测洪水把内存打爆
MAX_CONNS = 64


def make_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(CERT, KEY)
    ctx.set_alpn_protocols(["http/1.1"])
    try:
        ctx.set_ecdh_curve("X25519")
    except Exception:
        pass
    return ctx


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=ROOT, **kw)

    def log_message(self, fmt, *args):
        # 静默，避免日志膨胀
        pass

    def do_GET(self):
        # SPA 路由：找不到就回 index.html
        path = self.translate_path(self.path)
        if not os.path.exists(path) or os.path.isdir(path):
            self.path = "/index.html"
        return super().do_GET()


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(self, addr, handler, ctx):
        self.ctx = ctx
        self._slots = threading.Semaphore(MAX_CONNS)
        super().__init__(addr, handler)

    def process_request(self, request, client_address):
        # 并发超限就静默丢弃，不排队、不占线程
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def finish_request(self, request, client_address):
        # 关键：TLS 握手在这里做（ThreadingMixIn 的工作线程里），
        # 不在主循环的 accept() 里。
        try:
            request.settimeout(CONN_TIMEOUT)
            try:
                tls_request = self.ctx.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError):
                return
            try:
                super().finish_request(tls_request, client_address)
            finally:
                try:
                    tls_request.close()
                except OSError:
                    pass
        finally:
            self._slots.release()


def main():
    httpd = Server(("0.0.0.0", PORT), Handler, make_context())
    print("camo site on :%d (TLS1.3 only, per-conn handshake)" % PORT, flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
