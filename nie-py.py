#!/usr/bin/env python3
"""
nie-py — minimal Python nie chat client (standard library only)

Usage:
  python nie-py.py [--relay ws://127.0.0.1:3210/ws] [--keyfile identity.key]
  python nie-py.py --insecure --relay wss://localhost:8443/ws
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import threading
import urllib.parse

# ---------------------------------------------------------------------------
# Ed25519 — pure Python, public domain, ~100 lines
# Based on the reference implementation at https://ed25519.cr.yp.to/
# ---------------------------------------------------------------------------

_P = 2**255 - 19  # field prime
_Q = 2**252 + 27742317777372353535851937790883648493  # group order
_D = (-121665 * pow(121666, _P - 2, _P)) % _P  # curve constant
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)  # sqrt(-1) mod p


def _recover_x(y: int, sign: int):
    """Recover the x coordinate of a point given y and the sign of x."""
    y2 = y * y % _P
    x2 = (y2 - 1) * pow(_D * y2 + 1, _P - 2, _P) % _P
    if x2 == 0:
        return 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if x % 2 != sign:
        x = _P - x
    return x


# Base point in extended (X:Y:Z:T) coordinates
_B_Y = 4 * pow(5, _P - 2, _P) % _P
_B_X = _recover_x(_B_Y, 0)
_B = (_B_X, _B_Y, 1, _B_X * _B_Y % _P)


def _point_add(P1, P2):
    """Add two extended-coordinate points."""
    x1, y1, z1, t1 = P1
    x2, y2, z2, t2 = P2
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def _scalarmul(s: int, P_):
    """Scalar multiplication via Montgomery ladder.
    Always performs exactly 256 iterations with 2 point ops each,
    so the loop count and op count don't leak scalar bit-length or
    trailing-zero count. Note: Python big-int arithmetic is not
    constant-time at the hardware level, but this removes the most
    obvious algorithmic timing leak.
    """
    R0 = (0, 1, 1, 0)  # identity
    R1 = P_
    for i in range(255, -1, -1):
        if (s >> i) & 1:
            R0 = _point_add(R0, R1)
            R1 = _point_add(R1, R1)
        else:
            R1 = _point_add(R0, R1)
            R0 = _point_add(R0, R0)
    return R0


def _encode_point(P_) -> bytes:
    """Encode extended-coordinate point to 32 bytes."""
    x, y, z, _ = P_
    zi = pow(z, _P - 2, _P)
    x, y = x * zi % _P, y * zi % _P
    buf = bytearray(y.to_bytes(32, 'little'))
    buf[31] |= (x & 1) << 7
    return bytes(buf)


def ed25519_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """Derive (expanded_secret[64], public_key[32]) from a 32-byte seed."""
    h = hashlib.sha512(seed).digest()
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    pub = _encode_point(_scalarmul(int.from_bytes(a, 'little'), _B))
    return bytes(h), pub


def ed25519_sign(expanded: bytes, pubkey: bytes, msg: bytes) -> bytes:
    """Sign msg with the expanded private key. Returns 64-byte signature."""
    a = bytearray(expanded[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    a_int = int.from_bytes(a, 'little')
    r = int.from_bytes(hashlib.sha512(expanded[32:] + msg).digest(), 'little') % _Q
    R = _encode_point(_scalarmul(r, _B))
    k = int.from_bytes(hashlib.sha512(R + pubkey + msg).digest(), 'little') % _Q
    S = (r + k * a_int) % _Q
    return R + S.to_bytes(32, 'little')


def pub_id(pubkey: bytes) -> str:
    """nie PubId = hex(SHA-256(verifying_key_bytes))."""
    return hashlib.sha256(pubkey).hexdigest()


# ---------------------------------------------------------------------------
# WebSocket — minimal client-side implementation
# ---------------------------------------------------------------------------

def _recv_exact(sock, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('connection closed')
        buf += chunk
    return buf


def ws_connect(url: str, insecure: bool = False):
    """Open a WebSocket connection. Returns the raw socket."""
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme
    host = parsed.hostname
    port = parsed.port or (443 if scheme == 'wss' else 80)
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query

    sock = socket.create_connection((host, port), timeout=15)
    sock.settimeout(None)
    if scheme == 'wss':
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)

    key = base64.b64encode(os.urandom(16)).decode()
    handshake = (
        f'GET {path} HTTP/1.1\r\n'
        f'Host: {host}:{port}\r\n'
        f'Upgrade: websocket\r\n'
        f'Connection: Upgrade\r\n'
        f'Sec-WebSocket-Key: {key}\r\n'
        f'Sec-WebSocket-Version: 13\r\n'
        f'\r\n'
    ).encode()
    sock.sendall(handshake)

    resp = b''
    while b'\r\n\r\n' not in resp:
        resp += sock.recv(4096)
    status = resp.split(b'\r\n')[0]
    if b'101' not in status:
        raise RuntimeError(f'WebSocket upgrade failed: {status!r}')
    return sock


def ws_recv(sock) -> tuple[int, bytes]:
    """Read one WebSocket frame. Returns (opcode, payload)."""
    h = _recv_exact(sock, 2)
    opcode = h[0] & 0x0F
    masked = (h[1] >> 7) & 1
    length = h[1] & 0x7F
    if length == 126:
        length = struct.unpack('!H', _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack('!Q', _recv_exact(sock, 8))[0]
    mask = _recv_exact(sock, 4) if masked else None
    payload = _recv_exact(sock, length)
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


def ws_send_text(sock, text: str):
    """Send a masked text frame (clients must mask per RFC 6455)."""
    data = text.encode('utf-8')
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    n = len(data)
    if n < 126:
        hdr = bytes([0x81, 0x80 | n]) + mask
    elif n < 65536:
        hdr = bytes([0x81, 0xFE]) + struct.pack('!H', n) + mask
    else:
        hdr = bytes([0x81, 0xFF]) + struct.pack('!Q', n) + mask
    sock.sendall(hdr + masked)


def ws_send_pong(sock, data: bytes = b''):
    """Send a pong control frame."""
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    sock.sendall(bytes([0x8A, 0x80 | len(data)]) + mask + masked)


# ---------------------------------------------------------------------------
# nie protocol
# ---------------------------------------------------------------------------

def nie_auth(sock, expanded: bytes, pubkey: bytes) -> str:
    """
    Perform the nie challenge-response handshake.
    Returns the server-confirmed pub_id.
    """
    opcode, data = ws_recv(sock)
    msg = json.loads(data)
    if msg.get('type') != 'challenge':
        raise RuntimeError(f"Expected challenge, got: {msg}")
    nonce = msg['nonce']

    # Sign the raw UTF-8 bytes of the nonce (matches Rust nonce.as_bytes())
    sig = ed25519_sign(expanded, pubkey, nonce.encode('utf-8'))

    ws_send_text(sock, json.dumps({
        'type': 'authenticate',
        'pub_key': base64.b64encode(pubkey).decode(),
        'nonce': nonce,
        'signature': base64.b64encode(sig).decode(),
    }))

    opcode, data = ws_recv(sock)
    msg = json.loads(data)
    if msg.get('type') == 'auth_failed':
        raise RuntimeError(f"Auth failed: {msg.get('reason')}")
    if msg.get('type') != 'auth_ok':
        raise RuntimeError(f"Expected auth_ok, got: {msg}")
    return msg['pub_id']


def encode_chat(text: str) -> str:
    """Encode a chat message as a Broadcast JSON string."""
    clear = json.dumps({'type': 'chat', 'text': text})
    payload = base64.b64encode(clear.encode('utf-8')).decode()
    return json.dumps({'type': 'broadcast', 'payload': payload})


def decode_clear(payload_b64: str) -> dict | None:
    """Decode a base64 payload as ClearMessage JSON. Returns None on failure."""
    try:
        return json.loads(base64.b64decode(payload_b64))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description='nie chat client (Python, stdlib only)')
    ap.add_argument('--relay', default='ws://127.0.0.1:3210/ws',
                    help='Relay WebSocket URL (default: ws://127.0.0.1:3210/ws)')
    ap.add_argument('--keyfile', default='identity.key',
                    help='Path to 32-byte identity seed file')
    ap.add_argument('--insecure', action='store_true',
                    help='Skip TLS certificate verification (dev only)')
    args = ap.parse_args()

    # Load or generate the 32-byte seed
    if os.path.exists(args.keyfile):
        seed = open(args.keyfile, 'rb').read()
        if len(seed) != 32:
            sys.exit(f'ERROR: {args.keyfile}: expected 32 bytes, got {len(seed)}')
        print(f'Loaded identity from {args.keyfile}')
    else:
        seed = os.urandom(32)
        with open(args.keyfile, 'wb') as f:
            f.write(seed)
        print(f'Generated new identity → {args.keyfile}')

    expanded, pubkey = ed25519_from_seed(seed)
    my_id = pub_id(pubkey)
    print(f'pub_id: {my_id}')

    print(f'Connecting to {args.relay} ...')
    sock = ws_connect(args.relay, insecure=args.insecure)

    server_id = nie_auth(sock, expanded, pubkey)
    if server_id != my_id:
        sys.exit(f'ERROR: server returned unexpected pub_id {server_id!r}')
    print('Authenticated.')

    # Shared state (names dict protected by lock)
    names: dict[str, str] = {}
    lock = threading.Lock()
    stop = threading.Event()

    def label(pid: str) -> str:
        with lock:
            nick = names.get(pid)
        suffix = ' (you)' if pid == my_id else ''
        return (nick or pid[:12] + '…') + suffix

    def reader():
        try:
            while not stop.is_set():
                opcode, data = ws_recv(sock)

                if opcode == 8:  # close
                    print('\n[server closed the connection]')
                    stop.set()
                    break
                if opcode == 9:  # ping
                    ws_send_pong(sock, data)
                    continue
                if opcode != 1:  # not text
                    continue

                try:
                    msg = json.loads(data)
                except json.JSONDecodeError:
                    continue

                t = msg.get('type')

                if t == 'directory_list':
                    online = msg.get('online', [])
                    offline = msg.get('offline', [])
                    with lock:
                        for u in online + offline:
                            if u.get('nickname'):
                                names[u['pub_id']] = u['nickname']
                    print(f"\n[{len(online)} online, {len(offline)} offline]")
                    for u in online:
                        pid = u['pub_id']
                        nick = u.get('nickname') or pid[:12] + '…'
                        marker = ' (you)' if pid == my_id else ''
                        print(f'  {nick}{marker}')
                    print()

                elif t == 'user_joined':
                    pid = msg['pub_id']
                    if msg.get('nickname'):
                        with lock:
                            names[pid] = msg['nickname']
                    if pid != my_id:
                        print(f'\n*** {label(pid)} joined')

                elif t == 'user_left':
                    print(f"\n*** {label(msg['pub_id'])} left")

                elif t == 'user_nickname':
                    pid = msg['pub_id']
                    nick = msg['nickname']
                    with lock:
                        names[pid] = nick
                    marker = ' (you)' if pid == my_id else ''
                    print(f'\n*** {pid[:12]}… is now known as {nick}{marker}')

                elif t == 'deliver':
                    from_id = msg['from']
                    clear = decode_clear(msg.get('payload', ''))
                    if clear and clear.get('type') == 'chat':
                        print(f"\n<{label(from_id)}> {clear.get('text', '')}")
                    elif clear and clear.get('type') == 'profile':
                        fields = clear.get('fields', {})
                        print(f'\n[profile {label(from_id)}]: {fields}')

                elif t == 'error':
                    print(f"\n[error {msg.get('code')}: {msg.get('message')}]")

        except (ConnectionError, OSError):
            if not stop.is_set():
                print('\n[disconnected]')
            stop.set()

    threading.Thread(target=reader, daemon=True).start()

    print('Type a message and Enter to send. Commands: /iam <name>  /quit')
    try:
        while not stop.is_set():
            try:
                line = input()
            except EOFError:
                break

            line = line.strip()
            if not line:
                continue

            if line == '/quit':
                break
            elif line.startswith('/iam '):
                nickname = line[5:].strip()
                ws_send_text(sock, json.dumps({'type': 'set_nickname', 'nickname': nickname}))
            else:
                ws_send_text(sock, encode_chat(line))

    except KeyboardInterrupt:
        pass

    stop.set()
    try:
        sock.close()
    except OSError:
        pass
    print('[bye]')


if __name__ == '__main__':
    main()
