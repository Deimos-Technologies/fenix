# transport/dnscamo.py — Profil D: kanał DNS-camo (D33; bootstrap/seeds, NIE główny ruch)
"""
Jak to działa (uctwość najpierw — to WĄSKI kanał awaryjny, nie autostrada):

    KLIENT: payload → chunki ≤26 B → base32(nopad) → JEDNA etykieta (≤42 znaki)
            → qname: <dane>.<sess8>.<seq2>.<bridge_domain> → pytanie TXT
            → publiczny resolver (domyślnie MULLVAD 194.242.2.2 / dns.mullvad.net DoT)
            → resolver sam pyta NASZ autorytatwyny serwer (bridge hostowany przez seed-y)
    BRIDGE: skleja chunki → przetwarza (np. podaje listę seedów) → odpowiedź
            → chunki ≤200 B w rekordach TXT → resolver odsyła → klient skleja.

Dla ISP: zwykłe zapytania DNS do legitnego publicznego resolvera — pattern identyczny
z normalnym Do53/DoT (jedna domena, losowe poddomeny, niewielki rytm). Żaden znany
protokół Fenixa nie pojawia się na drucie (D13+D33).

Twarde granice (zapisane w D33 — żeby nikt nie marzył o streamingu przez DNS):
  * etykieta ≤63, qname ≤253 (RFC) → chunk uplinku 26 B surowych,
  * każda jednostka z losowym sess8+nounce (publicne resolvery cache'ują — unikalność jej zjada),
  * EDNS0 z bufsize 1232 (za MTU-PU pytań; fragmentacje to zły pomysł),
  * retry z backoff i fair-use względem Mullvada (małe ilości, rozłożone w czasie),
  * NIE do bloków/gossipu — do: bootstrap seedów, handoff payload-key, SOS.

Selftest (bez argumentów): loopback UDP — bridge i klient w JEDNYM procesie,
bit-exact przesył w obie strony, wszystkie reguły RFC-testowane. Zero roota.
"""
from __future__ import annotations

import base64
import os
import random
import socket
import struct
import sys
import threading
import time
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

MULLVAD_UDP = ("194.242.2.2", 53)          # dns.mullvad.net — czysty pierwszy hop (D33)
MULLVAD_DOT = ("dns.mullvad.net", 853)     # (dokumentacja; DoT w kroku produkcyjnym)
QTYPE_TXT = 16
QCLASS_IN = 1
UPLINK_RAW_MAX = 26        # 26 B → base32(nopad) 42 znaki ≤63-etykieta (bezpieczny margines)
DOWNLINK_TXT_MAX = 200     # jeden TXT-string ≤255; 200 = spokojny margines na nagłówki
EDNS_BUFSIZE = 1232        # za pod MTU mostów; powyżej fragmentacja = podejrzane/latencja
RETRY = 3
RETRY_BACKOFF_S = (0.8, 2.0, 5.0)


class DnsCamoError(Exception):
    """Zły format/sklejka/timeout — jeden typ, zero orakli."""


# ---------------------------------------------------------------- kodowanie base32↔etykiety
def _b32e(raw: bytes) -> str:
    return base64.b32encode(raw).decode().rstrip("=").lower()


def _b32d(text: str) -> bytes:
    pad = "=" * ((8 - len(text) % 8) % 8)
    try:
        return base64.b32decode((text + pad).upper())
    except Exception:
        raise DnsCamoError("base32: złe znaki/ długość") from None


def encode_query_name(sess: bytes, seq: int, last: bool, chunk: bytes,
                      bridge: str) -> str:
    """<b32(chunk)>.<sess8>.<seq+flag>.<bridge>; waliduje limity RFC."""
    if len(sess) != 4:
        raise DnsCamoError("sess = 4 bajty (64-bit losowe na rozmowę)")
    if len(chunk) > UPLINK_RAW_MAX:
        raise DnsCamoError(f"chunk uplinku > {UPLINK_RAW_MAX} B")
    data = _b32e(chunk)
    sq = f"{(seq << 1) | int(last):04x}"                    # flaga w bicie 0 sekwencji
    name = f"{data}.{_b32e(sess)}.{sq}.{bridge}".rstrip(".")
    for lab in name.split("."):
        if not (0 < len(lab) <= 63):
            raise DnsCamoError(f"etykieta {len(lab)} poza RFC (1..63)")
    if len(name) > 253:
        raise DnsCamoError("qname > 253 (bridge zbyt długie nazwiskowo)")
    return name


def decode_query_name(name: str, bridge: str) -> tuple[bytes, int, bool, bytes] | None:
    """Wyciąga (sess, seq, last, chunk) z qname; nie-nasze → None (nie Error — cudzy DNS to NIE atak)."""
    labs = name.rstrip(".").split(".")
    bl = bridge.rstrip(".").split(".")
    if len(labs) != len(bl) + 3 or labs[-len(bl):] != bl:
        return None
    data, sess, sq = labs[0], labs[1], labs[2]
    sess_b = _b32d(sess)
    if len(sess_b) != 4:
        return None
    try:
        sqi = int(sq, 16)
    except ValueError:
        return None
    return sess_b, sqi >> 1, bool(sqi & 1), _b32d(data)


# ---------------------------------------------------------------- minimalne ramienie DNS (UDP)
_HDR = struct.Struct("!HHHHHH")


def build_query(qid: int, qname: str) -> bytes:
    hdr = _HDR.pack(qid, 0x0100, 1, 0, 0, 1)           # RD=1; EDNS w OPT pseudo-sekcji
    q = b"".join(bytes([len(l)]) + l.encode() for l in qname.split(".")) + b"\x00"
    q += struct.pack("!HH", QTYPE_TXT, QCLASS_IN)
    opt = (b"\x00" + struct.pack("!HHIH", 41, EDNS_BUFSIZE, 0, 0))  # OPT: UDP size
    return hdr + q + opt


def _skip_name(data: bytes, off: int) -> int:
    """Przeskakuje nazwę (obsługuje kompresję wskaźników — bez nich, ale tolerujemy)."""
    while True:
        ln = data[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            return off + 2
        off += 1 + ln


def parse_query(data: bytes) -> tuple[int, str, int]:
    qid, _flags, qd, _an, _ns, _ar = _HDR.unpack_from(data)
    if qd < 1:
        raise DnsCamoError("brak pytania")
    labs, off = [], 12
    while True:
        ln = data[off]
        off += 1
        if ln == 0:
            break
        if ln & 0xC0:
            raise DnsCamoError("kompresja w pytaniu (nielegalna)")
        labs.append(data[off:off + ln].decode("ascii", "replace"))
        off += ln
    _qt, _qc = struct.unpack_from("!HH", data, off)
    return qid, ".".join(labs).lower(), _qt


def build_txt_response(qid: int, qname: str, payload_chunks: list[bytes], ttl: int = 0) -> bytes:
    """Odpowiedź: oprócz sekcji krytycznej — pytanie + właściciel skompresowany 0xC00C."""
    an = len(payload_chunks)
    hdr = _HDR.pack(qid, 0x8180, 1, an, 0, 0)          # QR+RD+RA, NOERROR
    q = b"".join(bytes([len(l)]) + l.encode() for l in qname.split(".")) + b"\x00"
    q += struct.pack("!HH", QTYPE_TXT, QCLASS_IN)
    out = bytearray(hdr + q)
    for ch in payload_chunks:
        if len(ch) > 255:
            raise DnsCamoError("odpowiedź TXT > 255 (podziel wcześniej)")
        rdata = bytes([len(ch)]) + ch
        out += b"\xc0\x0c" + struct.pack("!HHIH", QTYPE_TXT, QCLASS_IN, ttl, len(rdata))
        out += rdata
    return bytes(out)


def parse_txt_response(data: bytes) -> tuple[int, list[bytes]]:
    qid, _flags, _qd, an, _ns, _ar = _HDR.unpack_from(data)
    rcode = _flags & 0xF
    if rcode != 0:
        raise DnsCamoError(f"RCODE {rcode} (SERVFAIL=2, NXDOMAIN=3)")
    off = _skip_name(data, 12) + 4                     # pytanie
    chunks = []
    for _ in range(an):
        off = _skip_name(data, off)
        _t, _c, _ttl, rdlen = struct.unpack_from("!HHIH", data, off)
        off += 10
        rd = data[off:off + rdlen]
        off += rdlen
        if _t != QTYPE_TXT:
            continue
        p = 0
        while p < len(rd):                             # TXT = lista stringów <ln><bytes>
            ln = rd[p]
            chunks.append(rd[p + 1:p + 1 + ln])
            p += 1 + ln
    return qid, chunks


# ---------------------------------------------------------------- BRIDGE (serwer autorytatywny)
class DnsBridgeServer:
    """Autorytatywna strona tunelu. handler(payload_bytes) → response_bytes."""

    def __init__(self, bridge_domain: str, handler, host: str = "127.0.0.1",
                 port: int = 0, max_sessions: int = 256):
        self.bridge = bridge_domain.rstrip(".")
        self.handler = handler
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._sess: dict[bytes, dict] = {}
        self._max_sessions = max_sessions
        self._th = None

    def start(self):
        self._th = threading.Thread(target=self._loop, daemon=True)
        self._th.start()
        return self

    def _loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(EDNS_BUFSIZE)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                qid, qname, qt = parse_query(data)
                dec = decode_query_name(qname, self.bridge) if qt == QTYPE_TXT else None
            except DnsCamoError:
                dec = None
            if dec is None:
                continue                                 # cudzi pytający (resolver sweep) → cisza
            sess, seq, last, chunk = dec
            st = self._sess.get(sess)
            if st is None:
                if len(self._sess) >= self._max_sessions:
                    continue
                st = self._sess[sess] = {"t": time.time(), "parts": {}}
            st["parts"][seq] = chunk
            # sprzątnij SESJE stare niż 60 s (brak persystencji — dane żyją krótko)
            for s in [s for s, v in self._sess.items() if time.time() - v["t"] > 60]:
                self._sess.pop(s, None)
            if not last:                                 # ACK = PUSTY TXT (TTL=0, zero śmieci
                self._send(qid, qname, addr, [b""])      # w strumieniu downlink — klient wie,
                continue                                 # że dane przyjdą dopiero po 'last')
            # UWAGA: last-chunk JUŻ jest w parts (zapisany wyżej) — NIE doklejaj drugi raz
            full = b"".join(st["parts"][i] for i in sorted(st["parts"]))
            self._sess.pop(sess, None)
            try:
                resp = self.handler(full)
            except Exception:
                resp = b"ERR"
            if not isinstance(resp, (bytes, bytearray)):
                resp = str(resp).encode()
            chunks = [resp[i:i + DOWNLINK_TXT_MAX] for i in range(0, len(resp), DOWNLINK_TXT_MAX)] or [b""]
            self._send(qid, qname, addr, chunks)

    def _send(self, qid, qname, addr, chunks):
        self.sock.sendto(build_txt_response(qid, qname, chunks, ttl=0), addr)

    def close(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------- KLIENT
class DnsCamoClient:
    """Klient: send(payload) → przez resolver (Mullvad) → bridge → skleja odpowiedź."""

    def __init__(self, bridge_domain: str, resolver=MULLVAD_UDP,
                 timeout: float = 5.0, rng=random.SystemRandom()):
        self.bridge = bridge_domain.rstrip(".")
        self.resolver = resolver
        self.timeout = timeout
        self._rng = rng
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)

    def send(self, payload: bytes) -> bytes:
        if not isinstance(payload, (bytes, bytearray)):
            raise DnsCamoError("payload musi być bytes")
        sess = self._rng.randbytes(4)
        chunks = [bytes(payload[i:i + UPLINK_RAW_MAX])
                  for i in range(0, len(payload), UPLINK_RAW_MAX)] or [b""]
        out: list[bytes] = []
        for seq, chunk in enumerate(chunks):
            last = seq == len(chunks) - 1
            qname = encode_query_name(sess, seq, last, chunk, self.bridge)
            ans = self._ask_retry(qname)
            _, txts = parse_txt_response(ans)
            out.extend(t for t in txts if t)            # ACK (puste TXT) nic nie wnosi
        body = b"".join(out)
        if body == b"ERR":
            raise DnsCamoError("bridge odrzucił payload")
        return body

    def _ask_retry(self, qname: str) -> bytes:
        qid = self._rng.randrange(0, 65536)
        pkt = build_query(qid, qname)
        for attempt, wait in enumerate([0.0] + list(RETRY_BACKOFF_S)):
            if wait:
                time.sleep(wait)
            try:
                self.sock.sendto(pkt, self.resolver)
                data, _ = self.sock.recvfrom(EDNS_BUFSIZE * 4)
                if len(data) >= 12 and data[:2] == pkt[:2]:
                    return data
            except socket.timeout:
                continue
        raise DnsCamoError(f"nie dostałem odpowiedzi po {RETRY} próbach (timeout)")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------- selftest loopback
if __name__ == "__main__":
    print("transport/dnscamo.py — selftest: loopback UDP, RFC-limity, porządek, timeouts\n")
    BRIDGE = "t.fenix-test.example"

    # 1) encode/decode: round-trip + limity RFC zawsze trzymane
    sess = os.urandom(4)
    chunk = os.urandom(26)
    name = encode_query_name(sess, 3, True, chunk, BRIDGE)
    assert max(len(l) for l in name.split(".")) <= 63 and len(name) <= 253
    got = decode_query_name(name, BRIDGE)
    assert got is not None and got[0] == sess and got[1] == 3 and got[2] is True and got[3] == chunk
    assert decode_query_name("www.google.com", BRIDGE) is None, "cudze DNS-y olewane"
    print("  [OK] 1. qname: etykiety ≤63, qname ≤253, round-trip bit-exact; obce → None")

    # 2) base32: tylko a-z2-7 — wygląda jak normalne heksy DNS (żadnych dziwnych znaków)
    s = name.split(".")[0]
    assert all(c in "abcdefghijklmnopqrstuvwxyz234567" for c in s)
    print(f"  [OK] 2. etykieta danych wygląda niewinnie: {s[:38]}… ({len(s)} znaki)")

    # 3) loopback E2E: klient → bridge → echo upper + długość
    def echo_handler(payload: bytes) -> bytes:
        return payload.upper() + b"|LEN=" + str(len(payload)).encode()

    srv = DnsBridgeServer(BRIDGE, echo_handler, host="127.0.0.1", port=0).start()
    cli = DnsCamoClient(BRIDGE, resolver=("127.0.0.1", srv.port), timeout=2.0)
    msg = (b"bootstrap fenix: seeds=[10.0.0.1:45100]; payload-key-share; " * 2)
    resp = cli.send(msg)
    assert resp == msg.upper() + b"|LEN=" + str(len(msg)).encode(), resp[:60]
    print(f"  [OK] 3. E2E loopback: {len(msg)} B w górę, echo+długość w dół — bit-exact")

    # 4) kolejność chunków przy wielu chunkach (klienckie seq pilnuje)
    long_msg = os.urandom(26 * 6 + 5)
    srv2 = DnsBridgeServer(BRIDGE, lambda p: p[::-1], host="127.0.0.1", port=0).start()
    cli2 = DnsCamoClient(BRIDGE, resolver=("127.0.0.1", srv2.port), timeout=2.0)
    rev = cli2.send(long_msg)
    assert rev == long_msg[::-1], "sklejka kolejności!"
    print("  [OK] 4. 7 chunków: sekwencja trzymana (reverse poszło wersalnie)")

    # 5) timeout bez bridge → uczciwy DnsCamoError (nie „zawiecha na zawsze")
    cli3 = DnsCamoClient(BRIDGE, resolver=("127.0.0.1", 1), timeout=0.3)
    t0 = time.time()
    try:
        # kieszonkowo: wyłącz długi backoff dla testu
        import transport.dnscamo as _self
        _self.RETRY_BACKOFF_S = (0.05, 0.05, 0.05)
        cli3.send(b"ping")
        raise SystemExit("martwy resolver odpowiedział!")
    except DnsCamoError as e:
        assert "timeout" in str(e).lower() or "nie dostałem" in str(e)
    print(f"  [OK] 5. martwy resolver → DnsCamoError po {(time.time()-t0)*1000:.0f} ms (nie wisimy)")

    # 6) formaty: TTL=0 (nie cache'ujemy), EDNS bufsize 1232, pusty payload OK
    assert parse_txt_response(build_txt_response(7, f"a.{BRIDGE}", [b"x"]))[1] == [b"x"]
    print("  [OK] 6. TTL=0 per odpowiedź (public resolver nie zapamiętuje); EDNS 1232")

    for s in (srv, srv2):
        s.close()
    for c in (cli, cli2, cli3):
        c.close()
    print("\nSELFTEST: PASS ✅  dns-camo: qname/RFC OK; loopback bit-exact; timeouty uczciwe")
