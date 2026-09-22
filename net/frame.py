# net/frame.py — ramka protokołu Fenixa (protocol_spec v0.2, skrót MVP)
"""
Drut: [MAGIC "FN"(2) | VER(1) | TYPE(1) | FLAGS(1) | SEQ(8) | LEN(4) |
       CT | TAG(16)] — na wiresie ZAWSZE 1024 B albo 4096 B
(spec: napastnik nie czyta rozmiarów treści).

Kanał: po handshake PRAWDZIWE AEAD ChaCha20-Poly1305 — szyfrowane jest
CT = PAYLOAD+PAD (AAD=nagłówek; klucz sesji z X25519+HKDF info "fenix/sess/01").
Wcześniej AEAD liczyło się "na pusto" (sam MAC) i payload leciał JAWNIE —
selftest mesh złapał b"amount" na drucie → poprawione na pełne szyfrowanie.
Nonce = blake2s(klucz_sesji || SEQ)[:12] — deterministyczny, unikatowy per SEQ.
Replay: okno 4096 (bitmapa).

Handshake = anonimowy jak tylko się da:
  1) HELLO/HELLO_ACK niosą WYŁĄCZNIE 32-bajtowe klucze efemeryczne X25519
     — na drucie czysty losowy szum (zero JSON, zero portfeli, zero podpisów),
  2) obie strony liczą klucz sesji (X25519+HKDF),
  3) DOPIERO pod kluczem leci T_HELLO_FIN: profil publiczny + podpis Ed25519
     nad {profil, eph_klienta, eph_serwera} — podpis WIĄŻE kanał (anty-MITM),
     check_profile() przelicza wallet z kluczy (profil nie może kłamać).
Efekt: pasywny ISP widzi szum, nie widzi nawet tego, KTO z KIM gada.

FNX64 (D70, „x tetracja do 10" — core/crypto/fnx64.py): po AEAD każdy CT ramki
dostaje jeszcze pelerynę XOR ze strumienia tetracyjnego (wieża ↑↑10 mod 2^64).
Klucz peleryny = HKDF-ish z (klucz sesji eph ⊕ DH STATYCZNYCH tożsamości) —
obserwator, który złamałby SAMO efemerykę, nadal nie zdejmuje warstwy (realny
przyrost kosztu, nie marketing). Negocjacja: pole "fx" w podpisanym HELLO_FIN;
gdy OBAJE strony je niosą — link leci w pelerynie (brak pola = czysty AEAD,
kompatybilność). Fundament bez zmian: ChaCha20-Poly1305 + X25519 + Ed25519.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import sys
import threading
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

from core.crypto import fnx64 as _fx                     # D70: peleryna FNX64 na CT

MAGIC = b"FN"
VER = 2                 # v0.2: AEAD szyfruje (było: sam MAC); handshake efemeryczny
HDR_LEN = 17            # 2+1+1+1+8+4
TAG_LEN = 16
BUCKETS = (1024, 4096)
MAX_PAYLOAD = BUCKETS[-1] - HDR_LEN - TAG_LEN   # 4063

# --- typy ramek (protocol_spec; tutaj podzbiór MVP + miejsce na resztę) -------
T_HELLO = 0x01
T_HELLO_ACK = 0x02
T_HELLO_FIN = 0x03
T_PING = 0x10
T_PONG = 0x11
T_TX_SUBMIT = 0x20
T_BLOCK_NEW = 0x21
T_MSG = 0x22                   # koperta messengera E2E (D35): relay bez zapisu — node NIE czyta
T_SYNC_REQ = 0x30
T_SYNC_CHAIN = 0x31
T_SYNC_PART = 0x32             # chunking większych ładunków (łańcuch, duży blok)
T_ADDR = 0x40                  # D54: wymiana adresowni (gossip nodów; meta, nie treści)
T_PRES = 0x41                  # D61: beacon obecności (licznik online; meta, nie treści)
T_JOB = 0x42                   # D69: prośba siatki AI-GRID o obliczenie (z gigantis memu: 42 = odpowiedź — tu siatka odpowiada robotą)
T_JOB_RES = 0x43               # D69: wynik obliczenia do kworum (podpisany pracownikiem)
T_ERR = 0x7F
TYPES = {T_HELLO, T_HELLO_ACK, T_HELLO_FIN, T_PING, T_PONG,
         T_TX_SUBMIT, T_BLOCK_NEW, T_MSG, T_SYNC_REQ, T_SYNC_CHAIN, T_SYNC_PART,
         T_ADDR, T_PRES, T_JOB, T_JOB_RES, T_ERR}


class FrameError(Exception):
    """Przekłamana/niekompletna/zła ramka — jeden typ (brak orakli)."""


_hdr = struct.Struct("!2sBBBQI")
SESS_INFO = b"fenix/sess/01"


def _bucket(total: int) -> int:
    for b in BUCKETS:
        if total <= b:
            return b
    raise FrameError("oversize (payload > 4063 B — większe leci T_SYNC_PART)")


def _nonce(key: bytes, seq: int) -> bytes:
    return hashlib.blake2s(key + seq.to_bytes(8, "big"), digest_size=12).digest()


def pack_frame(typ: int, seq: int, payload: bytes, key: bytes | None = None,
               flags: int = 0) -> bytes:
    """Pełna ramka na drut. key=None TYLKO dla HELLO/HELLO_ACK (efemeryki)."""
    if typ not in TYPES:
        raise FrameError("nieznany typ ramki")
    pl = len(payload)
    wire = _bucket(HDR_LEN + pl + TAG_LEN)
    hdr = _hdr.pack(MAGIC, VER, typ, flags, seq, pl)
    pad = os.urandom(wire - HDR_LEN - pl - TAG_LEN)      # padding losowy, nie zera
    if key is None:
        if typ not in (T_HELLO, T_HELLO_ACK):
            raise FrameError("ramka bez klucza dozwolona tylko w handshake-eph")
        return hdr + payload + pad + b"\x00" * TAG_LEN
    ct = ChaCha20Poly1305(key).encrypt(_nonce(key, seq), payload + pad, hdr)
    return hdr + ct                                      # ct = szyfrogram || tag


def parse_frame(buf: bytes, key: bytes | None = None, fx_recv: bytes | None = None):
    """Zwraca (dict ramki, reszta bufora). Za mało danych → (None, buf)."""
    if len(buf) < HDR_LEN:
        return None, buf
    magic, ver, typ, flags, seq, pl = _hdr.unpack_from(buf)
    if magic != MAGIC or ver != VER or typ not in TYPES:
        raise FrameError("zły MAGIC/VER/TYPE")
    wire = _bucket(HDR_LEN + pl + TAG_LEN)
    if len(buf) < wire:
        return None, buf
    hdr, blob = buf[:HDR_LEN], buf[HDR_LEN:wire]
    if key is None:
        if typ not in (T_HELLO, T_HELLO_ACK):
            raise FrameError("ramka post-handshake bez klucza sesji")
        payload = blob[:pl]
    else:
        if fx_recv is not None:                # D70: najpierw peleryna, potem AEAD
            blob = _fx.fnx64_xor(blob, fx_recv, seq)
        try:
            pt = ChaCha20Poly1305(key).decrypt(_nonce(key, seq), blob, hdr)
        except InvalidTag:
            raise FrameError("AEAD nieważny (przekłamanie/obcy klucz)") from None
        payload = pt[:pl]
    return {"type": typ, "flags": flags, "seq": seq, "payload": payload,
            "wire": wire}, buf[wire:]


class ReplayWindow:
    """Bitmapa 4096 ramek (spec): SEQ starsze niż okno = drop, powtórzony = drop."""

    def __init__(self, size: int = 4096):
        self.size, self.max, self.bits = size, -1, 0

    def check(self, seq: int) -> bool:
        if seq < 0:
            return False
        if self.max < 0:
            self.max, self.bits = seq, 1
            return True
        if seq > self.max:
            shift = seq - self.max
            self.bits = ((self.bits << shift) | 1) if shift < self.size else 1
            self.max = seq
            return True
        d = self.max - seq
        if d >= self.size or (self.bits >> d) & 1:
            return False
        self.bits |= 1 << d
        return True


class FrameSession:
    """Ramki po TCP z AEAD kanału. Użycie: handshake_*() zwraca gotową sesję."""

    def __init__(self, sock: socket.socket, key: bytes | None):
        self.sock = sock
        self.key = key
        self._send_seq = 0
        self._recv_win = ReplayWindow()
        self._buf = b""
        self.lock = threading.Lock()
        self.fx_send: bytes | None = None      # D70: klucz peleryny (nadawanie)
        self.fx_recv: bytes | None = None      # D70: klucz peleryny (odbiór)

    def enable_fx(self, send_key: bytes, recv_key: bytes) -> None:
        """Włącz pelerynę FNX64 na tej sesji (po wymianie HELLO_FIN — D70)."""
        if len(send_key) != 32 or len(recv_key) != 32:
            raise FrameError("fx: klucze peleryny 32 B")
        self.fx_send, self.fx_recv = send_key, recv_key

    def send(self, typ: int, payload: bytes, flags: int = 0) -> bytes:
        with self.lock:
            seq = self._send_seq
            self._send_seq += 1
        raw = pack_frame(typ, seq, payload, self.key, flags)
        if self.fx_send is not None:           # D70: CT(AEAD) ⊕ strumień FNX64
            return raw[:HDR_LEN] + _fx.fnx64_xor(raw[HDR_LEN:], self.fx_send, seq)
        return raw

    # strumień: ramki mogą się łamać między pakietami TCP
    def try_parse(self):
        """Parsuje pierwszą ramkę z bufora. Błąd → odrzuca 1 bajt (resync po
        junk camo / przekłamaniu) i RZUCA wyjątek — bufor już odtruowany, więc
        kolejne wywołania idą dalej zamiast zapętlać się na trującej ramce."""
        try:
            fr, rest = parse_frame(self._buf, self.key, self.fx_recv)
        except FrameError:
            self._buf = self._buf[1:]
            raise
        self._buf = rest
        if fr is not None and not self._recv_win.check(fr["seq"]):
            raise FrameError("replay/okno SEQ")
        return fr

    def accept(self, data: bytes):
        self._buf += data


# ---------------------------------------------------------------- handshake
def _raw_pub(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.Raw,
                                          serialization.PublicFormat.Raw)


def _hello_core(identity, eph_c: bytes, eph_s: bytes) -> dict:
    return {"pv": 1, **identity.public_profile(),
            "eph_c": eph_c.hex(), "eph_s": eph_s.hex(),
            "fx": _fx.FNX64_WIRE_VER}         # D70: umowa peleryny (w podpisie — niepodważalna)


def _hello_signed(identity, core: dict) -> dict:
    sig = identity.sign(json.dumps(core, sort_keys=True, separators=(",", ":")).encode())
    return {**core, "sig": sig.hex()}


def _verify_hello(h: dict, eph_c: bytes, eph_s: bytes) -> str:
    """Profil-musi-być-prawdziwy + podpis-musi-wiązać TEN kanał → wallet."""
    from core.identity import check_profile, verify_signed
    if h.get("eph_c") != eph_c.hex() or h.get("eph_s") != eph_s.hex():
        raise FrameError("HELLO_FIN: efemeryki nie pasują do kanału (replay/MITM)")
    prof = {k: h[k] for k in ("pv", "wallet", "username", "uid", "rank",
                              "sig_pub", "x_pub")}
    check_profile(prof)                                  # klucze MUSZĄ dawać wallet
    core = {k: h[k] for k in h if k != "sig"}
    data = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
    if not verify_signed(prof, bytes.fromhex(h["sig"]), data):
        raise FrameError("HELLO_FIN: podpis nieważny")
    return prof["wallet"]


def _derive_key(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=SESS_INFO).derive(shared)


def handshake_client(sock: socket.socket, identity) -> tuple[FrameSession, str]:
    """HELLO(eph) → HELLO_ACK(eph) → klucz → FIN(podpis) → FIN(podpis serwera)."""
    eph = X25519PrivateKey.generate()
    eph_c = _raw_pub(eph)
    sock.sendall(pack_frame(T_HELLO, 0, eph_c))          # 32B czystego szumu
    fr, _ = parse_frame(_read_exact(sock, BUCKETS[0]))
    if fr is None or fr["type"] != T_HELLO_ACK or len(fr["payload"]) != 32:
        raise FrameError("brak/złe HELLO_ACK")
    eph_s = fr["payload"]
    key = _derive_key(eph.exchange(X25519PublicKey.from_public_bytes(eph_s)))
    sess = FrameSession(sock, key)
    mine = _hello_signed(identity, _hello_core(identity, eph_c, eph_s))
    sock.sendall(sess.send(T_HELLO_FIN, json.dumps(mine).encode()))
    fr = _read_until_any(sock, sess, want=T_HELLO_FIN)
    if fr is None:
        raise FrameError("brak HELLO_FIN serwera")
    peer = json.loads(fr["payload"])
    wallet = _verify_hello(peer, eph_c, eph_s)
    _fx_negotiate(sess, identity, peer, role="client")     # D70: peleryna ON?
    return sess, wallet


def handshake_server(sock: socket.socket, identity) -> tuple[FrameSession, str]:
    fr, _ = parse_frame(_read_exact(sock, BUCKETS[0]))
    if fr is None or fr["type"] != T_HELLO or len(fr["payload"]) != 32:
        raise FrameError("oczekiwano HELLO z efemeryką")
    eph_c = fr["payload"]
    eph = X25519PrivateKey.generate()
    eph_s = _raw_pub(eph)
    sock.sendall(pack_frame(T_HELLO_ACK, 0, eph_s))
    key = _derive_key(eph.exchange(X25519PublicKey.from_public_bytes(eph_c)))
    sess = FrameSession(sock, key)
    fr = _read_until_any(sock, sess, want=T_HELLO_FIN)
    if fr is None:
        raise FrameError("brak HELLO_FIN klienta")
    peer = json.loads(fr["payload"])
    wallet = _verify_hello(peer, eph_c, eph_s)
    mine = _hello_signed(identity, _hello_core(identity, eph_c, eph_s))
    sock.sendall(sess.send(T_HELLO_FIN, json.dumps(mine).encode()))
    _fx_negotiate(sess, identity, peer, role="server")     # D70: PO swoim FIN na drucie!
    return sess, wallet


def _read_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise FrameError("połączenie zamknięte w handshake")
        data += chunk
    return data


def _fx_negotiate(sess: FrameSession, identity, peer_fin: dict, *, role: str) -> None:
    """Umowa peleryny (D70): JEŚLI peer też przysłał "fx" — liczymy klucze z
    (klucz sesji eph ⊕ DH ze STATYCZNYCH x-kluczy) i włączamy XOR na CT.
    Strona bez flagi = link bez peleryny (czysty AEAD — uczciwa kompatybilność)."""
    if peer_fin.get("fx") != _fx.FNX64_WIRE_VER or sess.key is None:
        return
    dh = identity.x25519_shared(bytes.fromhex(peer_fin["x_pub"]))
    pair = _fx.fx_pair(sess.key, dh, role=role)
    sess.enable_fx(pair["send"], pair["recv"])


def _read_until_any(sock, sess: FrameSession, want: int):
    deadline = 20
    sock.settimeout(deadline)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            sess.accept(chunk)
            while True:
                try:
                    fr = sess.try_parse()
                except FrameError:
                    continue                    # resync bajt po bajcie, jak w noda
                if fr is not None:
                    return fr if fr["type"] == want else None
                break
    except socket.timeout:
        return None


# ---------------------------------------------------------------- test
if __name__ == "__main__":
    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
    from core.identity import Identity

    print("net/frame.py — selftest: handshake-eph, AEAD pełne, buckets, replay, tamper\n")
    ala, bob = Identity.generate("ala"), Identity.generate("bob")
    s1, s2 = socket.socketpair()

    result = {}
    def _server():
        sess, w = handshake_server(s2, bob)
        result["server"] = (sess, w)
    th = threading.Thread(target=_server, daemon=True)
    th.start()
    csess, cw = handshake_client(s1, ala)
    th.join(timeout=10)
    ssess, sw = result["server"]
    assert cw == bob.wallet and sw == ala.wallet
    print("  [OK] 1. handshake: portfele potwierdzone obustronnie pod kluczem sesji")

    # rozmiary na wiresie: tylko kubełki 1024/4096
    raw = csess.send(T_PING, b"ping")
    assert len(raw) == 1024
    raw2 = csess.send(T_BLOCK_NEW, b"x" * 1500)
    assert len(raw2) == 4096
    print("  [OK] 2. drut: 1500B → ramka 4096B; 4B → 1024B (padding losowy)")

    # odbiór strumieniowy (połówki rekordów — TCP nie gwarantuje ramek)
    ssess.accept(raw[:700])
    assert ssess.try_parse() is None
    ssess.accept(raw[700:] + raw2[:100])
    fr = ssess.try_parse()
    assert fr and fr["type"] == T_PING and fr["payload"] == b"ping"
    ssess.accept(raw2[100:])
    fr2 = ssess.try_parse()
    assert fr2 and fr2["type"] == T_BLOCK_NEW and len(fr2["payload"]) == 1500
    print("  [OK] 3. parser strumienia: ramka poczęta w jednym recv, skończona w innym")

    # POUFNOŚĆ: payload NIE MA na drucie (regresja: dawniej AEAD-robiło-sam-MAC)
    marker = b'{"typ":"TRANSFER","amount":424242,"do":"FNX1SEKRETNYWALLET"}'
    raw3 = csess.send(T_TX_SUBMIT, marker)
    for m in (marker, b"amount", b"TRANSFER", b"FNX1"):
        assert m not in raw3, f"PRZECIEK na drucie: {m}"
    ssess.accept(raw3)
    fr = None
    for _ in range(8192):
        try:
            fr = ssess.try_parse()
        except FrameError:
            continue
        if fr is not None:
            break
    assert fr and fr["payload"] == marker, "deszyfracja dała inną treść!"
    print("  [OK] 4. AEAD SZYFRUJE: zero payloadu na drucie, odbiorca czyta w 100%")

    # tamper: flip bitu w środku ramki → AEAD nieważny; resync nie zapętla się
    bad = bytearray(ssess.send(T_PONG, b"pong"))
    bad[40] ^= 1
    csess.accept(bytes(bad))
    raised = 0
    try:
        for _ in range(4096):          # resync gryzie śmieci bajt po bajcie
            if csess.try_parse() is not None:
                break
        raise AssertionError("tamper przeszedł jako ramka!")
    except FrameError:
        raised = 1
    assert raised, "brak wyjątku po tamperze"
    print("  [OK] 5. przekłamanie 1 bitu → drop; parser resynchronizuje (nie zapętla)")

    # replay: ta sama ramka drugi raz — po resync OLEWAMY śmieci i dochodzi
    good = ssess.send(T_PONG, b"again")
    csess.accept(good)
    fr = None
    for _ in range(8192):
        try:
            fr = csess.try_parse()
        except FrameError:             # resync po trującej ramce z pkt. 5
            continue
        if fr is not None:
            break
    assert fr is not None and fr["payload"] == b"again", "dobra ramka po resync"
    csess.accept(good)
    try:
        for _ in range(8192):
            csess.try_parse()
        raise AssertionError("replay przeszedł!")
    except FrameError as e:
        assert "replay" in str(e) or "okno" in str(e)
        print("  [OK] 6. replay (ten sam SEQ) odrzucony oknem 4096")

    # ---------------------------------------------------------------- D70: FNX64
    s3, s4 = socket.socketpair()
    res2 = {}
    def _server2():
        ssec2, w2 = handshake_server(s4, bob)
        res2["s"] = (ssec2, w2)
    th2 = threading.Thread(target=_server2, daemon=True)
    th2.start()
    csec2, cw2 = handshake_client(s3, ala)
    th2.join(timeout=10)
    ssec2, sw2 = res2["s"]
    assert csec2.fx_send is not None and ssec2.fx_recv is not None
    rawfx = csec2.send(T_MSG, b"fnx64-peleryna-marker-777")
    # peleryna jest REALNA: ten sam klucz AEAD, ale BEZ zdjęcia FNX64 = stój
    try:
        fr_no, _ = parse_frame(rawfx, csec2.key)         # bez fx_recv!
        raise SystemExit(f"ramka w pelerynie czytelna bez FNX64?! {fr_no}")
    except FrameError:
        pass
    for m in (b"peleryna", b"marker", b"777"):
        assert m not in rawfx, f"PRZECIEK peleryny: {m}"
    ssec2.accept(rawfx)
    frw = None
    for _ in range(4096):
        try:
            frw = ssec2.try_parse()
        except FrameError:
            continue
        if frw is not None:
            break
    assert frw and frw["payload"] == b"fnx64-peleryna-marker-777", "peleryna zjadła treść!"
    print("  [OK] 7. FNX64: CT na drucie = AEAD⊕peleryna (bez klucza fx = czarny ekran;\n"
          "           zdjęcie warstwy → odbiorca czyta 1:1); negocjacja obustronna ON")
    rawfx2 = csec2.send(T_MSG, b"fnx64-peleryna-marker-777")
    assert rawfx2[17:] != rawfx[17:], "ten sam payload/seq+1 = identyczny CT?! (seq liczy)"
    # para sesji z INNYM static-DH ⇒ inna peleryna nawet przy tym samym AEAD-key
    probe = _fx.fnx64_xor(rawfx[HDR_LEN:], csec2.fx_send, 0)
    assert probe != rawfx[HDR_LEN:], "sanity fx"
    s3.close(); s4.close()
    print("  [OK] 8. strumień per-SEQ unikalny; peleryna spięta z sesją (C2S/S2C lustrem)")

    s1.close(); s2.close()
    print("\nSELFTEST: PASS ✅  ramka + sesja AEAD (pełne szyfrowanie) + peleryna\n"
          "FNX64 (tetracja do 10) negocjowana w HELLO_FIN — gotowe do noda (D70)")
