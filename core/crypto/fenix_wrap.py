# crypto/fenix_wrap.py
"""
FNX-WRAP v1 — WŁASNA warstwa szyfrująca Fenixa.

Status prawny projektu: WARSTWA DODATKOWA (decyzja D2), NIGDY jedyna.
Zawsze działa WEWNĄTRZ kanału AEAD (XChaCha20-Poly1305 wg protocol_spec.md).
Gdyby FNX-WRAP pękł całkowicie — atakujący dalej stoi przed prawdziwym murem.
Gdyby mur miał pęknąć — wrap dokłada mu drugą ścianę. Defense in depth.

Konstrukcja = własny przepis złożony WYŁĄCZNIE z bezpiecznych składników:
  1. S-box 256B  — deterministyczna permutacja z łańcucha SHA-512.
                   PUBLICZNA i odtwarzalna. Zasada Kerckhoffsa (Filar 3):
                   bezpieczeństwo siedzi w KLUCZU, nie w tajności budowy.
  2. Szyfr blokowy Feistela — 128-bit blok, 24 rundy,
     F(x, rk) = S( rot(P( S(x⊕rk) )) ⊕rk )  — każdy bajt wyjścia zależy
     od klucza rundy i od wszystkich bajtów wejścia po kilku rundach (lawina).
  3. Tryb CTR — szyfr używany TYLKO w przód: XOR tekstu z keystreamem
     E(nonce⊕licznik). Zero paddingu (CTR tego nie potrzebuje) i zero kodu
     deszyfrującego blok = mniej miejsc na błąd. Padding robi warstwa ramek.
  4. Encrypt-then-MAC — tag = HMAC-SHA256(mac_key, FW1‖nonce‖len(aad)‖aad‖ct)[:16].
     NAJPIERW weryfikacja tagu, DOPIERO potem deszyfrowanie. Jeden typ wyjątku
     na wszystko złe — atakujący nie dowiaduje się CO nie pasowało.
  5. Rozdzielność kluczy — enc i mac wychodzą z master przez HKDF z RÓŻNYM
     labelami. Jeden klucz nigdy nie robi dwóch rzeczy naraz.

Co ta warstwa DAJE (szczerze):
  + głębia obrony: złamanie kanału wymaga obu kryptosystemów niezależnie
  + własny "podpis konstrukcyjny" sieci (nasz przepis, nasze stałe, nasza wersja)
  + nauka na żywym kodzie: S-box, Feistel, lawina, tryby, MAC
Czego NIE DAJE: samodzielnego bezpieczeństwa. Traktuj jak zamek na wewnętrznych
drzwiach sejfu — zamek Twój, sejf certyfikowany.

Wpięcie w protokół (M2, net/frame.py):
    sess = handshake(...)                                  # X25519→HKDF "fenix/sess/01"
    wrap = FenixWrap.from_session(sess_key)                # OSOBNY label HKDF!
    payload = wrap.encrypt(plaintext, aad=frame_header)    # nasza warstwa
    frame  = pad_to_1024_or_4096(build_frame(payload))     # protocol_spec
    wire   = aead_xchacha20_encrypt(frame, sess_enc_key)   # prawdziwy mur

Transakcje (M5): tx podpisana Ed25519 → wrap.encrypt(tx_bytes, aad=b"tx/"+typ)
→ ten sam kanał. Stealth address ukryje odbiorcę; rura szyfrująca się nie zmienia.

Wydajność (uczciwie): czysty Python ~0.2–2 MB/s zależnie od CPU. To WARSTWA
DODATKOWA dla control-plane'u (wiadomości, tx, zdarzenia — małe payloady). Bulk/file transfer
może ominąć wrap (to tylko dodatek) albo później dostanie wersję natywną (C/Rust).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"FW1"      # nagłówek wersji: "Fenix Wrap v1" — zmiana algorytmu = nowa wersja
ROUNDS = 24         # rundy Feistela: 16 to minimum edukacyjne, 24 = zapas
BLOCK = 16          # blok 128-bit
NONCE_LEN = 16      # losowy nonce na KAŻDĄ wiadomość (CTR + powtórzony nonce = katastrofa)
TAG_LEN = 16        # własny tag 16B; zewnętrzny AEAD i tak dokłada swój — to zapas

# Stała permutacja bajtów w funkcji rundy — dowolna, ale zamrożona na wieki
# (zmiana = inny algorytm = nowa wersja MAGIC).
_PERM = (3, 7, 1, 5, 0, 6, 2, 4)


def _build_sbox() -> bytes:
    """Deterministyczna permutacja 0..255 (Fisher-Yates po strumieniu SHA-512).

    Celowo PUBLICZNA: każdy może odtworzyć ten sam S-box. To nie słabość —
    sekretem jest klucz, nie budowa (Kerckhoffs). Permutacja (nie losowa
    tablica) gwarantuje, że substytucja jest odwracalna i bez powtórzeń.
    """
    stream = bytearray()
    c = 0
    while len(stream) < 4096:
        stream += hashlib.sha512(b"FENIX-WRAP/v1/sbox" + c.to_bytes(4, "big")).digest()
        c += 1
    arr = list(range(256))
    pos = 0
    for i in range(255, 0, -1):
        j = int.from_bytes(stream[pos:pos + 2], "big") % (i + 1)
        pos += 2
        arr[i], arr[j] = arr[j], arr[i]
    return bytes(arr)


SBOX = _build_sbox()


def _hkdf(ikm: bytes, info: bytes, length: int, salt: bytes = b"fenix-wrap-v1") -> bytes:
    """HKDF-SHA256 — z jednego materiału wyciąga NIEZALEŻNE klucze per label."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def _xor(a: bytes, b: bytes) -> bytes:
    """XOR bajt-stringów przez inty — najszybszy XOR w czystym Pythonie
    (jedna operacja w C zamiast pętli po bajtach). Krótszy przycina dłuższy."""
    n = min(len(a), len(b))
    return (int.from_bytes(a[:n], "big") ^ int.from_bytes(b[:n], "big")).to_bytes(n, "big")


class FenixWrapError(Exception):
    """CELOWO jeden typ wyjątku na wszystkie błędy wejścia — atakujący nie
    może się dowiedzieć, czy nie pasował tag, nagłówek czy długość (orakel
    to wektor ataku — patrz threat_model)."""


class FenixWrap:
    """Własna warstwa szyfrująca.

    master_key: ≥16B, MUSI pochodzić z HKDF z osobnym labelem niż klucz AEAD
    kanału (najlepiej: FenixWrap.from_session(sess_key) — wymusza rozdzielność).
    """

    def __init__(self, master_key: bytes):
        if len(master_key) < 16:
            raise FenixWrapError("master key za krótki (min 16B, celuj w 32B z HKDF)")
        # Rozdzielność: szyfrowanie i MAC to dwa różne klucze od dnia zero.
        enc_ikm = _hkdf(master_key, b"fenix/wrap/01/enc", 32)
        self._mac_key = _hkdf(master_key, b"fenix/wrap/01/mac", 32)
        # Key schedule: 24 rund × 8B klucza rundy — jeden HKDF, raz na sesję.
        rks = _hkdf(enc_ikm, b"fenix/wrap/01/roundkeys", 8 * ROUNDS)
        self._rk = [int.from_bytes(rks[8 * i:8 * i + 8], "big") for i in range(ROUNDS)]

    @classmethod
    def from_session(cls, sess_key: bytes) -> "FenixWrap":
        """JEDYNY zalecany sposób tworzenia w protokole: klucz wrapa = HKDF
        z klucza sesji pod OSOBNYM labelem. Klucz AEAD (fenix/sess/01) i klucz
        wrapa nigdy się nie spotkają — złamanie jednego nie rusza drugiego."""
        return cls(_hkdf(sess_key, b"fenix/wrap/01", 32))

    # --- wnętrze szyfru -----------------------------------------------------

    def _f(self, data8: bytes, rnd: int) -> bytes:
        """Funkcja rundy F: klucz rundy → substytucja → permutacja+rotacja → substytucja.
        Lawina: po kilku rundach każdy bit wyjścia zależy od każdego bitu wejścia."""
        rk = self._rk[rnd]
        x = (int.from_bytes(data8, "big") ^ rk).to_bytes(8, "big")
        x = x.translate(SBOX)                  # S: nieliniowość (bajt nie przechodzi "po prostej")
        x = bytes(x[i] for i in _PERM)         # P: rozrzuca bajty po pozycjach
        r = rnd & 7
        x = x[r:] + x[:r]                      # rotacja zależna od numeru rundy
        x = (int.from_bytes(x, "big") ^ rk).to_bytes(8, "big")
        x = x.translate(SBOX)                  # druga warstwa S na wyjściu
        return x

    def _enc_block(self, block16: bytes) -> bytes:
        """Feistel 24 rundy, blok 128-bit. W CTR używamy szyfru TYLKO w przód,
        więc funkcji deszyfrującej blok tu świadomie nie ma = mniej kodu, mniej ryzyka."""
        L, R = block16[:8], block16[8:]
        for rnd in range(ROUNDS):
            L, R = R, _xor(L, self._f(R, rnd))
        return L + R

    def _stream_xor(self, data: bytes, nonce: bytes) -> bytes:
        """Tryb CTR: keystream_i = E(nonce ⊕ i), szyfrogram = tekst ⊕ keystream.
        Deszyfrowanie = ta sama operacja (XOR jest swoją odwrotnością)."""
        out = bytearray(len(data))
        n_int = int.from_bytes(nonce, "big")
        for i in range(0, len(data), BLOCK):
            ctr = ((n_int ^ (i // BLOCK)) % (1 << 128)).to_bytes(BLOCK, "big")
            ks = self._enc_block(ctr)
            chunk = data[i:i + BLOCK]
            out[i:i + len(chunk)] = _xor(chunk, ks)
        return bytes(out)

    def _tag(self, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
        m = hmac.new(self._mac_key, digestmod=hashlib.sha256)
        m.update(MAGIC)
        m.update(nonce)
        # długość AAD w strumieniu zapobiega "przesunięciu granicy" aad/ct
        m.update(len(aad).to_bytes(4, "big"))
        m.update(aad)
        m.update(ct)
        return m.digest()[:TAG_LEN]

    # --- API ----------------------------------------------------------------

    def encrypt(self, plaintext: bytes, aad: bytes = b"", nonce: bytes | None = None) -> bytes:
        """Zwraca blob: MAGIC(3) ‖ NONCE(16) ‖ CT ‖ TAG(16).
        aad = dane NIEszyfrowane, ale uwierzytelniane (np. nagłówek ramki/typ tx)."""
        if nonce is None:
            nonce = os.urandom(NONCE_LEN)      # nowy losowy nonce na każdą wiadomość
        if len(nonce) != NONCE_LEN:
            raise FenixWrapError("nonce musi mieć dokładnie 16B")
        ct = self._stream_xor(plaintext, nonce)
        return MAGIC + nonce + ct + self._tag(nonce, ct, aad)

    def decrypt(self, blob: bytes, aad: bytes = b"") -> bytes:
        """Najpierw weryfikacja tagu (compare_digest — stały czas), potem deszyfr."""
        if len(blob) < len(MAGIC) + NONCE_LEN + TAG_LEN or blob[:3] != MAGIC:
            raise FenixWrapError("FNX-WRAP: odrzucono (nagłówek/tag)")
        nonce = blob[3:3 + NONCE_LEN]
        ct = blob[3 + NONCE_LEN:-TAG_LEN]
        tag = blob[-TAG_LEN:]
        if not hmac.compare_digest(tag, self._tag(nonce, ct, aad)):
            raise FenixWrapError("FNX-WRAP: odrzucono (nagłówek/tag)")
        return self._stream_xor(ct, nonce)


# ---------------------------------------------------------------------------
# Selftest — uruchom:  python crypto/fenix_wrap.py
# ---------------------------------------------------------------------------

def _selftest() -> None:
    print("FNX-WRAP v1 — selftest (warstwa dodatkowa, D2)\n")

    k = FenixWrap(os.urandom(32))
    msg = b"FNX tx: ALICJA -> BOB 0.5 FNX | podpis Ed25519 w srodku" * 3

    # 1) roundtrip z AAD (symulacja nagłówka ramki/typu transakcji)
    blob = k.encrypt(msg, aad=b"tx/TRANSFER")
    assert k.decrypt(blob, aad=b"tx/TRANSFER") == msg
    print("  [OK] 1. roundtrip (szyfruj→odszyfruj = to samo)")

    # 2) pusta wiadomość też działa (CTR bez paddingu to lubi)
    assert k.decrypt(k.encrypt(b"")) == b""
    print("  [OK] 2. pusta wiadomość")

    # 3) manipulacja JEDNYM bitem w szyfrogramie → odrzut
    bad = bytearray(blob)
    bad[NONCE_LEN + 5] ^= 1
    try:
        k.decrypt(bytes(bad), aad=b"tx/TRANSFER")
        raise AssertionError("przyjeto sfalszowany szyfrogram!")
    except FenixWrapError:
        print("  [OK] 3. manipulacja 1-bitowa = odrzut (HMAC EtM działa)")

    # 4) AAD nie pasuje (np. ktoś podmienił typ ramki) → odrzut
    try:
        k.decrypt(blob, aad=b"tx/RANK_UP")
        raise AssertionError("przyjeto ze zlym AAD!")
    except FenixWrapError:
        print("  [OK] 4. podmiana nagłówka = odrzut")

    # 5) obcy klucz → odrzut
    try:
        FenixWrap(os.urandom(32)).decrypt(blob, aad=b"tx/TRANSFER")
        raise AssertionError("przyjeto obcym kluczem!")
    except FenixWrapError:
        print("  [OK] 5. obcy klucz = odrzut")

    # 6) S-box jest permutacją (sanity konstrukcyjne)
    assert sorted(SBOX) == list(range(256))
    print("  [OK] 6. S-box = permutacja 256B")

    # 7) LAWINA: flip 1 bitu na wejściu bloku ≈ połowa bitów wyjścia się zmienia.
    #    To SERCE dobrego szyfru: brak lawiny = atakujący widzi zależności.
    import random
    random.seed(0xF11C0DE)
    diffs = []
    for _ in range(96):
        x = random.randbytes(16)
        y = k._enc_block(x)
        xb = bytearray(x)
        xb[random.randrange(16)] ^= 1 << random.randrange(8)
        y2 = k._enc_block(bytes(xb))
        diffs.append(sum(bin(a ^ b).count("1") for a, b in zip(y, y2)))
    mn, avg = min(diffs), sum(diffs) / len(diffs)
    assert mn >= 24 and 48 <= avg <= 80, f"slaba lawina: min={mn} avg={avg}"
    print(f"  [OK] 7. lawina: min={mn}/128, średnia={avg:.1f}/128 (ideał ≈ 64)")

    # 8) duża wiadomość + tempo (uczciwie: to Python, warstwa control-plane)
    big = os.urandom(100 * 1024)
    t0 = time.time()
    bb = k.encrypt(big, aad=b"msg/BLOB")
    dt = time.time() - t0
    assert k.decrypt(bb, aad=b"msg/BLOB") == big
    print(f"  [OK] 8. 100 KB roundtrip; tempo ~{100 / 1024 / dt:.2f} MB/s (Python)")

    # 9) DEMO WARSTW (D2 w praktyce): FNX-WRAP wewnątrz AES-256-GCM
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aes_key, n12 = os.urandom(32), os.urandom(12)
    aes = AESGCM(aes_key)
    wire = aes.encrypt(n12, blob, b"fenix-frame")     # blob = nasz wrap w środku

    # 9a) atakujący bez klucza kanału nie widzi nawet, że wrap istnieje:
    try:
        AESGCM(os.urandom(32)).decrypt(n12, wire, b"fenix-frame")
        raise AssertionError("AEAD przyjal obcy klucz!")
    except AssertionError:
        raise
    except Exception:
        print("  [OK] 9a. bez klucza kanału AEAD: zero widoczności (wrap ukryty)")

    # 9b) złamanie JEDNEJ warstwy ≠ złamanie kanału (niezależne klucze):
    inner = aes.decrypt(n12, wire, b"fenix-frame")    # mur "pękł" (znany klucz)
    try:
        FenixWrap(os.urandom(32)).decrypt(inner, aad=b"tx/TRANSFER")
        raise AssertionError("wrap przyjal obcy klucz!")
    except FenixWrapError:
        print("  [OK] 9b. mur pękł → wrap dalej trzyma (i odwrotnie)")

    print("\nSELFTEST: PASS ✅  (FNX-WRAP = własna warstwa DODATKOWA na AEAD — decyzja D2)")


if __name__ == "__main__":
    _selftest()
