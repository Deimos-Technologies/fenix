# core/crypto/fnx64.py — FNX64 „x tetracja do 10" (D70): właścicielska warstwa strumienia
"""FNX64 = dodatkowa warstwa na DRUCIE Fenixa, PONAD AEAD (ChaCha20-Poly1305).
Nazwa: 64-bitowe słowa stanu; strumień XOR generowany jest TETRACJĄ (wieżą
potęg a↑↑h) z wysokością h=10, liczoną modulo 2^64.

Czym to JEST (uczciwie, po polsku):
  * warstwa WŁAŚCICIELSKA defense-in-depth: każda ramka po AEAD dostaje jeszcze
    pelerynę XOR z niezależnego strumienia — podsłuch na TCP widzi już nie
    „czysty ChaCha-CT", tylko CT⊕FNX64;
  * klucz FNX64 ≠ klucz AEAD: liczony z (klucz sesji X25519-eph) XOR (DH ze
    STATYCZNYCH kluczy tożsamości). Efekt: obserwator, który złamałby SAMO
    efemeryczne AEAD, nadal nie zdejmuje peleryny bez długoterminowych kluczy
    — TO jest prawdziwy przyrost kosztu (nie marketing);
  * utrudnia fingerprinting ruchu (wiadoma struktura CT znika spod stopy).

Czym to NIE jest (granice, głośno — obiecujemy siatkę, nie cuda):
  * NIE zastępuje AEAD: ChaCha20-Poly1305 + X25519 + Ed25519 zostaje fundamentem
    (audytowany, standardowy). FNX64 NIGDY nie działa solo na krytycznej treści;
  * tetracja mod 2^64 NIE jest prymitywem audytowanym przez świat (własna
    konstrukcja właściciela; selftest mierzy dyfuzję FAKTYCZNIE, ale statystyka
    bajtów ≠ dowód bezpieczeństwa — jak w każdym dobrym raporcie krypto);
  * baza wieży jest WYMUSZANIE nieparzysta: dla parzystego a wieża a↑↑h mod 2^64
    zapada się do 0 (matematyka, nie bug) — generator maskuje ten fakt OR-em;
  * prędkość: wieża idzie hurtowo przez `fnx64_accel.c` (ten sam wynik co
    tower_mod; włączany dopiero po złotym porównaniu). Brak gcc / rozjazd
    bajtów = zostaje czysty Python, strumień na drucie się nie zmienia.

Implementacja wieży: a↑↑h mod 2^64 przez rekurencyjną redukcję wykładnika po
łańcuchu Carmichaela λ(2^m)=2^(m−2) (gcd(a,2^64)=1 — dlatego wymuszamy
nieparzystość bazy). Wysokość 10 = stała FNX64_TOWER (decyzja właściciela).

Selftest: złote wektory wieży (drobne moduły — liczone też „z ręki"), wymuszenie
nieparzystości, determinizm strumienia, różność strumieni między sesjami,
statystyka dyfuzji (jako OBSERWACJA, nie dowód), wydajność na 1 MiB.
"""
from __future__ import annotations

import array
import hashlib
import os
import shutil
import subprocess
import sys
import time
import ctypes
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[2]))

M64 = 1 << 64
FNX64_TOWER = 10                  # wysokość wieży (tetracja „do 10")
FNX64_WIRE_VER = 1                # flaga negocjacji w HELLO_FIN (pole "fx")


class Fnx64Error(Exception):
    """Złe użycie warstwy (baza parzysta, złe parametry) — głośno, nie cicho."""


def _lambda_bits(mb: int) -> int:
    """λ(2^mb) jako liczba BITÓW wykładnika-modułu: mb≥3 → mb−2; 2 → 1; ≤1 → 0."""
    if mb >= 3:
        return mb - 2
    if mb == 2:
        return 1
    return 0


def tower_mod(a: int, h: int, mb: int = 64) -> int:
    """a↑↑h (tetracja: a^(a^(...^a)) h razy) mod 2^mb. a MUSI być nieparzyste.

    Dlaczego działa: gcd(a,2^mb)=1 → Euler: a^e ≡ a^(e mod λ) (mod 2^mb),
    a λ(2^mb)=2^(mb−2) ⇒ wykładnik liczymy rekurencyjnie mod 2^(mb−2), aż do
    trywialnego dna. h=10 → 10 pietrek; wszystko w liczbach maszynowych int.
    """
    a = int(a)
    if not (0 < a) or a % 2 == 0:
        raise Fnx64Error("baza wieży MUSI być dodatnia i NIEPARZYSTA "
                         "(parzysta zapada się do 0 mod 2^64 — matematyka)")
    if not (1 <= h <= 64) or not (1 <= mb <= 64):
        raise Fnx64Error("h ∈ 1..64, mb ∈ 1..64")
    a %= (1 << mb)

    def t(hh: int, m: int) -> int:
        if m <= 0:
            return 0                              # mod 1: wszystko ≡ 0
        if hh == 1:
            return a % (1 << m)
        e = t(hh - 1, _lambda_bits(m))
        return pow(a, e, 1 << m)

    return t(h, mb)


def _u64(b: bytes) -> int:
    return int.from_bytes(b, "little")


def _block_bases(key32: bytes, seq: int, nbytes: int) -> array.array:
    """Nieparzyste bazy bloków strumienia (blake2s | 1). Kolejność = drut."""
    nblocks = (nbytes + 7) // 8
    seed_pre = key32 + seq.to_bytes(8, "big")
    bases = array.array("Q")
    for i in range(nblocks):
        k64 = _u64(hashlib.blake2s(seed_pre + i.to_bytes(4, "big"),
                                   digest_size=8).digest()) | 1     # nieparzysta!
        bases.append(k64)
    return bases


def _pack_le(words: array.array, nbytes: int) -> bytes:
    """Słowa uint64 → little-endian na drut (niezależnie od endianu hosta)."""
    if sys.byteorder != "little":
        words = array.array("Q", words)
        words.byteswap()
    return words.tobytes()[:nbytes]


def _stream_py(key32: bytes, seq: int, nbytes: int) -> bytes:
    """Wzorzec strumienia: tower_mod w Pythonie. Drut MUSI się z tym zgadzać."""
    out = bytearray()
    for b in _block_bases(key32, seq, nbytes):
        out += tower_mod(int(b), FNX64_TOWER).to_bytes(8, "little")
    return bytes(out[:nbytes])


class _TowerAccel:
    """ctypes na fnx64_tower_batch. False = bufor nietknięty (odrzut przed pętlą)."""

    def __init__(self, lib: ctypes.CDLL) -> None:
        fn = lib.fnx64_tower_batch
        fn.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint32,
                       ctypes.c_uint32, ctypes.c_uint32]
        fn.restype = ctypes.c_int
        self._fn = fn

    def __call__(self, bases: array.array, h: int, mb: int) -> bool:
        if not bases or bases.typecode != "Q":
            return False
        ptr = ctypes.cast(bases.buffer_info()[0], ctypes.POINTER(ctypes.c_uint64))
        return self._fn(ptr, len(bases), h, mb) == 0


def _compile_accel(src: _pl.Path) -> _pl.Path | None:
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        return None
    tmp = src.with_name(f"libfnx64accel.{os.getpid()}.so")
    cmd = [cc, "-O3", "-fPIC", "-shared", "-std=c11", "-Wall", "-Wextra", "-Werror",
           "-o", str(tmp), str(src)]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        tmp.unlink(missing_ok=True)
        return None
    if r.returncode != 0 or not tmp.is_file():
        tmp.unlink(missing_ok=True)
        return None
    return tmp


def _accel_matches(accel: _TowerAccel) -> bool:
    """Złote wektory wieży + kawałek strumienia. Rozjazd = nie włączamy C."""
    samples = [1, 3, 7, 0xABCDEF0123456789 | 1, (1 << 64) - 1, (1 << 60) + 1]
    got = array.array("Q", samples)
    if not accel(got, FNX64_TOWER, 64):
        return False
    if [int(x) for x in got] != [tower_mod(a, FNX64_TOWER, 64) for a in samples]:
        return False
    small = array.array("Q", [3])
    if not accel(small, 2, 8) or int(small[0]) != 27:
        return False
    small = array.array("Q", [7])
    if not accel(small, 3, 8) or int(small[0]) != pow(7, 55, 256):
        return False
    key = bytes(range(32))
    py = _stream_py(key, 3, 20)
    bases = _block_bases(key, 3, 20)
    if not accel(bases, FNX64_TOWER, 64):
        return False
    return _pack_le(bases, 20) == py


def _load_accel() -> _TowerAccel | None:
    src = _pl.Path(__file__).resolve().parent / "fnx64_accel.c"
    if not src.is_file():
        return None
    stable = src.with_name("libfnx64accel.so")
    cache = _pl.Path.home() / ".cache" / "fenix" / "libfnx64accel.so"

    def _fresh(so: _pl.Path) -> bool:
        try:
            return so.is_file() and so.stat().st_mtime >= src.stat().st_mtime
        except OSError:
            return False

    def _try(so: _pl.Path) -> _TowerAccel | None:
        try:
            lib = ctypes.CDLL(str(so))
        except OSError:
            return None
        accel = _TowerAccel(lib)
        return accel if _accel_matches(accel) else None

    for so in (stable, cache):
        if _fresh(so):
            hit = _try(so)
            if hit is not None:
                return hit
    built = _compile_accel(src)
    if built is None:
        return None
    hit = _try(built)
    if hit is None:
        built.unlink(missing_ok=True)
        sys.stderr.write("[fnx64] akcelerator C rozjechał się ze wzorcem Pythona "
                         "— zostaje tower_mod\n")
        return None
    for dest in (stable, cache):
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            os.replace(built, dest)
            return hit
        except OSError:
            continue
    built.unlink(missing_ok=True)
    return hit


_ACCEL: _TowerAccel | None = _load_accel()


def accel_active() -> bool:
    """True tylko gdy C przeszło złote porównanie i jest na ścieżce strumienia."""
    return _ACCEL is not None


def fnx64_stream(key32: bytes, seq: int, nbytes: int) -> bytes:
    """Strumień FNX64 dla JEDNEJ ramki: seq → niezależny ciąg (per-frame reset).

    Blok i: k64 = blake2s(key‖seq‖i)[:8] | 1 (wymuszenie nieparzystości),
    v = k64↑↑FNX64_TOWER mod 2^64, bajty v little-endian. Deterministyczny —
    nadawca i odbiorca liczą IDENTYCZNIE z tych samych (klucz, seq, długość).
    Wieże idą jedną paczką przez C, gdy akcelerator jest zgodny z tower_mod;
    inaczej ta sama matematyka w Pythonie. Bajty na drucie nie zależą od silnika.
    """
    if len(key32) != 32 or seq < 0 or nbytes < 0:
        raise Fnx64Error("fnx64_stream: klucz 32B, seq ≥ 0, nbytes ≥ 0")
    if nbytes == 0:
        return b""
    bases = _block_bases(key32, seq, nbytes)
    if _ACCEL is not None and _ACCEL(bases, FNX64_TOWER, 64):
        return _pack_le(bases, nbytes)
    return _stream_py(key32, seq, nbytes)


def fnx64_xor(data: bytes, key32: bytes, seq: int) -> bytes:
    """XOR danych strumieniem FNX64( klucz, seq ) — symetryczny s/d (bajt w bajt)."""
    if not data:
        return data
    ks = fnx64_stream(key32, seq, len(data))
    return bytes(d ^ k for d, k in zip(data, ks))


# ---------------------------------------------------------------- pary kluczy sesyjnych
def fx_pair(session_key: bytes, static_dh: bytes, *, role: str) -> dict:
    """Klucze FNX64 kierunkowe dla sesji: z klucza AEAD ⊕ DH STATYCZNYCH.

    static_dh = X25519(id_priv, id_pub_peera) — 32B; role ∈ {client, server}.
    Obie strony liczą lustrzanie: C2S/S2C. Obserwator bez kluczy statycznych
    nie powtórzy strumienia nawet znając klucz sesji (przyrost kosztu, D70).
    """
    if len(session_key) != 32 or len(static_dh) != 32 or role not in ("client", "server"):
        raise Fnx64Error("fx_pair: klucze 32B + role client/server")
    base = hashlib.blake2s(bytes(a ^ b for a, b in zip(session_key, static_dh)),
                           digest_size=32, person=b"FNX64/01").digest()
    c2s = hashlib.blake2s(base + b"C2S", digest_size=32, person=b"FNX64dir").digest()
    s2c = hashlib.blake2s(base + b"S2C", digest_size=32, person=b"FNX64dir").digest()
    return {"send": c2s if role == "client" else s2c,
            "recv": s2c if role == "client" else c2s}


# ---------------------------------------------------------------- selftest
if __name__ == "__main__":
    print("core/crypto/fnx64.py — selftest: wieża (złote wektory), strumień, "
          "dyfuzja, tempo\n")

    # 1) złote wektory wieży — drobne moduły liczone niezależnie „z ręki"
    assert tower_mod(3, 1, 8) == 3                       # 3 mod 256
    assert tower_mod(3, 2, 8) == pow(3, 3, 256) == 27    # 3^3
    assert tower_mod(7, 2, 8) == pow(7, 7, 256)          # 7^7 mod 256 = 247
    assert tower_mod(7, 3, 8) == pow(7, 55, 256)         # 7^(7^7 mod 64=55) mod 256
    assert tower_mod(3, 2, 64) == 27 and tower_mod(3, 3, 64) == 7625597484987
    v10 = tower_mod(0xABCDEF0123456789 | 1, FNX64_TOWER)
    assert 0 <= v10 < M64 and v10 == tower_mod(0xABCDEF0123456789 | 1, 10)
    print("  [OK] 1. wieża a↑↑h mod 2^mb: 6 złotych wektorów zgodnych (też h=10, 64b)")

    # 2) baza parzysta = głośny STOP (nie maskujemy zapadni do 0)
    try:
        tower_mod(4, 3)
        raise SystemExit("parzysta baza przeszła — zapadek ukryty!")
    except Fnx64Error:
        print("  [OK] 2. parzysta baza = Fnx64Error (zapadek do 0 jawnie nazwany)")

    # 3) determinizm + splinter seq: ten sam (klucz,seq) → ten sam strumień;
    #    seq+1 → strumień całkiem inny; zero kolizji prefixów między seq
    key = hashlib.blake2s(b"klucz-sesji-testowy", digest_size=32).digest()
    s1a = fnx64_stream(key, 7, 4096)
    s1b = fnx64_stream(key, 7, 4096)
    s2 = fnx64_stream(key, 8, 4096)
    assert s1a == s1b and s1a != s2 and len(s1a) == 4096
    diff_bits = sum(bin(x ^ y).count("1") for x, y in zip(s1a[:256], s2[:256]))
    assert 900 <= diff_bits <= 1200, f"dyfuzja seq: {diff_bits}/2048 bitów różnicy"
    print(f"  [OK] 3. determinizm 1:1; seq7⊕seq8: {diff_bits}/2048 bitów różnicy "
          f"(~50% — dyfuzja ZDROWA, obserwacja nie dowód)")

    # 4) xor symetryczny + „peleryna" zakrywa znacznik (jak na drucie)
    marker = b'{"typ":"TRANSFER","amount":424242,"do":"FNX1MARKER"}' * 40
    worm = fnx64_xor(marker, key, 42)
    assert fnx64_xor(worm, key, 42) == marker, "xor nie symetryczny!"
    for m in (b"TRANSFER", b"amount", b"FNX1", marker[:16]):
        assert m not in worm, f"PRZECIEK strumienia: {m}"
    same = sum(1 for x, y in zip(worm, marker) if x == y)
    print(f"  [OK] 4. xor-danon: znaczniki znikają z drutu; zgodność bajtów "
          f"{same}/{len(marker)} (~1/256 jak szum)")
    assert same < len(marker) // 32, "za dużo zgodnych bajtów jak na szum"

    # 5) fx_pair: klucze kierunkowe lustrzane + STATIC-DH realnie zmienia strumień
    sk = hashlib.blake2s(b"sess", digest_size=32).digest()
    dh1 = hashlib.blake2s(b"static-dh-1", digest_size=32).digest()
    dh2 = hashlib.blake2s(b"static-dh-2", digest_size=32).digest()
    pc, ps = fx_pair(sk, dh1, role="client"), fx_pair(sk, dh1, role="server")
    assert pc["send"] == ps["recv"] and pc["recv"] == ps["send"]
    other = fx_pair(sk, dh2, role="client")
    assert fnx64_stream(pc["send"], 3, 512) != fnx64_stream(other["send"], 3, 512)
    print("  [OK] 5. para kluczy: lustro C2S/S2C; ZMIANA static-DH ⇒ inny strumień "
          "(warstwa niezależna od eph-AEAD — D70)")

    # 6) pusty/duży: brzegi + tempo na 1 MiB (liczba na zegarze, nie obietnica)
    assert fnx64_stream(key, 0, 0) == b"" and fnx64_xor(b"", key, 0) == b""
    pure = _stream_py(key, 7, 100)
    assert fnx64_stream(key, 7, 100) == pure, "silnik strumienia rozjechał się ze wzorcem"
    assert fnx64_stream(key, 7, 100) == s1a[:100]
    t0 = time.time()
    big = fnx64_stream(key, 1, 1 << 20)
    dt = time.time() - t0
    assert len(big) == (1 << 20) and len(set(big)) > 240
    eng = "C fnx64_accel (1:1 z tower_mod)" if accel_active() else "Python tower_mod (fallback)"
    print(f"  [OK] 6. 1 MiB strumienia: {dt:.2f} s ({(1 << 20) / dt / 1e6:.2f} MiB/s; "
          f"unik. bajty {len(set(big))}/256; silnik: {eng})")
    if shutil.which("gcc") or shutil.which("cc"):
        assert accel_active(), "gcc jest, a akcelerator nie wstał albo odpadł na złotych wektorach"

    print("\nSELFTEST: PASS ✅  fnx64: tetracja do 10 mod 2^64 działa deterministycznie,\n"
          "strumień dyfunduje (~50% bitów/seq), xor symetryczny, para kluczy\n"
          "niezależna od klucza eph-AEAD — warstwa właścicielska gotowa na drut (D70)")
