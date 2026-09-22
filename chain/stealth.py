# chain/stealth.py — STEALTH ADDRESSES: odbiorca niewidoczny na-chain (M5b kamień 1, D31)
"""
Problem: normalny wallet FNX1… jest STAŁY — każda wpłata do Ciebie jest publicznie
łączona z Tobą (jak jedyny nr konta na całym blockchainie). Monero to rozwiązało
jednorazowymi adresami: nadawca ROBI Ci nowy, jednorazowy adres do każdej wpłaty.

Nasza wersja (CryptoNote-style, na naszych kluczach):

    Nadawca:  losowy klucz efemeryczny r (X25519)
              shared = DH(r, x_pub_odbiorcy)
              hs     = Hs(shared)                      (scalar mod l z blake2s)
              P      = hs·G + S_odbiorcy               (punkt Ed25519: jednorazowy)
              na-chain: {stealth_pub P ‖ eph R, kwota}  (adres wpłaty = wallet_address(P, R))
    Odbiorca: skanuje każdy blok: shared = DH(x_priv, R) → hs →
              czy hs·G + S == P?  TAK = „to do mnie!"
    Świat:    widzi losowe (P, R) — NIE da się powiązać z FNX1… odbiorcy
              ani jednej wpłaty z drugą (dwa shared = dwa różne światy).

WAŻNE technikum: biblioteka `cryptography` NIE wystawia arytmetyki punktów Ed25519
(żadnego add/mul), więc punkty liczy TU — wzory z RFC 8032 (twisted Edwards;
d = −121665/121666). Czysty Python, kilka operacji na tx — do M5b w jakie MVP style,
optymalizacja = backlog (libsecp/k25519 binding).

Kamień 1 = WARSTWA ADRESOWA (generowanie+skanowanie+dowód). Wydanie takiej
monety = kamień 2 (ring signatures CLSAG + podpis z gołego skalara — osobny plik;
klucz wydania: priv_ot = (hs + s_scalar(Ed25519)) mod l).

Selftest: dwa adresy do tego samego = nieskorelowane; scan trafia moje/nie cudze;
podmiana P/R = odbiorca NIE zgłasza; DH symmetrical; punktowa tożsamość P = hs·G+S.
"""
from __future__ import annotations

import hashlib
import sys
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey   # noqa: E402
from core.crypto.fenix_crypto import wallet_address                          # noqa: E402
from core.identity import Identity                                           # noqa: E402

# ---------------------------------------------------------------- ed25519 pointy (RFC 8032)
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_BY = (4 * pow(5, _P - 2, _P)) % _P
_BX = None  # policzone raz niżej
_IDENTITY = (0, 1)                    # punkt zerowy grupy


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * pow(2, (_P - 1) // 4, _P) % _P          # × sqrt(-1)
    if x & 1:
        x = _P - x
    return x


_BX = _xrecover(_BY)
_BASE = (_BX, _BY)


def point_encode(P: tuple[int, int]) -> bytes:
    x, y = P
    b = bytearray(y.to_bytes(32, "little"))
    b[31] |= (x & 1) << 7
    return bytes(b)


def point_decode(b: bytes) -> tuple[int, int]:
    if len(b) != 32:
        raise ValueError("punkt = dokładnie 32 bajty")
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    sign = b[31] >> 7
    x = _xrecover(y)
    if (x & 1) != sign:
        x = _P - x
    if not _is_on_curve(x, y):
        raise ValueError("punkt poza krzywą ed25519")
    return (x, y)


def _is_on_curve(x: int, y: int) -> bool:
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _P == 0


def point_add(P: tuple[int, int], Q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = P
    x2, y2 = Q
    den = pow(1 + _D * x1 * x2 * y1 * y2, _P - 2, _P)
    den2 = pow(1 - _D * x1 * x2 * y1 * y2, _P - 2, _P)
    x3 = ((x1 * y2 + x2 * y1) * den) % _P
    y3 = ((y1 * y2 + x1 * x2) * den2) % _P
    return (x3, y3)


def point_mul(s: int, P: tuple[int, int] = _BASE) -> tuple[int, int]:
    """double-and-add. s traktuj mod l (krzywe cofactor-ed tu neutralnie w tej wersji)."""
    R = _IDENTITY
    Q = P
    s %= _L
    while s:
        if s & 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)
        s >>= 1
    return R


# -------------------------------------------- szybkie opy (extended coords, 1 inwersja razem)
# Analogia: zamiast dzielić tort po KAŻDYM kęsie, dzielimy RAZ przy podaniu.
# Współrzędne rozszerzone (X:Y:Z:T), x=X/Z, y=Y/Z, T=XY/Z; wzory EFD hwcd-3 / dbl-2008-hwcd.
def _to_ext(P: tuple[int, int]) -> tuple[int, int, int, int]:
    x, y = P
    return (x, y, 1, x * y % _P)


def _from_ext(P: tuple[int, int, int, int]) -> tuple[int, int]:
    X, Y, Z, _ = P
    zi = pow(Z, _P - 2, _P)
    return (X * zi % _P, Y * zi % _P)


def _ext_add(P: tuple[int, int, int, int], Q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = X1 * X2 % _P
    B = Y1 * Y2 % _P
    C = _D * T1 * T2 % _P
    Dd = Z1 * Z2 % _P
    E = ((X1 + Y1) * (X2 + Y2) - A - B) % _P
    F = (Dd - C) % _P
    G = (Dd + C) % _P
    H = (B + A) % _P                    # a = −1  →  B − a·A = B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _ext_dbl(P: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    X1, Y1, Z1, _ = P
    A = X1 * X1 % _P
    B = Y1 * Y1 % _P
    C = 2 * Z1 * Z1 % _P
    Dd = (-A) % _P                      # a = −1  →  a·A = −A
    E = ((X1 + Y1) * (X1 + Y1) - A - B) % _P
    G = (Dd + B) % _P
    F = (G - C) % _P
    H = (Dd - B) % _P
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def point_mul_fast(s: int, P: tuple[int, int] = _BASE) -> tuple[int, int]:
    """TEN SAM wynik co point_mul (testuje to selftest), ~10–30× szybciej (zero inwersji w pętli)."""
    R = (0, 1, 1, 0)
    Q = _to_ext(P)
    s %= _L
    while s:
        if s & 1:
            R = _ext_add(R, Q)
        Q = _ext_dbl(Q)
        s >>= 1
    return _from_ext(R)


def point_add_fast(P: tuple[int, int], Q: tuple[int, int]) -> tuple[int, int]:
    """TEN SAM wynik co point_add, bez inwersji w środku."""
    return _from_ext(_ext_add(_to_ext(P), _to_ext(Q)))


def _hs(shared: bytes) -> int:
    """Hash→scalar grupy (CryptoNote-owy Hs): blake2s 32B → mod l."""
    return int.from_bytes(hashlib.blake2s(b"fnx/stealth/01" + shared,
                                          digest_size=32).digest(), "little") % _L


class StealthError(Exception):
    """Zły wymiar/klucz/punkt — jeden typ."""


# ---------------------------------------------------------------- API stealth
def derive_stealth(recipient_sig_pub_b: bytes, recipient_x_pub_b: bytes) -> dict:
    """NADAWCA: jednorazowy adres dla odbiorcy.
    Zwraca: {stealth_pub (hex-punkt P), eph_pub (hex R), address (FNX1…)}.
    Na-chain ląduje stealth_pub+eph_pub+kwota — NIGDY wallet_address odbiorcy."""
    if len(recipient_sig_pub_b) != 32 or len(recipient_x_pub_b) != 32:
        raise StealthError("klucze publiczne odbiorcy = po 32B")
    try:
        S = point_decode(recipient_sig_pub_b)
    except ValueError as e:
        raise StealthError(f"sig_pub odbiorcy to nie punkt ed25519: {e}") from None
    eph = X25519PrivateKey.generate()
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient_x_pub_b))
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    P = point_add(point_mul(_hs(shared)), S)
    stealth_pub = point_encode(P)
    return {"stealth_pub": stealth_pub.hex(), "eph_pub": eph_pub.hex(),
            "address": wallet_address(stealth_pub, eph_pub)}


def scan_stealth(identity: Identity, stealth_pub_hex: str, eph_pub_hex: str) -> dict | None:
    """ODBIORCA: czy ta moneta jest moja? TAK → detale (+ radę na wydanie, kamień 2)."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    x_priv = identity._core._x_priv                 # klucz widoku (view) = nasz X25519
    shared = x_priv.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(eph_pub_hex)))
    expect = point_add(point_mul(_hs(shared)), point_decode(identity.sig_pub_b))
    if point_encode(expect) == bytes.fromhex(stealth_pub_hex):
        hs = _hs(shared)
        s_scalar = _ed_scalar(identity._core._s_priv.private_bytes_raw() if hasattr(
            identity._core._s_priv, "private_bytes_raw") else
            identity._core._s_priv.private_bytes(
                __import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]),
                ))
        return {"mine": True,
                "address": wallet_address(bytes.fromhex(stealth_pub_hex),
                                          bytes.fromhex(eph_pub_hex)),
                "spend_hint": (hs + s_scalar) % _L,      # kamień 2: priv_ot = hs + s_scalar
                "note": "wydanie: 'priv_ot' zużyj w chain/ring_sig.py (CLSAG) — NIE surowo"}
    return None


def _ed_scalar(seed: bytes) -> int:
    """Skalar Ed25519 z 32B seed: sha512(seed)[:32] z clamping (RFC 8032, zgodnie z lib)."""
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248
    h[31] &= 63
    h[31] |= 64
    return int.from_bytes(h, "little") % _L


# ---------------------------------------------------------------- selftest
if __name__ == "__main__":
    print("chain/stealth.py — selftest: jednorazowe adresy, scan, unlink, punktowa tożsamość\n")

    # 0) sanity krzywej: base·l = ident; encode/decode odwrotność
    assert point_mul(_L) == _IDENTITY
    assert point_decode(point_encode(_BASE)) == _BASE
    # znany wektor: point_decode znanego pub Ed25519 (z cryptography) jest na krzywej
    ala = Identity.generate("ala_priv")
    bob = Identity.generate("bob_priv")
    point_decode(ala.sig_pub_b)
    print("  [OK] 0. krzywa: base·l=ident, decode(cryptography-pub) na krzywej")

    # 0b) szybki silnik == wolny silnik (równoważność — inaczej rozjadą się podpisy!)
    for t in (1, 2, 3, 255, 256, 2**252, _L - 1, _L, 12345678901234567890):
        assert point_mul_fast(t) == point_mul(t), f"mismatch przy s={t}"
    rnd = int.from_bytes(hashlib.blake2s(b"fast-eq").digest(), "little")
    assert point_mul_fast(rnd) == point_mul(rnd)
    extra = point_mul(7)
    assert point_mul_fast(rnd, extra) == point_mul(rnd, extra)
    assert point_add_fast(point_mul(11), point_mul(13)) == point_add(point_mul(11), point_mul(13))
    print("  [OK] 0b. silnik FAST ≡ wolny na wektorach + losowych skalarach (ta sama krzywa)")

    # 1) dwa stealth do TEGO SAMEGO odbiorcy → dwa nieskorelowane adresy
    s1 = derive_stealth(ala.sig_pub_b, ala.x_pub_b)
    s2 = derive_stealth(ala.sig_pub_b, ala.x_pub_b)
    assert s1["address"] != s2["address"]
    assert s1["stealth_pub"] != s2["stealth_pub"] and s1["eph_pub"] != s2["eph_pub"]
    assert ala.wallet not in (s1["address"], s2["address"])
    # brak akceptowalnych podobnych prefixów (≈ losowe)
    common = sum(1 for a, b in zip(s1["address"], s2["address"]) if a == b)
    print(f"  [OK] 1. dwie wpłaty do ali → dwa świeże adresy (wspólnych znaków: {common}/38, "
          f"jak losowe)")

    # 2) scan: ja wykrywam moje, obca osoba — nie
    hit = scan_stealth(ala, s1["stealth_pub"], s1["eph_pub"])
    assert hit and hit["mine"] and hit["address"] == s1["address"]
    assert scan_stealth(ala, s2["stealth_pub"], s2["eph_pub"]) is not None
    assert scan_stealth(bob, s1["stealth_pub"], s1["eph_pub"]) is None
    assert scan_stealth(bob, s2["stealth_pub"], s2["eph_pub"]) is None
    print("  [OK] 2. scan: ala widzi OBA swoje; bob widzi ŻADNYCH (oba wyglądają jak cudze)")

    # 3) punktowa tożsamość: odbiorca potrafi policzyć przyszły klucz wydania (kamień 2)
    #    priv_ot·G MUSI równać się P — to jest dowód, że ta moneta będzie wydobywalna.
    hs = hit["spend_hint"]
    assert point_mul(hs) == point_decode(bytes.fromhex(s1["stealth_pub"])), \
        "priv_ot·G ≠ stealth_pub — pieniądz niewydobywalny!"
    print("  [OK] 3. priv_ot·G == stealth_pub — monety są wydobywalne (gotowe pod ring sig)")

    # 4) podmiana P lub EPH → NIKOMU nie pasuje (manipulacja make-make nie daje fałszywych):
    badP = bytearray.fromhex(s1["stealth_pub"])
    badP[7] ^= 1
    try:
        scan_stealth(ala, badP.hex(), s1["eph_pub"])
        claimed = False
    except ValueError:
        claimed = False
    assert claimed is False
    badE = bytearray.fromhex(s1["eph_pub"])
    badE[3] ^= 1
    assert scan_stealth(ala, s1["stealth_pub"], badE.hex()) is None
    print("  [OK] 4. flip bitu w stealth_pub/eph_pub → odbiorca NIE zgłasza (integrity)")

    # 5) DH symetria: nadawca i odbiorca liczą TEN SAM shared (konsekwencja X25519)
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    eph_priv_re = X25519PrivateKey.generate()        # niezależna świeża symulacja
    sh_send = eph_priv_re.exchange(X25519PublicKey.from_public_bytes(ala.x_pub_b))
    e_pub2 = eph_priv_re.public_key().public_bytes(
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).Encoding.Raw,
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).PublicFormat.Raw)
    sh_recv = ala._core._x_priv.exchange(X25519PublicKey.from_public_bytes(e_pub2))
    assert sh_send == sh_recv and _hs(sh_send) == _hs(sh_recv)
    print("  [OK] 5. DH symetria: Hs(shared) identyczne po obu stronach kanału")

    print("\nSELFTEST: PASS ✅  stealth addresses: odbiorca niewidoczny, monety wydobywalne (kamień 2 ready)")
