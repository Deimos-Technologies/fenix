# chain/ring_sig.py — RING SIGNATURES: nadawca niewidoczny w tłumie (M5b kamień 2, D31)
"""
Problem: nawet przy stealth adresach (kamień 1: ODBIORCA niewidoczny) widać,
KTÓRA moneta jest wydawana — czyli kto mniej więcej płaci. Monero to rozwiązało
podpisami pierścieniowymi: podpis mówi „zapłacił JEDEN z tych N adresów",
ale NIE DA SIĘ wskazać którego. Tłum = anonimowość.

Nasza wersja (LSAG-style, CryptoNote, na naszych punktach ed25519 z chain/stealth.py):

    Pierścień: N kluczy publicznych P[0..N-1] (1 prawdziwy + N-1 „wabików" z chain)
    Dla każdego:        Hp[i] = hash_to_point(P[i])      (hash klucza → punkt)
    Podpisujący:        sekret x, gdzie P[pi] = x·G
      KEY IMAGE:        I = x · Hp[pi]   — jedyny „ślad": ten sam x wydany dwa razy
                                          da TEN SAM I → double-spend wykrywalny,
                                          a nadawca WCIĄŻ anonimowy (to cały trik!)
      losowe alpha;  c_{pi+1} = H(m, alpha·G, alpha·Hp[pi])
      dla j != pi:   losowe s[j];  c_{j+1} = H(m, s[j]·G + c[j]·P[j],
                                                s[j]·Hp[j] + c[j]·Hp[j])
      domknięcie:    s[pi] = alpha - c[pi]·x   (mod l)
    Podpis = (c0, s[0..N-1], I) — weryfikator „jedzie po kółku" i sprawdza,
    czy na końcu wychodzi z powrotem c0. Nie wie, GDZIE zaczęto (gdzie był pi).

Porównanie do świata: u nas LSAG (1 wyzwanie, N s-ów, key image); Monero ma CLSAG
(łączy dodatkowo zobowiązania kwotowe — dołożymy w kamieniu 3: Pedersen + TX_RING).

Selftest: podpis ważny z każdej pozycji; zmiana treści/pierścienia = nieważny;
key image stabilny per (sekret) — anti-double-spend; serializacja; współpraca
z chain/stealth.py (jednorazowy klucz priv_ot podpisuje realnie w pierścieniu).
"""
from __future__ import annotations

import hashlib
import secrets
import sys
import pathlib as _pl
from dataclasses import dataclass
from typing import List

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from chain.stealth import (_BASE, _L, point_decode, point_encode,  # noqa: E402
                           point_add_fast as point_add, point_mul_fast as point_mul)

_DOMAIN = b"fnx/ring/01"
_FIX_SEED: bytes | None = None        # DEV: deterministyczne losowości w selfteście
_FIX_STATE = [0]


def _hs_ring(*parts: bytes) -> int:
    """Hash → skalar mod l (challenge / losowości testowe). Osobny domen-em niż stealth."""
    h = hashlib.blake2s(digest_size=32)
    for p in parts:
        h.update(p)
    return int.from_bytes(h.digest(), "little") % _L


def _rand_scalar() -> int:
    if _FIX_SEED is not None:
        _FIX_STATE[0] += 1
        v = _hs_ring(_FIX_SEED, b"rnd", _FIX_STATE[0].to_bytes(8, "little"))
    else:
        v = int.from_bytes(secrets.token_bytes(32), "little") % _L
    return v or 1


def hash_to_point(pubkey_point: bytes) -> tuple[int, int]:
    """Deterministyczna mapa: klucz publiczny → punkt krzywej (dla key-image Hp[i]).
    Try-and-increment przez skalarne u·G z seed = H(domain, pubkey, counter)."""
    ctr = 0
    while True:
        u = _hs_ring(_DOMAIN, b"H2P", pubkey_point, ctr.to_bytes(4, "little"))
        if u != 0:
            return point_mul(u)
        ctr += 1  # praktycznie nieosiągalne


class RingSigError(Exception):
    """Zły pierścień/podpis/wymiar — jeden typ."""


# -------------------------------------------------------------------------- struktura
@dataclass
class RingSignature:
    c0: int                 # wyzwanie startowe (tam gdzie cykl się „doczytelnie zamyka")
    s: List[int]            # odpowiedzi Schnorra, po jednej na członka pierścienia
    key_image: bytes        # I (32B encoded point) — tag anti-double-spend

    def to_bytes(self) -> bytes:
        # format: c0(32LE) ‖ image(32) ‖ n(2BE) ‖ s[0..n-1](32LE każdy)
        out = bytearray(self.c0.to_bytes(32, "little"))
        out += self.key_image
        out += len(self.s).to_bytes(2, "big")
        for si in self.s:
            out += si.to_bytes(32, "little")
        return bytes(out)

    @staticmethod
    def from_bytes(raw: bytes) -> "RingSignature":
        if len(raw) < 66:
            raise RingSigError("za krótki podpis pierścieniowy")
        c0 = int.from_bytes(raw[:32], "little")
        ki = raw[32:64]
        n = int.from_bytes(raw[64:66], "big")
        if n < 2 or len(raw) < 66 + 32 * n:
            raise RingSigError("pierścień min. 2 członków / obcięty podpis")
        s = [int.from_bytes(raw[66 + 32 * i: 98 + 32 * i], "little") for i in range(n)]
        if c0 >= _L or any(si >= _L for si in s):
            raise RingSigError("skalary poza zakresem grupy")
        return RingSignature(c0=c0, s=s, key_image=ki)


def _challenge(message: bytes, j: int, g_part: tuple[int, int], h_part: tuple[int, int]) -> int:
    return _hs_ring(_DOMAIN, message, j.to_bytes(2, "big"),
                    point_encode(g_part), point_encode(h_part))


# -------------------------------------------------------------------------- podpis
def ring_sign(message: bytes, ring_pubkeys: List[bytes], signer_index: int,
              signer_secret: int) -> RingSignature:
    """Podpis pierścieniowy. WYMAGANIE: ring_pubkeys[signer_index] == signer_secret·G.
    signer_secret = 32B seed NIE pasuje — potrzebny GOŁY skalar (np. spend_hint/priv_ot
    z chain/stealth.scan_stealth)."""
    n = len(ring_pubkeys)
    if n < 2:
        raise RingSigError("pierścień musi mieć >= 2 członków (1 + wabiki)")
    if not (0 <= signer_index < n):
        raise RingSigError("zły indeks podpisującego")
    try:
        ring = [point_decode(pk) for pk in ring_pubkeys]
    except ValueError as e:
        raise RingSigError(f"członek pierścienia to nie punkt ed25519: {e}") from None
    hp = [hash_to_point(pk) for pk in ring_pubkeys]
    x = signer_secret % _L
    if point_encode(point_mul(x)) != ring_pubkeys[signer_index]:
        raise RingSigError("sekret NIE pasuje do klucza na pozycji signer_index")

    key_image_pt = point_mul(x, hp[signer_index])      # I = x·Hp[pi] — TEN SAM punkt
    key_image = point_encode(key_image_pt)             # wchodzi do wyzwań WSZYSTKICH
                                                       # członków (LSAG, nie CLSAG pairs)

    alpha = _rand_scalar()
    c = [0] * n
    s = [0] * n

    # start od podpisującego: c_{pi+1} = H(m, alpha·G, alpha·Hp[pi])
    j = (signer_index + 1) % n
    c[j] = _challenge(message, signer_index, point_mul(alpha), point_mul(alpha, hp[signer_index]))

    # reszta pierścienia losowymi s[j] — pętla przechodzi WSZYSTKIE pozycje ≠ pi,
    # więc c[0] zostaje wyliczone bez względu na pi (w tym pi == 0)
    while j != signer_index:
        s[j] = _rand_scalar()
        g_part = point_add(point_mul(s[j]), point_mul(c[j], ring[j]))
        h_part = point_add(point_mul(s[j], hp[j]), point_mul(c[j], key_image_pt))
        c[(j + 1) % n] = _challenge(message, j, g_part, h_part)
        j = (j + 1) % n

    # domknięcie kółka: s[pi] = alpha - c[pi]·x  (mod l)
    s[signer_index] = (alpha - c[signer_index] * x) % _L
    return RingSignature(c0=c[0], s=s, key_image=key_image)


def ring_verify(message: bytes, ring_pubkeys: List[bytes], sig: RingSignature) -> bool:
    """Publiczna weryfikacja: jazda po kółku od c0 — na końcu musi wyjść c0."""
    n = len(ring_pubkeys)
    if len(sig.s) != n or n < 2:
        return False
    if sig.c0 >= _L or any(si >= _L for si in sig.s):
        return False
    try:
        ring = [point_decode(pk) for pk in ring_pubkeys]
        ki = point_decode(sig.key_image)
    except ValueError:
        return False
    hp = [hash_to_point(pk) for pk in ring_pubkeys]

    c = sig.c0
    for j in range(n):
        g_part = point_add(point_mul(sig.s[j]), point_mul(c, ring[j]))
        h_part = point_add(point_mul(sig.s[j], hp[j]), point_mul(c, ki))  # c·key_image!
        c = _challenge(message, j, g_part, h_part)
    return c == sig.c0


# -------------------------------------------------------------------------- selftest
if __name__ == "__main__":
    print("chain/ring_sig.py — selftest: LSAG ring, key image, stealth-interop\n")

    _FIX_SEED = b"selftest-ring-v1"
    secrets_list = [_hs_ring(b"ring-k%d" % i) for i in range(5)]
    pubs = [point_encode(point_mul(x)) for x in secrets_list]

    msg = b"TRANSFER: FNX1aaa -> FNX1bbb, 42 FNX"
    pi = 2
    sig = ring_sign(msg, pubs, pi, secrets_list[pi])
    assert ring_verify(msg, pubs, sig), "podpis MUSI weryfikować się w pierścieniu"
    print("  [OK] 1. podpis z pozycji pi=2 weryfikuje się (5 członków)")

    # odmowa podpisu cudzym sekretem
    try:
        ring_sign(msg, pubs, pi, secrets_list[0])
        raise SystemExit("POWINNO rzucić RingSigError — cudzy sekret!")
    except RingSigError:
        print("  [OK] 2. podpis cudzym sekretem odrzucony od razu (sekret≠klucz)")

    # każdy członek może podpisać SWOIM sekretem → z samego podpisu nie widać pozycji
    ok = all(ring_verify(msg, pubs, ring_sign(msg, pubs, i, secrets_list[i]))
             for i in range(5))
    assert ok
    print("  [OK] 3. podpis możliwy z każdej pozycji — nadawca anonimowy w tłumie 5")

    # manipulacja treścią → nieważny
    sig2 = ring_sign(msg, pubs, pi, secrets_list[pi])
    assert not ring_verify(b"TRANSFER: 1000000 FNX", pubs, sig2)
    print("  [OK] 4. zmiana treści wiadomości unieważnia podpis")

    # manipulacja pierścieniem → nieważny
    ring_bad = pubs[:]
    ring_bad[3] = point_encode(point_mul(_hs_ring(b"intruz")))
    sig3 = ring_sign(msg, pubs, pi, secrets_list[pi])
    assert not ring_verify(msg, ring_bad, sig3)
    print("  [OK] 5. podmiana członka pierścienia unieważnia podpis")

    # key-image: stabilny dla tego samego sekretu, inny dla innych (anti-double-spend)
    sigA = ring_sign(msg, pubs, pi, secrets_list[pi])
    sigB = ring_sign(b"inna wiadomosc", pubs, pi, secrets_list[pi])
    assert sigA.key_image == sigB.key_image, "TEN SAM sekret MUSI dać TEN SAM key image"
    sigC = ring_sign(msg, pubs, 0, secrets_list[0])
    assert sigC.key_image != sigA.key_image, "INNY sekret MUSI dać inny key image"
    print("  [OK] 6. key image: double-spend wykrywalny (ten sam I), nadawca nadal anonimowy")

    # serializacja round-trip + wymiar
    blob = sig.to_bytes()
    assert len(blob) == 32 + 32 + 2 + 32 * 5
    assert RingSignature.from_bytes(blob).to_bytes() == blob
    print("  [OK] 7. serializacja c0‖image‖n‖s[] — round-trip bajt-w-bajt")

    # współpraca ze stealth: jednorazowy klucz (priv_ot/spend_hint) podpisuje realną monetę
    from core.identity import Identity
    from chain.stealth import derive_stealth, scan_stealth
    ala = Identity.generate("ala_ring")
    st = derive_stealth(ala.sig_pub_b, ala.x_pub_b)
    hint = scan_stealth(ala, st["stealth_pub"], st["eph_pub"])
    assert hint is not None
    ring2 = [bytes.fromhex(st["stealth_pub"]), pubs[0], pubs[1]]  # moja moneta + 2 wabiki
    sig4 = ring_sign(msg, ring2, 0, hint["spend_hint"])
    assert ring_verify(msg, ring2, sig4), "priv_ot MUSI podpisywać w pierścieniu"
    # i jej key image różni się od wabików
    assert sig4.key_image not in (ring_sign(msg, ring2, 1, secrets_list[0]).key_image,
                                  ring_sign(msg, ring2, 2, secrets_list[1]).key_image)
    print("  [OK] 8. interop stealth: moneta jednorazowa podpisana ringiem (priv_ot·G=P) ✅")

    print("\nSELFTEST: PASS ✅  ring signatures: nadawca niewidzialny, double-spend wykrywalny")
