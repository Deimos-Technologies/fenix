# chain/clsag.py — kamień 3b krypto-rdzeń: ukryte kwoty (MLSAG na [P, C-diff]) + blob kwotowy
"""
Etap 3a ukrywa POWIĄZANIA nadawca↔odbiorca (LSAG+stealth), ale kwoty są jawne.
Ten plik dokłada etap 3b: kwoty też znikają — analogia: „tasowana talia, a na
kartach jeszcze zakryta numeracja".

  ZOBOWIĄZANIE PEDERSENA (z chain/amount_hide): C = a·H + r·G
    → kwota a i sekret r ukryte w punkcie; weryfikator widzi tylko C.
  RING zobowiązań: member ringa = para (P_j stealth-pub, C_j zobowiązanie).
    D_j = C_j − (Σ C_out + fee·H)   ← „zobowiązanie-różnica"; podpisujący na
    swoim indeksie zna z = r_in − Σ r_out takie, że D_π = z·G (H się kasuje!).
  MLSAG = podpis pierścieniowy po DWÓCH kolumnach naraz [(P_j),(D_j)]:
    kolumna 1 dowodzi WŁASNOŚCI (priv_ot; key image I = x·Hp(P) = anty-double-spend),
    kolumna 2 dowodzi BILANSU (Σin = Σout + fee, BEZ ujawniania kwot).
  RANGE PROOF (Borromean z amount_hide): każdy C_out naprawdę ukrywa [0,2^64)
    → nikt nie wydrukuje FNX z powietrza na „ujemnej" kwocie.
  BLOB kwotowy: {a‖r} szyfrowane do odbiorcy (DH z ep, HKDF „FNXC1", AEAD+AAD=C)
    → tylko odbiorca dowiaduje się, ile dostał; świat patrzy na martwe punkty.

GRANICE uczciwie: to jest krypto-RDZEŃ 3b (build+verify+skan), NIE jeszcze zmiana
konsensusu — integracja z Ledger/TX_RING (v=2 payloady, rejestr ki jak dotąd,
retencja C w poolu jako wabiki) to NASTĘPNY kamień (patrz TODO M5b/3b).
Ochrona: wejścia/wyjścia ≤8, ring 5..11 jak dotąd, blob ≤96B, fee zostaje jawne
(jak w Monero — fee nie ustępuje anonimowości, bo i tak jest drobne).
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import pathlib as _pl
from dataclasses import dataclass
from typing import List, Callable

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from chain.block import canon                                                      # noqa: E402
from chain.tx_ring import MAX_AMT                                                  # noqa: E402
from chain.stealth import (point_encode, point_decode, point_add,                  # noqa: E402
                           point_mul_fast, point_add_fast, _hs as _hs_stealth,
                           _L as _CURVE_L, scan_stealth)
from chain.ring_sig import _hs_ring, hash_to_point                                # noqa: E402
from chain import amount_hide as ah                                                # noqa: E402

RING_MIN = 5
RING_MAX = 11
MAX_INS = 8
MAX_OUTS = 8
MAX_BLOB = 96                     # bajtów blobu kwotowego (nonce12 + ct44+u64…)


class ClsagError(Exception):
    """Błąd 3b — jeden typ z zewnątrz."""


def _neg(P):
    return ah._neg(P)


def _pt(x):
    """Punkt z bytes ALBO hex-stringa (ring-y w payloadach są hexowe)."""
    return point_decode(bytes.fromhex(x) if isinstance(x, str) else x)


def _fee_commit(fee: int):
    """fee·H jako punkt (jawne fee — jak Monero)."""
    return point_mul_fast(fee, ah._derive_h())


def _h32(s: str, what: str) -> bytes:
    if not isinstance(s, str) or len(s) != 64:
        raise ClsagError(f"{what}: oczekiwano 32B hex")
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise ClsagError(f"{what}: zły hex") from None


# -------------------------------------------------------------------------- MLSAG
@dataclass
class MlsagSig:
    """(c0, rs[j][2], key_image) — rozmiar zależy od N (5..11)."""
    c0: int
    rs: List[List[int]]           # po dwa skalary na membera
    key_image: bytes

    def to_bytes(self) -> bytes:
        n = len(self.rs)
        out = bytearray((2 * n).to_bytes(2, "big"))
        out += self.c0.to_bytes(32, "big")
        for pair in self.rs:
            for s in pair:
                out += s.to_bytes(32, "big")
        out += self.key_image
        return bytes(out)

    @staticmethod
    def from_bytes(raw: bytes) -> "MlsagSig":
        if len(raw) < 2:
            raise ClsagError("za krótki MLSAG")
        n2 = int.from_bytes(raw[:2], "big")
        if n2 < 2 or n2 % 2 or len(raw) != 2 + 32 * (1 + n2) + 32:
            raise ClsagError("zły rozmiar MLSAG")
        n = n2 // 2
        off = 2
        c0 = int.from_bytes(raw[off:off + 32], "big")
        off += 32
        rs = []
        for _ in range(n):
            rs.append([int.from_bytes(raw[off:off + 32], "big"),
                       int.from_bytes(raw[off + 32:off + 64], "big")])
            off += 64
        return MlsagSig(c0=c0, rs=rs, key_image=raw[off:off + 32])


def _mlsag_chal(msg: bytes, j: int, L1, L2, R1) -> int:
    """Wyzwanie z indeksem członka (jak w chain/ring_sig._challenge — ta konwencja)."""
    return _hs_ring(b"CLSAGv1" + msg + j.to_bytes(4, "big"), point_encode(L1),
                    point_encode(L2), point_encode(R1))


def mlsag_sign(msg: bytes, ring_P: List[bytes], ring_D: List, idx: int,
               x: int, z: int) -> MlsagSig:
    """x = priv_ot (P_idx = x·G), z = balans (D_idx = z·G). c0 = wyzwanie membera 0!"""
    n = len(ring_P)
    if not (RING_MIN <= n <= RING_MAX and len(ring_D) == n and 0 <= idx < n):
        raise ClsagError("mlsag: zły ring/index")
    P = [_pt(p) for p in ring_P]
    D = [d if isinstance(d, tuple) else _pt(d) for d in ring_D]
    hp = [hash_to_point(bytes.fromhex(p) if isinstance(p, str) else p) for p in ring_P]
    I = point_mul_fast(x, hp[idx])
    a1 = int.from_bytes(os.urandom(32), "big") % _CURVE_L
    a2 = int.from_bytes(os.urandom(32), "big") % _CURVE_L
    rs = [[0, 0] for _ in range(n)]
    c = [0] * n
    j = (idx + 1) % n
    c[j] = _mlsag_chal(msg, idx, point_mul_fast(a1), point_mul_fast(a2),
                       point_mul_fast(a1, hp[idx]))
    while j != idx:                        # przechodzi wszystkich ≠ idx → c[0] też zostanie
        rs[j] = [int.from_bytes(os.urandom(32), "big") % _CURVE_L,
                 int.from_bytes(os.urandom(32), "big") % _CURVE_L]
        L1 = point_add_fast(point_mul_fast(rs[j][0]), point_mul_fast(c[j], P[j]))
        L2 = point_add_fast(point_mul_fast(rs[j][1]), point_mul_fast(c[j], D[j]))
        R1 = point_add_fast(point_mul_fast(rs[j][0], hp[j]), point_mul_fast(c[j], I))
        c[(j + 1) % n] = _mlsag_chal(msg, j, L1, L2, R1)
        j = (j + 1) % n
    rs[idx] = [(a1 - c[idx] * x) % _CURVE_L, (a2 - c[idx] * z) % _CURVE_L]
    return MlsagSig(c0=c[0], rs=rs, key_image=point_encode(I))


def mlsag_verify(msg: bytes, ring_P: List[bytes], ring_D: List, sig: MlsagSig) -> bool:
    """Jazda po kółku od c0 (membera 0) — na końcu musi wyjść c0."""
    n = len(ring_P)
    if not (RING_MIN <= n <= RING_MAX and len(ring_D) == n and len(sig.rs) == n) \
            or len(sig.key_image) != 32:
        return False
    try:
        P = [_pt(p) for p in ring_P]
        D = [d if isinstance(d, tuple) else _pt(d) for d in ring_D]
        hp = [hash_to_point(bytes.fromhex(p) if isinstance(p, str) else p) for p in ring_P]
        I = point_decode(sig.key_image)
    except ValueError:
        return False
    c = sig.c0 % _CURVE_L
    for j in range(n):
        r1, r2 = sig.rs[j][0] % _CURVE_L, sig.rs[j][1] % _CURVE_L
        L1 = point_add_fast(point_mul_fast(r1), point_mul_fast(c, P[j]))
        L2 = point_add_fast(point_mul_fast(r2), point_mul_fast(c, D[j]))
        R1 = point_add_fast(point_mul_fast(r1, hp[j]), point_mul_fast(c, I))
        c = _mlsag_chal(msg, j, L1, L2, R1)
    return c == sig.c0 % _CURVE_L


# -------------------------------------------------------------------------- blob kwotowy
def _box_key(shared: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.hashes import SHA256
    return HKDF(algorithm=SHA256(), length=32, salt=b"FNXC1", info=b"amt").derive(shared)


def _stealth_with_shared(sig_pub_b: bytes, x_pub_b: bytes) -> dict:
    """derive_stealth + klucz blobowy (nadawca potrzebuje efemerycznego shared,
    którego tamta API celowo nie zwraca). TA SAMA matematyka co derive_stealth:
    P = Hs(shared)·G + S, R = eph_pub."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(x_pub_b))
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    S = point_decode(sig_pub_b)
    P = point_add(point_mul_fast(_hs_stealth(shared)), S)
    return {"stealth_pub": point_encode(P).hex(), "eph_pub": eph_pub.hex(),
            "shared": shared}


def seal_amount(shared: bytes, commit_b: bytes, amount: int, blinding: int) -> str:
    """{a(8B)‖r(32B)} → AEAD (AAD=C) → hex (nonce12‖ct)."""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    if not (0 <= amount <= MAX_AMT and 0 <= blinding < _CURVE_L):
        raise ClsagError("seal_amount: kwota/blinding poza zakresem")
    plain = struct.pack("!Q", amount) + blinding.to_bytes(32, "big")
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(_box_key(shared)).encrypt(nonce, plain, commit_b)
    return (nonce + ct).hex()


def open_amount(identity, eph_pub_hex: str, commit_b: bytes, blob_hex: str):
    """Odbiorca: (amount, r) albo None (nie-moje/zepsute). Weryfikuje C = commit(a, r)."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    try:
        blob = bytes.fromhex(blob_hex)
        if len(blob) < 12 or len(blob) > MAX_BLOB:
            return None
        shared = identity._core._x_priv.exchange(
            X25519PublicKey.from_public_bytes(bytes.fromhex(eph_pub_hex)))
        plain = ChaCha20Poly1305(_box_key(shared)).decrypt(blob[:12], blob[12:], commit_b)
        if len(plain) != 40:
            return None
        amount = struct.unpack("!Q", plain[:8])[0]
        blinding = int.from_bytes(plain[8:], "big")
        if ah.commit(amount, blinding) != commit_b:
            return None                      # blob kłamie względem zobowiązania!
        return amount, blinding
    except Exception:
        return None


def scan_hidden_for(identity, outs: List[dict]) -> List[dict]:
    """Moje ukryte coiny: [{sp, ep, C, amt, r, spend_hint}] (scan stealth + blob)."""
    mine = []
    for o in outs:
        hit = scan_stealth(identity, o["sp"], o["ep"])
        if not hit:
            continue
        got = open_amount(identity, o["ep"], bytes.fromhex(o["C"]), o["blob"])
        if got is None:
            continue
        mine.append({"sp": o["sp"], "ep": o["ep"], "C": o["C"], "amt": got[0],
                     "r": got[1], "spend_hint": hit["spend_hint"]})
    return mine


# -------------------------------------------------------------------------- hidden tx (v=2)
def _hidden_msg(payload: dict) -> bytes:
    core = {"v": payload["v"],
            "in": [{k: v for k, v in i.items() if k != "sig"} for i in payload["in"]],
            "out": payload["out"], "fee": payload["fee"]}
    return canon(core)


def build_hidden_tx(spends: List[dict], outs: List[dict], fee_iskry: int) -> dict:
    """spends: [{"ringP":[sp…], "ringC":[C…], "index":i, "x":priv_ot, "r_in":r}]
       outs:   [{"sig_pub":b32,"x_pub":b32,"amount":iskry}]
       → payload v=2 (podpisane MLSAG); kwoty NIE występują na jawie (fee jawne)."""
    if not (1 <= len(spends) <= MAX_INS and 1 <= len(outs) <= MAX_OUTS):
        raise ClsagError("budowa: 1..8 wejść i 1..8 wyjść")
    if not isinstance(fee_iskry, int) or not (0 <= fee_iskry <= MAX_AMT):
        raise ClsagError("budowa: złe fee")
    out_list, out_commits, sum_r_out, sum_amt_out = [], [], 0, 0
    for o in outs:
        sig_b, x_b = o["sig_pub"], o["x_pub"]
        amt = int(o["amount"])
        if not (0 < amt <= MAX_AMT):
            raise ClsagError("budowa: zła kwota wyjścia")
        r = ah.random_blinding()
        C_b = ah.commit(amt, r)
        st = _stealth_with_shared(sig_b, x_b)
        rp = ah.prove_range(amt, r)
        out_list.append({"sp": st["stealth_pub"], "ep": st["eph_pub"], "C": C_b.hex(),
                         "rp": rp.to_bytes().hex(),
                         "blob": seal_amount(st["shared"], C_b, amt, r)})
        out_commits.append(point_decode(C_b))
        sum_r_out = (sum_r_out + r) % _CURVE_L
        sum_amt_out += amt
    COM = point_mul_fast(fee_iskry, ah._derive_h())
    for c in out_commits:
        COM = point_add_fast(COM, c)
    # pseudoOut per wejście (Monero MLSAG, poprawne WIELO-WEJŚCIE):
    #   pseudo_i = commit(a_i, r_p_i), Σr_p = Σr_out → Σpseudo = ΣC_out + fee·H;
    #   ring kolumny 2: D_j = C_j − pseudo_i (dl na moim indeksie = r_in_i − r_p_i).
    #   Bez pseudoOut konstrukcja zamykała się na 1 wejście (złapał to test M7d!).
    r_p: list = [ah.random_blinding() for _ in spends]
    if len(spends) == 1:
        r_p[0] = sum_r_out % _CURVE_L
    else:
        r_p[-1] = (sum_r_out - sum(r_p[:-1])) % _CURVE_L
    # 1) ins bez podpisów (ki + pseudoOut od razu — są w kanonie!) → msg jak _hidden_msg
    ins, zs, sum_amt_in = [], [], 0
    for s, rp_i in zip(spends, r_p):
        ringP, ringC, idx = s["ringP"], s["ringC"], s["index"]
        if not (RING_MIN <= len(ringP) <= RING_MAX and len(ringC) == len(ringP)
                and 0 <= idx < len(ringP)):
            raise ClsagError("budowa: zły ring/index")
        amt_i = s.get("amt")
        if not isinstance(amt_i, int) or not (0 < amt_i <= MAX_AMT):
            raise ClsagError("budowa: wejście bez amt (pseudoOut wymaga nominału)")
        sum_amt_in += amt_i
        rawP = bytes.fromhex(ringP[idx]) if isinstance(ringP[idx], str) else ringP[idx]
        ki = point_encode(point_mul_fast(int(s["x"]), hash_to_point(rawP)))
        ins.append({"ringP": list(ringP), "ringC": list(ringC), "ki": ki.hex(),
                    "hC": ah.commit(amt_i, rp_i).hex(), "sig": ""})
        zs.append((int(s["r_in"]) - rp_i) % _CURVE_L)
    # portfel ZNA wszystkie kwoty → bilans sprawdzamy jawnie liczbami (fail-fast,
    # zanim cokolwiek podpiszemy); kryptograficznie bilans pilnuje Σpseudo w verify
    if sum_amt_in != sum_amt_out + fee_iskry:
        raise ClsagError("budowa: Σin ≠ Σout + fee (bilans złapany w build, przed podpisem)")
    msg = _hidden_msg({"v": 2, "in": ins, "out": out_list, "fee": int(fee_iskry)})
    # 2) podpis każdego wejścia (D = ringC − JEGO pseudoOut)
    for n_i, (s, z) in enumerate(zip(spends, zs)):
        idx = s["index"]
        pseudo_pts = point_decode(bytes.fromhex(ins[n_i]["hC"]))
        D = [point_add_fast(_pt(c), _neg(pseudo_pts)) for c in s["ringC"]]
        # sanity: na moim indeksie D MUSI być z·G — inaczej podpis nigdy nie zweryfikuje
        if D[idx] != point_mul_fast(z):
            raise ClsagError("budowa: r_in nie pasuje do zobowiązania wejścia (bilans≠)")
        sig = mlsag_sign(msg, s["ringP"], D, idx, int(s["x"]), z)
        ins[n_i]["sig"] = sig.to_bytes().hex()
    return {"v": 2, "in": ins, "out": out_list, "fee": int(fee_iskry)}


def verify_hidden_tx(payload: dict, pool_lookup: Callable[[str], dict | None]) -> List[str]:
    """Konsensus 3b. pool_lookup(sp_hex) → {"C": hex} lub None.
    Zwraca key-images (hex). Błąd = ClsagError (jak TxRingError)."""
    if not isinstance(payload, dict) or payload.get("v") != 2:
        raise ClsagError("clsag: brak v=2")
    ins, outs, fee = payload.get("in"), payload.get("out"), payload.get("fee")
    if not isinstance(ins, list) or not (1 <= len(ins) <= MAX_INS):
        raise ClsagError("clsag: 1..8 wejść")
    if not isinstance(outs, list) or not (1 <= len(outs) <= MAX_OUTS):
        raise ClsagError("clsag: 1..8 wyjść")
    if not isinstance(fee, int) or not (0 <= fee <= MAX_AMT):
        raise ClsagError("clsag: złe fee")
    out_C: List[bytes] = []
    for o in outs:
        if not isinstance(o, dict):
            raise ClsagError("clsag: wyjście nie-obiekt")
        _h32(o.get("sp", ""), "clsag.out.sp")
        _h32(o.get("ep", ""), "clsag.out.ep")
        C_b = _h32(o.get("C", ""), "clsag.out.C")
        try:
            rp = ah.RangeProof.from_bytes(bytes.fromhex(o.get("rp", "")))
        except (ValueError, ah.AmountError) as e:
            raise ClsagError(f"clsag: rp bajtowo zły: {e}") from None
        if not ah.verify_range(C_b, rp):
            raise ClsagError("clsag: range proof NIEZGODNY (druk FNX z powietrza?)")
        blob = o.get("blob", "")
        if not isinstance(blob, str) or not blob or len(blob) > 2 * MAX_BLOB:
            raise ClsagError("clsag: zły blob")
        out_C.append(C_b)
    COM = point_mul_fast(fee, ah._derive_h())
    for C_b in out_C:
        COM = point_add_fast(COM, point_decode(C_b))
    msg = _hidden_msg(payload)
    key_images: List[str] = []
    ring_size = None
    pseudo_sum = None
    for i in ins:
        ringP, ringC = i.get("ringP"), i.get("ringC")
        if not isinstance(ringP, list) or not isinstance(ringC, list) \
                or len(ringP) != len(ringC) or not (RING_MIN <= len(ringP) <= RING_MAX):
            raise ClsagError("clsag: zły ring")
        if ring_size is None:
            ring_size = len(ringP)
        elif len(ringP) != ring_size:
            raise ClsagError("clsag: mieszane rozmiary ringów (uniform)")
        pseudo_b = _h32(i.get("hC", ""), "clsag.hC")
        pseudo_pts = point_decode(pseudo_b)
        pseudo_sum = pseudo_pts if pseudo_sum is None else point_add_fast(pseudo_sum, pseudo_pts)
        D = []
        for cp, cc in zip(ringP, ringC):
            _h32(cp, "clsag.ringP.member")
            C_h = _h32(cc, "clsag.ringC.member")
            entry = pool_lookup(cp)
            if entry is None:
                raise ClsagError("clsag: member spoza poola")
            if entry.get("C") != cc:
                raise ClsagError("clsag: ringC ≠ zobowiązanie w poolu (podmianka)")
            D.append(C_h)
        Dpts = [point_add_fast(point_decode(C_h), _neg(pseudo_pts)) for C_h in D]
        ki = _h32(i.get("ki", ""), "clsag.ki")
        try:
            sig = MlsagSig.from_bytes(bytes.fromhex(i.get("sig", "")))
        except (ValueError, ClsagError) as e:
            raise ClsagError(f"clsag: zły podpis bajtowo: {e}") from None
        if not mlsag_verify(msg, ringP, Dpts, sig):
            raise ClsagError("clsag: podpis MLSAG NIEWAŻNY")
        if sig.key_image != ki:
            raise ClsagError("clsag: ki ≠ key_image z podpisu (podmianka)")
        key_images.append(ki.hex())
    # bilans globalny (wielo-wejście): Σ pseudoOut == Σ C_out + fee·H
    if pseudo_sum != COM:
        raise ClsagError("clsag: Σ pseudoOut ≠ Σout+fee·H (bilans wielo-wejścia ≠)")
    return key_images


# -------------------------------------------------------------------------- selftest E2E
if __name__ == "__main__":
    print("chain/clsag.py — selftest 3b: MLSAG ring, ukryte kwoty E2E, fałszerstwa\n")

    from core.identity import Identity
    from chain.stealth import derive_stealth, point_mul_fast as _pmf, point_add_fast as _paf

    # 1) MLSAG: sign/verify na losowych punktach (dekoracyjny, ale prawdziwy)
    def _mk_ring(n, idx):
        secs = [int.from_bytes(os.urandom(32), "big") % _CURVE_L for _ in range(n)]
        pubs = [point_encode(_pmf(s)) for s in secs]
        return secs, pubs

    N, IDX = 6, 2
    secs_P, pubs_P = _mk_ring(N, IDX)
    secs_D, pubs_D = _mk_ring(N, IDX)
    Dpts = [point_decode(p) for p in pubs_D]
    msg1 = b"hidden-tx-msg#1"
    sig = mlsag_sign(msg1, pubs_P, Dpts, IDX, secs_P[IDX], secs_D[IDX])
    assert mlsag_verify(msg1, pubs_P, Dpts, sig) is True
    print("  [OK] 1. MLSAG sign→verify (ring 6, dwie kolumny [P,D])")

    # 2) fałszerstwa MLSAG: inna wiadomość, podmieniony member, inny ki
    assert mlsag_verify(b"inna-wiadomosc", pubs_P, Dpts, sig) is False
    swapped = list(pubs_P); swapped[0], swapped[1] = swapped[1], swapped[0]
    assert mlsag_verify(msg1, swapped, Dpts, sig) is False
    sig_bad = MlsagSig(c0=sig.c0, rs=[list(p) for p in sig.rs],
                       key_image=bytes(32))
    assert mlsag_verify(msg1, pubs_P, Dpts, sig_bad) is False
    print("  [OK] 2. MLSAG: zła wiadomość / przestawiony member / inny key-image → False")

    # 3) E2E ukryty pool: 6 coinów (różni właściciele, RÓŻNE kwoty — decoys bez nominale!)
    ala, bob, ceo = Identity.generate("ala_c"), Identity.generate("bob_c"), \
        Identity.generate("ceo_c")
    pool: dict[str, dict] = {}          # sp → {ep, C, blob}
    owners = [(ala, 2), (bob, 3), (ala, 5), (ceo, 1), (bob, 7), (ala, 2)]

    def make_coin(who, amt_fnx):
        amt = amt_fnx * 10**8
        r = ah.random_blinding()
        C_b = ah.commit(amt, r)
        st = _stealth_with_shared(who.sig_pub_b, who.x_pub_b)
        blob = seal_amount(st["shared"], C_b, amt, r)
        pool[st["stealth_pub"]] = {"ep": st["eph_pub"], "C": C_b.hex(), "blob": blob}

    for who, amt in owners:
        make_coin(who, amt)
    assert len(pool) == 6
    print("  [OK] 3. pool ukryty: 6 coinów; na-chain tylko C (punkty), kwota NIGDZIE jawna")

    # 4) bob: scan znajduje DOKŁADNIE jego 2 coiny z kwotami (blob); ceo/eve nic nie widzi
    bobs = scan_hidden_for(bob, [{"sp": k, **v} for k, v in pool.items()])
    assert len(bobs) == 2 and sorted(c["amt"] for c in bobs) == [3 * 10**8, 7 * 10**8]
    eve = Identity.generate("eve_c")
    assert scan_hidden_for(eve, [{"sp": k, **v} for k, v in pool.items()]) == []
    print("  [OK] 4. scan: bob widzi swoje (3+7 FNX z blobów); obcy widzą martwe punkty")

    # 5) hidden spend: bob 3 FNX → 1.5 ceo + 1.4 change + 0.1 fee (ring = wszyscy)
    coin = next(c for c in bobs if c["amt"] == 3 * 10**8)
    ringP = list(pool.keys())
    ringC = [pool[k]["C"] for k in ringP]
    idx = ringP.index(coin["sp"])
    FEE = 10_000_000
    payload = build_hidden_tx(
        spends=[{"ringP": ringP, "ringC": ringC, "index": idx,
                 "x": coin["spend_hint"], "r_in": coin["r"], "amt": coin["amt"]}],
        outs=[{"sig_pub": ceo.sig_pub_b, "x_pub": ceo.x_pub_b, "amount": 150_000_000},
              {"sig_pub": bob.sig_pub_b, "x_pub": bob.x_pub_b, "amount": 140_000_000}],
        fee_iskry=FEE)
    assert json.dumps(payload).count('"amt"') == 0, "kwota wyciekła do payloadu!"
    kis = verify_hidden_tx(payload, lambda sp: pool.get(sp))
    assert len(kis) == 1
    print("  [OK] 5. hidden tx: MLSAG+balance OK; payload NIE zawiera pola amt")

    # 6) odbiór: ceo odzyskuje (1.5, r) i weryfikuje C; nowy stan poola spójny
    new_outs = [{"sp": o["sp"], "ep": o["ep"], "C": o["C"], "blob": o["blob"]}
                for o in payload["out"]]
    ceo_coins = scan_hidden_for(ceo, new_outs)
    assert len(ceo_coins) == 1 and ceo_coins[0]["amt"] == 150_000_000
    bob_change = scan_hidden_for(bob, new_outs)
    assert len(bob_change) == 1 and bob_change[0]["amt"] == 140_000_000
    spent_commit = point_decode(bytes.fromhex(coin["C"]))
    out_sum = _pmf(FEE, ah._derive_h())
    for o in payload["out"]:
        out_sum = _paf(out_sum, point_decode(bytes.fromhex(o["C"])))
    zcheck = (coin["r"] - ceo_coins[0]["r"] - bob_change[0]["r"]) % _CURVE_L
    assert ah.commit(0, zcheck) == point_encode(point_add_fast(
        spent_commit, _neg(out_sum))), "bilans zobowiązań ≠ na skalarach!"
    print(f"  [OK] 6. ceo odzyskał 1.5 FNX z blobu; ΣC_in = ΣC_out + fee·H (na skalarach)")

    # 7) fałszerstwa tx: kłamstwo fee (bilans≠), ki-podmianka, member spoza poola, rp-zepsuty
    import copy as _copy
    bad1 = _copy.deepcopy(payload)
    bad1["fee"] = FEE - 10_000_000          # kłamstwo fee → D się nie spina (z ≠)
    try:
        verify_hidden_tx(bad1, lambda sp: pool.get(sp))
        raise SystemExit("kłamstwo fee przeszło!")
    except ClsagError as e:
        assert "MLSAG" in str(e) or "NIEWAŻNY" in str(e)
    bad2 = _copy.deepcopy(payload)
    bad2["in"][0]["ki"] = bytes(32).hex()
    try:
        verify_hidden_tx(bad2, lambda sp: pool.get(sp))
        raise SystemExit("ki-podmianka przeszła!")
    except ClsagError as e:
        # ki jest w kanonie → podmiana psuje msg → łapie wiązanie MLSAG (albo porównanie ki)
        assert "key_image" in str(e) or "MLSAG" in str(e)
    try:
        verify_hidden_tx(payload, lambda sp: pool.get(sp) if sp != ringP[0] else None)
        raise SystemExit("member spoza poola przeszedł!")
    except ClsagError as e:
        assert "spoza poola" in str(e)
    bad3 = _copy.deepcopy(payload)
    rp3 = bytearray.fromhex(bad3["out"][0]["rp"])
    rp3[7] ^= 1
    bad3["out"][0]["rp"] = rp3.hex()
    try:
        verify_hidden_tx(bad3, lambda sp: pool.get(sp))
        raise SystemExit("zepsuty rp przeszedł!")
    except ClsagError:
        pass
    print("  [OK] 7. fałszerstwa: fee-kłamstwo / ki-podmianka / member obcy / rp-zepsuty → odrzuty")

    print("\nSELFTEST: PASS ✅  chain/clsag.py — 3b rdzeń: kwoty ukryte, bilans dowiedziony,\n"
          "double-spend po ki gotowy; integracja z ledgerem v=2 = chain/tx_hidden.py (D38) ✅")
