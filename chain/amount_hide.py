# chain/amount_hide.py — CONFIDENTIAL AMOUNTS: kwota niewidoczna na-chain (M5b kamień 3, D31)
"""
Problem: stealth + ring chowają ODBIORCĘ i NADAWCĘ, ale łańcuch wciąż pokazuje
ILE poszło („42 FNX"). Z kwot da się łączyć transakcje (kwota jest jak odcisk palca).
Monero to chowa „zobowiązaniami Pedersena". Nasza wersja:

    COMMITMENT (zamknięta kopia przypieczętowana):
        C = a·H + r·G
        a = kwota (iskry), r = „blinding" (losowy sekret znany stronom tx)
        H, G = dwa generatory; dlog(H względem G) NIEZNANY nikomu (H z hasha,
               cofactor-cleared) → C ukrywa kwotę (hiding) i nie da się podmienić (binding)

    TRIK HOMOMORFICZNY (sedno):
        commit(a, r1) + commit(b, r2) == commit(a+b, r1+r2)
        → węzły sprawdzają:  Σ C_wejść − Σ C_wyjść − fee·H == 0
        ...czyli „suma wejść = suma wyjść + fee" NIE WIDZąc żadnej kwoty. Weryfikacja
        bez ujawnienia — to jest cała prywatność kwotowa. Fee zostaje jawne (jak w Monero).

    RANGEPROOF (dowód zakresu, żeby nikt nie stworzył FNX z powietrza):
        C = a·H + r·G można "otworzyć" też jako a−l (kwota ujemna mod l) → inflacja!
        Lekarstwo (pre-bulletproof, Borromean): rozbij kwotę na bity:
            C_i = b_i·H + r_i·G,  Σ 2^i·r_i ≡ r (mod l)  →  Σ 2^i·C_i == C
        i dla KAŻDEGO bitu podpis pierścieniowy Borromean na {C_i, C_i−H}:
        „znam sekret jednego z dwojga" ≡ „b_i ∈ {0,1}" → kwota ∈ [0, 2^RANGE_BITS).
        Bulletproofs (krótsze dowody) = backlog D31.

Serializacja podpisów/proofów = stabilne bajty pod przyszły typ TX_RING.
Selftest: hiding/binding, homomorfizm+bilans (+fee), Borromean OK/fałszerstwa,
rangeproof 16-bit (szybki) + PEŁNY 64-bit (produkcyjny kształt), round-trip bajtów.
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

from chain.stealth import (_BASE, _IDENTITY, _L, _P, point_add_fast, point_decode,  # noqa: E402
                           point_encode, point_mul_fast)

RANGE_BITS = 64        # każda kwota < 2^64 iskier (≈1.8e11 FNX — wielokrotność supply; bezpieczne)
_PDOM = b"fnx/pedersen/01"
_RDOM = b"fnx/rangeproof/01"
_BDOM = b"fnx/borromean/01"
_FIX_SEED: bytes | None = None        # DEV: deterministyczne losowości w selfteście
_FIX_STATE = [0]


class AmountError(Exception):
    """Zła kwota/commitment/proof — jeden typ."""


def _hs_amt(*parts: bytes) -> int:
    h = hashlib.blake2s(digest_size=32)
    for p in parts:
        h.update(p)
    return int.from_bytes(h.digest(), "little") % _L


def random_blinding() -> int:
    if _FIX_SEED is not None:
        _FIX_STATE[0] += 1
        return _hs_amt(_FIX_SEED, b"blind", _FIX_STATE[0].to_bytes(8, "little")) or 1
    return int.from_bytes(secrets.token_bytes(32), "little") % _L or 1


# -------------------------------------------------------------------------- generator H
def _derive_h() -> tuple[int, int]:
    """Drugi generator H: hash→punkt z cofactor-clear. KLUCZOWE: nikt nie zna dlog(H wzgl. G)
    (NIE można użyć u·G ze znanym u — to zabiłoby binding!). Try-and-increment na y-coord."""
    ctr = 0
    while True:
        raw = hashlib.blake2s(_PDOM + b"H-gen" + ctr.to_bytes(4, "little"), digest_size=32).digest()
        try:
            cand = point_decode(raw)              # ~50% surowych hashy ląduje na krzywej
        except ValueError:
            ctr += 1
            continue
        h8 = point_mul_fast(8, cand)              # ×cofactor → na pewno w podgrupie rzędu l
        if h8 != _IDENTITY:
            return h8
        ctr += 1


_H = _derive_h()


def _neg(P: tuple[int, int]) -> tuple[int, int]:
    """−(x, y) = (−x, y) na edwards25519."""
    return ((_P - P[0]) % _P, P[1])


# -------------------------------------------------------------------------- commitments
def commit(amount: int, blinding: int) -> bytes:
    """C = amount·H + blinding·G (32B punkt). UKRYWA kwotę, WIĄŻE wartość."""
    if not 0 <= amount < (1 << RANGE_BITS):
        raise AmountError(f"kwota poza [0, 2^{RANGE_BITS})")
    blinding %= _L
    return point_encode(point_add_fast(point_mul_fast(amount, _H), point_mul_fast(blinding)))


def add_commits(*commits: bytes) -> bytes:
    """Homomorficzna suma commitmentów: Σ(a_i·H + r_i·G) = (Σa)·H + (Σr)·G."""
    acc = _IDENTITY
    for c in commits:
        try:
            acc = point_add_fast(acc, point_decode(c))
        except ValueError as e:
            raise AmountError(f"commitment to nie punkt ed25519: {e}") from None
    return point_encode(acc)


def sub_commit(c: bytes) -> bytes:
    """−C (do odejmowania w bilansie)."""
    try:
        return point_encode(_neg(point_decode(c)))
    except ValueError as e:
        raise AmountError(f"commitment to nie punkt ed25519: {e}") from None


def verify_balance(in_commits: List[bytes], out_commits: List[bytes], fee_iskry: int = 0) -> bool:
    """Σ wejść − Σ wyjść − fee·H == 0 (punkt identity)? WYMAGA zgodnych blindingów stron:
       Σ r_in ≡ Σ r_out (mod l) — to załatwia konstruktor tx. Fee jest JAWNE (jak w Monero)."""
    if fee_iskry < 0 or fee_iskry >= (1 << RANGE_BITS):
        return False
    try:
        lhs = point_decode(add_commits(*in_commits)) if in_commits else _IDENTITY
        rhs = point_decode(add_commits(*out_commits)) if out_commits else _IDENTITY
        if fee_iskry:
            rhs = point_add_fast(rhs, point_mul_fast(fee_iskry, _H))
        return point_encode(point_add_fast(lhs, _neg(rhs))) == point_encode(_IDENTITY)
    except AmountError:
        return False


# -------------------------------------------------------------------------- Borromean (dowody bitów)
def _bchal(msg: bytes, R_enc: bytes, ring_i: int, slot_i: int) -> int:
    return _hs_amt(_BDOM, msg, ring_i.to_bytes(2, "little"), slot_i.to_bytes(2, "little"), R_enc)


def _bfinal(msg: bytes, final_Rs: List[tuple[int, int]]) -> int:
    return _hs_amt(_BDOM + b"final", msg, b"".join(point_encode(R) for R in final_Rs))


@dataclass
class BorromeanSig:
    """Jeden podpis na M pierścieni naraz (e0 wspólne — to spaja dowody w całość).
       e0(32LE) ‖ m(2BE) ‖ per ring: nr(2BE) + nr×s(32LE)."""
    e0: int
    s: List[List[int]]

    def to_bytes(self) -> bytes:
        out = bytearray(self.e0.to_bytes(32, "little"))
        out += len(self.s).to_bytes(2, "big")
        for ring_s in self.s:
            out += len(ring_s).to_bytes(2, "big")
            for sv in ring_s:
                out += sv.to_bytes(32, "little")
        return bytes(out)

    @staticmethod
    def from_bytes(raw: bytes) -> "BorromeanSig":
        if len(raw) < 34:
            raise AmountError("za krótki podpis Borromean")
        e0 = int.from_bytes(raw[:32], "little")
        m = int.from_bytes(raw[32:34], "big")
        off = 34
        s: List[List[int]] = []
        for _ in range(m):
            if len(raw) < off + 2:
                raise AmountError("obcięty podpis Borromean")
            nr = int.from_bytes(raw[off:off + 2], "big")
            off += 2
            if nr < 2 or len(raw) < off + 32 * nr:
                raise AmountError("zły rozmiar pierścienia Borromean")
            ring_s = [int.from_bytes(raw[off + 32 * i: off + 32 * (i + 1)], "little") for i in range(nr)]
            off += 32 * nr
            s.append(ring_s)
        if off != len(raw):
            raise AmountError("nadmiarowe bajty po podpisie Borromean")
        if e0 >= _L or any(sv >= _L for ring_s in s for sv in ring_s):
            raise AmountError("skalary poza zakresem grupy")
        return BorromeanSig(e0=e0, s=s)


def borromean_sign(msg: bytes, rings: List[List[bytes]], signer_idx: List[int],
                   secrets_list: List[int]) -> BorromeanSig:
    """rings[r] = [P0..P_{nr-1}] (encoded); w ringu r znamy dlog P[j_r] = secrets_list[r].
    Fazy: (1) spacer PO podpisującym → finalR_r; (2) e0 = H(finalR wszystkich);
    (3) spacer PRZED od e0; (4) domknięcie s[j_r] = k_r − e·x_r."""
    m = len(rings)
    if not (m == len(signer_idx) == len(secrets_list)):
        raise AmountError("rings/idx/secrets muszą mieć tę samą długość")
    ring_pts: List[List[tuple[int, int]]] = []
    for r in range(m):
        if len(rings[r]) < 2 or not (0 <= signer_idx[r] < len(rings[r])):
            raise AmountError("zły pierścień/indeks podpisującego")
        try:
            pts = [point_decode(pk) for pk in rings[r]]
        except ValueError as e:
            raise AmountError(f"członek pierścienia to nie punkt: {e}") from None
        if point_encode(point_mul_fast(secrets_list[r])) != rings[r][signer_idx[r]]:
            raise AmountError(f"sekret NIE pasuje do rings[{r}][{signer_idx[r]}]")
        ring_pts.append(pts)

    k_r = [random_blinding() for _ in range(m)]
    a_r = [point_mul_fast(kv) for kv in k_r]
    s: List[List[int]] = [[0] * len(rings[r]) for r in range(m)]
    final_Rs: List[tuple[int, int]] = []

    # faza 1: pozycje PO podpisującym (j_r+1 .. nr-1) spacerem losowych s
    for r in range(m):
        nr = len(rings[r])
        jr = signer_idx[r]
        if jr == nr - 1:
            final_Rs.append(a_r[r])            # signer na końcu: finalR = k_r·G
            continue
        e = _bchal(msg, point_encode(a_r[r]), r, jr + 1)
        for i in range(jr + 1, nr - 1):
            s[r][i] = random_blinding()
            Ri = point_add_fast(point_mul_fast(s[r][i]), point_mul_fast(e, ring_pts[r][i]))
            e = _bchal(msg, point_encode(Ri), r, i + 1)
        s[r][nr - 1] = random_blinding()
        final_Rs.append(point_add_fast(point_mul_fast(s[r][nr - 1]),
                                       point_mul_fast(e, ring_pts[r][nr - 1])))

    # faza 2: wspólne wyzwanie startowe spajające WSZYSTKIE pierścienie
    e0 = _bfinal(msg, final_Rs)

    # fazy 3-4: pozycje PRZED podpisującym (0 .. j_r-1) od e0, potem domknięcie
    for r in range(m):
        jr = signer_idx[r]
        e = e0
        for i in range(jr):
            s[r][i] = random_blinding()
            Ri = point_add_fast(point_mul_fast(s[r][i]), point_mul_fast(e, ring_pts[r][i]))
            e = _bchal(msg, point_encode(Ri), r, i + 1)
        s[r][jr] = (k_r[r] - e * (secrets_list[r] % _L)) % _L
    return BorromeanSig(e0=e0, s=s)


def borromean_verify(msg: bytes, rings: List[List[bytes]], sig: BorromeanSig) -> bool:
    """Jazda z e0 do końca każdego pierścienia; e0 MUSI wyjść z H(finalR wszystkich)."""
    m = len(rings)
    if len(sig.s) != m or sig.e0 >= _L:
        return False
    try:
        final_Rs: List[tuple[int, int]] = []
        for r in range(m):
            nr = len(rings[r])
            if len(sig.s[r]) != nr or nr < 2 or any(sv >= _L for sv in sig.s[r]):
                return False
            pts = [point_decode(pk) for pk in rings[r]]
            e = sig.e0
            for i in range(nr - 1):
                Ri = point_add_fast(point_mul_fast(sig.s[r][i]), point_mul_fast(e, pts[i]))
                e = _bchal(msg, point_encode(Ri), r, i + 1)
            final_Rs.append(point_add_fast(point_mul_fast(sig.s[r][nr - 1]),
                                           point_mul_fast(e, pts[nr - 1])))
        return _bfinal(msg, final_Rs) == sig.e0
    except ValueError:
        return False


# -------------------------------------------------------------------------- rangeproof
@dataclass
class RangeProof:
    """Dowód: commit(a, r) ukrywa a ∈ [0, 2^n). Zawiera per-bit commitmenty C_i
       (weryfikator sam odtwarza C = Σ 2^i·C_i — to też DOWIĄZUJE proof do tej kwoty)."""
    bit_commits: List[bytes]
    sig: BorromeanSig

    def to_bytes(self) -> bytes:
        n = len(self.bit_commits)
        out = bytearray(n.to_bytes(2, "big"))
        for c in self.bit_commits:
            if len(c) != 32:
                raise AmountError("bit_commit = 32B")
            out += c
        out += self.sig.to_bytes()
        return bytes(out)

    @staticmethod
    def from_bytes(raw: bytes) -> "RangeProof":
        if len(raw) < 2:
            raise AmountError("za krótki RangeProof")
        n = int.from_bytes(raw[:2], "big")
        if n < 1 or len(raw) < 2 + 32 * n:
            raise AmountError("obcięte bit_commits")
        commits = [raw[2 + 32 * i: 2 + 32 * (i + 1)] for i in range(n)]
        return RangeProof(bit_commits=commits, sig=BorromeanSig.from_bytes(raw[2 + 32 * n:]))


def _range_msg(commit_b: bytes, bit_commits: List[bytes]) -> bytes:
    return hashlib.blake2s(_RDOM + commit_b + b"".join(bit_commits), digest_size=32).digest()


def prove_range(amount: int, blinding: int, bits: int = RANGE_BITS) -> RangeProof:
    """Dowód zakresu dla commit(amount, blinding). bits=64 w produkcji; selftest bierze mniej.
    r_0 dobieramy tak, by Σ 2^i·r_i ≡ blinding — dzięki temu Σ 2^i·C_i == C."""
    if bits < 2 or bits > RANGE_BITS:
        raise AmountError(f"bits musi być w [2, {RANGE_BITS}]")
    if not 0 <= amount < (1 << bits):
        raise AmountError(f"kwota poza zakresem {bits} bitów — proof niemożliwy")
    blinding %= _L
    r_i = [0] + [random_blinding() for _ in range(bits - 1)]
    r_i[0] = (blinding - sum((1 << i) * r_i[i] for i in range(1, bits))) % _L
    bit_commits = []
    for i in range(bits):
        b_i = (amount >> i) & 1
        bit_commits.append(point_encode(point_add_fast(point_mul_fast(b_i, _H),
                                                       point_mul_fast(r_i[i]))))
    commit_b = commit(amount, blinding)
    msg = _range_msg(commit_b, bit_commits)
    rings = []
    for i in range(bits):
        Ci = point_decode(bit_commits[i])
        rings.append([bit_commits[i], point_encode(point_add_fast(Ci, _neg(_H)))])
    sig = borromean_sign(msg, rings, [(amount >> i) & 1 for i in range(bits)], r_i)
    return RangeProof(bit_commits=bit_commits, sig=sig)


def verify_range(commit_b: bytes, proof: RangeProof, bits: int | None = None) -> bool:
    """(1) Σ 2^i·C_i == commit  (proof pasuje do TEJ kwoty)
       (2) Borromean: każdy bit ∈ {0,1}  →  kwota ∈ [0, 2^n)."""
    n = len(proof.bit_commits)
    if bits is not None and n != bits:
        return False
    if n < 2 or n > RANGE_BITS:
        return False
    try:
        target = point_decode(commit_b)
        pts = [point_decode(c) for c in proof.bit_commits]
    except ValueError:
        return False
    # Σ 2^i·C_i — Hornerem od najstarszego bitu (same szybkie addy; 2·IDENTITY=IDENTITY, OK)
    acc = _IDENTITY
    for i in range(n - 1, -1, -1):
        acc = point_add_fast(point_add_fast(acc, acc), pts[i])
    if acc != target:
        return False
    msg = _range_msg(commit_b, proof.bit_commits)
    rings = []
    for c in proof.bit_commits:
        Ci = point_decode(c)
        rings.append([c, point_encode(point_add_fast(Ci, _neg(_H)))])
    return borromean_verify(msg, rings, proof.sig)


# -------------------------------------------------------------------------- selftest
if __name__ == "__main__":
    print("chain/amount_hide.py — selftest: Pedersen + bilans + Borromean + rangeproof\n")

    _FIX_SEED = b"selftest-amt-v1"

    # 0) generator H: w podgrupie, niebanalny
    assert point_mul_fast(_L, _H) == _IDENTITY and _H != _IDENTITY and point_encode(_H) != point_encode(_BASE)
    print("  [OK] 0. generator H: l·H=0, H≠G — dlog(H wzgl. G) nieznany nikomu")

    # 1) hiding + determinizm
    r1, r2 = random_blinding(), random_blinding()
    c1, c2, c3 = commit(100, r1), commit(100, r2), commit(100, r1)
    assert c1 != c2 and c1 == c3 and len(c1) == 32
    assert commit(101, r1) != c1
    print("  [OK] 1. hiding: ta sama kwota + inny blinding = nieodróżnialne losowe 32B; deterministyczna powtórka")

    # 2) homomorfizm + bilans (z fee)
    ra, rb = random_blinding(), random_blinding()
    Ca, Cb = commit(60, ra), commit(40, rb)
    assert add_commits(Ca, Cb) == commit(100, (ra + rb) % _L)
    rout = (ra + rb) % _L                         # konstruktor tx: Σ r_in = Σ r_out; fee JAWNE (bez r) —
                                                  # bilans: 60H+ra·G + 40H+rb·G ?= 93H+rout·G + 7H  ⟺  100==93+7 i ra+rb==rout
    Cout = commit(93, rout)
    assert verify_balance([Ca, Cb], [Cout], fee_iskry=7), "bilans 60+40 → 93 + fee 7"
    assert not verify_balance([Ca, Cb], [Cout], fee_iskry=8), "złe fee MUSI wybuchnąć"
    assert not verify_balance([Ca, Cb], [commit(94, rout)], fee_iskry=7), "kwota wyjścia +1 MUSI wybuchnąć"
    print("  [OK] 2. homomorfizm: Σin − Σout − fee·H == 0 bez odsłaniania kwot; fałszywy bilans odrzucony")

    # 3) Borromean w czystej postaci: 3 pierścienie po 3
    xs = [random_blinding() for _ in range(3)]
    pubs3 = [point_encode(point_mul_fast(x)) for x in xs]
    decoy = [point_encode(point_mul_fast(random_blinding())) for _ in range(6)]
    rings3 = [[pubs3[0], decoy[0], decoy[1]], [decoy[2], pubs3[1], decoy[3]], [decoy[4], decoy[5], pubs3[2]]]
    bmsg = b"borromean-test-msg"
    bsig = borromean_sign(bmsg, rings3, [0, 1, 2], xs)
    assert borromean_verify(bmsg, rings3, bsig), "Borromean MUSI się zweryfikować"
    assert not borromean_verify(b"inny-msg", rings3, bsig), "podmiana wiadomości MUSI unieważnić"
    rings_bad = [[pubs3[0], decoy[1], decoy[0]], rings3[1], rings3[2]]
    assert not borromean_verify(bmsg, rings_bad, bsig), "przestawienie członka MUSI unieważnić"
    try:
        borromean_sign(bmsg, rings3, [0, 1, 2], [xs[0], xs[1], xs[0]])
        raise SystemExit("POWINNO rzucić AmountError — cudzy sekret na poz. 2")
    except AmountError:
        pass
    print("  [OK] 3. Borromean: 3×3 weryfikuje; zły msg/pierścień/sekret → odrzucone")

    # 4) rangeproof szybki: 16 bitów (mechanika identyczna jak produkcyjna)
    amt, blind = 54321, random_blinding()
    C = commit(amt, blind)
    proof16 = prove_range(amt, blind, bits=16)
    assert verify_range(C, proof16, bits=16), "rangeproof MUSI się zweryfikować"
    assert not verify_range(commit(amt + 1, blind), proof16, bits=16), "proof pod INNY commit — odrzucić"
    tampered = RangeProof(bit_commits=proof16.bit_commits[:], sig=proof16.sig)
    tb = bytearray(tampered.bit_commits[3])
    tb[5] ^= 1
    tampered.bit_commits[3] = bytes(tb)
    assert not verify_range(C, tampered, bits=16), "sabotaż bit_commit MUSI unieważnić"
    for bad_amt, bad_bits in ((-1, 16), (1 << 16, 16), (5, 1)):
        try:
            prove_range(bad_amt, blind, bits=bad_bits)
            raise SystemExit(f"POWINNO rzucić AmountError: amount={bad_amt}, bits={bad_bits}")
        except AmountError:
            pass
    print("  [OK] 4. rangeproof 16-bit: weryfikuje; inny commit/sabotaż/zakres → odrzucone")

    # 5) PEŁNY 64-bit (produkcyjny kształt) + bilans z proofami (udawana tx: 60+40 → 93 + 7)
    proof64_a = prove_range(60, ra)                # domyślnie RANGE_BITS=64
    proof64_c = prove_range(93, rout)
    assert verify_range(Ca, proof64_a) and verify_range(Cout, proof64_c)
    assert verify_balance([Ca, Cb], [Cout], fee_iskry=7)  # łańcuch: bilans + oba proofy = tx ważna
    size64 = len(proof64_a.to_bytes())
    assert size64 == 2 + 64 * 32 + (32 + 2 + 64 * (2 + 64))   # stabilny wymiar = 6308B
    print(f"  [OK] 5. PEŁNY 64-bit: proof={size64}B (~6KB/wyjście; bulletproofs w backlogu D31 to zmniejszą ~10×);"
          f" tx z ukrytymi kwotami WAŻNA mimo że nikt nie widzi liczb")

    # 6) serializacja + odporność na śmieci
    blob = proof64_a.to_bytes()
    assert RangeProof.from_bytes(blob).to_bytes() == blob
    try:
        RangeProof.from_bytes(blob[:-17])
        raise SystemExit("POWINNO rzucić AmountError — obcięty proof")
    except AmountError:
        pass
    try:
        commit(-5, 1)
        raise SystemExit("POWINNO rzucić AmountError — ujemna kwota")
    except AmountError:
        pass
    garbage = bytes(32)
    assert not verify_range(garbage, proof64_a), "commit-śmieć odrzucić"
    print("  [OK] 6. serializacja round-trip; śmieci/ujemne/obcięte → odrzucone")

    print("\nSELFTEST: PASS ✅  kwoty ukryte: bilans weryfikowalny BEZ ujawniania liczb, inflacja zablokowana")
