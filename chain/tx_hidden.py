# chain/tx_hidden.py — TX_SHIELD v2 + TX_RING v2: konsensus ukrytych kwot (3b→ledger, D38)
"""
Model (analogia „bankomat przy wejściu do lasu"):
  WEJŚCIE do poola (SHIELD v2): KWOTA WEJŚCIA jest publiczna (jak w Zcash t→z) —
    łańcuch widzi, że PRZEZ BRAMKĘ weszło X iskier. Konsensus wiąże spalenie z
    zobowiązaniem: nadawca publikuje amt + r_pub, a wszyscy sprawdzają tanio, że
    C == commit(amt, r_pub). Za bramką LAS ZACHOWUJE tylko:
        C (zobowiązanie Pedersena) + blob (zaszyfrowane {kwota‖r} dla właściciela).
    LEDGER NIE TRZYMA „amt" DLA WPISÓW v2 — kwota znika za bramką (to jest cały
    sens 3b: blockchain przestaje znać wartość monet).
  WNĘTRZE (RING v2): pełna mgła — chain/clsag.verify_hidden_tx: MLSAG (dwie
    kolumny [P, D=C−Σout−fee·H]) dowodzi Σin = Σout + fee BEZ ujawniania kwot;
    Borromean range proof per wyjście = „nie da się wydrukować ujemnej liczby";
    key-image = jeden pocisk, jeden strzał (rejestr w ledgerze jak w 3a).
  WYJŚCIE (UNSHIELD v2) = następny plik (uczciwy backlog) — dziś wartość żyje
  w MGL poola; wejście+transfer wewnętrzny wystarczają do prywatnych przekazów.

  MIGRACJA 3a: wpisy v1 ({ep, amt}) działają dalej przez v1-ściężkę (test!).
  Mieszanych ringów nie ma: ring v2 bierze członków TYLKO z wpisów v2 (po C),
  ring v1 nadal wymaga identycznego amt (nieznajomość C ≠ błąd, po prostu inna gra).
  Hardening v1 (złapane przy tej robocie!): SHIELD v1 z N wyjściami kredytował
  KAŻDEMU wyjściu pełne tx.amount (N× pieniądza z 1× wkładu) → teraz v1 musi mieć
  DOKŁADNIE 1 wyjście; wiele wyjść → używamy v2 (suma == amount weryfikowana).
"""
from __future__ import annotations

import json
import sys
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from chain.tx_ring import MAX_AMT, MAX_OUTS                                         # noqa: E402
from chain import clsag as cx                                                       # noqa: E402
from chain import amount_hide as ah                                                 # noqa: E402


class TxHiddenError(Exception):
    """Błąd formatu/konsensusu v2 (jak TxRingError w 3a)."""


MAX_MINT_OUTS = MAX_OUTS
_BLOB_HEX_MAX = 2 * cx.MAX_BLOB


def _h32(s: str, what: str) -> bytes:
    if not isinstance(s, str) or len(s) != 64:
        raise TxHiddenError(f"{what}: 64 znaki hex wymagane")
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise TxHiddenError(f"{what}: nie-hex") from None


def _scalar(s: str, what: str) -> int:
    if not isinstance(s, str) or len(s) != 64:
        raise TxHiddenError(f"{what}: 64 znaki hex (skalar) wymagane")
    try:
        v = int(s, 16)
    except ValueError:
        raise TxHiddenError(f"{what}: nie-hex") from None
    if not (0 < v < cx._CURVE_L):
        raise TxHiddenError(f"{what}: skalar poza 1..l-1")
    return v


# -------------------------------------------------------------------------- payload v (wspólne)
def payload_v(raw: str) -> int:
    """Wersja payloadu (1|2). Lekki peek dla dispatchu ledgera (shield i ring)."""
    try:
        p = json.loads(raw)
    except (TypeError, ValueError):
        raise TxHiddenError("payload: niepoprawny JSON") from None
    v = p.get("v") if isinstance(p, dict) else None
    if v not in (1, 2):
        raise TxHiddenError("payload: brak v∈{1,2}")
    return int(v)


# -------------------------------------------------------------------------- SHIELD v2 (wejście)
def make_shield2_out(sig_pub_b: bytes, x_pub_b: bytes, amt_iskry: int) -> dict:
    """STRONA PORTFELA: mint-wyjście v2 (stealth + C + rp + blob + jawnie amt/r_pub,
    bo wejście i tak jest publiczne — jak bilet pokazany na bramce lasu)."""
    if not isinstance(amt_iskry, int) or not (0 < amt_iskry <= MAX_AMT):
        raise TxHiddenError("mint: zła kwota")
    r = ah.random_blinding()
    C_b = ah.commit(amt_iskry, r)
    st = cx._stealth_with_shared(sig_pub_b, x_pub_b)   # ta sama matematyka co stealth
    rp = ah.prove_range(amt_iskry, r)
    return {"sp": st["stealth_pub"], "ep": st["eph_pub"], "C": C_b.hex(),
            "rp": rp.to_bytes().hex(),
            "blob": cx.seal_amount(st["shared"], C_b, amt_iskry, r),
            "amt": int(amt_iskry), "r_pub": "%064x" % r}


def shield2_payload(outs: list[dict]) -> str:
    """Tx.payload dla TX_SHIELD v2. outs = lista make_shield2_out(...)."""
    if not (1 <= len(outs) <= MAX_MINT_OUTS):
        raise TxHiddenError("shield v2: 1..8 mint-wyjść")
    return json.dumps({"v": 2, "mint": outs}, separators=(",", ":"), sort_keys=True)


def parse_shield2(raw: str) -> dict:
    try:
        p = json.loads(raw)
    except (TypeError, ValueError):
        raise TxHiddenError("shield v2: niepoprawny JSON") from None
    if not isinstance(p, dict) or p.get("v") != 2 or not isinstance(p.get("mint"), list):
        raise TxHiddenError("shield v2: brak {v:2, mint:[…]}")
    return p


def validate_shield2(raw: str, expected_total: int) -> list[dict]:
    """PEŁNA walidacja konsensusu mintu. Zwraca wyjścia v2 (dict-e).
       expected_total = tx.amount: suMA wszystkich mintów MUSI się równać spaleniu
       — inaczej byłaby drukarnia w lesie (test ataku poniżej)."""
    outs = parse_shield2(raw)["mint"]
    if not (1 <= len(outs) <= MAX_MINT_OUTS):
        raise TxHiddenError("shield v2: 1..8 mint-wyjść")
    total = 0
    out: list[dict] = []
    for o in outs:
        if not isinstance(o, dict):
            raise TxHiddenError("shield v2: mint nie-obiekt")
        _h32(o.get("sp", ""), "mint.sp")
        _h32(o.get("ep", ""), "mint.ep")
        C_b = _h32(o.get("C", ""), "mint.C")
        r_pub = _scalar(o.get("r_pub", ""), "mint.r_pub")
        amt = o.get("amt")
        if not isinstance(amt, int) or not (0 < amt <= MAX_AMT):
            raise TxHiddenError("mint.amt: int 1..MAX_AMT")
        # ── wiązanie spalenia z C: tanie, jawne, ZAMYKA drukarnię na wejściu ──
        if ah.commit(amt, r_pub) != C_b:
            raise TxHiddenError("mint: C ≠ commit(amt, r_pub) — podmiana na bramce!")
        try:
            rp = ah.RangeProof.from_bytes(bytes.fromhex(o.get("rp", "")))
        except (ValueError, ah.AmountError) as e:
            raise TxHiddenError(f"mint: rp bajtowo zły: {e}") from None
        if not ah.verify_range(C_b, rp):
            raise TxHiddenError("mint: range proof NIEZGODNY")
        blob = o.get("blob", "")
        if not isinstance(blob, str) or not blob or len(blob) > _BLOB_HEX_MAX:
            raise TxHiddenError("mint: zły blob")
        total += amt
        out.append({"sp": o["sp"], "ep": o["ep"], "C": o["C"], "blob": blob,
                    "amt": amt})
    if total != expected_total:
        raise TxHiddenError(f"mint: suma {total} ≠ spalonie {expected_total} (drukarnia?!)")
    return out


# -------------------------------------------------------------------------- RING v2 (wnętrze)
def parse_ring2(raw: str) -> dict:
    """Peek payloadu ringu v2 (ledger używa do ledger-side odczytów; PEŁNA
    weryfikacja = chain/clsag.verify_hidden_tx)."""
    try:
        p = json.loads(raw)
    except (TypeError, ValueError):
        raise TxHiddenError("ring v2: niepoprawny JSON") from None
    if not isinstance(p, dict) or p.get("v") != 2:
        raise TxHiddenError("ring v2: brak v=2")
    for k in ("in", "out", "fee"):
        if k not in p:
            raise TxHiddenError(f"ring v2: brak {k}")
    return p


def ring2_kis(raw: str) -> list[str]:
    """Key-image-y z payloadu v2 (dedup mempoola; bez pełnej walidacji)."""
    p = parse_ring2(raw)
    return [i.get("ki", "") for i in p["in"] if isinstance(i, dict)]


# -------------------------------------------------------------------------- UNSHIELD v2 (wyjście)
def parse_unshield2(raw: str) -> dict:
    """Peek payloadu UNSHIELD v2: {v:2, in, out, to, amt, fee} (out = reszta w mgle,
    MOŻE być [] gdy wypłata idealnie w punkcie)."""
    try:
        p = json.loads(raw)
    except (TypeError, ValueError):
        raise TxHiddenError("unshield v2: niepoprawny JSON") from None
    if not isinstance(p, dict) or p.get("v") != 2:
        raise TxHiddenError("unshield v2: brak v=2")
    for k in ("in", "out", "to", "amt", "fee"):
        if k not in p:
            raise TxHiddenError(f"unshield v2: brak {k}")
    return p


def _unshield_msg(payload: dict) -> bytes:
    from chain.block import canon
    core = {"v": payload["v"],
            "in": [{k: v for k, v in i.items() if k != "sig"} for i in payload["in"]],
            "out": payload["out"], "to": payload["to"],
            "amt": payload["amt"], "fee": payload["fee"]}
    return canon(core)


def build_unshield2(spends: list[dict], outs: list[dict], to_wallet: str,
                    amt_iskry: int, fee_iskry: int) -> dict:
    """STRONA PORTFELA: Σin = Σout_zmiany + amt + fee, gdzie amt Y WYCHODZI na jaw
    (z→t). spends/outs — format identyczny jak w clsag.build_hidden_tx."""
    from chain.stealth import point_encode, point_decode, point_add_fast
    if not (1 <= len(spends) <= cx.MAX_INS and 0 <= len(outs) <= cx.MAX_OUTS):
        raise TxHiddenError("unshield: 1..8 wejść; reszta 0..8 wyjść v2")
    if not isinstance(amt_iskry, int) or not (0 < amt_iskry <= MAX_AMT):
        raise TxHiddenError("unshield: zła kwota Y")
    if not isinstance(fee_iskry, int) or not (0 <= fee_iskry <= MAX_AMT):
        raise TxHiddenError("unshield: złe fee")
    if not isinstance(to_wallet, str) or not to_wallet:
        raise TxHiddenError("unshield: brak portfela docelowego")
    out_list, out_C, sum_r_out, sum_amt_out = [], [], 0, 0
    for o in outs:
        amt = int(o["amount"])
        if not (0 < amt <= MAX_AMT):
            raise TxHiddenError("unshield: zła kwota reszty")
        r = ah.random_blinding()
        C_b = ah.commit(amt, r)
        st = cx._stealth_with_shared(o["sig_pub"], o["x_pub"])
        out_list.append({"sp": st["stealth_pub"], "ep": st["eph_pub"], "C": C_b.hex(),
                         "rp": ah.prove_range(amt, r).to_bytes().hex(),
                         "blob": cx.seal_amount(st["shared"], C_b, amt, r)})
        out_C.append(point_decode(C_b))
        sum_r_out = (sum_r_out + r) % cx._CURVE_L
        sum_amt_out += amt
    # pseudoOut per wejście (jak w clsag — poprawne wielo-wejście, złapane testem M7d):
    #   Σ pseudo == Σ C_out + (Y+fee)·H; maski r_p: Σr_p = Σr_out.
    r_p: list = [ah.random_blinding() for _ in spends]
    if len(spends) == 1:
        r_p[0] = sum_r_out % cx._CURVE_L
    else:
        r_p[-1] = (sum_r_out - sum(r_p[:-1])) % cx._CURVE_L
    ins, zs, sum_amt_in = [], [], 0
    for s, rp_i in zip(spends, r_p):
        ringP, ringC, idx = s["ringP"], s["ringC"], s["index"]
        if not (cx.RING_MIN <= len(ringP) <= cx.RING_MAX and len(ringC) == len(ringP)
                and 0 <= idx < len(ringP)):
            raise TxHiddenError("unshield: zły ring/index")
        amt_i = s.get("amt")
        if not isinstance(amt_i, int) or not (0 < amt_i <= MAX_AMT):
            raise TxHiddenError("unshield: wejście bez amt (pseudoOut wymaga nominału)")
        sum_amt_in += amt_i
        rawP = bytes.fromhex(ringP[idx]) if isinstance(ringP[idx], str) else ringP[idx]
        ki = point_encode(cx.point_mul_fast(int(s["x"]), cx.hash_to_point(rawP)))
        ins.append({"ringP": list(ringP), "ringC": list(ringC), "ki": ki.hex(),
                    "hC": ah.commit(amt_i, rp_i).hex(), "sig": ""})
        zs.append((int(s["r_in"]) - rp_i) % cx._CURVE_L)
    # portfel zna kwoty → jawnie-liczbowy fail-fast (pseudoOut sam z siebie BILANSU
    # nie pilnuje po stronie builda; robi to verify przez Σpseudo w konsensusie)
    if sum_amt_in != sum_amt_out + amt_iskry + fee_iskry:
        raise TxHiddenError("unshield: Σin ≠ Σreszty + Y + fee (złapane w build, przed podpisem)")
    payload = {"v": 2, "in": ins, "out": out_list, "to": to_wallet,
               "amt": int(amt_iskry), "fee": int(fee_iskry)}
    msg = _unshield_msg(payload)
    for n_i, (s, z) in enumerate(zip(spends, zs)):
        idx = s["index"]
        pseudo_pts = cx.point_decode(bytes.fromhex(ins[n_i]["hC"]))
        D = [cx.point_add_fast(cx._pt(c), cx._neg(pseudo_pts)) for c in s["ringC"]]
        if D[idx] != cx.point_mul_fast(z):
            raise TxHiddenError("unshield: r_in≠bilans (Σin ≠ Σout + Y + fee)")
        sig = cx.mlsag_sign(msg, s["ringP"], D, idx, int(s["x"]), z)
        ins[n_i]["sig"] = sig.to_bytes().hex()
    return payload


def _check_v2_out(o, what="wyjście") -> bytes:
    """Wspólna walidacja wyjścia v2 (ring i unshield): sp/ep/C, rp, blob. → C_b."""
    if not isinstance(o, dict):
        raise TxHiddenError(f"{what}: nie-obiekt")
    _h32(o.get("sp", ""), f"{what}.sp")
    _h32(o.get("ep", ""), f"{what}.ep")
    C_b = _h32(o.get("C", ""), f"{what}.C")
    try:
        rp = ah.RangeProof.from_bytes(bytes.fromhex(o.get("rp", "")))
    except (ValueError, ah.AmountError) as e:
        raise TxHiddenError(f"{what}: rp bajtowo zły: {e}") from None
    if not ah.verify_range(C_b, rp):
        raise TxHiddenError(f"{what}: range proof NIEZGODNY (druk z powietrza?)")
    blob = o.get("blob", "")
    if not isinstance(blob, str) or not blob or len(blob) > _BLOB_HEX_MAX:
        raise TxHiddenError(f"{what}: zły blob")
    return C_b


def verify_unshield2(payload: dict, pool_lookup_c) -> tuple:
    """Konsensus wyjścia z mgły. pool_lookup_c(sp) → {\"C\": hex}|None.
    Zwraca (kis, to_wallet, amt). Błędy: TxHiddenError (równolegle do ClsagError)."""
    ins, outs, fee = payload.get("in"), payload.get("out"), payload.get("fee")
    to_w = payload.get("to")
    amt = payload.get("amt")
    if not isinstance(ins, list) or not (1 <= len(ins) <= cx.MAX_INS):
        raise TxHiddenError("unshield: 1..8 wejść")
    if not isinstance(outs, list) or not (0 <= len(outs) <= cx.MAX_OUTS):
        raise TxHiddenError("unshield: reszta 0..8 wyjść")
    if not isinstance(fee, int) or not (0 <= fee <= MAX_AMT):
        raise TxHiddenError("unshield: złe fee")
    if not isinstance(amt, int) or not (0 < amt <= MAX_AMT):
        raise TxHiddenError("unshield: zła kwota Y")
    if not isinstance(to_w, str) or not to_w:
        raise TxHiddenError("unshield: zły portfel docelowy")
    COM = cx.point_mul_fast(amt + fee, ah._derive_h())
    for o in outs:
        COM = cx.point_add_fast(COM, cx.point_decode(_check_v2_out(o)))
    msg = _unshield_msg(payload)
    kis: list[str] = []
    ring_size = None
    pseudo_sum = None
    for i in ins:
        ringP, ringC = i.get("ringP"), i.get("ringC")
        if not isinstance(ringP, list) or not isinstance(ringC, list) \
                or len(ringP) != len(ringC) or not (cx.RING_MIN <= len(ringP) <= cx.RING_MAX):
            raise TxHiddenError("unshield: zły ring")
        if ring_size is None:
            ring_size = len(ringP)
        elif len(ringP) != ring_size:
            raise TxHiddenError("unshield: mieszane rozmiary ringów (uniform)")
        pseudo_b = _h32(i.get("hC", ""), "unshield.hC")
        pseudo_pts = cx.point_decode(pseudo_b)
        pseudo_sum = pseudo_pts if pseudo_sum is None else cx.point_add_fast(pseudo_sum, pseudo_pts)
        D = []
        for cp, cc in zip(ringP, ringC):
            _h32(cp, "unshield.ringP.member")
            C_h = _h32(cc, "unshield.ringC.member")
            entry = pool_lookup_c(cp)
            if entry is None:
                raise TxHiddenError("unshield: member spoza poola (v1 nie gra, D38)")
            if entry.get("C") != cc:
                raise TxHiddenError("unshield: ringC ≠ zobowiązanie w poolu (podmianka)")
            D.append(C_h)
        ki = _h32(i.get("ki", ""), "unshield.ki")
        Dpts = [cx.point_add_fast(cx.point_decode(C_h), cx._neg(pseudo_pts)) for C_h in D]
        try:
            sig = cx.MlsagSig.from_bytes(bytes.fromhex(i.get("sig", "")))
        except (ValueError, cx.ClsagError) as e:
            raise TxHiddenError(f"unshield: zły podpis bajtowo: {e}") from None
        if not cx.mlsag_verify(msg, ringP, Dpts, sig):
            raise TxHiddenError("unshield: podpis MLSAG NIEWAŻNY")
        if sig.key_image != ki:
            raise TxHiddenError("unshield: ki ≠ key_image z podpisu (podmianka)")
        kis.append(ki.hex())
    # bilans globalny: Σ pseudoOut == Σ C_out + (Y+fee)·H
    if pseudo_sum != COM:
        raise TxHiddenError("unshield: Σ pseudoOut ≠ Σout+(Y+fee)·H (bilans ≠)")
    return kis, to_w, int(amt)


def unshield2_outputs(payload: dict) -> list[dict]:
    """Reszta z unshield → wpisy poolu v2 (jak ring2_outputs)."""
    return [{"sp": o["sp"], "ep": o["ep"], "C": o["C"], "blob": o["blob"], "v": 2}
            for o in payload["out"]]


def ring2_outputs(payload: dict) -> list[dict]:
    """Wyjścia v2 do zapisu w poolu: samo {sp, ep, C, blob, v:2} — BEZ amt/r/rp
    (rp/być może rzb? — rp niepotrzebne po weryfikacji; ledger trzyma MINIMUM,
    wystarczające relayom i scanom właścicieli)."""
    return [{"sp": o["sp"], "ep": o["ep"], "C": o["C"], "blob": o["blob"], "v": 2}
            for o in payload["out"]]


def shield2_pool_entries(outs: list[dict]) -> dict:
    """Wyjścia mintu → wpisy poolu {sp: {ep, C, blob, v:2}} (kwota zostaje za bramką)."""
    return {o["sp"]: {"ep": o["ep"], "C": o["C"], "blob": o["blob"], "v": 2}
            for o in outs}


# -------------------------------------------------------------------------- selftest E2E
if __name__ == "__main__":
    import time

    print("chain/tx_hidden.py — selftest KONSENSUS v2: mgła w poolu, drukarnia zamknięta\n")

    from core.identity import Identity
    from chain.ledger import Ledger, ChainError
    from chain.block import Tx, ISKRA, TX_RING, TX_SHIELD, TX_UNSHIELD, fee_split
    from chain.miner import mine
    from chain import tx_ring as txr

    L = Ledger()
    ala = Identity.generate("ala_h2")
    bob = Identity.generate("bob_h2")
    carol = Identity.generate("carol_h2")
    dana = Identity.generate("dana_h2")
    eve1 = Identity.generate("eve_h2")
    fred = Identity.generate("fred_h2")

    def kop(wallet: str):
        won = mine(L.block_template(wallet, zbits=2), max_tries=600_000)
        assert won is not None
        L.apply_block(won)          # sukces = None (patrz konwencja ledgera!)

    for _ in range(4):
        kop(ala.wallet)
        kop(bob.wallet)

    # 1) HARDENING v1 (złapana inflacja!): SHIELD v1 z 2 wyjściami = kredyt 2×amount
    #    → teraz odrzucony w MEMPOOLU i w RĘCZNIE ZBUDOWANYM BLOKU
    p_bad1 = txr.shield_payload([{"sp": "aa" * 32, "ep": "bb" * 32},
                                 {"sp": "cc" * 32, "ep": "dd" * 32}])
    t_bad1 = Tx.build_signed(TX_SHIELD, bob, "FNX-SHIELD", 1 * ISKRA, nonce=0,
                             payload=p_bad1)
    try:
        L.add_tx(t_bad1)
        raise SystemExit("SHIELD v1 z 2 wyjściami przeszedł mempool (inflacja!)")
    except ChainError as e:
        assert "1 wyjście" in str(e), str(e)
    tmpl = L.block_template(bob.wallet, zbits=2)
    tmpl.txs.append(t_bad1)
    won_bad = mine(tmpl, max_tries=600_000)
    try:
        L.apply_block(won_bad)
        raise SystemExit("SHIELD v1 z 2 wyjściami przeszedł BLOK (inflacja!)")
    except ChainError as e:
        assert "1 wyjście" in str(e), str(e)
    print("  [OK] 1. v1-hardening: SHIELD v1 z >1 wyjściem odrzucony (mempool i blok)")

    # 2) WEJŚCIE v2: kwota publiczna na bramce, za bramką ZNIKA (pool bez „amt")
    out_ala = make_shield2_out(ala.sig_pub_b, ala.x_pub_b, 3 * ISKRA)
    t_mint = Tx.build_signed(TX_SHIELD, ala, "FNX-SHIELD", 3 * ISKRA, nonce=0,
                             payload=shield2_payload([out_ala]))
    L.add_tx(t_mint)
    assert L.pool == {}, "mint ma wejść do poola dopiero z bloku"
    kop(ala.wallet)
    ent = L.pool[out_ala["sp"]]
    assert ent["v"] == 2 and ent["C"] == out_ala["C"] and ent["blob"] == out_ala["blob"]
    assert "amt" not in ent, "POOL ZNA KWOTĘ v2 — cały sens 3b leży!"
    print("  [OK] 2. mint v2: pool trzyma C+blob, kwota ZNIKŁA za bramką (brak amt)")

    # 3) ataki na bramkę: C≠commit, suma≠spalenie, rp=zepsuty
    def odrzucone(t, frag):
        try:
            L.add_tx(t)
            raise SystemExit(f"atak przeszedł: {frag}")
        except ChainError as e:
            assert frag in str(e), (frag, str(e))

    o_fake = dict(out_ala); o_fake["amt"] = 4 * ISKRA          # kłamstwo o kwocie
    odrzucone(Tx.build_signed(TX_SHIELD, ala, "FNX-SHIELD", 4 * ISKRA, nonce=2,
                              payload=shield2_payload([o_fake])), "podmiana")
    o2 = make_shield2_out(ala.sig_pub_b, ala.x_pub_b, 1 * ISKRA)
    o3 = make_shield2_out(ala.sig_pub_b, ala.x_pub_b, 1 * ISKRA)
    t_sum = Tx.build_signed(TX_SHIELD, ala, "FNX-SHIELD", 3 * ISKRA, nonce=2,
                            payload=shield2_payload([o2, o3]))    # suma 2 ≠ 3
    odrzucone(t_sum, "suma")
    o_rp = dict(o2); o_rp["rp"] = ("00" if o2["rp"][:2] != "00" else "01") + o2["rp"][2:]
    odrzucone(Tx.build_signed(TX_SHIELD, ala, "FNX-SHIELD", 1 * ISKRA, nonce=2,
                              payload=shield2_payload([o_rp])), "rp bajtowo")
    print("  [OK] 3. bramka v2: C≠commit / suma≠spalenie / rp-zepsuty → odrzuty")

    # 4) masa v2 do ringów: bob mincuje 5 × 1 FNX JEDNYM shieldem v1? nie — v2, 5 wyjść
    outs_bob = [make_shield2_out(bob.sig_pub_b, bob.x_pub_b, 1 * ISKRA)
                for _ in range(5)]
    t_bob = Tx.build_signed(TX_SHIELD, bob, "FNX-SHIELD", 5 * ISKRA, nonce=0,
                            payload=shield2_payload(outs_bob))
    L.add_tx(t_bob)
    kop(bob.wallet)
    assert all(L.pool[o["sp"]]["v"] == 2 for o in outs_bob)
    print("  [OK] 4. jeden SHIELD v2 = 5 mint-wyjść (suma==amount); pool 6 monet v2")

    # 5) MGŁA: ala wydaje 3 FNX w ringu 5 (sama + 4 wabiki bobów) — łańcuch nie widzi kwot
    ringP = [out_ala["sp"]] + [o["sp"] for o in outs_bob[:4]]
    ringC = [L.pool[s]["C"] for s in ringP]
    ring_outs = [{"sp": s, "ep": L.pool[s]["ep"], "C": L.pool[s]["C"],
                  "blob": L.pool[s]["blob"]} for s in ringP]
    found = cx.scan_hidden_for(ala, ring_outs)
    assert len(found) == 1 and found[0]["amt"] == 3 * ISKRA, "scan nie znalazł mojej monety"
    c0 = found[0]
    fee = fee_split(2 * ISKRA)[2]                              # 112_000 iskier D15
    spends = [{"ringP": ringP, "ringC": ringC, "index": ringP.index(c0["sp"]),
               "x": c0["spend_hint"], "r_in": c0["r"], "amt": c0["amt"]}]
    outs = [{"sig_pub": carol.sig_pub_b, "x_pub": carol.x_pub_b, "amount": 2 * ISKRA},
            {"sig_pub": ala.sig_pub_b, "x_pub": ala.x_pub_b,
             "amount": 3 * ISKRA - 2 * ISKRA - fee}]
    payload2 = cx.build_hidden_tx(spends, outs, fee)
    tx2 = Tx(type=TX_RING, sender="", recipient="", amount=0, nonce=0,
             payload=json.dumps(payload2, separators=(",", ":"), sort_keys=True))
    assert '"amt"' not in tx2.payload and str(2 * ISKRA) not in tx2.payload, \
        "payload v2 zdradza kwotę (ringP/ringC/C/rp/blob = zero liczb!)"
    L.add_tx(tx2)
    kop(bob.wallet)
    ki = payload2["in"][0]["ki"]
    assert ki in L.key_images
    scan_carol = cx.scan_hidden_for(carol, [{"sp": o["sp"], "ep": o["ep"], "C": o["C"],
                                             "blob": o["blob"]} for o in payload2["out"]])
    assert len(scan_carol) == 1 and scan_carol[0]["amt"] == 2 * ISKRA
    change = [o for o in cx.scan_hidden_for(ala, [{"sp": o["sp"], "ep": o["ep"],
              "C": o["C"], "blob": o["blob"]} for o in payload2["out"]])]
    assert len(change) == 1 and change[0]["amt"] == 1 * ISKRA - fee
    tx_pool_ama = all("amt" not in e for e in
                      (L.pool[o["sp"]] for o in payload2["out"]))
    assert tx_pool_ama, "wyjścia RING v2 nie mogą mieć amt w poolu"
    print("  [OK] 5. RING v2 w bloku: ki zapisane; carol widzi 2 FNX, ala resztę;")
    print("         payload i pool = ZERO liczb (mgła pełna wewnątrz)")

    # 6) double-spend: powtórka tx2 (mempool) i nowy build z tym samym ki → odrzuty
    try:
        L.add_tx(tx2)
        raise SystemExit("powtórka tx2 przeszła!")
    except ChainError as e:
        assert "już widziany" in str(e), str(e)
    payload_ds = cx.build_hidden_tx(spends, outs, fee)
    tx_ds = Tx(type=TX_RING, sender="", recipient="", amount=0, nonce=0,
               payload=json.dumps(payload_ds, separators=(",", ":"), sort_keys=True))
    try:
        L.add_tx(tx_ds)
        raise SystemExit("drugi strzał tym samym pociskiem (ki) przeszedł!")
    except ChainError as e:
        assert "key image" in str(e), str(e)
    print("  [OK] 6. double-spend (mempool): replay + nowe wyjścia z tym samym ki → odrzuty")

    # 7) drukarnia w MGLI (r_in zawyżony) → sanity w build; sig-podmianka → w add_tx
    try:
        cx.build_hidden_tx([{**spends[0], "r_in": (c0["r"] + 1) % cx._CURVE_L}], outs, fee)
        raise SystemExit("build przepuścił r_in≠bilansu!")
    except cx.ClsagError:
        pass
    pay_t = json.loads(json.dumps(payload2))
    pay_t["out"][0]["C"], pay_t["out"][1]["C"] = pay_t["out"][1]["C"], pay_t["out"][0]["C"]
    t_tam = Tx(type=TX_RING, sender="", recipient="", amount=0, nonce=0,
               payload=json.dumps(pay_t, separators=(",", ":"), sort_keys=True))
    try:
        L.add_tx(t_tam)
        raise SystemExit("podmianka C w wyjściach przeszła!")
    except ChainError:
        pass
    print("  [OK] 7. drukarnia: zły r_in złapany w build (sanity), podmianka C w konsensusie")

    # 8) MIGRACJA 3a: v1 działa dalej; ring v2 NIE przyjmie członka v1 (i odwrotnie)
    outs_v1 = []
    from chain.stealth import derive_stealth
    greg = Identity.generate("greg_h2")
    henry = Identity.generate("henry_h2")
    for who in (dana, eve1, fred, greg, henry):          # fundusze na start (coinbase)
        kop(who.wallet)
    for who in (dana, eve1, fred):
        st = derive_stealth(who.sig_pub_b, who.x_pub_b)
        L.add_tx(Tx.build_signed(TX_SHIELD, who, "FNX-SHIELD", 1 * ISKRA,
                                 nonce=0,     # świeże portfele, tylko coinbase → nonce 0
                                 payload=txr.shield_payload(
                                     [{"sp": st["stealth_pub"], "ep": st["eph_pub"]}])))
        outs_v1.append((who, st))
    kop(dana.wallet)
    assert all(L.pool[st["stealth_pub"]]["amt"] == 1 * ISKRA for _w, st in outs_v1), \
        "migracja: monety v1 nadal mają jawne amt"
    # v1-spend dany (RING_MIN=5 → dogrzej 2 kolejnych v1)
    for who in (greg, henry):
        st = derive_stealth(who.sig_pub_b, who.x_pub_b)
        L.add_tx(Tx.build_signed(TX_SHIELD, who, "FNX-SHIELD", 1 * ISKRA,
                                 nonce=0,
                                 payload=txr.shield_payload(
                                     [{"sp": st["stealth_pub"], "ep": st["eph_pub"]}])))
        outs_v1.append((who, st))
    kop(dana.wallet)
    ring_v1 = [st["stealth_pub"] for _w, st in outs_v1]
    scan_dana = txr.scan_payload_for(dana, [{"sp": s, "ep": L.pool[s]["ep"],
                                             "amt": L.pool[s]["amt"]} for s in ring_v1])
    fee1 = fee_split(1 * ISKRA)[2]
    p_v1 = txr.build_ring_tx(
        [{"ring": ring_v1, "index": ring_v1.index(scan_dana[0]["sp"]),
          "amount": 1 * ISKRA, "priv_ot": scan_dana[0]["spend_hint"]}],
        [{"sig_pub": eve1.sig_pub_b, "x_pub": eve1.x_pub_b,
          "amount": 1 * ISKRA - fee1}], fee1)
    L.add_tx(Tx(type=TX_RING, sender="", recipient="", amount=0, nonce=0,
                payload=json.dumps(p_v1, separators=(",", ":"), sort_keys=True)))
    # ring v2 z członkiem v1 → odrzut („member spoza poola" — lookup po C go nie widzi).
    # UWAGA: ekonomia musi się zgadzać (1 FNX = out + fee), bo test potwierdza, że
    # ZŁAMANIE następuje na regule v1-member, nie na bilansie kryptograficznym.
    fee_mix = fee_split(1 * ISKRA)[2]
    outs_mix = [{"sig_pub": carol.sig_pub_b, "x_pub": carol.x_pub_b,
                 "amount": 1 * ISKRA - fee_mix}]
    ringP_mix = [outs_bob[4]["sp"], outs_v1[1][1]["stealth_pub"]] + \
        [o["sp"] for o in outs_bob[:3]]
    ringC_mix = [L.pool[s].get("C", "00" * 32) for s in ringP_mix]
    scan_bob = cx.scan_hidden_for(bob, [{"sp": s, "ep": L.pool[s]["ep"],
                                         "C": L.pool[s].get("C", ""), "blob": L.pool[s].get("blob", "")}
                                        for s in ringP_mix])
    spends_mix = [{"ringP": ringP_mix, "ringC": ringC_mix,
                   "index": ringP_mix.index(scan_bob[0]["sp"]),
                   "x": scan_bob[0]["spend_hint"], "r_in": scan_bob[0]["r"],
                   "amt": scan_bob[0]["amt"]}]
    pay_mix = cx.build_hidden_tx(spends_mix, outs_mix, fee_mix)
    try:
        L.add_tx(Tx(type=TX_RING, sender="", recipient="", amount=0, nonce=0,
                    payload=json.dumps(pay_mix, separators=(",", ":"), sort_keys=True)))
        raise SystemExit("ring v2 z członkiem v1 przeszedł!")
    except ChainError as e:
        assert "member spoza poola" in str(e), str(e)
    print("  [OK] 8. migracja: v1-spend działa (ring 5×v1); ring v2 odrzuca członka v1")

    # 9) mempool-lookup v2: wabik z NIEKOPNIĘTEGO mintu boba uznany w ringu (jak w v1)
    o_late = make_shield2_out(bob.sig_pub_b, bob.x_pub_b, 1 * ISKRA)
    t_late = Tx.build_signed(TX_SHIELD, bob, "FNX-SHIELD", 1 * ISKRA,
                             nonce=L.nonce_of(bob.wallet),     # mempool bobów pusty
                             payload=shield2_payload([o_late]))
    L.add_tx(t_late)                                            # wisi w mempoolu
    assert L._pool_lookup_c_with_mempool(o_late["sp"]) == {"C": o_late["C"]}
    assert L._pool_lookup_c_with_mempool("12" * 32) is None
    print("  [OK] 9. lookup_c: wpis z MEMPOLA uznany (v≡1 szkoła); obcy sp → None")

    # 10) WYJŚCIE z mgły (UNSHIELD v2, 0x12): carol wypłaca 2 FNX na konto;
    #     kwota Y jawna (z→t), ki zamykane, kopacz widzi fee w coinbase (D39);
    #     double-spend + podwyższenie Y (bilans≠) odrzuty; reszta wraca do mgły
    assert L.balance_of(carol.wallet) == 0, "carol: porządki przed testem z→t"
    spend_carol = cx.scan_hidden_for(carol, [{"sp": o["sp"], "ep": o["ep"], "C": o["C"],
                                              "blob": o["blob"]} for o in payload2["out"]])
    fee_u = 1_000_000                                       # 0.01 FNX (łatwy rachunek)
    Y = 2 * ISKRA - fee_u
    ringP_u = [spend_carol[0]["sp"]] + [o["sp"] for o in outs_bob[:4]]
    ringC_u = [L.pool[s]["C"] for s in ringP_u]
    spends_u = [{"ringP": ringP_u, "ringC": ringC_u, "index": ringP_u.index(spend_carol[0]["sp"]),
                 "x": spend_carol[0]["spend_hint"], "r_in": spend_carol[0]["r"],
                 "amt": spend_carol[0]["amt"]}]
    pay_u = build_unshield2(spends_u, [], carol.wallet, Y, fee_u)     # bez reszty
    tx_u = Tx(type=TX_UNSHIELD, sender="", recipient="", amount=0, nonce=0,
              payload=json.dumps(pay_u, separators=(",", ":"), sort_keys=True))
    L.add_tx(tx_u)
    tmpl_u = L.block_template(bob.wallet, zbits=2)
    won_u = mine(tmpl_u, max_tries=600_000)
    # D39: coinbase = BR + fee minera ze WSZYSTKICH tx bloku:
    #   unshield(fee_u) + t_late(shield 1 FNX) + p_v1 z testu 8 (ring v1 fee=56000)
    exp_cb = 5 * ISKRA + fee_split(fee_u)[1] + fee_split(1 * ISKRA)[1] + fee_split(56000)[1]
    assert won_u.txs[0].amount == exp_cb, (won_u.txs[0].amount, exp_cb)
    L.apply_block(won_u)
    assert L.balance_of(carol.wallet) == Y, "carol ma dostać Y na koncie (z→t)"
    assert pay_u["in"][0]["ki"] in L.key_images
    # double-spend: ten sam ki drugi raz
    tx_u2 = Tx(type=TX_UNSHIELD, sender="", recipient="", amount=0, nonce=0,
               payload=json.dumps(pay_u, separators=(",", ":"), sort_keys=True))
    try:
        L.add_tx(tx_u2)
        raise SystemExit("powtórka unshield przeszła (już widziany)!")
    except ChainError:
        pass
    pay_u3 = build_unshield2(spends_u, [], carol.wallet, Y - 1, fee_u + 1)   # inny tx, to samo ki
    try:
        L.add_tx(Tx(type=TX_UNSHIELD, sender="", recipient="", amount=0, nonce=0,
                    payload=json.dumps(pay_u3, separators=(",", ":"), sort_keys=True)))
        raise SystemExit("unshield z tym samym ki przeszedł (double-spend)!")
    except ChainError as e:
        assert "key image" in str(e), str(e)
    # podwyższenie Y (bilans nie pasuje) → sanity już w build
    try:
        build_unshield2(spends_u, [], carol.wallet, Y + 7, fee_u)
        raise SystemExit("build przepuścił Y>Σin!")
    except TxHiddenError:
        pass
    print("  [OK] 10. UNSHIELD v2: Y na koncie carol; ki zamknięte; replay/double-spend/")
    print("           zawyżone Y odrzuty; fee do KOPACZA w coinbase (D39)")

    # 11) reszta z unshield WRACA do mgły (change-out v2 naprawdę w poolu)
    scan_bob2 = [c for c in cx.scan_hidden_for(
        bob, [{"sp": o["sp"], "ep": L.pool[o["sp"]]["ep"], "C": L.pool[o["sp"]]["C"],
               "blob": L.pool[o["sp"]]["blob"]} for o in [outs_bob[4]]] +
        [{"sp": o_late["sp"], "ep": L.pool[o_late["sp"]]["ep"], "C": L.pool[o_late["sp"]]["C"],
          "blob": L.pool[o_late["sp"]]["blob"]}])]
    one = [c for c in scan_bob2 if c["amt"] == 1 * ISKRA][0]
    fee_c = fee_split(1 * ISKRA // 2)[2]
    ringP_c = [one["sp"]] + [o["sp"] for o in outs_bob[:4]]
    ringC_c = [L.pool[s]["C"] for s in ringP_c]
    spends_c = [{"ringP": ringP_c, "ringC": ringC_c, "index": ringP_c.index(one["sp"]),
                 "x": one["spend_hint"], "r_in": one["r"], "amt": one["amt"]}]
    pay_c = build_unshield2(spends_c,
                            [{"sig_pub": bob.sig_pub_b, "x_pub": bob.x_pub_b,
                              "amount": 1 * ISKRA - (1 * ISKRA // 2) - fee_c}],
                            bob.wallet, 1 * ISKRA // 2, fee_c)
    L.add_tx(Tx(type=TX_UNSHIELD, sender="", recipient="", amount=0, nonce=0,
                payload=json.dumps(pay_c, separators=(",", ":"), sort_keys=True)))
    kop(bob.wallet)
    ch = cx.scan_hidden_for(bob, [{"sp": o["sp"], "ep": o["ep"], "C": o["C"],
                                   "blob": o["blob"]} for o in pay_c["out"]])
    assert len(ch) == 1 and ch[0]["amt"] == 1 * ISKRA - (1 * ISKRA // 2) - fee_c
    assert L.balance_of(bob.wallet) > 0
    print("  [OK] 11. unshield z resztą: change v2 wraca do mgły (scan boba ją widzi)")

    print("\nSELFTEST: PASS ✅  chain/tx_hidden.py — konsensus v2: bramka wiąże C ze spaleniem,")
    print("mgła w poolu (brak amt), MLSAG+RP+KI strzegą wnętrza, wyjście z→t zamyka pętlę (D39),")
    print("migracja v1 żywa, drukarnia zamknięta")
