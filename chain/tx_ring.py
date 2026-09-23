# chain/tx_ring.py — TX_RING (0x10) + TX_SHIELD (0x11): prywatny pool w ledgerze (M5b, etap 3a)
"""
SPAJA trzy kamienie D31 w prawdziwy blockchain:

    NADAWCA  — ukryty RINGIEM (chain/ring_sig.py): input = ring 5..11 wcześniejszych
               outputów poola o TEJ SAMEJ kwocie; świat wie „zapłacił właściciel jednego
               z nich", nie wie którego.
    ODBIORCA — ukryty STEALTH (chain/stealth.py): wyjście to świeży jednorazowy punkt P
               + klucz efemeryczny R; tylko odbiorca skanem wykryje „to moje".
    KWOTA    — JAWNA w etapie 3a (jak Monero 2014–2016). Ukrycie kwot on-chain wymaga
               CLSAG (wektorowy ring nad [P, C]); kamień 3 crypto (Pedersen+Borromean
               w chain/amount_hide.py) czeka na niego — backlog D31/3b, uczciwie.

MODEL POOLA (w Ledger):
    pool: { stealth_pub_hex: {"ep": eph_hex, "amt": iskry} }   # outputy poola
    key_images: set[hex64]   # JEDYNY ślad wydania: I = priv_ot·Hp(P_true).
                             # Ten sam I dwa razy = double-spend → odrzut. Którego
                             # outputu dotyczy — NIE DA SIĘ rozstrzygnąć (to jest cel).

TX_SHIELD (0x11): zwykły podpisany tx konta (sender debetowany jak przy transferze,
    fee D15 normalnie); payload: {"v":1,"out":[{"sp":hex32,"ep":hex32}]}; output
    trafia do poola z amt = tx.amount. Odbiorca zna go tylko po skanie stealth.
TX_RING (0x10): Tx.amount = 0, sender = "", brak account-nonce (anonimowość!) —
    zamiast tego: key images + podpisy ringowe. Payload:
    {"v":1,
     "in":[{"ring":[hex32×n],"ki":hex64,"amt":int,"sig":hex(RingSignature)}],
     "out":[{"sp":hex32,"ep":hex32,"amt":int}],
     "fee":int}
    Konsensus: wszystkie membery ringa istnieją w poolu i mają amt == deklarowane
    (wabiki dobieraj z tych samych nominałów!), Σin == Σout + fee, ring_verify trzyma,
    key_image z podpisu == deklarowane ki.

Selftest E2E na prawdziwym Ledgerze + PoW (zbits=2): funding → shield×5 → ring-spend
→ double-spend odrzucony → fałszerstwa (sumy/wabik/spoza poola/tampering) → adopt_chain
replay odtwarza pool i key_images identycznie.
"""
from __future__ import annotations

import json
import sys
import pathlib as _pl
from typing import Callable, List

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from chain.block import Tx, canon, TX_RING, TX_SHIELD, ISKRA                      # noqa: E402
from chain.ring_sig import ring_sign, ring_verify, hash_to_point, RingSignature, RingSigError  # noqa: E402
from chain.stealth import point_encode, point_mul_fast, point_decode             # noqa: E402
from chain.stealth import derive_stealth, scan_stealth                            # noqa: E402

RING_MIN = 5                 # mniej niż 5 wabików = za cienki tłum (etap 3a)
RING_MAX = 11                # więcej = rozrost bloku bez zysku
MAX_INS = 8
MAX_OUTS = 8
MAX_AMT = (1 << 64) - 1      # spójnie z RANGE_BITS z amount_hide (etap 3b)


class TxRingError(Exception):
    """Naruszenie konsensusu poola — jeden typ."""


# -------------------------------------------------------------------------- kluczowe pomocnicze
def key_image_of(priv_ot: int, stealth_pub_hex: str) -> bytes:
    """I = priv_ot · Hp(P) — stabilny „odcisk wydania" tego outputu; nic nie zdradza."""
    return point_encode(point_mul_fast(priv_ot, hash_to_point(bytes.fromhex(stealth_pub_hex))))


def pick_ring_candidates(pool: dict, amt: int) -> List[str]:
    """Memberowie-wabiki MUSZĄ mieć identyczny amt (etap 3a — inaczej podpisującego
    da się wskazać po kwocie). Zwraca klucze poola pasujące do nominału.
    Wpisy v2 (3b) NIE mają amt — pomijane (ring v1 gra tylko z v1, D38)."""
    return [sp for sp, v in pool.items() if v.get("amt") == amt]


def shield_payload(outs: List[dict]) -> str:
    """outs: [{"sp": hex, "ep": hex}] — stealth wyjście/e dla TX_SHIELD."""
    return json.dumps({"v": 1, "out": outs}, separators=(",", ":"), sort_keys=True)


def parse_payload(raw: str) -> dict:
    try:
        p = json.loads(raw)
        if isinstance(p, dict) and p.get("v") == 1:
            return p
    except (ValueError, TypeError):
        pass
    raise TxRingError("payload: niepoprawny JSON / brak v=1")


def _h32b(s: str, what: str) -> bytes:
    if not isinstance(s, str) or len(s) != 64:
        raise TxRingError(f"{what}: oczekiwano 32B hex")
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise TxRingError(f"{what}: zły hex") from None


def validate_shield_payload(raw: str) -> List[dict]:
    """Zwraca listę wyjść [{sp, ep}] albo rzuca TxRingError; 1..MAX_OUTS wyjść."""
    p = parse_payload(raw)
    outs = p.get("out")
    if not isinstance(outs, list) or not (1 <= len(outs) <= MAX_OUTS):
        raise TxRingError("shield: 1..8 wyjść")
    for o in outs:
        _h32b((o or {}).get("sp", ""), "shield.out.sp")
        _h32b((o or {}).get("ep", ""), "shield.out.ep")
    return outs


# -------------------------------------------------------------------------- TX_RING: budowa i walidacja
def ring_msg(payload: dict) -> bytes:
    """Kanon bez podpisów — TO jest podpisywane przez każdy input."""
    core = {"v": payload["v"],
            "in": [{k: v for k, v in i.items() if k != "sig"} for i in payload["in"]],
            "out": payload["out"], "fee": payload["fee"]}
    return canon(core)


def build_ring_tx(spends: List[dict], outs: List[dict], fee_iskry: int) -> dict:
    """spends: [{"ring":[hex…n],"index":i,"amount":iskry,"priv_ot":int}]
       outs:   [{"sig_pub":bytes32,"x_pub":bytes32,"amount":iskry}]  → stealth per wyjście.
    Zwraca payload-dict (Tx.payload = json.dumps z sort_keys)."""
    if not (1 <= len(spends) <= MAX_INS and 1 <= len(outs) <= MAX_OUTS):
        raise TxRingError("budowa: 1..8 wejść i 1..8 wyjść")
    ins = []
    for sp in spends:
        ring, idx = sp["ring"], sp["index"]
        if not (RING_MIN <= len(ring) <= RING_MAX and 0 <= idx < len(ring)):
            raise TxRingError("budowa: zły ring/index")
        ki = key_image_of(sp["priv_ot"], ring[idx])
        ins.append({"ring": list(ring), "ki": ki.hex(), "amt": int(sp["amount"]), "sig": ""})
    out_list = []
    for o in outs:
        st = derive_stealth(o["sig_pub"], o["x_pub"])
        out_list.append({"sp": st["stealth_pub"], "ep": st["eph_pub"], "amt": int(o["amount"])})
    payload = {"v": 1, "in": ins, "out": out_list, "fee": int(fee_iskry)}
    msg = ring_msg(payload)
    for i, sp in enumerate(spends):
        try:
            sig = ring_sign(msg, [bytes.fromhex(h) for h in sp["ring"]],
                            sp["index"], sp["priv_ot"])
        except RingSigError as e:
            raise TxRingError(f"podpis inputu {i}: {e}") from None
        payload["in"][i]["sig"] = sig.to_bytes().hex()
    return payload


def validate_ring_tx(payload: dict, pool_lookup: Callable[[str], int | None]) -> List[str]:
    """Pełna walidacja konsensusu (bez rejestrów key-images — to robi Ledger).
    pool_lookup(stealth_pub_hex) -> amt | None.  Zwraca listę key-images (hex)."""
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise TxRingError("ring: brak v=1")
    ins, outs, fee = payload.get("in"), payload.get("out"), payload.get("fee")
    if not isinstance(ins, list) or not (1 <= len(ins) <= MAX_INS):
        raise TxRingError("ring: 1..8 wejść")
    if not isinstance(outs, list) or not (1 <= len(outs) <= MAX_OUTS):
        raise TxRingError("ring: 1..8 wyjść")
    if not isinstance(fee, int) or fee < 0 or fee > MAX_AMT:
        raise TxRingError("ring: złe fee")

    # pre-walidacja typów (inaczej canon spadnie na TypeError zamiast TxRingError)
    for i in ins:
        if not isinstance(i, dict) or not isinstance(i.get("ring"), list):
            raise TxRingError("ring: wejście nie-obiekt/brak ring")
        for m in i["ring"]:
            if not isinstance(m, str):
                raise TxRingError("ring: member nie-string-hex")
        if not isinstance(i.get("sig", ""), str) or not isinstance(i.get("ki", ""), str):
            raise TxRingError("ring: sig/ki muszą być hex-stringami")

    msg = ring_msg(payload)
    key_images: List[str] = []
    sum_in = 0
    ring_size = None
    for n_i, i in enumerate(ins):
        if not isinstance(i, dict):
            raise TxRingError("ring: wejście nie-obiekt")
        ring, ki, amt, sig_hex = i.get("ring"), i.get("ki"), i.get("amt"), i.get("sig", "")
        if not isinstance(ring, list) or not (RING_MIN <= len(ring) <= RING_MAX):
            raise TxRingError("ring: rozmiar ringa poza [5, 11]")
        if ring_size is None:
            ring_size = len(ring)
        elif len(ring) != ring_size:
            raise TxRingError("ring: mieszane rozmiary ringów (teraz uniform)")
        if not isinstance(amt, int) or not (0 < amt <= MAX_AMT):
            raise TxRingError("ring: zła kwota wejścia")
        for sp_hex in ring:
            _h32b(sp_hex, "ring.member")
            member_amt = pool_lookup(sp_hex)
            if member_amt is None:
                raise TxRingError("ring: member spoza poola")
            if member_amt != amt:
                raise TxRingError("ring: member o innej kwocie niż deklarowana (wabik zły)")
        ki_b = _h32b(ki, "ring.ki")
        try:
            sig = RingSignature.from_bytes(bytes.fromhex(sig_hex))
        except (ValueError, RingSigError) as e:
            raise TxRingError(f"ring: zły podpis bajtowo: {e}") from None
        if not ring_verify(msg, [bytes.fromhex(h) for h in ring], sig):
            raise TxRingError("ring: podpis pierścieniowy NIEWAŻNY")
        if sig.key_image != ki_b:
            raise TxRingError("ring: ki ≠ key_image z podpisu")
        key_images.append(ki)
        sum_in += amt

    sum_out = 0
    for o in outs:
        if not isinstance(o, dict):
            raise TxRingError("ring: wyjście nie-obiekt")
        _h32b(o.get("sp", ""), "ring.out.sp")
        _h32b(o.get("ep", ""), "ring.out.ep")
        amt = o.get("amt")
        if not isinstance(amt, int) or not (0 < amt <= MAX_AMT):
            raise TxRingError("ring: zła kwota wyjścia")
        sum_out += amt
    if sum_in != sum_out + fee:
        raise TxRingError(f"ring: Σin({sum_in}) ≠ Σout({sum_out}) + fee({fee}) — próba druku FNX")
    return key_images


def ring_outputs(payload: dict) -> List[dict]:
    return [{"sp": o["sp"], "ep": o["ep"], "amt": int(o["amt"])} for o in payload["out"]]


def scan_payload_for(identity, outs: List[dict]) -> List[dict]:
    """Portfel: które wyjścia (shield/ring payload) są moje? → [{sp,ep,amt,spend_hint}]"""
    mine = []
    for o in outs:
        hit = scan_stealth(identity, o["sp"], o["ep"])
        if hit:
            mine.append({"sp": o["sp"], "ep": o["ep"], "amt": o.get("amt", 0),
                         "spend_hint": hit["spend_hint"]})
    return mine


# -------------------------------------------------------------------------- selftest E2E
if __name__ == "__main__":
    from core.identity import Identity
    from chain.ledger import Ledger, BLOCK_REWARD, ChainError
    from chain.block import TREASURY_WALLET_DEV, fee_split
    from chain.miner import mine

    print("chain/tx_ring.py — selftest E2E: prawdziwy ledger + PoW + pool + key images\n")
    TRE = TREASURY_WALLET_DEV
    L = Ledger(TRE)
    ala = Identity.generate("ala_ring_e2e")
    bob = Identity.generate("bob_ring_e2e")
    ceo = Identity.generate("ceo_ring_e2e")

    def kop_blok(tag: str):
        tmpl = L.block_template(ala.wallet, zbits=2)
        won = mine(tmpl, max_tries=200_000)
        assert won is not None, f"mining nie trafił ({tag})"
        L.apply_block(won)
        return won

    # 1) funding: 6 bloków do ali (5 FNX każdy → 30 FNX)
    for _ in range(6):
        kop_blok("funding")
    assert L.balance_of(ala.wallet) == 6 * BLOCK_REWARD
    print(f"  [OK] 1. funding: ala ma {L.balance_of(ala.wallet) // ISKRA} FNX z PoW (zbits=2)")

    # 2) SHIELD×5 po 10 FNX — brakuje jej na 50: zrób 4× po 7 FNX różnymi odbiorcami
    #    (4 do ali, 1 do boba — wszystkie o TYM SAMYM nominale 2 FNX dla wabików)
    NOM = 2 * ISKRA
    recips = [ala, ala, ala, bob, ala]
    for idx, rec in enumerate(recips):
        st = derive_stealth(rec.sig_pub_b, rec.x_pub_b)
        tx = Tx.build_signed(TX_SHIELD, ala, "FNX-SHIELD", NOM,
                             nonce=idx, payload=shield_payload([{"sp": st["stealth_pub"],
                                                                 "ep": st["eph_pub"]}]))
        L.add_tx(tx)
        kop_blok(f"shield#{idx}")
    assert len(L.pool) == 5
    spent_fee = 5 * fee_split(NOM)[2]
    # ala: 11 wykopanych bloków ×5 FNX (6 funding + 5 shield) − shield amounts − fee;
    # D39: ala KOPIE bloki ze shieldami → część „owner" fee WRACA do niej w coinbase
    back_fee = 5 * fee_split(NOM)[1]
    assert L.balance_of(ala.wallet) == 11 * BLOCK_REWARD - 5 * NOM - spent_fee + back_fee, \
        f"saldo: {L.balance_of(ala.wallet)} != {11 * BLOCK_REWARD - 5 * NOM - spent_fee + back_fee}"
    print(f"  [OK] 2. 5× SHIELD po 2 FNX → pool={len(L.pool)} outputów; świat NIE WIE czyje (stealth)")

    # 3) bob znajduje SWÓJ output skanem; buduje ring: wszystkie 5 (jego + 4 wabiki)
    bobs = scan_payload_for(bob, [{"sp": k, "ep": v["ep"], "amt": v["amt"]}
                                  for k, v in L.pool.items()])
    assert len(bobs) == 1
    my = bobs[0]
    assert my["amt"] == NOM
    ring = pick_ring_candidates(L.pool, NOM)
    assert len(ring) == 5 and my["sp"] in ring
    idx_mine = ring.index(my["sp"])
    print(f"  [OK] 3. bob widzi TYLKO swój output (scan); ring={len(ring)} (1 jego + 4 wabiki, indeks {idx_mine})")

    # 4) spend: 2 FNX → 1.9 FNX do ceo + 0.1 fee; mempool → blok
    payload = build_ring_tx(
        spends=[{"ring": ring, "index": idx_mine, "amount": NOM, "priv_ot": my["spend_hint"]}],
        outs=[{"sig_pub": ceo.sig_pub_b, "x_pub": ceo.x_pub_b, "amount": 190_000_000}],
        fee_iskry=10_000_000)
    rtx = Tx(type=TX_RING, sender="", recipient="", amount=0, nonce=0,
             payload=json.dumps(payload, separators=(",", ":"), sort_keys=True))
    L.add_tx(rtx)
    kis_before = set(L.key_images)
    kop_blok("ring-spend")
    assert len(L.key_images) == len(kis_before) + 1
    new_outs = [k for k in L.pool if k not in ring or True]
    ceo_hits = scan_payload_for(ceo, [{"sp": k, "ep": v["ep"], "amt": v["amt"]}
                                      for k, v in L.pool.items()])
    assert len(ceo_hits) == 1 and ceo_hits[0]["amt"] == 190_000_000
    from chain.block import fee_split
    _, owner_fee, _ = fee_split(10_000_000)
    print(f"  [OK] 4. RING-SPEND w bloku: 2 FNX → ceo 1.9 (+fee 0.1 rozdzielone D15); "
          f"world widzi: ring z 5, ki={list(L.key_images)[0][:12]}… — NIE WIE że to bob")

    # 5) DOUBLE-SPEND: ten sam output jeszcze raz → ten sam ki → odrzut
    payload2 = build_ring_tx(
        spends=[{"ring": ring, "index": idx_mine, "amount": NOM, "priv_ot": my["spend_hint"]}],
        outs=[{"sig_pub": ala.sig_pub_b, "x_pub": ala.x_pub_b, "amount": NOM - 10_000_000}],
        fee_iskry=10_000_000)
    rtx2 = Tx(type=TX_RING, sender="", recipient="", amount=0, nonce=0,
              payload=json.dumps(payload2, separators=(",", ":"), sort_keys=True))
    try:
        L.add_tx(rtx2)
        raise SystemExit("DOUBLE-SPEND PRZYJĘTY!")
    except ChainError as e:
        assert "key image" in str(e) or "już" in str(e)
    print("  [OK] 5. double-spend: powtórka key-image odrzucona (ślad bez ujawnienia nadawcy)")

    # 6) FAŁSZERSTWA
    # 6a) sumy się nie spinają (drukowanie FNX)
    bad = dict(payload)
    bad["out"] = [{"sp": payload["out"][0]["sp"], "ep": payload["out"][0]["ep"],
                   "amt": 999 * ISKRA}]
    try:
        validate_ring_tx(bad, lambda sp: L.pool.get(sp, {}).get("amt") if sp in L.pool else None)
        raise SystemExit("druk FNX przeszedł!")
    except TxRingError:
        pass
    # 6b) wabik spoza poola
    fake_sp = point_encode(point_mul_fast(7)).hex()
    bad2 = json.loads(json.dumps(payload))
    bad2["in"][0]["ring"] = [fake_sp] * 5
    try:
        validate_ring_tx(bad2, lambda sp: L.pool[sp]["amt"] if sp in L.pool else None)
        raise SystemExit("member spoza poola przeszedł!")
    except TxRingError:
        pass
    # 6c) sabotowany podpis
    bad3 = json.loads(json.dumps(payload))
    sig_b = bytearray.fromhex(bad3["in"][0]["sig"])
    sig_b[10] ^= 1
    bad3["in"][0]["sig"] = bytes(sig_b).hex()
    try:
        validate_ring_tx(bad3, lambda sp: L.pool[sp]["amt"] if sp in L.pool else None)
        raise SystemExit("sabotowany podpis przeszedł!")
    except TxRingError:
        pass
    print("  [OK] 6. fałszerstwa: druk-suma / member spoza poola / sabotowany sig → odrzucone")

    # 7) replay: świeży Ledger odtwarza WSZYSTKO od genesis — pool i ki identyczne
    L2 = Ledger(TRE)
    for b in L.chain[1:]:
        L2.apply_block(b)
    assert L2.pool == L.pool and L2.key_images == L.key_images
    assert L2.balance_of(ala.wallet) == L.balance_of(ala.wallet)
    print("  [OK] 7. replay łańcucha: pool+key_images odtworzone bit-w-bit (spójność fork/restart)")

    print("\nSELFTEST: PASS ✅  blockchain: prywatny pool DZIAŁA (nadawca/odbiorca ukryci; kwoty do 3b)")
