# gui/pool_panel.py — zakładka Pool (M7c): moje prywatne coiny + wysyłka TX_RING z GUI
"""
Co robi (analogia „talia przetasowana przy kasie"):
  Publiczny przelew (zakładka Portfel) = płacisz kartą — widać kto komu.
  TX_RING = bierzesz 5+ identycznych banknotów z wspólnej puli, podpisujesz
  pierścieniowo (LSAG: każdy z 5 MOŻE być nadawcą), świat widzi tłum, nie Ciebie.

Ten moduł daje GUI trzy rzeczy:
  1) MOJE coiny w poolu (scan stealth; odfiltrowane od wydanych — pool TRZYMA
     wydane outputy jako wabiki, Monero-style, więc filtrujemy po key-images),
  2) MÓJ ADRES PRYWATNY FNXS1… (stealth: sig_pub‖x_pub + checksum 8 znaków),
     który wysyłasz znajomemu, żeby mógł Ci zapłacić anonimowo,
  3) WYSYŁKA: plan (coiny+wabiki, Σin=Σout+fee, reszta do siebie) → podpisane
     TX_RING → rozsyłka przez IPC albo dev-mempool (ten sam fallback co Portfel).

ŹRÓDŁA DANYCH: demon żywy → IPC (pool_decoys/pool_mine/submit); martwy → dev-ledger.
Sekrety (priv_ot/spend_hint) NIGDY nie lecą przez IPC — GUI liczy je lokalnie
skanem (test pilnuje drutu). UCZCIWOŚĆ W UI: kwoty w poolu są JAWNE (etap 3a);
ukryte są POWIĄZANIA nadawca↔odbiorca. Ukrycie kwot = CLSAG (3b, problem P4).
"""
from __future__ import annotations

import hashlib
import json
import random
import sys
import pathlib as _pl
from dataclasses import dataclass

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from chain.block import (ISKRA, Tx, TX_RING, TX_SHIELD, TX_UNSHIELD,             # noqa: E402
                         fee_split)
from chain.ledger import ChainError                                              # noqa: E402
from chain import tx_ring as txr                                                  # noqa: E402
from chain import clsag as cx                                                     # noqa: E402
from chain import tx_hidden as txh                                                # noqa: E402
from chain.stealth import derive_stealth                                          # noqa: E402
from core.identity import (IdentityError,                                        # noqa: E402
                           encode_stealth_address as _core_encode,
                           decode_stealth_address as _core_decode,
                           STEALTH_ADDR_PREFIX as POOL_ADDR_PREFIX)
from gui.backend_ipc import IpcError                                              # noqa: E402


class PoolError(Exception):
    """Błąd zakładki Pool — jeden typ (GUI pokazuje bez zgadywania)."""


# -------------------------------------------------------------------------- adres FNXS1
# Codec przeniesiony do core/identity.py (jeden kod dla pool+messengera) — tu delegat,
# żeby stare importy i odwołania GUI działały bez zmian.
def encode_stealth_address(sig_pub_b: bytes, x_pub_b: bytes) -> str:
    try:
        return _core_encode(sig_pub_b, x_pub_b)
    except IdentityError as e:
        raise PoolError(str(e)) from None


def decode_stealth_address(addr: str) -> tuple[bytes, bytes]:
    try:
        return _core_decode(addr)
    except IdentityError as e:
        raise PoolError(str(e)) from None


# -------------------------------------------------------------------------- kontroler Pool
@dataclass
class PoolController:
    """Logika zakładki Pool. identity z GUI; ledger=None → tylko IPC (i odwrotnie)."""
    identity: object                       # core.identity.Identity
    ledger: object | None = None
    ipc: object | None = None              # BackendIpc; None = dev
    rng: random.Random = None

    def __post_init__(self):
        if self.rng is None:
            self.rng = random.Random()

    # ---------------- źródła (IPC > dev) ----------------
    def _ipc_alive(self) -> bool:
        if self.ipc is None:
            return False
        try:
            self.ipc.status()
            return True
        except IpcError:
            return False

    def my_coins(self) -> list[dict]:
        """Moje NIEWYDANE coiny: [{sp, ep, amt, priv_ot}] (priv_ot liczony LOKALNIE)."""
        if self._ipc_alive():
            outs = self.ipc.pool_mine()             # daemon już odfiltrował wydane
            mine = txr.scan_payload_for(self.identity, outs)   # lokalny licznik priv_ot
            return mine
        if self.ledger is not None:
            pool = self.ledger.pool
            all_outs = [{"sp": k, "ep": v["ep"], "amt": v["amt"]}
                        for k, v in pool.items() if "amt" in v]   # v1-only; v2 = M7d
            mine = txr.scan_payload_for(self.identity, all_outs)
            kis = self.ledger.key_images            # hex set
            return [c for c in mine
                    if txr.key_image_of(c["spend_hint"], c["sp"]).hex() not in kis]
        raise PoolError("brak źródła poola (ani IPC, ani dev-ledger)")

    def decoy_ring(self, amount: int, my_sp: str) -> tuple[list, int]:
        """Ring ≤ RING_MAX dla nominału: mój output + losowe wabiki; index mojego."""
        if self._ipc_alive():
            cands = list(self.ipc.pool_decoys(amount))
        elif self.ledger is not None:
            cands = txr.pick_ring_candidates(self.ledger.pool, amount)
        else:
            raise PoolError("brak źródła poola")
        if my_sp not in cands:
            raise PoolError("mój output zniknął z poola?! (rozjazd z demonem?)")
        others = [c for c in cands if c != my_sp]
        need = min(txr.RING_MAX, max(txr.RING_MIN, len(cands))) - 1
        if len(others) < txr.RING_MIN - 1:
            raise PoolError(f"za cienki tłum dla {amount / ISKRA:g} FNX: "
                            f"{len(others) + 1}/{txr.RING_MIN} outputów tego nominału. "
                            f"Zrób więcej shieldów lub poczekaj na innych.")
        self.rng.shuffle(others)
        ring = [my_sp] + others[:need]
        self.rng.shuffle(ring)
        return ring, ring.index(my_sp)

    # ---------------- plan + budowa ----------------
    def my_address(self) -> str:
        return encode_stealth_address(self.identity.sig_pub_b, self.identity.x_pub_b)

    def plan_send(self, to_addr: str, amount: int) -> dict:
        """(dry-run) Wybiera coiny, wabiki, liczy fee/resztę. Rzuca PoolError po polsku."""
        sig_b, x_b = decode_stealth_address(to_addr)
        if not isinstance(amount, int) or amount <= 0:
            raise PoolError("kwota musi być > 0 (w iskrach)")
        fee = fee_split(amount)[2]              # ten sam cennik co przelew publiczny
        coins = self.my_coins()
        if not coins:
            raise PoolError("brak prywatnych coinów — najpierw zrób SHIELD (Portfel)")
        plan_in, acc = [], 0
        for c in sorted(coins, key=lambda c: -c["amt"]):
            plan_in.append(c)
            acc += c["amt"]
            if acc >= amount + fee:
                break
        if acc < amount + fee:
            raise PoolError(f"za mało w poolu: masz {sum(c['amt'] for c in coins) / ISKRA:g} FNX, "
                            f"potrzeba {(amount + fee) / ISKRA:g} FNX (kwota+fee)")
        if len(plan_in) > txr.MAX_INS:
            raise PoolError(f"za dużo wejść ({len(plan_in)} > {txr.MAX_INS}) — "
                            f"scalonaj coiny najpierw (wyślij do siebie)")
        # tłum dla każdego nominału (sucha próba — bez podpisów)
        for c in plan_in:
            self.decoy_ring(c["amt"], c["sp"])
        change = acc - amount - fee
        outs = [{"sig_pub": sig_b, "x_pub": x_b, "amount": amount, "to": "recipient"}]
        if change > 0:
            outs.append({"sig_pub": self.identity.sig_pub_b, "x_pub": self.identity.x_pub_b,
                         "amount": change, "to": "me (reszta)"})
        return {"inputs": plan_in, "sum_in": acc, "amount": amount, "fee": fee,
                "change": change, "outs": outs}

    def build_send(self, to_addr: str, amount: int) -> Tx:
        """Podpisane TX_RING (świat widzi tłum, nie nas)."""
        plan = self.plan_send(to_addr, amount)
        spends = []
        for c in plan["inputs"]:
            ring, idx = self.decoy_ring(c["amt"], c["sp"])
            spends.append({"ring": ring, "index": idx, "amount": c["amt"],
                           "priv_ot": c["spend_hint"]})
        outs = [{"sig_pub": o["sig_pub"], "x_pub": o["x_pub"], "amount": o["amount"]}
                for o in plan["outs"]]
        payload = txr.build_ring_tx(spends, outs, plan["fee"])
        return Tx(type=TX_RING, sender="", recipient="", amount=0, nonce=0,
                  payload=json.dumps(payload, separators=(",", ":"), sort_keys=True))

    def submit(self, tx: Tx) -> str:
        """Rozsyłka: IPC (demon gossippuje) → dev-mempool (fallback jak w Portfelu)."""
        if self._ipc_alive():
            return self.ipc.submit_tx_dict(tx.to_dict())
        if self.ledger is not None:
            try:
                self.ledger.add_tx(tx)
            except ChainError as e:
                raise PoolError(str(e)) from None
            return tx.txid()
        raise PoolError("brak kanału rozsyłki (ani IPC, ani dev-ledger)")

    def send_private(self, to_addr: str, amount: int) -> str:
        """Jedno wołanie dla GUI: plan+podpis+rozsyłka → txid."""
        return self.submit(self.build_send(to_addr, amount))

    # ---------------- v2 (3b, D38/D39): mgła — pool bez kwot ----------------
    def _nonce_of(self, wallet: str) -> int:
        if self._ipc_alive():
            return int(self.ipc.nonce(wallet))
        if self.ledger is not None:
            return self.ledger.nonce_of(wallet) + sum(
                1 for t in self.ledger.mempool if t.sender == wallet)
        raise PoolError("brak źródła nonce (ani IPC, ani dev-ledger)")

    def build_shield2_tx(self, amount: int, to_addr: str | None = None) -> Tx:
        """WEJŚCIE do mgły: TX_SHIELD v2 (mój FNXS1 domyślnie = do siebie)."""
        sig_b, x_b = decode_stealth_address(to_addr) if to_addr else \
            (self.identity.sig_pub_b, self.identity.x_pub_b)
        if not isinstance(amount, int) or amount <= 0:
            raise PoolError("kwota mintu musi być > 0 (w iskrach)")
        out = txh.make_shield2_out(sig_b, x_b, amount)
        return Tx.build_signed(TX_SHIELD, self.identity, "FNX-SHIELD", amount,
                               nonce=self._nonce_of(self.identity.wallet),
                               payload=txh.shield2_payload([out]))

    def all_v2_outs(self) -> list[dict]:
        """Wszystkie wpisy v2 (sp/ep/C/blob — publiczne dane łańcucha, zero sekretów)."""
        if self._ipc_alive():
            outs: list = []
            off = 0
            while True:
                page = self.ipc.pool_page(off, 200)
                got = page.get("outs", [])
                outs.extend(o for o in got if o.get("v") == 2)
                off += len(got)
                if not got or off >= page.get("total", 0):
                    break
            return outs
        if self.ledger is not None:
            return [{"sp": k, "ep": v["ep"], "C": v["C"], "blob": v["blob"]}
                    for k, v in self.ledger.pool.items() if "C" in v]
        raise PoolError("brak źródła poola v2 (ani IPC, ani dev-ledger)")

    def _known_kis(self) -> set:
        if self._ipc_alive():
            return set(self.ipc.pool_kis())
        if self.ledger is not None:
            return set(self.ledger.key_images)
        raise PoolError("brak źródła key-images")

    def my_hidden_coins(self) -> list[dict]:
        """Moje NIEWYDANE monety mgły [{sp, ep, C, amt, r, spend_hint}]
        (scan C/blob LOKALNIE — kwoty nie widzi ani demon, ani drut)."""
        mine = cx.scan_hidden_for(self.identity, self.all_v2_outs())
        kis = self._known_kis()
        return [c for c in mine
                if txr.key_image_of(c["spend_hint"], c["sp"]).hex() not in kis]

    def _v2_ring(self, my_sp: str) -> tuple[list, list, int]:
        """Ring mgły: (ringP, ringC, mój index); decoys DOWOLNYCH kwot (D36)."""
        outs = self.all_v2_outs()
        by_sp = {o["sp"]: o for o in outs}
        others = [s for s in by_sp if s != my_sp]
        if len(others) < txr.RING_MIN - 1:
            raise PoolError(f"za cienki tłum w mgle: {len(others) + 1}/{txr.RING_MIN} wpisów v2. "
                            f"Zrób więcej shieldów v2 albo poczekaj na innych.")
        self.rng.shuffle(others)
        ringP = [my_sp] + others[:txr.RING_MIN - 1]
        self.rng.shuffle(ringP)
        return ringP, [by_sp[s]["C"] for s in ringP], ringP.index(my_sp)

    def plan_hidden_send(self, to_addr: str, amount: int) -> dict:
        """(dry-run) Wysyłka w mgle: coiny+fee+reszta+wabiki. Błędy po polsku."""
        sig_b, x_b = decode_stealth_address(to_addr)
        if not isinstance(amount, int) or amount <= 0:
            raise PoolError("kwota musi być > 0 (w iskrach)")
        fee = fee_split(amount)[2]              # ten sam cennik D15/D39
        coins = self.my_hidden_coins()
        if not coins:
            raise PoolError("brak monet w mgle — najpierw SHIELD v2 (mint)")
        plan_in, acc = [], 0
        for c in sorted(coins, key=lambda c: -c["amt"]):
            plan_in.append(c)
            acc += c["amt"]
            if acc >= amount + fee:
                break
        if acc < amount + fee:
            raise PoolError(f"za mało w mgle: masz {sum(c['amt'] for c in coins) / ISKRA:g} FNX, "
                            f"potrzeba {(amount + fee) / ISKRA:g} FNX (kwota+fee)")
        if len(plan_in) > cx.MAX_INS:
            raise PoolError(f"za dużo wejść ({len(plan_in)} > {cx.MAX_INS}) — scalaj monety")
        for c in plan_in:
            self._v2_ring(c["sp"])                       # sucha próba tłumu mgły
        change = acc - amount - fee
        outs = [{"sig_pub": sig_b, "x_pub": x_b, "amount": amount, "to": "recipient"}]
        if change > 0:
            outs.append({"sig_pub": self.identity.sig_pub_b, "x_pub": self.identity.x_pub_b,
                         "amount": change, "to": "me (reszta do mgły)"})
        return {"inputs": plan_in, "sum_in": acc, "amount": amount, "fee": fee,
                "change": change, "outs": outs}

    def build_hidden_send(self, to_addr: str, amount: int) -> Tx:
        """TX_RING v2 w mgle (świat nie widzi ani nadawcy, ani KWOTY, ani odbiorcy)."""
        plan = self.plan_hidden_send(to_addr, amount)
        spends = []
        for c in plan["inputs"]:
            ringP, ringC, idx = self._v2_ring(c["sp"])
            spends.append({"ringP": ringP, "ringC": ringC, "index": idx,
                           "x": c["spend_hint"], "r_in": c["r"], "amt": c["amt"]})
        outs = [{"sig_pub": o["sig_pub"], "x_pub": o["x_pub"], "amount": o["amount"]}
                for o in plan["outs"]]
        payload = cx.build_hidden_tx(spends, outs, plan["fee"])
        return Tx(type=TX_RING, sender="", recipient="", amount=0, nonce=0,
                  payload=json.dumps(payload, separators=(",", ":"), sort_keys=True))

    def send_hidden(self, to_addr: str, amount: int) -> str:
        """Jedno wołanie dla GUI (v2): plan+podpis+rozsyłka → txid."""
        return self.submit(self.build_hidden_send(to_addr, amount))

    def plan_unshield(self, amount: int) -> dict:
        """(dry-run) Wyjście z mgły na MOJE konto; kwota jawna; reszta wraca do mgły."""
        if not isinstance(amount, int) or amount <= 0:
            raise PoolError("kwota wypłaty musi być > 0 (w iskrach)")
        fee = fee_split(amount)[2]
        coins = self.my_hidden_coins()
        if not coins:
            raise PoolError("brak monet w mgle — nie ma czego wypłacać")
        plan_in, acc = [], 0
        for c in sorted(coins, key=lambda c: -c["amt"]):
            plan_in.append(c)
            acc += c["amt"]
            if acc >= amount + fee:
                break
        if acc < amount + fee:
            raise PoolError(f"za mało w mgle na wypłatę: masz {sum(c['amt'] for c in coins) / ISKRA:g} FNX, "
                            f"potrzeba {(amount + fee) / ISKRA:g} FNX (kwota+fee)")
        if len(plan_in) > cx.MAX_INS:
            raise PoolError(f"za dużo wejść ({len(plan_in)} > {cx.MAX_INS}) — scalaj monety")
        for c in plan_in:
            self._v2_ring(c["sp"])
        change = acc - amount - fee
        outs = ([{"sig_pub": self.identity.sig_pub_b, "x_pub": self.identity.x_pub_b,
                  "amount": change, "to": "me (reszta do mgły)"}] if change > 0 else [])
        return {"inputs": plan_in, "sum_in": acc, "amount": amount, "fee": fee,
                "change": change, "outs": outs, "to_wallet": self.identity.wallet}

    def build_unshield_tx(self, amount: int) -> Tx:
        """TX_UNSHIELD v2: mgła → moje konto (zl→t jak w Zcash)."""
        plan = self.plan_unshield(amount)
        spends = []
        for c in plan["inputs"]:
            ringP, ringC, idx = self._v2_ring(c["sp"])
            spends.append({"ringP": ringP, "ringC": ringC, "index": idx,
                           "x": c["spend_hint"], "r_in": c["r"], "amt": c["amt"]})
        payload = txh.build_unshield2(spends, plan["outs"], plan["to_wallet"],
                                      plan["amount"], plan["fee"])
        return Tx(type=TX_UNSHIELD, sender="", recipient="", amount=0, nonce=0,
                  payload=json.dumps(payload, separators=(",", ":"), sort_keys=True))

    def unshield(self, amount: int) -> str:
        """Jedno wołanie dla GUI (wyjście z mgły): plan+podpis+rozsyłka → txid."""
        return self.submit(self.build_unshield_tx(amount))


# -------------------------------------------------------------------------- WIDOK pomocniczy
def coins_summary(coins: list[dict]) -> str:
    """Tekst do etykiety GUI: ile coinów i iskier (bez kluczy!)."""
    total = sum(c["amt"] for c in coins)
    return f"{len(coins)} szt. · razem {total / ISKRA:g} FNX"


# -------------------------------------------------------------------------- selftest (headless)
if __name__ == "__main__":
    import os as _os

    print("gui/pool_panel.py — selftest: adres FNXS1, plan z resztą, TX_RING E2E,\n"
          "cienki tłum odrzucony, priv_ot NIGDY nie leci przez IPC\n")

    from core.identity import Identity
    from chain.ledger import Ledger, BLOCK_REWARD
    from chain.block import TX_SHIELD
    from chain.miner import mine

    TRE = "FNX1" + "0" * 32
    L = Ledger(TRE)
    ala = Identity.generate("ala_pool")
    bob = Identity.generate("bob_pool")

    def kop():
        won = mine(L.block_template(ala.wallet, zbits=2), max_tries=200_000)
        assert won is not None
        L.apply_block(won)

    for _ in range(9):
        kop()

    # tłum 2 FNX: 5× dla ali + 2× dla boba (7 ≥ RING_MIN)
    NOM = 2 * ISKRA
    for i in range(7):
        rec = ala if i < 5 else bob
        st = derive_stealth(rec.sig_pub_b, rec.x_pub_b)
        L.add_tx(Tx.build_signed(TX_SHIELD, ala, "FNX-SHIELD", NOM, nonce=i,
                                 payload=txr.shield_payload([{"sp": st["stealth_pub"],
                                                              "ep": st["eph_pub"]}])))
        kop()
    assert len(L.pool) == 7

    pctl = PoolController(identity=ala, ledger=L)

    # 1) adres FNXS1: round-trip + walidacje
    addr = pctl.my_address()
    assert addr.startswith("FNXS1")
    sb, xb = decode_stealth_address(addr)
    assert sb == ala.sig_pub_b and xb == ala.x_pub_b
    for bad in (addr[1:], addr[:-2] + "00", "FNX1" + addr[5:], addr + "ff"):
        try:
            decode_stealth_address(bad)
            raise SystemExit(f"zły adres przeszedł: {bad[:16]}…")
        except PoolError:
            pass
    print("  [OK] 1. adres FNXS1: round-trip; prefiks/długość/checksum łapią literówki")

    # 2) moje coiny: ala=5 szt., bob=2 szt., odfiltrowanie wydanych (ki)
    coins_ala = pctl.my_coins()
    coins_bob = PoolController(identity=bob, ledger=L).my_coins()
    assert len(coins_ala) == 5 and len(coins_bob) == 2
    assert all(c["amt"] == NOM and "spend_hint" in c for c in coins_ala)
    assert coins_summary(coins_ala) == "5 szt. · razem 10 FNX"
    print("  [OK] 2. my_coins: ala 5×2 FNX, bob 2×2 FNX (+priv_ot lokalnie)")

    # 3) plan: 3 FNX do boba (2 coiny), reszta do ali; fee jak fee_split
    amt = 3 * ISKRA
    bob_addr = PoolController(identity=bob, ledger=L).my_address()
    plan = pctl.plan_send(bob_addr, amt)
    assert plan["sum_in"] == 2 * NOM and plan["amount"] == amt
    assert plan["fee"] == fee_split(amt)[2]
    expect_change = 2 * NOM - amt - plan["fee"]
    assert plan["change"] == expect_change and plan["outs"][-1]["to"] == "me (reszta)"
    print(f"  [OK] 3. plan: 2×2 FNX pokrywa 3 FNX; fee={plan['fee'] / ISKRA:g}, "
          f"reszta {expect_change / ISKRA:g} FNX wraca do nadawcy")

    # 4) TX_RING E2E: podpis→mempool→blok; bob dostaje 3 FNX anonimowo; ki zapisane
    tx = pctl.build_send(bob_addr, amt)
    assert tx.type == TX_RING and not tx.sender and not tx.recipient
    txid = pctl.submit(tx)
    assert any(t.txid() == txid for t in L.mempool)
    assert not any("priv" in t.payload or "spend_hint" in t.payload for t in L.mempool), \
        "SEKRET w payloadzie tx!"
    kis_before = len(L.key_images)
    kop()
    assert len(L.key_images) == kis_before + 2        # 2 wejścia = 2 key-images
    bobs_now = PoolController(identity=bob, ledger=L).my_coins()
    assert len(bobs_now) == 3 and any(c["amt"] == amt for c in bobs_now)
    spent = [c for c in pctl.my_coins() if c["amt"] == NOM]
    assert len(pctl.my_coins()) == 5 - 2 + 1, "2 wydane + 1 reszta"
    print("  [OK] 4. TX_RING w bloku: bob +3 FNX (anonimowo), 2 ki, reszta wróciła; "
          "payload bez sekretów")

    # 5) double-spend podwójnie broniony: (a) my_coins filtruje wydane po ki,
    #    (b) nawet ręczne złożenie tx z już wydanego coinu → ledger odrzuca (ki!)
    spent_coins = [c for c in coins_ala
                   if txr.key_image_of(c["spend_hint"], c["sp"]).hex() in L.key_images]
    assert len(spent_coins) == 2, "2 coiny poszły w test 4"
    assert all(txr.key_image_of(c["spend_hint"], c["sp"]).hex() not in L.key_images
               for c in pctl.my_coins()), "my_coins pokazuje wydane!"
    sc = spent_coins[0]
    ring5 = txr.pick_ring_candidates(L.pool, sc["amt"])
    idx5 = ring5.index(sc["sp"])
    payload5 = txr.build_ring_tx(
        spends=[{"ring": ring5, "index": idx5, "amount": sc["amt"],
                 "priv_ot": sc["spend_hint"]}],
        outs=[{"sig_pub": bob.sig_pub_b, "x_pub": bob.x_pub_b,
               "amount": sc["amt"] - 10_000_000}],
        fee_iskry=10_000_000)
    bad_tx = Tx(type=TX_RING, sender="", recipient="", amount=0, nonce=0,
                payload=json.dumps(payload5, separators=(",", ":"), sort_keys=True))
    try:
        L.add_tx(bad_tx)
        raise SystemExit("DOUBLE-SPEND przez panel przeszedł!")
    except ChainError as e:
        assert "key image" in str(e) or "już" in str(e)
    print("  [OK] 5. double-spend: my_coins filtruje ki; ręczna próba → ledger odrzuca (ki)")

    # 6) błędy po polsku: za duża kwota, zły adres, cienki tłum
    try:
        pctl.plan_send(bob_addr, 1000 * ISKRA)
        raise SystemExit("za duża kwota przeszła!")
    except PoolError as e:
        assert "za mało w poolu" in str(e)
    try:
        pctl.plan_send("FNXS1" + "aa", ISKRA)
        raise SystemExit("zły adres przeszedł!")
    except PoolError as e:
        assert "znaków" in str(e) or "literówka" in str(e) or "FNXS1" in str(e)
    L2 = Ledger(TRE)                                   # pusty ledger — tłum 0
    for _ in range(3):
        won = mine(L2.block_template(bob.wallet, zbits=2), max_tries=200_000)
        L2.apply_block(won)
    st = derive_stealth(bob.sig_pub_b, bob.x_pub_b)
    L2.add_tx(Tx.build_signed(TX_SHIELD, bob, "FNX-SHIELD", NOM, nonce=0,
                              payload=txr.shield_payload([{"sp": st["stealth_pub"],
                                                           "ep": st["eph_pub"]}])))
    won2 = mine(L2.block_template(bob.wallet, zbits=2), max_tries=200_000)
    assert won2 is not None
    L2.apply_block(won2)
    pctl_thin = PoolController(identity=bob, ledger=L2)
    try:
        pctl_thin.plan_send(addr, ISKRA)
        raise SystemExit("cienki tłum przeszedł!")
    except PoolError as e:
        assert "za cienki tłum" in str(e)
    print("  [OK] 6. błędy: za mało środków / zły adres / tłum 1<5 — wszystko po polsku")

    # 7) wielodzielnikowe wejścia: 5 FNX = 2+2+1 (1 FNX coin z tamtego change + nowy)
    #    przy okazji: MAX_OUTS strażnik
    st_self = derive_stealth(ala.sig_pub_b, ala.x_pub_b)
    L.add_tx(Tx.build_signed(TX_SHIELD, ala, "FNX-SHIELD", NOM,
                             nonce=L.nonce_of(ala.wallet),   # 7 shieldów już zjadło 0..6
                             payload=txr.shield_payload([{"sp": st_self["stealth_pub"],
                                                          "ep": st_self["eph_pub"]}])))
    kop()
    big = pctl.plan_send(bob_addr, 5 * ISKRA)
    assert len(big["inputs"]) >= 2 and big["sum_in"] >= 5 * ISKRA + big["fee"]
    tx_big = pctl.send_private(bob_addr, 5 * ISKRA)
    L.apply_block(mine(L.block_template(ala.wallet, zbits=2), max_tries=200_000))
    bobs2 = PoolController(identity=bob, ledger=L).my_coins()
    assert any(c["amt"] == 5 * ISKRA for c in bobs2)
    print("  [OK] 7. multi-input: 5 FNX złożone z kilku coinów → bob dostał 1 output")

    # 8) widok: SKIP headless; helper coins_summary bez kluczy
    assert "FNXS1" not in coins_summary(coins_ala)
    if _os.environ.get("DISPLAY"):
        print("  [OK] 8. widok: panel składany przez fenix_gui (DISPLAY obecne)")
    else:
        assert callable(coins_summary)
        print("  [OK] 8. widok: SKIP (headless; zakładka Pool = gui/fenix_gui.py _p_pool)")

    # 9) MGŁA v2 (M7d, D38/D39): mint z GUI → scan C/blob → wysyłka w mgle →
    #    wyjście z mgły na konto. Kwota nigdy nie pojawia się w poolu.
    print("\n  -- v2 (3b): mgła --")
    carol9 = Identity.generate("carol_p2")
    # 6 monet po 1 FNX (mempool-wave: nonce auto z kontrolera; jedna akcja kopnięcia)
    for _ in range(6):
        L.add_tx(pctl.build_shield2_tx(1 * ISKRA))
    kop()
    hid = pctl.my_hidden_coins()
    assert len(hid) == 6 and all(c["amt"] == 1 * ISKRA for c in hid), (
        [c.get("amt") for c in hid], "miało być 6×1 FNX w mgle")
    assert all("amt" not in L.pool[c["sp"]] for c in hid), "pool NIE może znać kwoty v2!"
    assert all(L.pool[c["sp"]]["v"] == 2 for c in hid)
    print("  [OK] 9a. mint v2 z GUI: 6 monet w mgle; scan C/blob je znajduje; pool bez amt")
    # cienki tłum mgły? (jest 6 v2 → ring 5 OK); zerowy: nowy leder z 1 monetą → odrzut
    L9 = Ledger()
    pc9 = PoolController(identity=carol9, ledger=L9, ipc=None)
    o9 = txh.make_shield2_out(carol9.sig_pub_b, carol9.x_pub_b, 1 * ISKRA)
    L9.pool[o9["sp"]] = {"ep": o9["ep"], "C": o9["C"], "blob": o9["blob"], "v": 2}
    try:
        pc9.plan_hidden_send(pc9.my_address(), 5 * ISKRA // 10)
        raise SystemExit("cienki tłum mgły przeszedł!")
    except PoolError as e:
        assert "za cienki tłum w mgle" in str(e) or "za mało w mgle" in str(e), str(e)
    print("  [OK] 9b. cienki tłum mgły odrzucony po polsku (1/5 wpisów v2)")
    # wysyłka w MGLE: ala → carol 2 FNX (potrzeba 3 monet: 2 FNX + fee)
    fee9 = fee_split(2 * ISKRA)[2]
    plan9 = pctl.plan_hidden_send(
        encode_stealth_address(carol9.sig_pub_b, carol9.x_pub_b), 2 * ISKRA)
    assert plan9["fee"] == fee9 and plan9["change"] == 3 * ISKRA - 2 * ISKRA - fee9
    tx9 = pctl.build_hidden_send(
        encode_stealth_address(carol9.sig_pub_b, carol9.x_pub_b), 2 * ISKRA)
    assert '"amt"' not in tx9.payload and str(2 * ISKRA) not in tx9.payload, \
        "payload v2 zdradza kwotę!"
    txid9 = pctl.submit(tx9)
    kop()
    pc_carol = PoolController(identity=carol9, ledger=L, ipc=None)
    got9 = [c for c in pc_carol.my_hidden_coins() if c["amt"] == 2 * ISKRA]
    assert len(got9) == 1, "carol ma widzieć dokładnie 2 FNX (scan C/blob mgły)"
    ala_rest = [c for c in pctl.my_hidden_coins()]
    assert any(c["amt"] == plan9["change"] for c in ala_rest), "reszta wróciła do mgły"
    assert len(ala_rest) == 6 - 3 + 1, f"3 wydane + reszta: {len(ala_rest)}"
    print("  [OK] 9c. wysyłka w mgle: carol widzi 2 FNX; reszta do ali; payload = zero liczb")
    # double-spend reprezentatywnie: ta sama tx → reject (ki)
    try:
        pctl.submit(tx9)
        raise SystemExit("powtórka tx9 przeszła!")
    except PoolError:
        pass
    # wyjście z mgły: ala wypłaca 1 FNX na konto (kwota jawna; reszta z powrotem)
    bal0 = L.balance_of(ala.wallet)
    txu9 = pctl.build_unshield_tx(1 * ISKRA)
    assert '"amt":100000000' in txu9.payload, "wyjście z→t MA pokazywać kwotę (jak Zcash)"
    pctl.submit(txu9)
    won9 = mine(L.block_template(ala.wallet, zbits=2), max_tries=200_000)   # kop() + coinbase
    L.apply_block(won9)
    assert L.balance_of(ala.wallet) == bal0 + 1 * ISKRA + won9.txs[0].amount, \
        "konto po unshield = bal0 + Y + coinbase tego bloku (kopie ala)"
    # unshield 1 FNX wydaje: change-coin (99_888_000 < 1 FNX+fee nie wystarczy) + 1 FNX coin
    hid2 = pctl.my_hidden_coins()
    assert len(hid2) == len(ala_rest) - 1, \
        f"unshield wydaje 2 monety (reszta+1), zostaje {len(ala_rest) - 1}: {len(hid2)}"
    print("  [OK] 9d. wyjście z mgły: +1 FNX na koncie ali; ki strzały; reszta żyje w mgle")
    assert coins_summary(hid2), "coins_summary też dla mgły"
    print("  [OK] 9. MGŁA v2 E2E (M7d): mint/scan/wysyłka/wyjście; pool nigdy nie zna kwot")

    print("\nSELFTEST: PASS ✅  gui/pool_panel.py — prywatna wysyłka z GUI działa\n"
          "(ring 5+, reszta do siebie, ki-filtr, błędy po polsku, zero sekretów na drucie,\n"
          "mgła v2: mint/C-blob-scan/hidden-send/unshield — kwoty poza zasięgiem łańcucha)")
