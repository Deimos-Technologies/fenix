# app/xmr_swap.py — Swap XMR → „świeży" FNX: wash-desk z ZASADĄ ZEROWEGO LINKU (D34)
"""
Przepływ (dlaczego to daje czysty coin na wyjściu):

    1. Desk podaje JEDNORAZOWY subadres XMR (per użytkownik per raz — jak przytulić
       nowy, pusty portfel do każdej wpłaty; Monero z natury nie ujawnia, skąd przyszło).
    2. Użytkownik wysyła XMR z dowolnej historii — Boże narodzenie blockchaina XMR
       nie wie o tym nic (ring/stealth Monero robi swoje przed nami).
    3. Desk trzyma depozyt w RAM z LOSOWYM opóźnieniem wypłaty 30–120 min
       (kurier nie jedzie od razu — konwój rozjeżdża się o różnych porach,
       więc po czasie nie da się powiązać „który vanio do którego").
    4. Wypłata: REALNA tx on-chain z portfela desku → wallet użytkownika,
       kwota po kursie z owner-oracle (D30, podpisany dokument, fee 3%).
    5. **TTL-SHRED**: po wypłacie + 24 h rekord linku DEPOSYT↔WALLET znika bezpowrotnie
       z RAM (D9: kopia zapasowa linków NIE ISTNIEJE → nie ma czego wyciągnąć).
       Desk BEZ tej zasady byłby honeypotem; z nią jest niewart uwagi.

Uczciwe zastrzeżenie (D34): do czasu TTL-shred desk TECHNICZNIE widzi link
(HTLC XMR⇄FNX nie istnieje — XMR nie ma skryptów; roadmap multi-desk/adaptory).
To NIE jest mixer-piramida: to kontrolowana, uczciwa wymiana z minimem danych.

Kurs: z oracle D30 — crypto_cents_usd_per_whole["XMR"] (centy za 1 XMR cały).
Atomic: 1 XMR = 10^12 piconero (tak jak w Monero).

Selftest: kurs dokładnie; delay okno zegar-wstrzykiwany; wypłata on-chain;
TTL-shred usuwa linki; duplikat tx_hash; gateway produkcyjny = uczciwy stub.
"""
from __future__ import annotations

import json
import sys
import time
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from app.exchange import RateOracle, ExchangeError            # noqa: E402
from chain.block import Tx, TX_TRANSFER, ISKRA               # noqa: E402
from chain.ledger import Ledger                              # noqa: E402
from core.identity import Identity                           # noqa: E402

XMR_ATOMIC = 10**12                    # 1 XMR = 10^12 piconero (konwencja Monero)
SWAP_FEE_PCT = 3                       # fee 3%: prąd XMR + zmienność (D34, w ToS)
DELAY_MIN_S, DELAY_MAX_S = 30 * 60, 120 * 60     # okno opóźnienia wypłaty (anty-korelacja)
TTL_SHRED_S = 24 * 3600                # po wypłacie link żyje max 24 h → OSTATECZNIE ginie
MIN_ATOMIC = int(0.05 * XMR_ATOMIC)    # 0.05 XMR minimalny depozyt
MAX_ATOMIC = int(50 * XMR_ATOMIC)      # 50 XMR maksymalny (anty-laundering, ToS)
MIN_CONFIRMATIONS = 10                 # hard final na XMR przed uznaniem depozytu
MAX_SWAPS_PER_WALLET_DAY = 3


class SwapError(Exception):
    """Błędny depozyt/kurs/stan — jeden typ (złodziej nie wie co)."""


# ---------------------------------------------------------------- gateway XMR
class XmrGateway:
    """Interfejs monero-wallet-rpc operatora. Kontrakt:
    next_subaddress() → {"index", "address"}; get_tx(tx_hash) →
    {confirmations, amount_atomic, subaddr_index}."""

    def next_subaddress(self) -> dict:
        raise NotImplementedError

    def get_tx(self, tx_hash: str) -> dict:
        raise NotImplementedError


class MoneroRpcGateway(XmrGateway):
    """PRODUKCJA: monero-wallet-rpc z XMR desku (wymaga hostingu operatora — D34).
    Nie udajemy, że działa bez niego."""

    def __init__(self, rpc_url: str | None = None):
        self.rpc_url = rpc_url

    def next_subaddress(self) -> dict:
        raise NotImplementedError("MoneroRpcGateway: potrzebny monero-wallet-rpc (D34)")


class StubXmrGateway(XmrGateway):
    """TESTY: kontrolowane depozyty."""

    def __init__(self):
        self._idx = 0
        self._txs: dict[str, dict] = {}

    def next_subaddress(self) -> dict:
        self._idx += 1
        return {"index": self._idx, "address": f"8SUB{self._idx:040d}"}

    def feed_tx(self, tx_hash: str, amount_atomic: int, subaddr_index: int,
                confirmations: int = 10):
        self._txs[tx_hash] = {"confirmations": confirmations,
                              "amount_atomic": amount_atomic,
                              "subaddr_index": subaddr_index}

    def get_tx(self, tx_hash: str) -> dict:
        v = self._txs.get(tx_hash)
        if v is None:
            raise SwapError("XMR: nieznany tx_hash")
        return v


# ---------------------------------------------------------------- desk swap
class XmrSwapDesk:
    """Desk: rejestr depozytó→FINALNE wypłaty w FNX; RAM-only + TTL-shred."""

    def __init__(self, desk_identity: Identity, ledger: Ledger,
                 oracle: RateOracle, gateway: XmrGateway,
                 rng=None, clock=time.time):
        self.idn = desk_identity
        self.ledger = ledger
        self.oracle = oracle
        self.gateway = gateway
        import random as _r
        self._rng = rng or _r.SystemRandom()
        self._clock = clock
        self.swaps: dict[str, dict] = {}          # tx_hash → rekord (WSZYSTKO w RAM)
        self._used_hashes: set[str] = set()
        self._daily: dict[tuple, int] = {}

    # -------- etap 1: user prosi o subadres
    def new_deposit_address(self, user_wallet: str) -> dict:
        sub = self.gateway.next_subaddress()
        return {"address": sub["address"], "index": sub["index"],
                "for_wallet": user_wallet,
                "note": "wyślij XMR TYLKO na TEN subadres; min "
                        f"{MIN_ATOMIC / XMR_ATOMIC} XMR / max {MAX_ATOMIC / XMR_ATOMIC} XMR"}

    # -------- etap 2: user zgłasza wpłatę (kurs zamrażany TERAZ — fair obie strony)
    def register_deposit(self, tx_hash: str, user_wallet: str, oracle_doc: bytes) -> dict:
        if tx_hash in self._used_hashes:
            raise SwapError("tx_hash już zgłoszony (anti-replay)")
        tx = self.gateway.get_tx(tx_hash)
        if tx["confirmations"] < MIN_CONFIRMATIONS:
            raise SwapError(f"depozyt: {tx['confirmations']} potwierdzeń < {MIN_CONFIRMATIONS}")
        atomic = tx["amount_atomic"]
        if not (MIN_ATOMIC <= atomic <= MAX_ATOMIC):
            raise SwapError(f"kwota poza oknem {MIN_ATOMIC / XMR_ATOMIC}–{MAX_ATOMIC / XMR_ATOMIC} XMR")
        day = int(self._clock()) // 86400
        if self._daily.get((user_wallet, day), 0) >= MAX_SWAPS_PER_WALLET_DAY:
            raise SwapError(f"limit {MAX_SWAPS_PER_WALLET_DAY} swapów/dzień/wallet (D34)")
        q = self.oracle.verify(oracle_doc)
        try:
            xmr_cents = q["crypto_cents_usd_per_whole"]["XMR"]
        except (KeyError, TypeError):
            raise SwapError("oracle nie podaje kursu XMR (D34 potrzebuje crypto_cents)") from None
        iskry = (atomic * xmr_cents * (100 - SWAP_FEE_PCT) * 10**8) \
            // (q["usd_cents_per_fnx"] * 100 * XMR_ATOMIC)
        now = self._clock()
        release_at = now + self._rng.randint(DELAY_MIN_S, DELAY_MAX_S)
        self._used_hashes.add(tx_hash)
        self._daily[(user_wallet, day)] = self._daily.get((user_wallet, day), 0) + 1
        rec = {"tx_hash": tx_hash, "wallet": user_wallet, "atomic": atomic,
               "iskry": iskry, "registered": now, "release_at": release_at,
               "released": False, "purge_at": None}
        self.swaps[tx_hash] = rec
        return rec

    # -------- etap 3: zegar odpychadła — wypłata po delay (realna tx on-chain)
    def release_due(self) -> list[dict]:
        """Zwalnia wszystkie dojrzewłe swapy. Wołać z pętli noda/GUI co ~minutę."""
        now = self._clock()
        out = []
        for rec in self.swaps.values():
            if rec["released"] or rec["release_at"] > now:
                continue
            nonce = self.ledger.nonce_of(self.idn.wallet) + \
                sum(1 for t in self.ledger.mempool if t.sender == self.idn.wallet)
            tx = Tx.build_signed(TX_TRANSFER, self.idn, rec["wallet"],
                                 rec["iskry"], nonce=nonce)
            self.ledger.add_tx(tx)
            rec["released"] = True
            rec["released_at"] = now
            rec["txid"] = tx.txid()
            rec["purge_at"] = now + TTL_SHRED_S      # odliczanie shredu START
            out.append(rec)
        return out

    # -------- etap 4: TTL-shred — linki GINĄ (bez backup; D9)
    def purge_expired(self) -> int:
        now = self._clock()
        dead = [h for h, r in self.swaps.items()
                if r["released"] and r["purge_at"] is not None and now >= r["purge_at"]]
        for h in dead:
            del self.swaps[h]
        return len(dead)

    # statystyki bez linków (do GUI; bez par wallet↔hash!)
    def stats(self) -> dict:
        rel = sum(1 for r in self.swaps.values() if r["released"])
        return {"open": len(self.swaps) - rel, "released_pending_shred": rel,
                "ttl_shred_s": TTL_SHRED_S}


# ---------------------------------------------------------------- selftest
if __name__ == "__main__":
    print("app/xmr_swap.py — selftest: kurs, delay, on-chain release, TTL-shred, duplikaty\n")
    from app.exchange import make_oracle_doc
    from chain.miner import mine

    owner = Identity.generate("owner_x")
    desk_idn = Identity.generate("swapdesk")
    user = Identity.generate("monero_mike")
    TRE = "FNX1" + "0" * 32
    L = Ledger(TRE)
    # zasil DESK (do wypłaty potrzeba ≥ ok. 801 FNX przy minimalnym depozycie 0.05 XMR)
    for _ in range(170):
        won = mine(L.block_template(desk_idn.wallet, zbits=4), max_tries=100_000)
        assert won
        L.apply_block(won)
    assert L.balance_of(desk_idn.wallet) >= 850 * ISKRA

    oracle = RateOracle(owner.sig_pub_b)
    doc = make_oracle_doc(owner, usd_cents_per_fnx=100,
                          crypto_cents={"XMR": 1_650_000})   # 1 XMR = $16 500

    # zegar wstrzykiwany (kontrola czasu w teście — determinizm)
    now = {"t": 1_760_000_000.0}
    fake_clock = lambda: now["t"]                    # noqa: E731
    import random
    rng = random.Random(42)
    gw = StubXmrGateway()
    desk = XmrSwapDesk(desk_idn, L, oracle, gw, rng=rng, clock=fake_clock)

    # 1) subadresy jednorazowe i różne
    a1 = desk.new_deposit_address(user.wallet)
    a2 = desk.new_deposit_address(user.wallet)
    assert a1["address"] != a2["address"] and a1["index"] != a2["index"]
    print(f"  [OK] 1. subadresy jednorazowe: idx {a1['index']} ≠ idx {a2['index']}")

    # 2) rejestr depozytu: kurs dokładnie (fee 3%), delay w oknie [30,120] min
    dep_atomic = MIN_ATOMIC                      # 0.05 XMR — minimum (zaokrąglenie tanie)
    txh = "a" * 64
    gw.feed_tx(txh, amount_atomic=dep_atomic, subaddr_index=a1["index"])
    # mało potwierdzeń → odmowa najpierw
    txh_bad = "b" * 64
    gw.feed_tx(txh_bad, amount_atomic=1, subaddr_index=a1["index"], confirmations=3)
    try:
        desk.register_deposit(txh_bad, user.wallet, doc)
        raise SystemExit("mało potwierdzeń przeszło!")
    except SwapError:
        pass
    rec = desk.register_deposit(txh, user.wallet, doc)
    exp = (dep_atomic * 1_650_000 * 97 * 10**8) // (100 * 100 * XMR_ATOMIC)
    assert rec["iskry"] == exp, (rec["iskry"], exp)
    assert DELAY_MIN_S <= rec["release_at"] - rec["registered"] <= DELAY_MAX_S
    print(f"  [OK] 2. depozyt {dep_atomic / XMR_ATOMIC} XMR → {exp / ISKRA:.4f} FNX "
          f"przy fee 3%; delay={rec['release_at'] - rec['registered']:.0f} s")

    # 3) duplikat tx_hash → odmowa (anti-replay)
    try:
        desk.register_deposit(txh, user.wallet, doc)
        raise SystemExit("duplikat przeszedł!")
    except SwapError:
        print("  [OK] 3. ponowne zgłoszenie tego samego tx_hash → odmowa")

    # 4) ZEGAR: przed oknem nic nie leci; po oknie tx w mempool z DOKŁADNĄ kwotą
    assert desk.release_due() == [], "za wcześnie na wypłatę!"
    now["t"] = rec["release_at"] + 1
    out = desk.release_due()
    assert len(out) == 1 and out[0]["released"]
    txout = next(t for t in L.mempool if t.txid() == out[0]["txid"])
    assert txout.recipient == user.wallet and txout.amount == exp
    assert txout.sender == desk_idn.wallet and txout.verify_signature()
    print(f"  [OK] 4. release po delay: tx on-chain podpisana deskem, kwota {txout.amount} iskier")

    # 5) TTL-SHRED: po wypłacie + 24 h rekord linku GINIE (bez kopii)
    assert txh in desk.swaps, "link żyje do TTL (to OK — serwis)"
    assert desk.purge_expired() == 0, "za wcześnie na shred"
    now["t"] = rec["release_at"] + TTL_SHRED_S + 60
    n = desk.purge_expired()
    assert n == 1 and txh not in desk.swaps and txh not in desk.stats().get("hash", "")
    assert json.dumps(desk.swaps) == "{}", "jakiś link przeżył 24 h po wypłacie!"
    assert desk.stats()["open"] == 0 and desk.stats()["released_pending_shred"] == 0
    print("  [OK] 5. TTL-shred: po 24 h od wypłaty link depozyt↔wallet NIE ISTNIEJE")

    # 6) produkcyjny gateway = uczciwy stub (jak PaysafeGateway)
    try:
        MoneroRpcGateway().next_subaddress()
        raise SystemExit("MoneroRpcGateway udawał działanie!")
    except NotImplementedError as e:
        assert "monero-wallet-rpc" in str(e)
        print("  [OK] 6. MoneroRpcGateway: uczciwy NotImplementedError do czasu hostingu (D34)")

    print("\nSELFTEST: PASS ✅  swap XMR→FNX: kurs z oracle; delay-antykorelacja; linki giną")
