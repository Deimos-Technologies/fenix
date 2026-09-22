# app/fnx_coin.py — Giełda FNX-COIN (D65): cena rodzi się Z ŁAŃCUCHA, kupno + sprzedaż
"""
Czym to jest ( jednym zdaniem ): kantor FNX, którego KURSU nie ustawia żaden
człowiek — cena jest policzona wyłącznie z publicznych faktów łańcucha
( wykopana podaż, wysokość, zarejestrowani, attesterzy, głosy ) i każdy węzeł
liczy ją IDENTYCZNIE ( bit-w-bit, jak cały nasz konsensus ).

Dlaczego tak (D65):
  * D30/D32 miały kurs PODPISYWANY przez ownera — jedna osoba trzymała
    termostat ceny (kłóciło się z „żaden człowiek nie ma przycisku").
    FNX-COIN zdejmuje ten przycisk: model jest jawny, stałe ROBOCZE §12,
    zmiana = głosowanie VOTE_EVT (D60), nie podpis jednej ręki.
  * Książeczka zleceń (orderbook P2P) zostaje roadmapą (D32: market-maker
    z rankami) — tu jest desk market-maker, który KUPUJE i SPRZEDAJE
    ze swojego magazynu po cenie z krzywej.

KRZYWA v1 (int-only, ROBOCZE §12 — głosowalne D60):
    kapitał[¢] = FLOOR_CAP + PER_USER·users + PER_ATT·attesterzy
               + PER_VOTE·głosy + WORK·wysokość
    cena[¢/FNX] = max(BASE, kapitał·ISKRA // max(podaż_iskry, ISKRA))
  Czytankowo: podaż w MIANOWNIKU — więcej wykopanego przy tej samej
  aktywności = rozcieńczenie, cena ↓; użytkownicy/attesterzy/głosy/wysokość
  w LICZNIKU — sieć żyje i pracuje, kapitał ↑, cena ↑. Podłoga BASE_CENTS,
  więc genesis (podaż 0) i hiperinflacja nie psują wzoru.
  Spread SPREAD_PPM każdą stronę = marża desku (zostaje w jego magazynie).
  Handel z desk nie rusza krzywej (transfer ≠ emisja; saldo desku ≠ fakt
  łańcuchowy) — NIE da się „powpychać" ceny handlując z kantorem.

Uczciwe granice (czytać głośno):
  * Desk NIGDY nie drukuje FNX — sprzedaje wyłącznie ze swojego salda;
    pusty magazyn = uczciwy komunikat „brak zapasów", nie „przybliżenie".
  * Waluta fiat: rail dostarcza własny kurs FX PLN↔USD (świat zewnętrzny,
    nie da się z łańcucha). Cena FNX w USD-centach — nasza, z łańcucha.
  * Kurs sprzedaży liczony jest z chwili KSIĘGOWANIA (settle), nie wysłania
    transferu — jak w kantorze „kurs z chwili zaksięgowania".
  * LEGAL_NOTICE: przyjmowanie pieniędzy (obie strony) = usługa finansowa
    (VASP/rejestr, kontrakt operatora rail) — zadanie właściciela, nie kodu (P7).

Selftest (bez argumentów): krzywa (jednostkowo), determinizm klonów, stats
z żywej księgi, kupno E2E na-prawdę w Ledgerze, fail-path bez obciążenia rail,
sprzedaż E2E + replay + cudzy txid + niepotwierdzona, limity, inwariant no-mint.
"""
from __future__ import annotations

import json
import sys
import time
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from chain.block import Tx, TX_TRANSFER, ISKRA, fee_split            # noqa: E402
from chain.ledger import Ledger, BLOCK_REWARD                        # noqa: E402
from core.identity import Identity                                   # noqa: E402

MODEL = "fnx-coin-curve v1 (D65, ⚠️ROBOCZE §12 — stałe pod VOTE_EVT D60)"

# ---- krzywa: stałe robocze (§12; zmiana = głosowanie, nie edycja ręczna) ----
BASE_CENTS = 1                # podłoga ceny — nigdy za darmo, nigdy ujemnie
FLOOR_CAP_CENTS = 100         # kapitał startowy sieci (1.00 $)
PER_USER_CENTS = 100          # +1.00 $ kapitału za zarejestrowanego (username)
PER_ATT_CENTS = 500           # +5.00 $ za attesterę PoU (udowodniona obecność)
PER_VOTE_CENTS = 1            # +0.01 $ za oddany głos (żywe gremium)
WORK_CENTS_PER_BLOCK = 1      # +0.01 $ za blok pracy (koszt wydobycia)
SPREAD_PPM = 20_000           # 2% każdą stronę — marża desku (magazyn)
# ---- okno handlu + higiena limitów (jak D32) ----
MIN_TRADE_MINOR = 500         # 5.00 jednostki fiat min
MAX_TRADE_MINOR = 500_00      # 500.00 max
MAX_TRADES_PER_WALLET_DAY = 5

LEGAL_NOTICE = (
    "FNX-COIN: przyjmowanie wpłat i wypłaty (fiat/krypto) to usługa finansowa "
    "— operator raila potrzebuje rejestru (VASP/anti-laundering) i kontraktu "
    "(P7, zadanie właściciela). Desk NIE emituje FNX: sprzedaje z własnego "
    "magazynu; cena liczona deterministycznie z łańcucha (MODEL, stałe §12 "
    "przelatywalne głosowaniem D60)."
)


class ExchangeError(Exception):
    """Jeden typ błędu handlu — złodziej nie dowie się, co dokładnie spadło."""


# ------------------------------------------------------------------- statystyki łańcucha
def supply_stats(ledger: Ledger) -> dict:
    """TYLKO fakty łańcuchowe (każdy węzeł policzy identycznie, replay bit-w-bit).
    podaż = Σ sald — ground truth: fee-burn nigdy nie był zaksięgowany, więc
    spalone FNX po prostu nie istnieją w tej sumie (deflacja z D15 w cenie)."""
    return {"height": ledger.height(),
            "supply": sum(ledger.balances.values()),          # iskry
            "users": len(ledger.usernames),
            "attesters": len(ledger.pou),
            "votes_cast": sum(len(m) for m in ledger.votes.values()),
            "donors": len(ledger.donations)}


def curve_price_cents(stats: dict) -> int:
    """Czysta funkcja krzywej: centy USD za 1 FNX. Int-only — deterministyczna."""
    cap = (FLOOR_CAP_CENTS
           + PER_USER_CENTS * stats["users"]
           + PER_ATT_CENTS * stats["attesters"]
           + PER_VOTE_CENTS * stats["votes_cast"]
           + WORK_CENTS_PER_BLOCK * stats["height"])
    return max(BASE_CENTS, cap * ISKRA // max(stats["supply"], ISKRA))


def quote_pair(ledger: Ledger) -> dict:
    """Cena środka + ask/bid z spreadem + stats (widok dla GUI / raportu)."""
    stats = supply_stats(ledger)
    p = curve_price_cents(stats)
    ask = max(p + 1, p * (10 ** 6 + SPREAD_PPM) // 10 ** 6)
    bid = min(p, max(BASE_CENTS, p * (10 ** 6 - SPREAD_PPM) // 10 ** 6))
    return {"model": MODEL, "price_cents": p, "ask_cents": ask, "bid_cents": bid,
            "spread_ppm": SPREAD_PPM, "stats": stats}


# ------------------------------------------------------------------- rail płatności (świat zewnętrzny)
class Rail:
    """Kontrakt raila (pieniądz fiat/krypto POZA łańcuchem FNX):
    debit(kwota_minor, waluta, ref) → pay_id  |  refund(pay_id)  |
    payout(kwota_minor, waluta, ref) → out_id  |  fx_millicents(waluta)→int """""

    def fx_millicents(self, currency: str) -> int:
        raise NotImplementedError

    def debit(self, amount_minor: int, currency: str, ref: str) -> str:
        raise NotImplementedError

    def refund(self, pay_id: str) -> None:
        raise NotImplementedError

    def payout(self, amount_minor: int, currency: str, ref: str) -> str:
        raise NotImplementedError


class ProductionRail(Rail):
    """PRODUKCJA: prawdziwy operator (bank/PSC-out/XMR-desk). Wymaga KONTRAKTU
    i rejestru (P7) — udawanie, że działa bez niego, byłoby fałszywą obietnicą."""

    def fx_millicents(self, currency: str) -> int:
        raise NotImplementedError(
            "ProductionRail: operator płatności wymaga kontraktu + rejestru — P7/legal")


class StubRail(Rail):
    """TESTY/dev: księguje debity/wypłaty/zwroty w RAM; FX deklarowany jawnie."""

    def __init__(self, fx_millicents_map: dict[str, int]):
        self._fx = dict(fx_millicents_map)     # np. {"PLN": 25, "USD": 100}
        self.debits: list[tuple[int, str, str]] = []
        self.payouts: list[tuple[int, str, str]] = []
        self.refunds: list[str] = []

    def fx_millicents(self, currency: str) -> int:
        mc = self._fx.get(currency)
        if not isinstance(mc, int) or mc <= 0:
            raise ExchangeError(f"rail nie obsługuje waluty {currency}")
        return mc

    def debit(self, amount_minor: int, currency: str, ref: str) -> str:
        self.fx_millicents(currency)
        pid = f"pay-{len(self.debits)}-{abs(hash((amount_minor, ref))) % 10 ** 8}"
        self.debits.append((amount_minor, currency, ref))
        return pid

    def refund(self, pay_id: str) -> None:
        self.refunds.append(pay_id)

    def payout(self, amount_minor: int, currency: str, ref: str) -> str:
        self.fx_millicents(currency)
        oid = f"out-{len(self.payouts)}-{abs(hash((amount_minor, ref))) % 10 ** 8}"
        self.payouts.append((amount_minor, currency, ref))
        return oid


# ------------------------------------------------------------------- FNX-COIN desk
class CoinDesk:
    """Market-maker z ceną z łańcucha. Klucz identity podpisuje tx kredytowe
    (jak desk D32), ale KURSU nie podpisuje nikt — liczy go łańcuch."""

    def __init__(self, desk_identity: Identity, ledger: Ledger, rail: Rail):
        self.idn = desk_identity
        self.ledger = ledger
        self.rail = rail
        self.receipts: list[dict] = []          # paragony: bez danych płatności
        self._daily: dict[tuple, int] = {}       # (wallet, dzień, kierunek) → n
        self._settled: set[str] = set()          # txid sprzedaży (anti-replay)

    # -- wspólne --
    def _check_limit(self, wallet: str, day: int, side: str) -> None:
        key = (wallet, day, side)
        if self._daily.get(key, 0) >= MAX_TRADES_PER_WALLET_DAY:
            raise ExchangeError(
                f"limit {MAX_TRADES_PER_WALLET_DAY} {side}/dzień/wallet (higiena D32)")

    def _bump_limit(self, wallet: str, day: int, side: str) -> None:
        key = (wallet, day, side)
        self._daily[key] = self._daily.get(key, 0) + 1

    def _fiat_to_cents(self, amount_minor: int, currency: str) -> int:
        return amount_minor * self.rail.fx_millicents(currency) // 1000

    def _cents_to_minor(self, cents: int, currency: str) -> int:
        return cents * 1000 // self.rail.fx_millicents(currency)

    # -- KUPNO: fiat → FNX po ask --
    def quote_buy(self, amount_minor: int, currency: str) -> dict:
        if not (MIN_TRADE_MINOR <= amount_minor <= MAX_TRADE_MINOR):
            raise ExchangeError(
                f"kwota poza oknem {MIN_TRADE_MINOR/100:.2f}–"
                f"{MAX_TRADE_MINOR/100:.2f} {currency}")
        qp = quote_pair(self.ledger)
        cents = self._fiat_to_cents(amount_minor, currency)
        iskry = cents * ISKRA // qp["ask_cents"]
        if iskry <= 0:
            raise ExchangeError("za mało nawet na 1 iskrę przy tym kursie")
        return {"side": "buy", "fnx": iskry / ISKRA, "iskry": iskry,
                "rate_cents": qp["ask_cents"], "value_cents": cents,
                "model": qp["model"]}

    def buy(self, user_wallet: str, amount_minor: int, currency: str,
            pay_ref: str) -> dict:
        """Pełny flow kupna: rail.debit → realna tx desk→user (mempool).
        Kolejność ma znaczenie: najpierw WALIDACJE + inwentarz, potem pieniądz,
        na końcu tx; błąd łańcucha = refund raila (nic nie ginie po drodze)."""
        q = self.quote_buy(amount_minor, currency)
        day = int(time.time()) // 86400
        self._check_limit(user_wallet, day, "buy")
        fee_need = sum(fee_split(q["iskry"]))
        # inwentarz: saldo KSIĘGOWE minus to, co już wisi w mempoolu desku
        inv = self.ledger.balance_of(self.idn.wallet)
        pending = sum(t.amount + sum(fee_split(t.amount))
                      for t in self.ledger.mempool if t.sender == self.idn.wallet)
        if inv - pending < q["iskry"] + fee_need:
            raise ExchangeError("FNX-COIN: magazyn pusty — sprzedaż wstrzymana "
                                "(desk NIE drukuje FNX; próbuj po kolejnych blokach)")
        pay_id = self.rail.debit(amount_minor, currency, pay_ref)
        nonce = self.ledger.nonce_of(self.idn.wallet) + \
            sum(1 for t in self.ledger.mempool if t.sender == self.idn.wallet)
        tx = Tx.build_signed(TX_TRANSFER, self.idn, user_wallet, q["iskry"], nonce=nonce)
        try:
            self.ledger.add_tx(tx)
        except Exception:
            self.rail.refund(pay_id)                    # pieniądz wraca, zero śladu długu
            raise ExchangeError("łańcuch odrzucił kredyt — płatność zwrócona") from None
        self._bump_limit(user_wallet, day, "buy")
        rec = {"kind": "fnx_coin_buy", "wallet": user_wallet, "currency": currency,
               "amount_minor": amount_minor, "iskry": q["iskry"],
               "rate_cents": q["rate_cents"], "txid": tx.txid(), "day": day}
        self.receipts.append(rec)
        return rec

    # -- SPRZEDAŻ: FNX → fiat po bid (kurs z chwili księgowania) --
    def quote_sell(self, iskry: int, currency: str) -> dict:
        if not (1 <= iskry):
            raise ExchangeError("sprzedaż od 1 iskry wzwyż")
        qp = quote_pair(self.ledger)
        cents = iskry * qp["bid_cents"] // ISKRA
        if cents <= 0:
            raise ExchangeError("za mała kwota przy tym kursie (bid pod progiem)")
        return {"side": "sell", "fnx": iskry / ISKRA, "iskry": iskry,
                "rate_cents": qp["bid_cents"], "value_cents": cents,
                "model": qp["model"]}

    def _find_confirmed(self, txid: str):
        """Szuka tx WYŁĄCZNIE w blokach (potwierdzone). Mempool = 'w drodze'."""
        for b in self.ledger.chain:
            for t in b.txs:
                if t.txid() == txid:
                    return t
        return None

    def settle_sell(self, txid: str, currency: str, payout_ref: str) -> dict:
        """Księguje sprzedaż: user zrobił transfer → desk, my wypłacamy rail."""
        if txid in self._settled:
            raise ExchangeError("ta sprzedaż już zaksięgowana (replay-stój)")
        if any(t.txid() == txid for t in self.ledger.mempool):
            raise ExchangeError("transfer jeszcze w mempoolu — wykop blok, "
                                "settle dopiero po potwierdzeniu (kurs z księgowania)")
        tx = self._find_confirmed(txid)
        if tx is None:
            raise ExchangeError("nie znaleziono potwierdzonego transferu o tym txid")
        if tx.type != TX_TRANSFER or tx.recipient != self.idn.wallet:
            raise ExchangeError("to nie jest sprzedaż do FNX-COIN "
                                "(transfer musi iść NA adres desku)")
        q = self.quote_sell(tx.amount, currency)
        day = int(time.time()) // 86400
        self._check_limit(tx.sender, day, "sell")
        minor = self._cents_to_minor(q["value_cents"], currency)
        out_id = self.rail.payout(minor, currency, payout_ref)
        self._settled.add(txid)
        self._bump_limit(tx.sender, day, "sell")
        rec = {"kind": "fnx_coin_sell", "wallet": tx.sender, "currency": currency,
               "iskry": tx.amount, "rate_cents": q["rate_cents"],
               "value_cents": q["value_cents"], "amount_minor": minor,
               "txid": txid, "out_id": out_id, "day": day}
        self.receipts.append(rec)
        return rec


def price_info(ledger: Ledger) -> dict:
    """Kokpit cenowy (GUI/raport): cena, ask/bid, kapitał, statystyki łańcucha."""
    qp = quote_pair(ledger)
    s = qp["stats"]
    return {**qp,
            "price_usd": f"${qp['price_cents']/100:.4f}",
            "ask_usd": f"${qp['ask_cents']/100:.4f}",
            "bid_usd": f"${qp['bid_cents']/100:.4f}",
            "supply_fnx": s["supply"] / ISKRA,
            "legal": LEGAL_NOTICE}


# ---------------------------------------------------------------- selftest
if __name__ == "__main__":
    print("app/fnx_coin.py — selftest: krzywa z łańcucha, kupno+sprzedaż E2E, "
          "determinizm klonów, fail-path, replay, limity, no-mint\n")
    from chain.miner import mine

    # ---- 1. krzywa jednostkowo: podłoga, aktywność↑, rozcieńczenie↓, potwory int
    base = {"height": 0, "supply": 0, "users": 0, "attesters": 0,
            "votes_cast": 0, "donors": 0}
    # genesis (podaż 0): pierwszy/jedyny FNX kosztuje CAŁY kapitał (FLOOR_CAP),
    # a podłoga BASE_CENTS pilnuje dolnego brzegu przy hiper-rozcieńczeniu (patrz 'mon')
    assert curve_price_cents(base) == FLOOR_CAP_CENTS, \
        "genesis: 1 FNX = cały kapitał startowy (podaż 0)"
    hot = {**base, "supply": 100 * ISKRA, "height": 100, "users": 5}
    cold = {**base, "supply": 100 * ISKRA, "height": 100, "users": 0}
    assert curve_price_cents(hot) > curve_price_cents(cold), "aktywność podnosi cenę"
    deep = {**base, "supply": 10 ** 6 * ISKRA, "height": 100, "users": 5}
    assert curve_price_cents(deep) < curve_price_cents(hot), \
        "więcej wykopanego = rozcieńczenie (cena w dół)"
    mon = {**base, "supply": 10 ** 18 * ISKRA, "height": 10 ** 9}
    assert curve_price_cents(mon) == BASE_CENTS, \
        "hiper-rozcieńczenie: cena spada NA podłogę i nie niżej (int bez overflow)"
    print("[OK] 1. krzywa: genesis=cały kapitał; users↑→cena↑; podaż↑→rozcieńczenie↓; "
          "potwór 10^18 → podłoga trzyma, zero overflow")

    # ---- 2. żywa księga: desk sfinansowany kopaniem (JAK exchange D32)
    desk = Identity.generate("fnx_coin_desk")
    user = Identity.generate("klient_feliks")
    TRE = "FNX1" + "0" * 32
    L = Ledger(TRE)
    mined_blocks = []
    for _ in range(3):
        tmpl = L.block_template(desk.wallet, zbits=2)
        won = mine(tmpl, max_tries=300_000)
        assert won, "dev-kopanie nie wypaliło w limicie prób"
        L.apply_block(won)
        mined_blocks.append(won)
    s0 = supply_stats(L)
    assert s0["height"] == 3 and s0["supply"] == sum(L.balances.values()) == \
        L.balance_of(desk.wallet) > 0, "stats = prawda księgi (Σsald, height)"
    supply_after_fund = s0["supply"]
    print(f"[OK] 2. stats z księgi: height={s0['height']}, podaż={s0['supply']/ISKRA} FNX "
          f"(Σsald), users=0")

    # ---- 3. determinizm: KLON z replay identyczny bit-w-bit (to jest konsensus ceny)
    L2 = Ledger(TRE)
    for b in mined_blocks:
        L2.apply_block(b)
    assert price_info(L)["price_cents"] == price_info(L2)["price_cents"], \
        "dwa węzły = ta sama cena (bit-w-bit)"
    assert supply_stats(L) == supply_stats(L2), "stats klonów identyczne"
    assert json.dumps(price_info(L), sort_keys=True) == \
        json.dumps(price_info(L2), sort_keys=True), "kokpit klonów zgodny w całości"
    print("[OK] 3. determinizm: klon z replay → identyczna cena i kokpit (JSON zgodny)")

    # ---- 4. ask/bid geometrycznie
    qp = quote_pair(L)
    assert qp["ask_cents"] > qp["price_cents"] >= qp["bid_cents"] >= BASE_CENTS
    print(f"[OK] 4. ask {qp['ask_cents']}¢ > cena {qp['price_cents']}¢ ≥ bid "
          f"{qp['bid_cents']}¢ (spread {SPREAD_PPM} ppm)")

    # ---- 5. KUPNO E2E na-prawdę
    rail = StubRail({"PLN": 25, "USD": 100})
    cd = CoinDesk(desk, L, rail)
    rec = cd.buy(user.wallet, 2500, "PLN", "paragon-kiosk-04")     # 25.00 PLN ≈ 6.25$
    tmpl = L.block_template(desk.wallet, zbits=2)
    won = mine(tmpl, max_tries=300_000)
    assert won
    L.apply_block(won)
    assert L.balance_of(user.wallet) == rec["iskry"], \
        "user dostał DOKŁADNIE kwotę z kwotacji (fee płaci desk)"
    assert len(rail.debits) == 1 and not rail.refunds, "rail obciążony raz, bez zwrotu"
    print(f"[OK] 5. kupno E2E: 25 PLN → {rec['iskry']/ISKRA} FNX on-chain "
          f"(kurs {rec['rate_cents']}¢), txid …{rec['txid'][:12]}")

    # ---- 6. fail-path: pusty magazyn NIE obciąża raila; złe okno/waluta
    broke = Identity.generate("desk_pusty")
    rail2 = StubRail({"PLN": 25})
    cd2 = CoinDesk(broke, L, rail2)
    try:
        cd2.buy(user.wallet, 2500, "PLN", "x")
        raise AssertionError("pusty desk nie powinien sprzedać")
    except ExchangeError:
        pass
    assert not rail2.debits, "rail NIE obciążony gdy magazyn pusty (pieniądz na końcu)"
    for bad_amt, bad_cur in ((1, "PLN"), (60_000, "PLN"), (2500, "GBP")):
        try:
            cd.buy(user.wallet, bad_amt, bad_cur, "x")
            raise AssertionError(f"przyjęto złe zlecenie {bad_amt} {bad_cur}")
        except ExchangeError:
            pass
    print("[OK] 6. fail-path: pusty magazyn=odmowa BEZ obciążenia rail; "
          "okno kwot i waluta pilnowane")

    # ---- 7. SPRZEDAŻ E2E: user→desk transfer, blok, settle; + strażnicy
    buy_bal = L.balance_of(user.wallet)
    sell_amt = buy_bal // 2
    un = L.nonce_of(user.wallet)
    stx = Tx.build_signed(TX_TRANSFER, user, desk.wallet, sell_amt, nonce=un)
    L.add_tx(stx)
    stxid = stx.txid()
    try:
        cd.settle_sell(stxid, "PLN", "iban-hash-77")
        raise AssertionError("settle przed potwierdzeniem nie wolno")
    except ExchangeError:
        pass
    tmpl = L.block_template(desk.wallet, zbits=2)
    won = mine(tmpl, max_tries=300_000)
    assert won
    L.apply_block(won)
    srec = cd.settle_sell(stxid, "PLN", "iban-hash-77")
    assert len(rail.payouts) == 1 and srec["iskry"] == sell_amt
    for again in (stxid,):
        try:
            cd.settle_sell(again, "PLN", "iban-hash-77")
            raise AssertionError("replay sprzedaży przeszedł!")
        except ExchangeError:
            pass
    try:
        cd.settle_sell("ff" * 32, "PLN", "x")
        raise AssertionError("cudzy/niemający txid przyjęty")
    except ExchangeError:
        pass
    alien = Identity.generate("alien_ala")
    ax = Tx.build_signed(TX_TRANSFER, user, alien.wallet, 1, nonce=L.nonce_of(user.wallet))
    L.add_tx(ax)
    tmpl = L.block_template(desk.wallet, zbits=2)
    won = mine(tmpl, max_tries=300_000)
    assert won
    L.apply_block(won)
    try:
        cd.settle_sell(ax.txid(), "PLN", "x")
        raise AssertionError("transfer NIE-do-desku zaksięgowany jako sprzedaż!")
    except ExchangeError:
        pass
    print(f"[OK] 7. sprzedaż E2E: {sell_amt/ISKRA} FNX → {srec['amount_minor']/100:.2f} "
          f"PLN (bid {srec['rate_cents']}¢); replay/cudzy-txid/nie-do-desku/niepotwierdzona "
          f"= stój")

    # ---- 8. limity dzienne per kierunek (test 5 zużył już 1 buy usera tego dnia)
    for _ in range(MAX_TRADES_PER_WALLET_DAY - 1):
        cd.buy(user.wallet, 500, "PLN", "limit-test")
    try:
        cd.buy(user.wallet, 500, "PLN", "raz-za-długi-kiosk")
        raise AssertionError(f"{MAX_TRADES_PER_WALLET_DAY + 1}. kupno tego dnia przeszło")
    except ExchangeError:
        pass
    print(f"[OK] 8. limit {MAX_TRADES_PER_WALLET_DAY} buy/dzień/wallet trzyma "
          f"(razem z kupnem z kroku 5; sprzedaż ma osobny licznik — {srec['kind']} OK)")

    # ---- 9. inwariant no-mint Z KSIĘGOWANIEM: podaż = fundacja + kopanie − burn.
    # Handel (transfery kupna/sprzedaży) ani drzemie — dokopały je TYLKO bloki.
    extra_blocks = [b for b in L.chain if b.height > s0["height"]]
    minted_extra = len(extra_blocks) * BLOCK_REWARD
    burned_extra = sum(fee_split(t.amount)[0]
                       for b in extra_blocks for t in b.txs[1:] if t.sender)
    s1 = supply_stats(L)
    assert s1["supply"] == supply_after_fund + minted_extra - burned_extra, \
        "księgowanie podaży nie gra — gdzieś FNX się urodził znikąd!"
    print(f"[OK] 9. no-mint z księgowaniem: podaż = fundacja {supply_after_fund} "
          f"+ kopanie {minted_extra} − burn {burned_extra} = {s1['supply']} iskr "
          f"(handel: 0 nowych FNX)")

    print("\nSELFTEST: PASS ✅  app/fnx_coin.py — giełda FNX-COIN (D65): cena z faktów "
          "łańcucha (podaż/users/attesterzy/głosy/wysokość, int-only), kupno i sprzedaż "
          "E2E na prawdziwym Ledgerze, determinizm klonów bit-w-bit, fail-path bez "
          "obciążenia rail, replay-strażnicy, limity dzienne, inwariant no-mint")
