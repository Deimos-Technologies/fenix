# app/exchange.py — Własna giełda FNX: wpłaty PSC → kredyt on-chain (M-EX, D32)
"""
To jest desk wymiany Fenixa — NIE pełny orderbook (ten przychodzi z rankami
market-maker), tylko solidny portmonetka-wymiennik:

    WPŁATA: użytkownik kupuje PSC w kiosku (gotówka!) → podaje 16-cyfrowy PIN
    → gateway PSC (merchant) autoryzuje + realizuje voucher → MY liczymy to
    w FNX po kursie dnia (owner-oracle D30) minus opłaty (PSC 5% + desk 1%)
    → portfel użytkownika dostaje REALNĄ TRANSAKCJĘ on-chain od portfela giełdy
    (podpis kluczem giełdy, nonce z ledgera — dokładnie jak zwykły transfer).

    WYPŁATA FIATA: **NIE przez PSC** (Paysafecard jest cash-in only).
    Wypłaty: krypto (XMR/…) albo vouchery wyjściowe — osobna decyzja, ten plik
    tego nie implementuje i uczciwie o tym mówi w LEGAL_NOTICE.

HIGIENA (twarde, D32):
  * PIN PSC = gotówka w postaci tekstu: weryfikacja → realizacja → ZAPOMNIENIE.
    W rejestrze zostaje wyłącznie sha256(pin) jako proof-of-redemption.
  * Kurs z Podpisanego Owner-Oracle (D30; Ed25519): data, rate, waluty, sig.
    Wygasły/źle podpisany kurs = odmowa wymiany (żadnych „przybliżonych" cen).
  * Limity dzienne per wallet (anty-laundering pod progiem właściciela z ToS).

Selftest (bez argumentów): stub-gateway, pełny przelew na-prawdę w Ledgerze,
higiena PIN, ponowne użycie vouchera, limity, wygasły oracle, legalny stub API.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey   # noqa: E402

from chain.block import Tx, TX_TRANSFER, ISKRA               # noqa: E402
from chain.ledger import Ledger                              # noqa: E402
from core.identity import Identity                           # noqa: E402

LEGAL_NOTICE = (
    "Giełda FNX krypto⇄fiat i przyjmowanie PSC to usługa finansowa: operator "
    "musi mieć merchant account (Paysafe MID) i rejestr pod Anti-laundering/"
    "VASP. Desk NIE wypłaca fiat przez PSC (cash-in only). Szczegóły: D32 + ToS."
)

PSC_FEE_PCT = 5          # koszt operatora za PSC (D32, w ToS)
DESK_FEE_PCT = 1         # fee wymiany → skarbiec operatora (D32)
MAX_DEPOSITS_PER_WALLET_DAY = 5
MIN_DEPOSIT_MINOR = 500          # 5.00 jednostki waluty fiata
MAX_DEPOSIT_MINOR = 500_00       # 500.00
SUPPORTED_FIAT = ("PLN", "EUR", "USD")


class ExchangeError(Exception):
    """Błędna wpłata/kurs/limit — JEDEN typ, zero orakli (złodziej nie wie co)."""


# ---------------------------------------------------------------- oracle kursu (D30)
class RateOracle:
    """Kurs z owner-oracle: podpisany JSON {valid_until, usd_cents_per_fnx,
    fx_usd_per_fiat (milli-cents centów na 1 minor unit fiat), issued_at}; weryfikacja sig."""

    def __init__(self, owner_pub_b: bytes):
        self._pub = Ed25519PublicKey.from_public_bytes(owner_pub_b)

    def verify(self, doc_json: bytes) -> dict:
        try:
            outer = json.loads(doc_json)
            payload = json.dumps(outer["quote"], sort_keys=True,
                                 separators=(",", ":")).encode()
            self._pub.verify(bytes.fromhex(outer["sig"]), payload)
        except Exception:
            raise ExchangeError("oracle: podpis kursu nieważny (D30)") from None
        q = outer["quote"]
        if q.get("valid_until", 0) < time.time():
            raise ExchangeError("oracle: kurs wygasł — nie wymieniam na ślepo")
        if not all(isinstance(q.get(k), int) and q[k] > 0
                   for k in ("usd_cents_per_fnx", "valid_until")):
            raise ExchangeError("oracle: niekompletny/zły kurs")
        return q


def make_oracle_doc(owner: Identity, *, usd_cents_per_fnx: int,
                    valid_for_s: int = 86400,
                    fx_millicents: dict | None = None,
                    crypto_cents: dict | None = None) -> bytes:
    """Narzędzie operatora: podpisuje kurs (Ed25519 kluczem ownera master D14).
    crypto_cents: centy USD za CAŁĄ jednostkę krypto (np. {"XMR": 1650000} = $16 500)
    — swap XMR→FNX (D34) bierze kurs stąd, nie „z powietrza"."""
    q = {"v": 1, "issued_at": int(time.time()),
         "valid_until": int(time.time()) + valid_for_s,
         "usd_cents_per_fnx": usd_cents_per_fnx,
         # ile mili-cents USD kosztuje 1 minor jednostki fiat (PLN gr: ~25.3 = 0.253¢)
         "fx_millicents_usd_per_minor": fx_millicents or {"PLN": 25, "EUR": 108, "USD": 100}}
    if crypto_cents:
        q["crypto_cents_usd_per_whole"] = crypto_cents
    sig = owner.sign(json.dumps(q, sort_keys=True, separators=(",", ":")).encode())
    return json.dumps({"quote": q, "sig": sig.hex()}).encode()


# ---------------------------------------------------------------- voucher PSC
def validate_psc_pin(pin: str) -> str:
    """16 cyfr (grupy po 4 z myślnikami dopuszczalne). Zwraca kanoniczny PIN."""
    digits = pin.replace("-", "").replace(" ", "")
    if not (digits.isdigit() and len(digits) == 16):
        raise ExchangeError("PSC: PIN to 16 cyfr (xxxx-xxxx-xxxx-xxxx)")
    return digits


def pin_proof(pin_digits: str) -> str:
    """WYŁĄCZNIE hash — proof-of-redemption. PIN sam w sobie NIGDY nie jest zapisany."""
    return hashlib.sha256(f"fnx-psc:{pin_digits}".encode()).hexdigest()


class PscGateway:
    """Interfejs operatora PSC. Prawdziwe wdrożenie = Paysafe merchant API (MID).
    Kontrakt: check(pin) → {status: unused|used|blocked, amount_minor, currency}
             redeem(pin) → committed=True albo wyjątek."""

    def check(self, pin_digits: str) -> dict:
        raise NotImplementedError

    def redeem(self, pin_digits: str) -> bool:
        raise NotImplementedError


class PaysafeGateway(PscGateway):
    """PRODUKCJA: HTTPS api.paysafecard.com, MID+klucz API operatora.
    UWAGA: to wymaga KONTRAKTU z Paysafe (KYC operatora) — zadanie poza kodem (D32).
    Tudelenie 'że działa bez kontraktu' byłoby fałszywą obietnicą — stąd wyjątek."""

    def __init__(self, mid: str | None = None, api_key: str | None = None):
        self.mid, self.api_key = mid, api_key

    def check(self, pin_digits: str) -> dict:
        raise NotImplementedError(
            "PaysafeGateway: potrzebny kontrakt merchantski (MID+API key) — D32 §prawo")


class StubPscGateway(PscGateway):
    """TESTY: wirtualna kasa z voucherami o znanych PIN-ach."""

    def __init__(self, vouchers: dict[str, dict]):
        # {"1111000022223333": {"amount_minor": 1000, "currency": "PLN"}}
        self._v = {k: dict(v, status="unused") for k, v in vouchers.items()}

    def check(self, pin_digits: str) -> dict:
        v = self._v.get(pin_digits)
        if v is None:
            raise ExchangeError("PSC: nieznany/aktywowany gdzie indziej kod")
        return v

    def redeem(self, pin_digits: str) -> bool:
        v = self._v.get(pin_digits)
        if v is None or v["status"] != "unused":
            raise ExchangeError("PSC: kod zużyty/niedostępny do realizacji")
        v["status"] = "used"
        return True


# ---------------------------------------------------------------- desk wymiany
class ExchangeDesk:
    """Portmonetka-wymiennik: oracle + ledger + portfel giełdy + gateway PSC."""

    def __init__(self, desk_identity: Identity, ledger: Ledger,
                 oracle: RateOracle, gateway: PscGateway,
                 fiat: str = "PLN"):
        if fiat not in SUPPORTED_FIAT:
            raise ExchangeError(f"fiat nieobsługiwany (mamy: {SUPPORTED_FIAT})")
        self.idn = desk_identity      # klucz giełdy (podpisuje tx kredytowe)
        self.ledger = ledger
        self.oracle = oracle
        self.gateway = gateway
        self.fiat = fiat
        self.receipts: list[dict] = []          # proof-of-redemption + txid (ZERO PIN)
        self._daily: dict[tuple, int] = {}       # (wallet, day) → liczba wpłat

    def _check_limit(self, wallet: str, day: int) -> None:
        used = self._daily.get((wallet, day), 0)
        if used >= MAX_DEPOSITS_PER_WALLET_DAY:
            raise ExchangeError(f"limit {MAX_DEPOSITS_PER_WALLET_DAY} wpłat/dzień/wallet (D32)")

    def quote(self, amount_minor: int, oracle_doc: bytes) -> dict:
        """Ile FNX (iskry) dostanę za amount_minor PLN → do pokazania PRZED PSC."""
        if not (MIN_DEPOSIT_MINOR <= amount_minor <= MAX_DEPOSIT_MINOR):
            raise ExchangeError(f"kwota poza oknem {MIN_DEPOSIT_MINOR/100:.2f}–"
                                f"{MAX_DEPOSIT_MINOR/100:.2f} {self.fiat}")
        q = self.oracle.verify(oracle_doc)
        fx_mc = q["fx_millicents_usd_per_minor"].get(self.fiat)
        if not isinstance(fx_mc, int) or fx_mc <= 0:
            raise ExchangeError(f"oracle nie podaje kursu {self.fiat}/USD")
        fee_mul = (100 - PSC_FEE_PCT - DESK_FEE_PCT)          # 94%
        iskry = (amount_minor * fx_mc * 10**8 * fee_mul) \
            // (q["usd_cents_per_fnx"] * 1000 * 100)
        return {"iskry": iskry, "fnx": iskry / ISKRA,
                "rate_cents_per_fnx": q["usd_cents_per_fnx"],
                "fees_pct": PSC_FEE_PCT + DESK_FEE_PCT, "fiat": self.fiat}

    def deposit_psc(self, user_wallet: str, pin: str, amount_minor: int,
                    oracle_doc: bytes) -> dict:
        """Pełny flow: PSC → kredyt on-chain do user_wallet."""
        pin_digits = validate_psc_pin(pin)
        proof = pin_proof(pin_digits)               # WYŁĄCZNIE hash zostaje w pamięci
        quote = self.quote(amount_minor, oracle_doc)
        day = int(time.time()) // 86400
        self._check_limit(user_wallet, day)
        try:
            info = self.gateway.check(pin_digits)
            if info["status"] != "unused":
                raise ExchangeError("PSC: kod już zużyty/zablokowany")
            if info["amount_minor"] != amount_minor or info["currency"] != self.fiat:
                raise ExchangeError("PSC: kod nie zgadza się z deklaracją kwoty/waluty")
            if not self.gateway.redeem(pin_digits):
                raise ExchangeError("PSC: realizacja odrzucona (merchant)")
        finally:
            pin, pin_digits = "", ""                # best-effort zapomnij ASAP
        # KREDYT ON-CHAIN: prawdziwa tx z portfela giełdy → użytkownika.
        # Nonce = chain + moje tx-y w mempoolu (Ethereum-model; ledger liczy to samo).
        nonce = self.ledger.nonce_of(self.idn.wallet) + \
            sum(1 for t in self.ledger.mempool if t.sender == self.idn.wallet)
        tx = Tx.build_signed(TX_TRANSFER, self.idn, user_wallet,
                             quote["iskry"], nonce=nonce)
        self.ledger.add_tx(tx)                       # mempool noda; kopanie księguje
        self._daily[(user_wallet, day)] = self._daily.get((user_wallet, day), 0) + 1
        rec = {"kind": "psc_deposit", "fiat": self.fiat,
               "amount_minor": amount_minor, "wallet": user_wallet,
               "iskry": quote["iskry"], "txid": tx.txid(), "proof": proof,
               "day": day}
        self.receipts.append(rec)
        return rec


# ---------------------------------------------------------------- selftest
if __name__ == "__main__":
    print("app/exchange.py — selftest: PSC→on-chain, higiena PIN, limity, oracle, stub→API\n")
    import secrets as _s

    owner = Identity.generate("owner_master")
    desk_idn = Identity.generate("fenix_desk")
    user = Identity.generate("klient_ela")
    TRE = "FNX1" + "0" * 32
    L = Ledger(TRE)

    # zasil desk czymś realnym: blok z coinbase dla giełdy (szablon + 'kopanie')
    tmpl = L.block_template(desk_idn.wallet, zbits=4)
    from chain.miner import mine
    won = mine(tmpl, max_tries=500_000)
    assert won
    L.apply_block(won)
    assert L.balance_of(desk_idn.wallet) > 0

    oracle = RateOracle(owner.sig_pub_b)
    doc = make_oracle_doc(owner, usd_cents_per_fnx=100,    # 1 FNX = 1.00 USD
                          fx_millicents={"PLN": 25, "EUR": 108, "USD": 100})

    pin_ok = "1111-2222-3333-4444"
    gw = StubPscGateway({pin_ok.replace("-", ""): {"amount_minor": 1000, "currency": "PLN"}})
    desk = ExchangeDesk(desk_idn, L, oracle, gw, fiat="PLN")

    # 1) wycena: 10.00 PLN → fee 6% brutto (5+1); 1 PLN = 0.25¢; 1 FNX = $1
    qt = desk.quote(1000, doc)
    exp = (1000 * 25 * 10**8 * 94) // (100 * 1000 * 100)
    assert qt["iskry"] == exp and qt["fees_pct"] == 6
    print(f"  [OK] 1. quote: 10.00 PLN → {qt['fnx']:.8f} FNX (fee {qt['fees_pct']}%)")

    # 2) pełny depozyt: kod PSC → tx w mempool, hash dowodu, ZERO PIN-a w rekordzie
    rec = desk.deposit_psc(user.wallet, pin_ok, 1000, doc)
    assert rec["proof"] == pin_proof(pin_ok.replace("-", ""))
    blob = json.dumps(rec)
    assert pin_ok not in blob and pin_ok.replace("-", "") not in blob, "PIN w rekordzie!!"
    assert any(t.txid() == rec["txid"] for t in L.mempool)
    tx = next(t for t in L.mempool if t.txid() == rec["txid"])
    assert tx.sender == desk_idn.wallet and tx.recipient == user.wallet
    assert tx.verify_signature(), "tx kredytowa podpisana kluczem giełdy"
    print(f"  [OK] 2. deposit: tx on-chain (mempool), proof=sha256(pin), PIN ≢ rekord")

    # 3) powtórka tego samego vouchera (zużyty) → odmowa
    try:
        desk.deposit_psc(user.wallet, pin_ok, 1000, doc)
        raise SystemExit("zużyty voucher przeszedł!")
    except ExchangeError:
        print("  [OK] 3. zużyty PSC → odmowa (status used, bez frazy-orakla)")

    # 4) higiena rejestru: nigdzie pełnego PIN, nawet po błędach
    try:
        desk.deposit_psc(user.wallet, "9999-8888-7777-6666", 1000, doc)
    except ExchangeError:
        pass
    full = json.dumps(desk.receipts)
    assert "9999888877776666" not in full and pin_ok.replace("-", "") not in full
    print("  [OK] 4. rejestr: nawet odrzucone PIN-y nie zostawiają śladu (gotówka ≠ dane)")

    # 5) limit dzienny per wallet (D32)
    pins = {f"{1000+i:04d}000000000000".replace("-", ""): {"amount_minor": 1000,
            "currency": "PLN"} for i in range(8)}
    gw2 = StubPscGateway(pins)
    desk2 = ExchangeDesk(desk_idn, L, oracle, gw2, fiat="PLN")
    ok = 0
    for p in pins:
        try:
            desk2.deposit_psc(user.wallet, p, 1000, doc)
            ok += 1
        except ExchangeError:
            pass
    assert ok == MAX_DEPOSITS_PER_WALLET_DAY, f"limit {ok}"
    print(f"  [OK] 5. limit: przeszło dokładnie {ok}={MAX_DEPOSITS_PER_WALLET_DAY} wpłat/dzień")

    # 6) wygasły/źle podpisany oracle → odmowa (ceny 'na oko' nie istnieją)
    stale = make_oracle_doc(owner, usd_cents_per_fnx=100, valid_for_s=-10)
    try:
        desk.quote(1000, stale)
        raise SystemExit("wygasły kurs aktywny!")
    except ExchangeError:
        pass
    intruder = Identity.generate("kruszwil")
    fake = make_oracle_doc(intruder, usd_cents_per_fnx=1)
    try:
        desk.quote(1000, fake)
        raise SystemExit("cudzy podpis kursu zaakceptowany!")
    except ExchangeError:
        print("  [OK] 6. wygasły + cudzy oracle → odmowa (kurs TYLKO od ownera, D30)")

    # 7) produkcyjny gateway: uczciwy stub — bez kontraktu NIE tłumaczy sukcesu
    try:
        PaysafeGateway().check("0" * 16)
        raise SystemExit("PaysafeGateway udawał działanie!")
    except NotImplementedError as e:
        assert "MID" in str(e)
        print("  [OK] 7. PaysafeGateway: uczciwy NotImplementedError dopóki brak MID (D32)")

    print("\nSELFTEST: PASS ✅  giełda: PSC→on-chain działa; higiena i limity twarde")
