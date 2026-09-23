# chain/donate.py — DONATE DO SKARBCA OWNERA: TX_DONATE 0x14 (D50)
"""
Zasada systemu (decyzja właściciela 2026-08-06): użytkownik może z własnej woli
zasilić skarbiec ownera DOWOLNĄ kwotą — sam wybiera ile. To nie fee, nie podatek,
nie „ranga": czysty, dobrowolny datek. Jak rzucenie banknotu do skarbonki przy
okienku — tyle ile chcesz, kiedy chcesz, zero razy też jest OK.

Model (analogia: skarbonka z wąskim otworem — wchodzi wszystko, wychodzi nic;
klucz do skarbonki ma TYLKO owner, bo wpłata idzie wprost na JEGO skarbiec):
    TX_DONATE (0x14) — podpisany tx konta, identyczny mechanicznie jak TRANSFER,
    ale z TRZEMA twardymi regułami konsensusu:
      1) recipient MUSI być skarbcem tego noda (ledger.treasury) — datek do
         „kogoś innego" to zwykły TX_TRANSFER, nie TX_DONATE (nie oszukujemy
         odznak: donate = wsparcie ownera, i kropka);
      2) amount DOWOLNE ≥ 1 iskry (użytkownik wybiera — żadnych progów wejścia);
      3) CAŁY amount ląduje w skarbcu ownera + część ownerska fee też do
         skarbca (jak usługi rejestru D39 — kopacz z donate nie zarabia;
         dzięki temu „100% dla ownera" jest prawdą, nie marketingiem).
    Payload OPCJONALNY: {"v":1,"note":"..."} — JAWNA karteczka ≤140 znaków
    (publiczna na zawsze! GUI ostrzega: nie wpisuj nic prywatnego).

Po co to rejestrować? ledger.donations {wallet: suma_iskier} — kumulatywny licznik
darczyństwa, napędza odznaki DONOR I/II/III (chain/badges.py, D52). Rejestr jest
deterministyczny z bloków (replay/adopt bit-w-bit), więc odznaka donor to FAKT
z konsensusu, nie samozwańczy sticker.

Prywatność uczciwie: donate jest JAWNE (nadawca + kwota + skarbiec na łańcuchu).
Wersję „z mgły" (donate przez TX_RING → skarbiec-pool) zostawiamy backlogowi —
skarbiec na razie siedzi w warstwie jawnej (fnx_spec §12/P5).
"""
from __future__ import annotations

import json
import sys
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

DONATE_MIN_ISKRY = 1               # użytkownik wybiera kwotę; próg = anty-zerowy spam
DONATE_NOTE_MAX = 140              # jawna karteczka (publiczna!) — twardy sufit znaków


class DonateError(Exception):
    """Naruszenie reguł datku — jeden typ (jak RankError/ContactRefError)."""


def donate_payload(note: str = "") -> str:
    """>>> GUI buduje karteczkę; pusta = brak payloadu wcale (najmniej śladu)."""
    if not note:
        return ""
    if not isinstance(note, str) or len(note) > DONATE_NOTE_MAX:
        raise DonateError(f"karteczka max {DONATE_NOTE_MAX} znaków (i tak jest JAWNA)")
    return json.dumps({"v": 1, "note": note}, separators=(",", ":"), sort_keys=True,
                      ensure_ascii=False)


def parse_donate_payload(raw: str) -> dict:
    """'' → {} (legalne); inaczej musi być {"v":1,...}; zła forma = odrzut konsensusu."""
    if raw == "":
        return {}
    try:
        p = json.loads(raw)
    except (ValueError, TypeError):
        raise DonateError("payload: niepoprawny JSON") from None
    if not isinstance(p, dict) or p.get("v") != 1:
        raise DonateError("payload: brak v=1")
    note = p.get("note", "")
    if not isinstance(note, str) or len(note) > DONATE_NOTE_MAX:
        raise DonateError(f"payload: note max {DONATE_NOTE_MAX} znaków")
    return p


def validate_donate(tx, treasury: str) -> dict:
    """Walidacja konsensusu (mempool + blok idą TYM SAMYM kodem).
    Zwraca sparsowany payload (karteczkę), przy poprawnym tx nigdy nie rzuca."""
    if tx.recipient != treasury:
        raise DonateError("recipient ≠ skarbiec ownera — datek komuś innemu to "
                          "zwykły TX_TRANSFER (D50: donate NIE udaje transferu)")
    if tx.amount < DONATE_MIN_ISKRY:
        raise DonateError("amount musi być ≥ 1 iskry (zerowy datek = spam rejestru)")
    return parse_donate_payload(tx.payload)


def apply_donate(donations: dict, sender_wallet: str, amount: int) -> None:
    """Kumulatywny licznik darczyństwa (napęd DONOR I/II/III w badges)."""
    donations[sender_wallet] = donations.get(sender_wallet, 0) + int(amount)


# -------------------------------------------------------------------------- selftest E2E
if __name__ == "__main__":
    import tempfile

    from chain.block import Tx, TX_DONATE, TX_TRANSFER, ISKRA, fee_split
    from chain.ledger import Ledger, ChainError
    from chain.miner import mine
    from core.identity import Identity

    print("chain/donate.py — selftest: TX_DONATE 0x14 do skarbca ownera (D50)\n")

    TREZ = "FNX1" + "a" * 32
    L = Ledger(TREZ)
    ala = Identity.generate("ala_don")
    bob = Identity.generate("bob_don")

    def kop(tag: str):
        t = L.block_template(ala.wallet, zbits=2)
        w = mine(t, max_tries=300_000)
        assert w is not None, f"kopanie padło: {tag}"
        L.apply_block(w)

    # fundusz: 2 bloki po 5 FNX dla ali (coinbase), fee zostawia resztę
    kop("A")
    kop("B")
    bal0 = L.balance_of(ala.wallet)
    trez0 = L.balance_of(TREZ)
    print(f"  [i] start: ala={bal0} iskier, skarbiec={trez0}")

    # 1) donate z KARTECZKĄ: kwota użytkownika (3 FNX + kapitał), cała do skarbca;
    #    licznik darczyństwa rośnie; fee ownerskie też do skarbca (D50: 100% ownerowi)
    kwota = 3 * ISKRA
    tx1 = Tx.build_signed(TX_DONATE, ala, TREZ, kwota, nonce=0,
                          payload=donate_payload("za świetny projekt!"))
    L.add_tx(tx1)
    kop("1")
    assert L.donations.get(ala.wallet) == kwota, L.donations
    _, owner_fee, fee_tot = fee_split(kwota)
    assert L.balance_of(TREZ) == trez0 + kwota + owner_fee, \
        "skarbiec ≠ +kwota+fee ownerskie (D50: 100% dla ownera)"
    assert L.balance_of(ala.wallet) == bal0 - kwota - fee_tot + 5 * ISKRA, \
        L.balance_of(ala.wallet)     # +5 FNX = nagroda bloku (fee donate→skarbiec, nie kopacz)
    print("  [OK] 1. TX_DONATE: kwota użytkownika CAŁA do skarbca (+fee ownerskie), "
          "licznik darczyństwa działa")

    # 2) donate do CUDZEGO walleta (nie skarbca) = odrzut — to ma być TX_TRANSFER
    try:
        L.add_tx(Tx.build_signed(TX_DONATE, ala, bob.wallet, ISKRA, nonce=1))
        raise SystemExit("donate do cudzego walleta przeszedł!")
    except ChainError as e:
        assert "TX_TRANSFER" in str(e), str(e)
    # 2b) zerowa kwota = spam rejestru = odrzut
    try:
        L.add_tx(Tx.build_signed(TX_DONATE, ala, TREZ, 0, nonce=1))
        raise SystemExit("zerowy donate przeszedł!")
    except ChainError as e:
        assert "≥ 1 iskry" in str(e), str(e)
    print("  [OK] 2. donate do NIE-skarbca odrzucony (to TX_TRANSFER); kwota 0 odrzucona")

    # 3) karteczka: za długa / zły JSON / zła wersja = odrzut; pusta = legalna
    for bad in (donate_payload("x" * 10), ):
        pass  # sama konstrukcja krótkiej karteczki jest OK — brak wyjątku
    for mk in (lambda: donate_payload("y" * 200),
               lambda: Tx.build_signed(TX_DONATE, ala, TREZ, ISKRA, nonce=1,
                                       payload="{nie-json")):
        try:
            r = mk()
            if isinstance(r, Tx):            # zły JSON leci dopiero do mempoola
                L.add_tx(r)
            raise SystemExit("wadliwa karteczka przeszła!")
        except (DonateError, ChainError):
            pass
    tx3 = Tx.build_signed(TX_DONATE, ala, TREZ, 5, nonce=1)     # payload = ""
    L.add_tx(tx3)
    kop("3")
    assert L.donations[ala.wallet] == kwota + 5
    print("  [OK] 3. karteczka >140 / zły JSON odrzucone; pusty payload legalny; "
          "kumulacja po drugim dacie OK")

    # 4) nonce/bilans jak przy TRANSFER: brak środków i zły nonce = odrzut
    try:
        L.add_tx(Tx.build_signed(TX_DONATE, bob, TREZ, 10 * ISKRA, nonce=0))
        raise SystemExit("donate bez środków przeszedł!")
    except ChainError as e:
        assert "środk" in str(e), str(e)
    print("  [OK] 4. brak środków = odrzut (pełna kontrola bilansu/nonce jak TRANSFER)")

    # 5) chain.dat: zrzut+odczyt = rejestr donations odbudowany bit-w-bit z bloków
    with tempfile.NamedTemporaryFile(suffix=".dat") as f:
        L.save_chain(f.name)
        L2 = Ledger.load_chain(f.name, treasury=TREZ)
        assert L2.donations == L.donations, "donations po load ≠ (replay zepsuty)"
        assert L2.balance_of(TREZ) == L.balance_of(TREZ)
    print("  [OK] 5. chain.dat: donations + skarbiec identyczne po pełnym replay")

    print("\nSELFTEST: PASS ✅  chain/donate.py — datek do skarbca ownera:\n"
          "kwota dowolna (użytkownika), 100% do skarbca, rejestr napędza DONOR (D52),\n"
          "cudzy recipient / zero / zła karteczka / brak środków = odrzut po polsku.")
