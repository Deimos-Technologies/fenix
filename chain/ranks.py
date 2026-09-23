# chain/ranks.py — RANGI ON-CHAIN: TX_RANK_UP 0x14 (D16/D28: ranga NIE jest samo-edytowalna)
"""
Zasada systemu (D28): user może edytować username+avatar, ALE rangi nie — „śćiernij
sfotoszopa". Ranga musi pochodzić z KONSENSUSU, inaczej każdy sobie nada fenixa.
Dotychczas ranga żyła tylko w core/identity (lokalna etykieta). Ten moduł daje jej
życie na-chain: wallet PŁACI i po 6 potwierdzeniach ranga jest PUBLICZNIE JEGO.

Model (analogia: kupno legitymacji w okienku — kasa idzie do spółdzielni, legitymacja
ważna po odbiorze, nie przy szybie):
    TX_RANK_UP (0x14) — podpisany tx konta; payload {"v":1,"rank":"vip","tier":1}?
    NIE — tier wyprowadzamy z samej nazwy (RANKS z core.identity = jedno źródło
    prawdy; druga kolumna w payloadzie = okazja do rozjazdu). Payload: {"v":1,"rank":"vip"}.
      BUYABLE: donor/vip/vip+/svip/elite. ghost = start darmowy (bez tx).
      selite/fenix = SYSTEMOWE (owner/konsensus) — TX ich NIGDY nie nadaje
      (strażnik: nawet z podpisem walleta odrzut; zastrzeżenie D16/D28).
      UPGRADE = dopłata RÓŻNICY (TODO §RANGI): nowa musi być DROŻSZA niż aktualna;
      DOWNGRADE i remis (ta sama) = odrzut (system nie baluje w wycofywanie).
      AKTYWACJA PO 6 POTWIERDZENIACH (spec): zapis {rank, height, until}; aktywna gdy
      tip.height ≥ height + 6 — do tego czasu GUI pokazuje „oczekuje (x/6)".
      ✶ WYGASANIE 30 DNI (decyzja właściciela 2026-08-06, D51): ranga jest jak
      legitymacja miesięczna — kasa pobrana raz, ważność = 30 dni od BLOKU zakupu
      (until = block.timestamp + 30d). Po terminie konsensus znów widzi ghost:
      nie kasujemy wpisu (historia zostaje), po prostu active_rank ją ignoruje.
      RENEW: kupno TEJ SAMEJ rangi jeszcze za życia = przedłużenie o 30 dni za
      pełną cenę (stos ważności max 60 dni — nie gromadzimy „lat vip-a" z góry).
      Wygasła → kupno od nowa za pełną cenę (wygasła ranga = cena bazowa 0).
      Determinizm: czas bierzemy z timestampu BLOKU (konsensus), nie z zegara
      systemowego — każdy nod liczy ważność identycznie, bit-w-bit.
      PRYWATNOŚĆ uczciwie: kupno jest na razie JAWNE (tip ze spec: kupuj ze świeżego
      walletu; kupno z mgły = RANK_UP płacony UNSHIELD-em = backlog).

Ekonomia: amount = CENA globa (min. dopłata różnicy). Split jak ID_DECLARE (fee
    D15: burn + skarbiec; kopacz NIE dostaje — legitymacja to usługa rejestru,
    nie praca potwierdzania). PROPORCJA 50/50 burn-skarbiec = NADAL otwarta decyzja
    właściciela (TODO §RANGI) — tu trzymamy standard D15 spójnie.

Ceny: ⚠️ ROBOCZE (tabela do decyzji przy emisji §12/P5; wyraźnie oznaczone!).
Rejestr: ranks {wallet: {"rank": str, "height": int}}. Replay/adopt bit-w-bit.
"""
from __future__ import annotations

import json
import sys
import time
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from chain.block import ISKRA                          # noqa: E402
from core.identity import RANKS, rank_tier             # noqa: E402

RANK_ACTIVATION_CONFS = 6            # potwierdzeń do aktywności (spec §RANGI)
RANK_TTL_S = 30 * 86400              # D51 (decyzja właściciela): ranga wygasa po 30 dniach
RANK_MAX_STOCK_S = 2 * RANK_TTL_S    # renew: stos ważności max 60 dni — bez odkładania lat
RANK_PRICE = {                       # ⚠️ ROBOCZE (decyzja §12/P5): iskry za rangę
    "donor": 1 * ISKRA,
    "vip": 5 * ISKRA,
    "vip+": 10 * ISKRA,
    "svip": 25 * ISKRA,
    "elite": 60 * ISKRA,
}
BUYABLE = tuple(RANK_PRICE)          # ghost = start; selite/fenix = systemowe (NIE z TX)


class RankError(Exception):
    """Naruszenie rejestru rang — jeden typ."""


def rank_payload(rank: str) -> str:
    if rank not in RANKS:
        raise RankError(f"nieznana ranga: {rank!r}")
    return json.dumps({"v": 1, "rank": rank}, separators=(",", ":"), sort_keys=True)


def parse_rank_payload(raw: str) -> dict:
    try:
        p = json.loads(raw)
    except (ValueError, TypeError):
        raise RankError("payload: niepoprawny JSON") from None
    if not isinstance(p, dict) or p.get("v") != 1:
        raise RankError("payload: brak v=1")
    return p


def _entry_active(ent: dict | None, now_ts: int) -> bool:
    """Wpis żyje CZASOWO? until=None = stary zapis (legacy = bez terminu)."""
    if not ent:
        return False
    until = ent.get("until")
    return until is None or now_ts < until


def validate_rank_payload(raw: str, ranks: dict, sender_wallet: str,
                          now_ts: int | None = None) -> tuple[str, int, bool]:
    """Walidacja konsensusu. ranks: {wallet: {"rank","height","until"}} (chain ∪ mempool).
    now_ts: mempool → zegar lokalny; blok → b.timestamp (determinizm!). Zwraca
    (rank, amount_required, renew). D51: wygasła ranga NIE obniża ceny bazowej
    (cur_price=0), RENEW żywej = pełna cena i +30 dni do stosu."""
    now_ts = int(time.time()) if now_ts is None else int(now_ts)
    rank = parse_rank_payload(raw).get("rank")
    if not isinstance(rank, str) or rank not in RANKS:
        raise RankError("rank poza tabelą core.identity (jedno źródło prawdy)")
    if rank == "ghost":
        raise RankError("ghost jest darmowy od startu — nie kupuje się go")
    if rank not in BUYABLE:
        raise RankError(f"ranga '{rank}' jest SYSTEMOWA (selite/fenix) — TX jej nie nada (D16)")
    cur = ranks.get(sender_wallet)
    cur_live = _entry_active(cur, now_ts)
    if cur and cur_live and rank == cur["rank"]:
        return rank, RANK_PRICE[rank], True     # RENEW: pełna cena, dokłada 30 dni (D51)
    cur_price = RANK_PRICE.get(cur["rank"], 0) if (cur and cur_live) else 0
    new_price = RANK_PRICE[rank]
    if new_price <= cur_price:
        raise RankError(
            f"'{rank}' ({new_price}) nie jest wyższa niż aktualna '{cur['rank']}' "
            f"({cur_price}) — upgrade = dopłata różnicy, downgrade/remis = odrzut")
    return rank, new_price - cur_price, False   # UPGRADE = dopłata RÓŻNICY (spec)


def apply_rank(ranks: dict, rank: str, height: int, sender_wallet: str,
               ts: int, renew: bool = False) -> None:
    """Mutacja roboczego rejestru (walidacja MUSI przejść wcześniej).
    ts = timestamp BLOKU (konsensus liczy ważność z łańcucha, nie z zegara)."""
    ent = ranks.get(sender_wallet)
    if renew and _entry_active(ent, ts):        # przedłużenie: ranga zostaje, until rośnie
        ent["until"] = min(ent["until"] + RANK_TTL_S, int(ts) + RANK_MAX_STOCK_S)
        return                                  # height bez zmian — renew NIE resetuje 6 confs
    ranks[sender_wallet] = {"rank": rank, "height": int(height),
                            "until": int(ts) + RANK_TTL_S}


def active_rank(ranks: dict, tip_height: int, wallet: str,
                now_ts: int | None = None) -> str:
    """Ranga AKTYWNA walletowi (po 6 potwierdzeniach — blok zakupu + 5 następnych
    na szczycie, jak w standardzie „N confs"; spójne z pending_rank).
    D51: po terminie (until ≤ czas) konsensus znów widzi ghost. W konsensusie
    wołaj z now_ts=timestamp tipa — nie z zegara (determinizm bit-w-bit)."""
    ent = ranks.get(wallet)
    if not ent or tip_height < ent["height"] + RANK_ACTIVATION_CONFS - 1:
        return "ghost"
    if not _entry_active(ent, int(time.time()) if now_ts is None else int(now_ts)):
        return "ghost"
    return ent["rank"]


def rank_time_left(ranks: dict, tip_height: int, wallet: str,
                   now_ts: int | None = None) -> int | None:
    """Sekund ważności do końca (GUI: „wygasa za N dni"); None gdy brak rangi aktywnej."""
    if active_rank(ranks, tip_height, wallet, now_ts) == "ghost":
        return None
    ent = ranks[wallet]
    if ent.get("until") is None:
        return None                             # legacy bez terminu
    now = int(time.time()) if now_ts is None else int(now_ts)
    return max(0, ent["until"] - now)


def pending_rank(ranks: dict, tip_height: int, wallet: str) -> tuple[str, int] | None:
    """(rank, ile_confs_już) — ranga oczekująca na 6 potwierdzeń; None gdy brak/gotowa."""
    ent = ranks.get(wallet)
    if not ent:
        return None
    confs = tip_height - ent["height"] + 1
    if confs >= RANK_ACTIVATION_CONFS:
        return None
    return ent["rank"], max(1, confs)


# -------------------------------------------------------------------------- selftest E2E
if __name__ == "__main__":
    from core.identity import Identity
    from chain.block import (Tx, TREASURY_WALLET_DEV, TX_RANK_UP, TX_TRANSFER)
    from chain.ledger import Ledger, BLOCK_REWARD, ChainError
    from chain.miner import mine

    print("chain/ranks.py — selftest E2E: ranga z konsensusu, nie z fotoszopa (D28)\n")
    TRE = TREASURY_WALLET_DEV
    L = Ledger(TRE)
    ala, bob = (Identity.generate(n) for n in ("ala_rank", "bob_rank"))

    def kop(tag: str):
        tmpl = L.block_template(bob.wallet, zbits=2)     # kopie bob (ala płaci z salda)
        won = mine(tmpl, max_tries=200_000)
        assert won is not None, f"mining nie trafił ({tag})"
        L.apply_block(won)

    # 1) funding ali (2 topnie z rzędu przez alię? bob kopie; sponsor = przelew)
    for _ in range(10):
        kop("funding-bob")
    t0 = Tx.build_signed(TX_TRANSFER, bob, ala.wallet, 40 * ISKRA, nonce=0)
    L.add_tx(t0)
    kop("fund-ala")

    # 2) systemowe odrzucone; ghost odrzucony; nieznana odrzucona
    for r in ("fenix", "selite", "ghost", "vip++"):
        try:
            L.add_tx(Tx.build_signed(TX_RANK_UP, ala, "FNX-RANKS", ISKRA, nonce=0,
                                     payload=rank_payload(r)))
            if r == "vip++":
                raise SystemExit("rank_payload wpisał nieznaną — validator zje?")
            raise SystemExit(f"ranga '{r}' przeszła z TX!")
        except ChainError:
            pass
        except RankError:
            pass
    print("  [OK] 1. funding + strażnik: fenix/selite/ghost z TX odrzucone (systemowe)")

    # 3) ala kupuje VIP za 5 FNX (top) → oczekuje 6 confs → aktywna
    assert active_rank(L.ranks, L.height(), ala.wallet) == "ghost"
    t1 = Tx.build_signed(TX_RANK_UP, ala, "FNX-RANKS", RANK_PRICE["vip"], nonce=0,
                         payload=rank_payload("vip"))
    L.add_tx(t1)
    kop("buy-vip")
    assert L.ranks[ala.wallet]["rank"] == "vip"
    assert active_rank(L.ranks, L.height(), ala.wallet) == "ghost", "vip aktywny ZA WCZEŚNIE"
    pend = pending_rank(L.ranks, L.height(), ala.wallet)
    assert pend and pend[0] == "vip", "brak statusu oczekującego"
    for _ in range(RANK_ACTIVATION_CONFS - 1):
        kop("conf")
    assert active_rank(L.ranks, L.height(), ala.wallet) == "vip", \
        f"vip nieaktywny po {RANK_ACTIVATION_CONFS} confs (Pending={pending_rank(L.ranks, L.height(), ala.wallet)})"
    assert pending_rank(L.ranks, L.height(), ala.wallet) is None
    print(f"  [OK] 2. VIP: zapis od razu, AKTYWNA po {RANK_ACTIVATION_CONFS} potwierdzeniach "
          f"(okienko pending {pend[1]}/6)")

    # 4) RENEW (D51): ta sama ŻYWA ranga = przedłużenie o 30 dni za PEŁNĄ cenę
    nonce = L.nonce_of(ala.wallet)
    until0 = L.ranks[ala.wallet]["until"]
    try:
        L.add_tx(Tx.build_signed(TX_RANK_UP, ala, "FNX-RANKS", RANK_PRICE["vip"] - 1,
                                 nonce=nonce, payload=rank_payload("vip")))
        raise SystemExit("zaniżone przedłużenie przeszło!")
    except ChainError as e:
        assert "pełna cena" in str(e), str(e)
    L.add_tx(Tx.build_signed(TX_RANK_UP, ala, "FNX-RANKS", RANK_PRICE["vip"],
                             nonce=nonce, payload=rank_payload("vip")))
    kop("renew-vip")
    nu = L.ranks[ala.wallet]["until"]
    assert nu > until0, f"renew nie wydłużył ważności ({until0} → {nu})"
    assert L.ranks[ala.wallet]["rank"] == "vip" and L.ranks[ala.wallet]["height"] > 0
    print("  [OK] 3. RENEW (D51): ta sama ranga = pełna cena; ważność +30 dni; zaniżona odrzucona")

    # 4b) downgrade żywej rangi → odrzut; zaniżona dopłata UPGRADE → odrzut
    nonce = L.nonce_of(ala.wallet)
    try:
        L.add_tx(Tx.build_signed(TX_RANK_UP, ala, "FNX-RANKS", RANK_PRICE["donor"],
                                 nonce=nonce, payload=rank_payload("donor")))
        raise SystemExit("downgrade rangi przeszedł!")
    except ChainError as e:
        assert "nie jest wyższa" in str(e)
    due = RANK_PRICE["svip"] - RANK_PRICE["vip"]
    try:
        L.add_tx(Tx.build_signed(TX_RANK_UP, ala, "FNX-RANKS", due - 1, nonce=nonce,
                                 payload=rank_payload("svip")))
        raise SystemExit("zaniżona dopłata różnicy przeszła!")
    except ChainError as e:
        assert "amount" in str(e) or "fee" in str(e) or "dopłata" in str(e), str(e)
    L.add_tx(Tx.build_signed(TX_RANK_UP, ala, "FNX-RANKS", due, nonce=nonce,
                             payload=rank_payload("svip")))
    kop("up-svip")
    for _ in range(RANK_ACTIVATION_CONFS):
        kop("conf2")
    assert active_rank(L.ranks, L.height(), ala.wallet) == "svip"
    print("  [OK] 4. upgrade vip→svip = dopłata różnicy 20 FNX; downgrade/zaniżona odrzucone")

    # 5) skarbiec rośnie z ranków (split D15 jak ID_DECLARE); replay bit-w-bit
    tre = L.balance_of(TRE)
    assert tre > 0, "skarbiec powinien zebrać fee z ranków"
    L2 = Ledger(TRE)
    for b in L.chain[1:]:
        L2.apply_block(b)
    assert L2.ranks == L.ranks, "replay ≠ stan rang"
    assert active_rank(L2.ranks, L2.height(), ala.wallet) == "svip"
    print("  [OK] 5. skarbiec z fee ranków (D39-spójne); replay odtwarza rejestr (until też)")

    # 6) WYGASANIE 30 DNI (D51): po terminie konsensus widzi ghost; po wygaśnięciu
    #    kupno od nowa = pełna cena; downgrade po wygaśnięciu DROGIEJ = legalny;
    #    stos renew ma kapturek 60 dni; renew NIE resetuje 6 confs
    ts0 = 1_700_000_000
    scr: dict = {}
    rank_w, amt_w, renew_w = validate_rank_payload(rank_payload("vip"), scr, "W", now_ts=ts0)
    assert (rank_w, amt_w, renew_w) == ("vip", RANK_PRICE["vip"], False)
    apply_rank(scr, "vip", 10, "W", ts0)
    assert active_rank(scr, 10 + RANK_ACTIVATION_CONFS, "W", now_ts=ts0 + 1000) == "vip"
    left = rank_time_left(scr, 10 + RANK_ACTIVATION_CONFS, "W", now_ts=ts0 + 1000)
    assert left == RANK_TTL_S - 1000, left
    _, amt_r, renew_r = validate_rank_payload(rank_payload("vip"), scr, "W", now_ts=ts0 + 1000)
    assert renew_r and amt_r == RANK_PRICE["vip"], "renew żywej rangi ≠ pełna cena"
    h0 = scr["W"]["height"]
    apply_rank(scr, "vip", 11, "W", ts0 + 1000, renew=True)
    assert scr["W"]["until"] == ts0 + 2 * RANK_TTL_S and scr["W"]["height"] == h0, \
        "renew zmienił height (reset confs) albo źle podbił until"
    apply_rank(scr, "vip", 12, "W", ts0 + 2000, renew=True)
    assert scr["W"]["until"] == ts0 + 2000 + RANK_MAX_STOCK_S, "stos renew bez kapturka 60d!"
    past_due = scr["W"]["until"] + 1
    assert active_rank(scr, 99, "W", now_ts=past_due) == "ghost", "wygasła ranga dalej świeci"
    assert rank_time_left(scr, 99, "W", now_ts=past_due) is None
    _, amt_e, renew_e = validate_rank_payload(rank_payload("vip"), scr, "W", now_ts=past_due)
    assert not renew_e and amt_e == RANK_PRICE["vip"], "po wygaśnięciu kupno ≠ pełna cena"
    _, amt_d, _ = validate_rank_payload(rank_payload("donor"), scr, "W", now_ts=past_due)
    assert amt_d == RANK_PRICE["donor"], "wygasła vip blokuje tańszą donor!"
    print("  [OK] 6. D51: ranga wygasa po 30d (konsensus z timestampu bloku); renew stos ≤60d\n"
          "           bez resetu 6 confs; po wygaśnięciu re-buy pełna cena, downgrade legalny")

    print("\nSELFTEST: PASS ✅  chain/ranks.py — ranga z konsensusu (TX_RANK_UP):\n"
          "systemowe niedostępne, upgrade=dopłata różnicy, aktywacja po 6 confs,\n"
          "WYGASANIE 30 dni + renew (D51, decyzja właściciela), replay czysty")
