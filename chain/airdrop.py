# chain/airdrop.py — TX_AIRDROP 0x15: kamień milowy 1 000 000 użytkowników (D62)
"""
Analogia: jubileusz fabryki. Gdy dziennik rejestracji przekroczy MILION wpisów,
dyrekcja losuje z rejestru JEDNĄ osobę i wręcza jej premię — ale losowanie robi
nie dyrektor, tylko maszyna losująca napędzana hash poprzedniego bloku (nikt nie
przyłoży ręki do kul). Każdy węzeł liczy zwycięzcę identycznie — replay bit-w-bit.

Zasada konsensusu (TX_AIRDROP — zdarzenie SYSTEMOWE jak TX_BAN_EVT op=ban):
  • MILICJA prawdy: licznik = rejestr username on-chain (ID_DECLARE — żywa,
    jawna metryka „użytkownik-znany-po-nicku"; NIE liczy anonymousghost'ów —
    uczciwie opisane w raporcie),
  • kamień milowy = IEŁY zbiór {1 000 000} (⚠️ ROBOCZE — fnx_spec §12/P5:
    docelowo decyzja właściciela; pole do rozszerzenia na listę prógów),
  • przy PRZEKROCZENIU progu (count(names) >= próg) DOKŁADNIE JEDEN airdrop
    na kamień (drugi ten sam kamień = odrzut),
  • odbiorca + kwota (1..10 FNX) = deterministyczne z blake2s(prev‖milestone):
    idx = hash % len(sorted(names)); gdy wylosowany wallet jest ZBANOWANY —
    przesuwamy do następnego (tombstone wygrywa z loterią, D18),
  • sender/sig puste (moc dowodowa = matematyka kamienia, nie klucz),
  • skąd FNX: Z NICZEGO (emission-event; ⚠️ ROBOCZE §12 — docelowo: z
    skarbca albo z harmonogramu emisji; jawne w raporcie, nie skrywane).

Czego ten plik NIE robi (uczciwie):
  • NIE gwarantuje, że „1 000 000 username = 1 000 000 ludzi" — jeden człowiek
    może mieć N nicków (fee 1 FNX spowalnia sybila, nie kasuje go). To proxy,
    opisane wprost w docs + raporcie,
  • NIE daje nikomu władzy: nikt nie wybiera odbiorcy ani kwoty — wybiera
    blok poprzedni; kopacz może co najwyżej NIE włączyć zdarzenia (przejdzie
    przy następnym bloku innego kopacza).
"""
from __future__ import annotations

import hashlib
import sys
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from chain.block import ISKRA            # noqa: E402

MILESTONE_USERS = 1_000_000            # ⚠️ ROBOCZE (fnx_spec §12/P5 — decyzja właściciela)
AMT_MIN_FNX = 1
AMT_MAX_FNX = 10                       # losowe 1..10 FNX (zakres — spec właściciela)


class AirdropError(Exception):
    """Błędy kamienia milowego — jedna klasa, komunikaty po polsku."""


def milestone_due(names_count: int, fired: set[int], *,
                  milestone: int = MILESTONE_USERS) -> bool:
    """Czy blok może wystrzelić airdrop: próg osiągnięty i NIE odstrzelony wcześniej."""
    return names_count >= milestone and milestone not in fired


def pick_recipient(names: dict, bans: dict, prev_hash_hex: str, milestone: int) -> str | None:
    """Deterministyczny zwycięzca z rejestru username (sorted — wszystkie węzły
    liczą tę samą kolejność); zbanowany → następny w kolejce (wrap-around)."""
    keys = sorted(names.keys())
    if not keys:
        return None
    import chain.ban_evt as _be
    h = hashlib.blake2s(bytes.fromhex(prev_hash_hex) +
                        b":airdrop:" + milestone.to_bytes(8, "big")).digest()
    start = int.from_bytes(h, "big") % len(keys)
    for step in range(len(keys)):
        name = keys[(start + step) % len(keys)]
        wallet = names[name]
        if not _be.is_banned(bans, wallet):
            return wallet
    return None                                    # WSZYSCY zbanowani → brak zdarzenia


def pick_amount(prev_hash_hex: str, milestone: int) -> int:
    """Deterministyczna kwota 1..AMT_MAX FNX z drugiego skrośnięcia (inny label)."""
    h = hashlib.blake2s(bytes.fromhex(prev_hash_hex) +
                        b":airdrop-amt:" + milestone.to_bytes(8, "big")).digest()
    n = AMT_MIN_FNX + int.from_bytes(h[:4], "big") % (AMT_MAX_FNX - AMT_MIN_FNX + 1)
    return n * ISKRA


def airdrop_payload(milestone: int) -> str:
    from chain.block import canon
    return canon({"v": 1, "op": "airdrop", "milestone": milestone}).decode()


def parse_payload(raw: str) -> dict:
    import json
    try:
        p = json.loads(raw)
    except (ValueError, TypeError):
        raise AirdropError("payload: niepoprawny JSON") from None
    if not isinstance(p, dict) or p.get("v") != 1 or p.get("op") != "airdrop":
        raise AirdropError("payload: brak v=1/op=airdrop")
    m = p.get("milestone")
    if not isinstance(m, int) or isinstance(m, bool) or m <= 0:
        raise AirdropError("milestone ma być int > 0")
    return p


def validate_airdrop_tx(tx_amount: int, tx_recipient: str, raw: str,
                        names: dict, bans: dict, fired: set[int],
                        prev_hash_hex: str, *, milestone: int = MILESTONE_USERS) -> None:
    """Pełna walidacja konsensusowa zdarzenia (blok; szablon używa plan()).
    Rzuca AirdropError przy każdym odchyleniu od matematyki kamienia."""
    p = parse_payload(raw)
    if p["milestone"] != milestone:
        raise AirdropError(f"nieznany kamień milowy {p['milestone']} (ten hard-fork zna "
                           f"{milestone}; ⚠️ ROBOCZE §12)")
    if not milestone_due(len(names), fired, milestone=milestone):
        raise AirdropError(f"kamień {milestone}: próg nieosiągnięty (jest {len(names)}) "
                           "albo już odstrzelony — 1 zdarzenie / kamień")
    want_w = pick_recipient(names, bans, prev_hash_hex, milestone)
    if want_w is None:
        raise AirdropError("cały rejestr na tombstone — zdarzenie wstrzymane (D18)")
    if tx_recipient != want_w:
        raise AirdropError("odbiorca ≠ wylosowany z blake2s(prev‖milestone) — ręka przy kulach!")
    want_amt = pick_amount(prev_hash_hex, milestone)
    if tx_amount != want_amt:
        raise AirdropError(f"kwota ≠ wylosowana {want_amt} iskier (1..{AMT_MAX_FNX} FNX)")


def plan_airdrop(names: dict, bans: dict, fired: set[int], prev_hash_hex: str,
                 *, milestone: int = MILESTONE_USERS) -> tuple[str, int] | None:
    """Szablon bloku/kopacz: (wallet, kwota) gdy kamień DOSTRZEGALNY, inaczej None."""
    if not milestone_due(len(names), fired, milestone=milestone):
        return None
    w = pick_recipient(names, bans, prev_hash_hex, milestone)
    if w is None:
        return None
    return w, pick_amount(prev_hash_hex, milestone)


# ---------------------------------------------------------------- selftest
if __name__ == "__main__":
    import time

    print("chain/airdrop.py — selftest: TX_AIRDROP 0x15 (D62) — kamień milowy 1M\n")
    from core.identity import Identity
    from chain.ledger import Ledger, BLOCK_REWARD
    from chain.block import Tx, TX_AIRDROP, TX_ID_DECLARE
    from chain.miner import mine
    import chain.usernames as _un

    now = int(time.time())

    # 1) czyste funkcje: determinizm + zakres kwot + skip zbanowanego
    names_t = {f"n{i:03d}": f"FNX1{'a' * 4}{i:028d}"[:36] for i in range(40)}
    import chain.ban_evt as _be
    h1, h2 = "aa" * 32, "bb" * 32
    w1 = pick_recipient(names_t, {}, h1, MILESTONE_USERS)
    assert pick_recipient(names_t, {}, h1, MILESTONE_USERS) == w1, "losowanie niedeterministyczne!"
    assert w1 in set(names_t.values())
    a1 = pick_amount(h1, MILESTONE_USERS)
    assert AMT_MIN_FNX * ISKRA <= a1 <= AMT_MAX_FNX * ISKRA
    ws = {pick_recipient(names_t, {}, f"{i:064x}", MILESTONE_USERS) for i in range(8)}
    assert len(ws) > 1, "różne hashe dają ten sam wybór?!"
    # zbanowany odpada z loterii (tombstone > fortuna, D18): symulacja bans
    assert pick_recipient(names_t, {w1: {"active": True}}, h1, MILESTONE_USERS) != w1
    print("  [OK] 1. determinizm+rozkład: hash=maszyna losująca; zbanowany odpada z kul")

    # 2) E2E łańcuch z małym roboczym progiem (dev): rejestrujemy 3 nicki → TYLKO 1 airdrop
    DEV_MILE = 3
    from chain.block import TX_TRANSFER
    L = Ledger(airdrop_milestone=DEV_MILE)
    ida = Identity.generate("drop_ala")
    won = mine(L.block_template(ida.wallet, zbits=2), max_tries=200_000)
    assert won
    L.apply_block(won)
    crew = [Identity.generate(f"drop_c{i}") for i in range(3)]
    for i, w in enumerate(crew):                   # dotacja na claim (1 FNX + zapas na fee)
        L.add_tx(Tx.build_signed(TX_TRANSFER, ida, w.wallet, 2 * ISKRA, i))
    won1 = mine(L.block_template(ida.wallet, zbits=2), max_tries=200_000)
    assert won1
    L.apply_block(won1)
    nicks = ("milu", "mile2", "mile3")
    for w, nick in zip(crew, nicks):               # claim = 1 username / wallet (reguła D28)
        L.add_tx(Tx.build_signed(TX_ID_DECLARE, w, "FNX-NAMES", _un.CLAIM_FEE, 0,
                                 payload=_un.username_payload("claim", nick)))
    won2 = mine(L.block_template(ida.wallet, zbits=2), max_tries=200_000)
    assert won2
    L.apply_block(won2)
    assert len(L.usernames) >= DEV_MILE, f"mam {len(L.usernames)}"
    # szablon NASTĘPNEGO bloku musi zawierać airdrop z (wallet,kwota) policzoną z prev
    prev2 = L.tip().hash()
    plan = plan_airdrop(L.usernames, L.bans,
                        set(L.airdrop_fired), prev2, milestone=DEV_MILE)
    assert plan is not None
    tpl = L.block_template(ida.wallet, zbits=2)
    got = [t for t in tpl.txs if t.type == TX_AIRDROP]
    assert len(got) == 1, f"szablon bez airdropu: {[t.type for t in tpl.txs]}"
    assert got[0].recipient == plan[0] and got[0].amount == plan[1]
    assert got[0].sender == "" and got[0].sig == "", "airdrop = zdarzenie systemowe"
    bal0 = L.balance_of(plan[0])
    won3 = mine(tpl, max_tries=200_000)
    assert won3
    L.apply_block(won3)
    assert L.balance_of(plan[0]) == bal0 + plan[1], "zwycięzca nie dostał kasy"
    assert DEV_MILE in set(L.airdrop_fired)
    print(f"  [OK] 2. E2E: 3 rejestracje → blok z TX_AIRDROP: {plan[1] // ISKRA} FNX "
          f"→ {plan[0][:12]}… (1/kamień)")

    # 3) manipulacja bloku: inna kwota/odbiorca = cały blok odrzucony; duplikat = odrzut
    won3b = mine(L.block_template(ida.wallet, zbits=2), max_tries=200_000)
    assert won3b and not any(t.type == TX_AIRDROP for t in won3b.txs), \
        "drugiego strzału TEGO SAMEGO kamienia nie wolno"
    names2 = dict(L.usernames)
    fired2 = set(L.airdrop_fired)
    try:
        validate_airdrop_tx(plan[1] + 1, plan[0], airdrop_payload(DEV_MILE),
                            names2, L.bans, set(), prev2, milestone=DEV_MILE)
        raise SystemExit("zawyżona kwota przeszła!")
    except AirdropError as e:
        assert "kwota" in str(e)
    zly = next(v for v in names2.values() if v != plan[0])
    try:
        validate_airdrop_tx(plan[1], zly, airdrop_payload(DEV_MILE),
                            names2, L.bans, set(), prev2, milestone=DEV_MILE)
        raise SystemExit("podmiana odbiorcy przeszła!")
    except AirdropError as e:
        assert "odbiorca" in str(e)
    try:
        validate_airdrop_tx(plan[1], plan[0], airdrop_payload(DEV_MILE),
                            names2, L.bans, fired2, prev2, milestone=DEV_MILE)
        raise SystemExit("powtórka kamienia przeszła!")
    except AirdropError as e:
        assert "odstrzelony" in str(e)
    print("  [OK] 3. anty-ręka-przy-kulach: zła kwota/odbiorca/powtórka = blok odrzucony")

    # 4) replay: adopt_chain odtwarza airdrop BIT-W-BIT (maszyna losująca jest ta sama)
    L2 = Ledger(airdrop_milestone=DEV_MILE)
    assert L2.adopt_chain(L.chain)
    assert L2.airdrop_fired == L.airdrop_fired
    assert L2.balance_of(plan[0]) == L.balance_of(plan[0])
    snap = L.snapshot()
    assert "airdrops" in snap and "airdrop_fired" in snap
    print("  [OK] 4. replay/adopt/snapshot: zwycięzca i kamień bit-w-bit identyczni")

    print("\nSELFTEST: PASS ✅  chain/airdrop.py — TX_AIRDROP 0x15 (D62):\n"
          "kamień milowy 1M zarejestrowanych → dokładnie 1 zdarzenie; odbiorca+kwota\n"
          "z blake2s(prev‖milestone) (nikt nie przyłoży ręki); zbanowany odpada;\n"
          "emission-event ⚠️ ROBOCZY §12 — decyzja właściciela: skąd FNX finalnie.")
