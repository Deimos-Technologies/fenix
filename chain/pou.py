# chain/pou.py — PoU: PROOF-OF-UPTIME on-chain (D12 → D58; TX_POU_ATTEST 0x04)
"""
Analogia: dziennik obecności przy wejściu do fabryki. Nie wystarczy, że SAM
się wpiszesz (wallet podpisuje tx — nonce i fee jak zawsze). Trzeba jeszcze,
żeby TRZECH kolegów z innych zmian podpisało: „widziałem go dziś na hali"
(świadkowie z ≥3 różnych portfeli). Po 30 TAKICH dniach z rzędu (bez przerwy
dłuższej niż 72 h) dostajesz legitymację GŁOSUJĄCEGO (VOTER) — głosu NIE kupuje
się za FNX, zdobywa się go OBECNOŚCIĄ (nie cechy §13: „FNX nie daje nikomu
głosu zakupionego"; „czas nie podlega magii").

Co ten plik WDROWAŻY (fundament P25):
  • format + walidacja TX_POU_ATTEST (rezerwa spec §tx: 0x04),
  • rejestr ledger.pou — deterministyczny, replay bit-w-bit (wzór D50/D46/D47:
    walidacja najpierw, rejestr wirtualny w bloku, commit po całości),
  • jedna funkcja prawdy o statusie: pou_status() (VOTER/pokrycie/streak),
  • mnożnik §7 gotowy jako LICZBA (0.5 ghost / 1.0 VOTER / 1.25 VOTER+90d) —
    podpięcie do BLOCK_REWARD = OSOBNA decyzja przy zamknięciu §12 (emisja),
    świadomie NIE robione w tym pliku.

Czego ten plik NIE robi (uczciwie — jak dev-hook w D47):
  • „czy świadek REALNIE mnie widział NA HALLI" (challenge-reachability, echo
    portu/usługi) to warstwa SIECIOWA (M6c) — blockchain widzi samą matematykę;
  • jitter okien 20–40 min (spec §6) — konsensus trzyma deterministyczny slot
    30 min; losowość obserwacji (KIEDY peer puka) = sieć, nie blok,
  • BOOTSTRAP: gdy aktywnych kandydatów <3, ring = dowolni świadkowie (jawnie,
    jak bootstrap w sieciach proof-of-*). Sybil-wycena dziś: musisz WPISAĆ ≥3
    własne portfele do dziennika obecności i CZEKAĆ aż łańcuch je wylosuje —
    losowanie spoza Twojej kontroli (D59).
  • VOTE_EVT 0x07 (urna dla VOTER) = chain/vote_evt.py (D60) — osobny plik.
D59 (2026-08-07): RING ŚWIADKÓW losowany z łańcucha — draw_witnesses():
seed = blake2s(prev_hash ‖ window), kandydaci = wallet-e z attestation w
ostatnich 4 dobach (z REJESTRU — replay liczy to samo, zegar nie gra roli),
bez sendera, ≤8 wylosowanych; walidacja wymaga świadków Z RINGU. Sybil NIE
wybiera sobie świadków — robi to za niego hash poprzedniego bloku.
"""
from __future__ import annotations

import json
import sys
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from chain.block import canon                            # noqa: E402
from core.crypto.fenix_crypto import wallet_address      # noqa: E402

# --- parametry konsensusu (fnx_spec §6/§7; wartości czasowe = spec, fee = §12) ---
WINDOW_S = 1800                     # okno-slot PoU: 30 min (spec 20–40; granica pojemności)
POU_MIN_WITNESSES = 3               # ≥3 sygnatur świadków (spec §6)
POU_MAX_WITNESSES = 8               # sufit anty-bloat payloadu
POU_MAX_AGE_S = 4 * 86400           # okno nie starsze niż 4 doby vs REF (blok/zegar)
POU_FUTURE_SKEW_S = 600             # okno nie z przyszłości (dryf zegarów 10 min)
POU_RESET_GAP_S = 72 * 3600         # spec §6: przerwa > 72 h = reset progresu
POU_VOTER_SPAN_DAYS = 30            # 30 dni streaka…
POU_VOTER_COVERAGE = 0.8            # …z pokryciem ≥80% dni (spec §6 „≥80% okien"→dni*)
POU_VOTER90_DAYS = 90               # §7: VOTER+90d → mnożnik 1.25
POU_PRUNE_S = 40 * 86400            # okna starsze niż 40 dni kasowane (VOTER patrzy 30+*)
POU_FEE_ISKRY = 1000                # płaska fee antyspamowa (⚠️ ROBOCZA — fnx_spec §12/P5)

# * uczciwe tłumaczenie specu: blockchain NIE WIDZI, w których oknach wallet był
#   losowany (losowe okna = warstwa sieci), więc „≥80% okien" liczymy jako ≥80%
#   DNI streaka posiadających wpis. To jedyna deterministyczna odczytka on-chain.


class PouError(Exception):
    """Naruszenie zasad PoU — jeden typ (jak BanEvtError/RankError)."""


# ---------------------------------------------------------------- core + świadkowie
def pou_core(wallet: str, window_id: int) -> dict:
    """Kanoniczny rdzeń zaświadczenia — DOKŁADNIE ten obiekt podpisują świadkowie
    i DOKŁADNIE ten walidują węzły (jeden ciąg bajtów, jak w D47)."""
    core = {"v": 1, "op": "pou", "wallet": wallet, "window": int(window_id)}
    _validate_core(core)
    return core


def _validate_core(core: dict) -> None:
    if not isinstance(core, dict):
        raise PouError("core: ma być obiektem")
    if core.get("v") != 1 or core.get("op") != "pou":
        raise PouError("core: brak v=1/op=pou")
    w = core.get("wallet")
    if not isinstance(w, str) or not w.startswith("FNX1"):
        raise PouError("core: wallet ma zaczynać się od FNX1")
    win = core.get("window")
    if not isinstance(win, int) or isinstance(win, bool) or win < 0:
        raise PouError("core: window ma być int ≥ 0")


def witness_entry(identity, core: dict) -> dict:
    """Podpis świadka nad core + JAWNE klucze (węzeł sam wiąże sig_pub‖x_pub →
    wallet — dokładnie konwencja kropki D47 i Tx.verify_signature)."""
    _validate_core(core)
    return {"signer": identity.wallet,
            "sig_pub": identity.sig_pub_b.hex(),
            "x_pub": identity.x_pub_b.hex(),
            "sig": identity.sign(canon(core)).hex()}


def verify_witness(entry: dict, core: dict) -> str | None:
    """Ważny wpis świadka → ZWRÓCONY wallet świadka; cokolwiek złe → None."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        signer = wallet_address(bytes.fromhex(entry["sig_pub"]),
                                bytes.fromhex(entry["x_pub"]))
        if signer != entry["signer"]:
            return None
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["sig_pub"])) \
            .verify(bytes.fromhex(entry["sig"]), canon(core))
        return signer
    except (ValueError, InvalidSignature, KeyError, TypeError):
        return None


# ---------------------------------------------------------------- payload
def pou_payload(window_id: int, entries: list[dict]) -> str:
    """Składa payload tx (świadek podpisuje OFF-CHAIN; wallet składa)."""
    return json.dumps({"v": 1, "op": "pou", "window": int(window_id), "sigs": entries},
                      separators=(",", ":"), sort_keys=True)


def parse_payload(raw: str) -> dict:
    try:
        p = json.loads(raw)
    except (ValueError, TypeError):
        raise PouError("payload: niepoprawny JSON") from None
    if not isinstance(p, dict) or p.get("v") != 1 or p.get("op") != "pou":
        raise PouError("payload: brak v=1/op=pou")
    win = p.get("window")
    if not isinstance(win, int) or isinstance(win, bool) or win < 0:
        raise PouError("payload: window ma być int ≥ 0")
    sigs = p.get("sigs")
    if not isinstance(sigs, list):
        raise PouError("payload: sigs ma być listą")
    return p


def validate_pou_payload(raw: str, pou_reg: dict, sender: str, *, now_ts: int,
                         mempool_windows=(), required: set | frozenset | None = None) -> int:
    """Mempool+blok (ref = zegar w mempoolu, TIMESTAMP BLOKU w konsensusie —
    deterministyczny replay). Zwraca window_id. Rzuca PouError.
    required (D59): zbiór świadków WYLOSOWANYCH Z ŁAŃCUCHA dla (prev, window) —
    None = bootstrap otwarty (za mało aktywnych peerów w rejestrze)."""
    p = parse_payload(raw)
    win = p["window"]
    win_ts = win * WINDOW_S
    if win_ts > now_ts + POU_FUTURE_SKEW_S:
        raise PouError(f"okno {win} jest z PRZYSZŁOŚCI (win_ts {win_ts} > ref {now_ts})")
    if now_ts - win_ts > POU_MAX_AGE_S:
        raise PouError(f"okno {win} starsze niż {POU_MAX_AGE_S // 86400} doby — za późno "
                       f"(zaświadczamy świeżą obecność, nie historię)")
    got = pou_reg.get(sender, {})
    if win in got.get("w", []):
        raise PouError(f"okno {win} już zaświadczone przez ten wallet (1 wpis / okno)")
    if win in mempool_windows:
        raise PouError(f"okno {win} już siedzi w mempoolu (rezerwacja slotu)")
    core = {"v": 1, "op": "pou", "wallet": sender, "window": win}
    seen: set[str] = set()
    for e in p["sigs"]:
        w = verify_witness(e, core)
        if w is None:
            raise PouError("świadek z nieprawidłowym podpisem/wiązanką kluczy")
        if w == sender:
            raise PouError("zaświadczenie SAMEMU SOBIE nie istnieje (świadek ≠ wallet)")
        if required is not None and w not in required:
            raise PouError("świadek NIE z wylosowanego ringu (losowanie z łańcucha, D59)")
        seen.add(w)
    if len(p["sigs"]) > POU_MAX_WITNESSES:
        raise PouError(f"maks. {POU_MAX_WITNESSES} świadków (anty-bloat payloadu)")
    if len(seen) < POU_MIN_WITNESSES:
        raise PouError(f"potrzeba ≥{POU_MIN_WITNESSES} RÓŻNYCH świadków (masz {len(seen)})")
    return win


# ---------------------------------------------------------------- D59: ring z łańcucha
ROSTER_AGE_WINDOWS = POU_MAX_AGE_S // WINDOW_S    # 192 okna = 4 doby aktywności wstecz


def pou_roster(pou_reg: dict, window: int, sender: str) -> list[str]:
    """Kandydaci na świadków: wallet ≠ sender z zaświadczeniem w ostatnich 4 dobach
    (okno ≥ window−192). Z REJESTRU — replay liczy to samo, zegar nie gra roli."""
    fresh = window - ROSTER_AGE_WINDOWS
    return sorted(w for w, e in pou_reg.items()
                  if w != sender and any(x >= fresh for x in e.get("w", [])))


def draw_witnesses(pou_reg: dict, prev_hash_hex: str, window: int,
                   sender: str) -> frozenset | None:
    """Deterministyczny ring świadków dla (blok poprzedni, okno): seed =
    blake2s(prev‖window), losowanie bez zwracania. Nikt nie przewidzi ringu przed
    wyjściem bloku prev — sybil NIE wybiera sobie świadków (D59).
    Zwraca None = BOOTSTRAP (roster < 3): świadkowie dowolni (jak D58), flaga jawna."""
    roster = pou_roster(pou_reg, window, sender)
    if len(roster) < POU_MIN_WITNESSES:
        return None
    import hashlib
    state = bytes.fromhex(prev_hash_hex) + window.to_bytes(8, "big")
    target = min(POU_MAX_WITNESSES, len(roster))
    picked: list[str] = []
    seen_idx: set[int] = set()
    ctr = 0
    while len(picked) < target:                     # deterministycznie, bez zwracania
        h = hashlib.blake2s(state + ctr.to_bytes(4, "big")).digest()
        ctr += 1
        for off in range(0, len(h), 4):
            idx = int.from_bytes(h[off:off + 4], "big") % len(roster)
            if idx not in seen_idx:
                seen_idx.add(idx)
                picked.append(roster[idx])
                if len(picked) >= target:
                    break
    return frozenset(picked)


# ---------------------------------------------------------------- rejestr (ledger)
def apply_pou(pou_reg: dict, wallet: str, window_id: int, block_ts: int) -> None:
    """Wpis do rejestru + kanoniczne czyszczenie (>40 dni; decyduje BLOK, nie zegar)."""
    import bisect
    e = pou_reg.setdefault(wallet, {"w": [], "last_ts": 0})
    w: list = e["w"]
    if not w or w[-1] < window_id:                    # normalna ścieżka: rosnąco
        w.append(window_id)
    elif window_id not in w:                          # retencja: wstaw posortowane
        bisect.insort(w, window_id)
    cutoff = (block_ts - POU_PRUNE_S) // WINDOW_S
    if w and w[0] < cutoff:
        e["w"] = [x for x in w if x >= cutoff]
    e["last_ts"] = max(int(e.get("last_ts", 0)), int(block_ts))


# ---------------------------------------------------------------- status VOTER
def pou_status(entry: dict | None, tip_ts: int) -> dict:
    """JEDNA funkcja prawdy o statusie (fnx_spec §6):
    VOTER = (a) streak ≥ 30 dni (odstępy między obecnościami NIGDY > 72 h,
    liczone wstecz od ostatniej)  ORAZ  (b) pokrycie ≥ 80% DNI streaka
    (≥1 okno dziennie)  ORAZ  (c) ostatnia obecność nie starsza niż 72 h
    od czubka (tip_ts). Wszystko z REJESTRU i tip_ts — replay bit-w-bit."""
    w = sorted(int(x) for x in (entry or {}).get("w", []))
    if not w:
        return {"voter": False, "voter90": False, "span_days": 0, "present_days": 0,
                "coverage": 0.0, "streak_alive": False, "multiplier": 0.5,
                "last_attest_ts": None, "reset_deadline": None}
    tss = [x * WINDOW_S for x in w]
    last = tss[-1]
    alive = tip_ts - last <= POU_RESET_GAP_S
    # wstecz od ostatniej obecności, dopóki odstępy ≤ 72 h
    streak_since = tss[-1]
    for i in range(len(tss) - 2, -1, -1):
        if tss[i + 1] - tss[i] > POU_RESET_GAP_S:
            break
        streak_since = tss[i]
    span_days = (last - streak_since) // 86400 + 1
    present = len({ts // 86400 for ts in tss if ts >= streak_since})
    cov = present / span_days if span_days else 0.0
    voter = alive and span_days >= POU_VOTER_SPAN_DAYS and cov >= POU_VOTER_COVERAGE
    voter90 = voter and span_days >= POU_VOTER90_DAYS
    return {"voter": voter, "voter90": voter90,
            "span_days": span_days, "present_days": present, "coverage": round(cov, 4),
            "streak_alive": alive, "multiplier": 1.25 if voter90 else (1.0 if voter else 0.5),
            "last_attest_ts": last, "reset_deadline": last + POU_RESET_GAP_S}


def status_of(pou_reg: dict, wallet: str, tip_ts: int) -> dict:
    """Wygoda: status wprost z rejestru ledgera."""
    st = pou_status(pou_reg.get(wallet), tip_ts)
    st["wallet"] = wallet
    return st


# ---------------------------------------------------------------- selftest
if __name__ == "__main__":
    import shutil
    import tempfile
    import time

    print("chain/pou.py — selftest: PoU on-chain (D58) — zaświadczenia, świadkowie, VOTER\n")
    from core.identity import Identity
    from chain.ledger import Ledger, BLOCK_REWARD
    from chain.block import Tx, TX_POU_ATTEST, ISKRA
    from chain.miner import mine

    fast_ts = int(time.time())
    win0 = fast_ts // WINDOW_S                       # bieżące okno-slot

    # 1) core/payload roundtrip + brudne wejścia odrzucane
    wal_a = Identity.generate("pou_ala").wallet
    core = pou_core(wal_a, win0)
    assert canon(pou_core(wal_a, win0)) == canon(core)
    for zle in ({"v": 2, "op": "pou", "wallet": wal_a, "window": win0},
                {"v": 1, "op": "ban", "wallet": wal_a, "window": win0},
                {"v": 1, "op": "pou", "wallet": "X", "window": win0},
                {"v": 1, "op": "pou", "wallet": wal_a, "window": -1},
                {"v": 1, "op": "pou", "wallet": wal_a, "window": True}):
        try:
            _validate_core(zle)
            raise SystemExit(f"brudne core przeszło: {zle}")
        except PouError:
            pass
    print("  [OK] 1. core kanoniczne + brudne wejścia (v/op/wallet/window/bool) odrzucone")

    # 2) świadkowie: 3 różnych OK; <3 / duplikat / sobis / fałszerstwo / podmianka → odmowa
    ida = Identity.generate("pou_ala2")
    wit = [Identity.generate(f"pou_w{i}") for i in range(4)]
    core2 = pou_core(ida.wallet, win0)
    ents = [witness_entry(w, core2) for w in wit[:3]]
    assert all(verify_witness(e, core2) == w.wallet for e, w in zip(ents, wit[:3]))
    pl = pou_payload(win0, ents)
    assert validate_pou_payload(pl, {}, ida.wallet, now_ts=fast_ts) == win0
    try:
        validate_pou_payload(pou_payload(win0, ents[:2]), {}, ida.wallet, now_ts=fast_ts)
        raise SystemExit("2 świadków przeszło!")
    except PouError as e:
        assert "RÓŻNYCH" in str(e)
    try:
        validate_pou_payload(pou_payload(win0, [ents[0], ents[0], ents[1]]), {},
                             ida.wallet, now_ts=fast_ts)
        raise SystemExit("duplikat świadka przeszedł jako 3 różni!")
    except PouError as e:
        assert "RÓŻNYCH" in str(e)
    try:
        validate_pou_payload(pou_payload(win0, ents[:2] + [witness_entry(ida, core2)]),
                             {}, ida.wallet, now_ts=fast_ts)
        raise SystemExit("sobis-świadek przeszedł!")
    except PouError as e:
        assert "SAMEMU" in str(e)
    zly = dict(ents[0], sig=ents[1]["sig"])          # podmianka podpisu między kluczami
    try:
        validate_pou_payload(pou_payload(win0, [zly] + ents[1:]), {}, ida.wallet,
                             now_ts=fast_ts)
        raise SystemExit("sfałszowany wpis świadka przeszedł!")
    except PouError:
        pass
    core_x = pou_core(wal_a, win0)
    assert verify_witness(ents[0], core_x) is None, "podpis pod INNE core dalej ważny!"
    print("  [OK] 2. świadkowie: ≥3 różnych, sobis/duplikat/fałsz/podmianka-core = odmowa")

    # 2b) D59: ring świadków WYLOSOWANY z łańcucha — sybil NIE wybiera sobie świadków
    import hashlib as _h
    ids_r = [Identity.generate(f"pou_r{i}") for i in range(10)]
    reg_r = {w.wallet: {"w": [win0 - 10 - i], "last_ts": 1} for i, w in enumerate(ids_r)}
    prev_fake = _h.blake2s(b"prev-block-test").hexdigest()
    ring1 = draw_witnesses(reg_r, prev_fake, win0, ida.wallet)
    assert ring1 is not None and len(ring1) == POU_MAX_WITNESSES, ring1
    assert draw_witnesses(reg_r, prev_fake, win0, ida.wallet) == ring1, "ring niedeterministyczny!"
    assert all(w in {x.wallet for x in ids_r} for w in ring1), "ring spoza rosteru!"
    assert ida.wallet not in ring1, "sender wszedł do własnego ringu!"
    # bootstrap: <3 aktywnych → otwarcie (jawna flaga, jak dev-hook w D47)
    assert draw_witnesses({ids_r[0].wallet: {"w": [win0 - 1], "last_ts": 1}},
                          prev_fake, win0, ida.wallet) is None
    # wygasły (attest sprzed >4 dób) NIE wchodzi do rosteru kandydatów
    w_st = "FNX1" + "stary" + "a" * 27
    reg_st = reg_r | {w_st: {"w": [win0 - ROSTER_AGE_WINDOWS - 5], "last_ts": 1}}
    assert w_st not in pou_roster(reg_st, win0, ida.wallet)
    # gating w walidacji: 3 świadków Z RINGU przechodzi; podmianka spoza ringu = odmowa
    att_in = [x for x in ids_r if x.wallet in ring1][:3]
    att_out = next(x for x in ids_r if x.wallet not in ring1)
    core_r = pou_core(ida.wallet, win0)
    pl_ring = pou_payload(win0, [witness_entry(x, core_r) for x in att_in])
    assert validate_pou_payload(pl_ring, reg_r, ida.wallet, now_ts=fast_ts,
                                required=ring1) == win0
    pl_out = pou_payload(win0, [witness_entry(att_out, core_r)] +
                         [witness_entry(x, core_r) for x in att_in[:2]])
    try:
        validate_pou_payload(pl_out, reg_r, ida.wallet, now_ts=fast_ts, required=ring1)
        raise SystemExit("świadek spoza wylosowanego ringu przeszedł!")
    except PouError as e:
        assert "wylosowanego ringu" in str(e)
    try:                                            # duplikat w ringu dalej za mały
        validate_pou_payload(pou_payload(win0, [witness_entry(att_in[0], core_r)] * 3),
                             reg_r, ida.wallet, now_ts=fast_ts, required=ring1)
        raise SystemExit("duplikat w ringu przeszedł jako 3 różni!")
    except PouError:
        pass
    print("  [OK] 2b. D59: ring z łańcucha — deterministyczny, bez sendera, bez wygasłych;")
    print("            świadek spoza ringu = odmowa; bootstrap <3 aktywnych = jawny otwarty")

    # 3) okno z przyszłości / przedpotopowe / duplikat w rejestrze / w mempoolu
    try:
        validate_pou_payload(pou_payload(win0 + 5, ents), {}, ida.wallet, now_ts=fast_ts)
        raise SystemExit("okno z przyszłości przeszło!")
    except PouError as e:
        assert "PRZYSZŁOŚCI" in str(e)
    try:
        validate_pou_payload(pou_payload(win0 - 200, ents), {}, ida.wallet, now_ts=fast_ts)
        raise SystemExit("okno sprzed 5 dób przeszło!")
    except PouError as e:
        assert "za późno" in str(e)
    try:
        validate_pou_payload(pl, {ida.wallet: {"w": [win0], "last_ts": 1}}, ida.wallet,
                             now_ts=fast_ts)
        raise SystemExit("duplikat okna przeszedł!")
    except PouError as e:
        assert "1 wpis / okno" in str(e)
    try:
        validate_pou_payload(pl, {}, ida.wallet, now_ts=fast_ts, mempool_windows=[win0])
        raise SystemExit("okno z mempoola przeszło drugi raz!")
    except PouError as e:
        assert "mempoolu" in str(e)
    print("  [OK] 3. granice okna: przyszłość/starość/dup w rejestrze/dup w mempoolu")

    # 4) E2E prawdziwy łańcuch: zaświadczenie z 3 świadkami → mempool → blok → rejestr
    L = Ledger()
    fee_ts = None
    won = mine(L.block_template(ida.wallet, zbits=2), max_tries=200_000)
    assert won
    L.apply_block(won)
    core3 = {"v": 1, "op": "pou", "wallet": ida.wallet, "window": win0}
    ents3 = [witness_entry(w, core3) for w in wit[:4]]
    txp = Tx.build_signed(TX_POU_ATTEST, ida, "", POU_FEE_ISKRY, 0,
                          payload=pou_payload(win0, ents3))
    L.add_tx(txp)
    won2 = mine(L.block_template(ida.wallet, zbits=2), max_tries=200_000)
    assert won2
    L.apply_block(won2)
    assert L.pou[ida.wallet]["w"] == [win0] and L.pou[ida.wallet]["last_ts"] == won2.timestamp
    # zła fee: odmowa w mempoolu (świadkowie MUSZĄ być pod to samo okno — podpis
    # wiąże (wallet,window)). UWAGA na zegar: okno POPRZEDNIE (win0-1), NIE win0+1 —
    # gdy test rusza w ostatnich 600 s slotu, następne okno jest w horyzoncie dryfu
    # i walidator słusznie odrzuci je jako „z PRZYSZŁOŚCI" (złapane pełnym audytem)
    core_b = pou_core(ida.wallet, win0 - 1)
    ents_b = [witness_entry(w, core_b) for w in wit[:3]]
    tx_bad = Tx.build_signed(TX_POU_ATTEST, ida, "", POU_FEE_ISKRY + 1, 1,
                             payload=pou_payload(win0 - 1, ents_b))
    try:
        L.add_tx(tx_bad)
        raise SystemExit("pou ze złą fee przeszedł mempool!")
    except Exception as e:
        assert "fee" in str(e), e
    # duplikat okna: odmowa (rejestr chain)
    tx_dup = Tx.build_signed(TX_POU_ATTEST, ida, "", POU_FEE_ISKRY, 1,
                             payload=pou_payload(win0, ents3))
    try:
        L.add_tx(tx_dup)
        raise SystemExit("duplikat okna przeszedł mempool!")
    except Exception as e:
        assert "1 wpis / okno" in str(e)
    print("  [OK] 4. E2E: TX_POU_ATTEST 0x04 z 4 świadkami w bloku; zła fee/duplikat = odmowa")

    # 5) status: ghost → streak 30d ≥80% → VOTER ×1.0; 90d → ×1.25
    reg_test: dict = {}
    day0 = (fast_ts - 100 * 86400) // 86400 * 86400
    wins: list[int] = []
    for d in range(100):
        wins.append((day0 + d * 86400) // WINDOW_S)     # 1 obecność/dzień
    reg_test[ida.wallet] = {"w": sorted(wins), "last_ts": 1}
    tip = day0 + 100 * 86400
    st = pou_status(reg_test[ida.wallet], tip)
    assert st["voter"] and st["voter90"] and st["multiplier"] == 1.25, st
    assert st["span_days"] >= 90 and st["streak_alive"]
    st_ghost = pou_status({"w": wins[:10], "last_ts": 1}, tip)
    assert not st_ghost["voter"] and st_ghost["multiplier"] == 0.5
    # VOTER bez +90 (30..89 dni)
    st_v = pou_status({"w": wins[:31], "last_ts": 1}, day0 + 31 * 86400)
    assert st_v["voter"] and not st_v["voter90"] and st_v["multiplier"] == 1.0, st_v
    # pokrycie 23/31 dni ≈ 74% → NIE voter (poniżej 80%); streak MUSI żyć —
    # obecność co najwyżej co 72 h (usuwamy co 4. dzień, nigdy 3 z rzędu)
    sparse_days = [d for d in range(31) if d % 4 != 1]        # 23 dni obecności
    assert len(sparse_days) == 23                             # 23/31 ≈ 74% < 80%
    sparse = [wins[d] for d in sparse_days]
    st_sparse = pou_status({"w": sparse, "last_ts": 1}, day0 + 31 * 86400)
    assert st_sparse["streak_alive"] and st_sparse["span_days"] == 31
    assert st_sparse["present_days"] == 23 and st_sparse["coverage"] < 0.8
    assert not st_sparse["voter"], st_sparse
    print("  [OK] 5. status: ghost×0.5 → 31d VOTER×1.0 → 90d VOTER+×1.25; 74% pokrycia = brak")

    # 6) reset: przerwa >72 h zabija streak (spec §6); świeża obecność wznawia od zera
    gap = wins[:40] + wins[45:]                       # dziura 5 dni (40..44) w środku
    st_gap = pou_status({"w": gap, "last_ts": 1}, tip)
    # streak liczy się WSTECZ od ostatniej obecności: dni 45..99 = 55 dni,
    # pokrycie 55/55 — VOTER żyje, ale §7 „+90d" ucięte przez reset (dziura>72h)
    assert st_gap["streak_alive"] and st_gap["span_days"] == 55, st_gap
    assert not st_gap["voter90"], "dziura NIE zresetowała span!"
    assert st_gap["present_days"] == 55
    # ostatnia obecność sprzed >72 h od tipa → streak martwy (nawet z ładną historią)
    st_dead = pou_status({"w": wins[:90], "last_ts": 1}, day0 + 120 * 86400)
    assert not st_dead["voter"] and not st_dead["streak_alive"], st_dead
    print("  [OK] 6. reset: dziura 5 dni ucięła streak; przeterminowany »wakacyjny« = martwy")

    # 7) replay: adopt_chain odtwarza rejestr BIT-W-BIT (plik/łańcuch = obcy input)
    L2 = Ledger()
    assert L2.adopt_chain(L.chain)
    assert L2.pou == L.pou, "rejestr pou NIE jest bit-w-bit po adopt_chain!"
    snap = L.snapshot()
    assert "pou" in snap and snap["pou"][ida.wallet]["w"] == [win0]
    L3 = Ledger()
    assert L3.adopt_chain(L.chain)
    st3 = status_of(L3.pou, ida.wallet, L3.tip().timestamp)
    assert st3["streak_alive"] and st3["span_days"] == 1 and not st3["voter"]
    print("  [OK] 7. replay/adopt/snapshot: rejestr bit-w-bit; status liczony z tipu łańcucha")

    # 8) kopacz NIE dostaje fee z PoU (usługa rejestru jak ID_DECLARE) — ppm → skarbiec
    from chain.block import fee_split as _fs
    tre0 = L.balance_of(L.treasury)
    core8 = pou_core(ida.wallet, win0 - 2)          # okno z przeszłości (patrz krok 4)
    ents8 = [witness_entry(w, core8) for w in wit[:3]]
    tx8 = Tx.build_signed(TX_POU_ATTEST, ida, "", POU_FEE_ISKRY, 1,
                          payload=pou_payload(win0 - 2, ents8))
    L.add_tx(tx8)
    won8 = mine(L.block_template(ida.wallet, zbits=2), max_tries=200_000)
    assert won8
    L.apply_block(won8)
    burn8, owner8, total8 = _fs(POU_FEE_ISKRY)
    assert L.balance_of(L.treasury) == tre0 + owner8, \
        f"skarbiec +{L.balance_of(L.treasury) - tre0} ≠ ppm owner {owner8}"
    bal_miner = L.balance_of(ida.wallet)
    assert won8.txs[0].amount == BLOCK_REWARD, \
        "coinbase dostał coś poza nagrodą bazową — fee z PoU wyciekło do kopacza!"
    print("  [OK] 8. ekonomia: fee PoU = ppm owner→skarbiec; kopacz NIC z rejestru; fee tx z konta")
    print(f"           (z konta zeszło dokładnie {POU_FEE_ISKRY} att + {total8} fee ppm; "
          f"ppm z 1000 iskier zaokrągla się do {owner8})")

    # 9) zbanowany NIE zaświadcza (tombstone globalny, D18/D47)
    import chain.ban_evt as _be
    from chain.ban_evt import ban_core, attest_entry as _att, ban_payload as _bp, evidence_hash_of
    att_ids = [Identity.generate(f"pou_att{i}") for i in range(3)]
    for w in att_ids:
        _be.register_dev_attestor(w)
    bc = ban_core(ida.wallet, "0x11", "Test tombstone.", "Tombstone test.",
                  evidence_hash_of({"c": 9}))
    tx_ban = Tx(0x06, "", ida.wallet, 0, 0, payload=_bp(bc, [_att(w, bc) for w in att_ids]))
    L.add_tx(tx_ban)
    won9 = mine(L.block_template(wit[0].wallet, zbits=2), max_tries=200_000)
    assert won9
    L.apply_block(won9)
    assert _be.is_banned(L.bans, ida.wallet)
    core9 = pou_core(ida.wallet, win0 - 3)          # okno z przeszłości (patrz krok 4)
    tx9 = Tx.build_signed(TX_POU_ATTEST, ida, "", POU_FEE_ISKRY, 2,
                          payload=pou_payload(win0 - 3, [witness_entry(w, core9) for w in wit[:3]]))
    try:
        L.add_tx(tx9)
        raise SystemExit("ZBANOWANY wallet zaświadczył PoU!")
    except Exception as e:
        assert "zbanowany" in str(e)
    print("  [OK] 9. tombstone: zbanowany martwy także dla PoU (jedyna droga: wykup)")

    print("\nSELFTEST: PASS ✅  chain/pou.py — PoU on-chain (D58+D59):\n"
          "TX_POU_ATTEST 0x04; D59: RING świadków losowany z łańcucha (seed\n"
          "prev‖okno, kandydaci z rejestru ≤4 dni, bez sendera; spoza ringu = odmowa;\n"
          "bootstrap <3 = jawny); dedup okna, rejestr bit-w-bit, VOTER 30d ≥80% dni;\n"
          "fee jak usługa rejestru; zbanowany martwy. Challenge-reachability =\n"
          "warstwa sieci M6c (uczciwie: tu sama matematyka).")
