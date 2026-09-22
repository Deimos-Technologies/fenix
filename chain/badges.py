# chain/badges.py — ODZNAKI PROFILU (D52): „za co się należy" liczone, nie wklejane
"""
Zasada systemu (decyzja właściciela 2026-08-06): profil użytkownika pokazuje
ODZNAKI (badges) z grafikami. Kluczowe jak przy rangach (D28): odznaka NIE jest
stickerem, który sobie sam wklejasz — to WERDYKT wyliczony z faktów. Dwie klasy
faktów, oznaczone uczciwie przy każdej odznace:

    verify="chain" — policzone z blockchaina; każdy nod policzy identycznie
                     (bit-w-bit), oszukanie = podrobienie konsensusu;
    verify="local" — z LOKALNEGO licznika tego noda (stats.json, net/fenix_node
                     D54): godziny hostowania, „byłem pierwszym nodem", „mam
                     stronę". To flair oznaczony jako licznik własny — GUI
                     pokazuje gwiazdkę „licznik lokalny", bo kolega z innego
                     noda tego nie zweryfikuje. Bez ściemy: co jest chain, a co
                     lokalne, stoi jasno napisane.

KATALOG (kod → jak zdobyć):
    rank_owner       [chain] aktywna ranga ≠ ghost (tier = nazwa rangi; wygasa → gasi się)
    host_100h        [local] ≥100 h hostowania noda           (Strażnik Czasu I)
    host_1000h       [local] ≥1000 h                          (Strażnik Czasu II)
    host_10kh        [local] ≥10000 h                         (Strażnik Czasu III)
    webmaster        [local] stworzenie własnej strony (1×)   (Architekt)
    donor_t1/t2/t3   [chain] datki do skarbca ownera ≥1/≥100/≥1000 FNX (chain/donate D50)
    first_node       [local] był pierwszym nodem sieci (gdy nikogo nie było; D54)
    miner_100        [chain] ≥100 wykopanych bloków (coinbase recipient; Górnik)
    guardian         [chain] ≥1 podpisana kropka k-z-n w TX_BAN_EVT (Czuwający, D47)
    early_bird       [chain] pierwszy tx w sieci na wysokości ≤ EARLY_HEIGHT (Ptak Wczesny)

Prywatność: evaluate_badges liczy LOKALNIE nad własnym ledgerem — nic nie
wysyłamy. Odznaki chain są i tak publiczne na łańcuchu; lokalne żyją w GUI
właściciela (i tak może je sfotoszopować — dlatego uczciwie: „licznik lokalny").
"""
from __future__ import annotations

import sys
import time
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from chain.block import ISKRA                          # noqa: E402
from chain import ranks as rks                         # noqa: E402

EARLY_HEIGHT = 1000                # pierwszy tx nie wyżej niż ten blok → Ptak Wczesny
DONOR_T1, DONOR_T2, DONOR_T3 = ISKRA, 100 * ISKRA, 1000 * ISKRA   # progi donor (FNX)
MINER_BLOCKS = 100                 # bloków do odznaki Górnik
HOST_T1_H, HOST_T2_H, HOST_T3_H = 100.0, 1000.0, 10000.0          # godziny hostowania

# ------------------------- katalog: jedno źródło prawdy (GUI maluje Z TEJ tabeli) ----
BADGE_CATALOG: dict[str, dict] = {
    "rank_owner":  {"name": "Właściciel Legitymacji", "en": "Rank Owner",
                    "desc": "kupno rangi on-chain (vip/elite/…) — odznaka gaśnie razem "
                            "z rangą po 30 dniach (D51)",
                    "icon": "rank.png", "verify": "chain", "tier": "rank"},
    "host_100h":   {"name": "Strażnik Czasu I", "en": "Time Warden I",
                    "desc": "≥100 godzin hostowania noda (licznik lokalny)",
                    "icon": "host.png", "verify": "local", "tier": 1},
    "host_1000h":  {"name": "Strażnik Czasu II", "en": "Time Warden II",
                    "desc": "≥1000 godzin hostowania noda (licznik lokalny)",
                    "icon": "host.png", "verify": "local", "tier": 2},
    "host_10kh":   {"name": "Strażnik Czasu III", "en": "Time Warden III",
                    "desc": "≥10000 godzin hostowania noda (licznik lokalny)",
                    "icon": "host.png", "verify": "local", "tier": 3},
    "webmaster":   {"name": "Architekt", "en": "Webmaster",
                    "desc": "stworzenie własnej strony w sieci (1×; licznik lokalny)",
                    "icon": "webmaster.png", "verify": "local", "tier": 1},
    "donor_t1":    {"name": "Dobroczyńca I", "en": "Donor I",
                    "desc": "≥1 FNX datku do skarbca ownera (TX_DONATE, D50)",
                    "icon": "donor.png", "verify": "chain", "tier": 1},
    "donor_t2":    {"name": "Dobroczyńca II", "en": "Donor II",
                    "desc": "≥100 FNX datków łącznie do skarbca ownera",
                    "icon": "donor.png", "verify": "chain", "tier": 2},
    "donor_t3":    {"name": "Dobroczyńca III", "en": "Donor III",
                    "desc": "≥1000 FNX datków łącznie do skarbca ownera",
                    "icon": "donor.png", "verify": "chain", "tier": 3},
    "first_node":  {"name": "Założyciel", "en": "First Node",
                    "desc": "był pierwszym nodem, gdy sieć była pusta (claim lokalny, D54)",
                    "icon": "first_node.png", "verify": "local", "tier": 1},
    "miner_100":   {"name": "Górnik", "en": "Miner",
                    "desc": f"≥{MINER_BLOCKS} wykopanych bloków (coinbase na własny wallet)",
                    "icon": "miner.png", "verify": "chain", "tier": 1},
    "guardian":    {"name": "Czuwający", "en": "Guardian",
                    "desc": "≥1 podpisana kropka k-z-n w werdykcie TX_BAN_EVT (D47)",
                    "icon": "guardian.png", "verify": "chain", "tier": 1},
    "early_bird":  {"name": "Ptak Wczesny", "en": "Early Bird",
                    "desc": f"pierwszy tx w sieci na wysokości ≤{EARLY_HEIGHT} (pioneer)",
                    "icon": "early_bird.png", "verify": "chain", "tier": 1},
}


class BadgeError(Exception):
    """Błędy warstwy odznak — jeden typ."""


def _badge(code: str, **extra) -> dict:
    b = {"code": code, **BADGE_CATALOG[code]}
    b.update(extra)
    return b


def scan_chain(ledger, wallet: str) -> dict:
    """JEDEN przejazd po blokach: coinbase, kropki k-z-n, pierwszy tx.
    Deterministyczne — każdy nod policzy identycznie (fundament verify=chain)."""
    from chain import ban_evt as bevt                     # lokalny import: zero cyklu
    mined = 0
    attested = 0
    first_h: int | None = None
    for b in ledger.chain:
        txs = getattr(b, "txs", [])
        if txs and txs[0].recipient == wallet and txs[0].type == 0x01:   # TX_COINBASE
            mined += 1
            if first_h is None:
                first_h = b.height
        for tx in txs[1:]:
            if tx.sender == wallet and first_h is None:
                first_h = b.height
            if tx.type == 0x06:                             # TX_BAN_EVT: kropki attestorów
                try:
                    p = bevt.parse_ban_payload(tx.payload)
                    if p.get("op") == "ban":
                        attested += sum(1 for e in p.get("sigs", [])
                                        if e.get("signer") == wallet)
                except Exception:                           # zły payload = nie istnieje
                    pass
    return {"mined": mined, "attested": attested, "first_height": first_h}


def evaluate_badges(ledger, wallet: str, stats: dict | None = None,
                    now_ts: int | None = None) -> list[dict]:
    """Werdykt: lista ZDOBYTYCH odznak (dict z katalogu + pole 'why' z liczbą).
    stats: licznik lokalny noda {"uptime_hours": float, "site_created": bool,
    "first_node_ever": bool} (net/fenix_node D54); None = tylko fakty z chain."""
    stats = dict(stats or {})
    now_ts = int(time.time()) if now_ts is None else int(now_ts)
    earned: list[dict] = []

    # ------------- chain: ranga (żyjąca — wygaśnięcie rangi gasi i odznakę, D51) ---
    rank = rks.active_rank(ledger.ranks, ledger.height(), wallet, now_ts=now_ts)
    if rank != "ghost":
        earned.append(_badge("rank_owner", why=f"ranga '{rank}' aktywna", tier=rank))

    # ------------- chain: datki do skarbca ownera (D50 → progi DONOR) --------------
    donated = int(ledger.donations.get(wallet, 0))
    for code, thr in (("donor_t3", DONOR_T3), ("donor_t2", DONOR_T2), ("donor_t1", DONOR_T1)):
        if donated >= thr:                              # przyznajemy WSZYSTKIE osiągnięte progi
            earned.append(_badge(code, why=f"{donated // ISKRA} FNX datków łącznie"))

    # ------------- chain: skan bloków (górnik, czuwający, wczesny ptak) ------------
    sc = scan_chain(ledger, wallet)
    if sc["mined"] >= MINER_BLOCKS:
        earned.append(_badge("miner_100", why=f"{sc['mined']} wykopanych bloków"))
    if sc["attested"] >= 1:
        earned.append(_badge("guardian", why=f"{sc['attested']}× kropka k-z-n"))
    if sc["first_height"] is not None and sc["first_height"] <= EARLY_HEIGHT:
        earned.append(_badge("early_bird", why=f"debiut w bloku #{sc['first_height']}"))

    # ------------- local: licznik hosta (uczciwie oznaczone jako licznik lokalny) --
    hours = float(stats.get("uptime_hours", 0.0))
    for code, thr in (("host_10kh", HOST_T3_H), ("host_1000h", HOST_T2_H), ("host_100h", HOST_T1_H)):
        if hours >= thr:
            earned.append(_badge(code, why=f"{hours:.0f} h hostowania noda"))
    if stats.get("site_created"):
        earned.append(_badge("webmaster", why="własna strona w sieci (1×)"))
    if stats.get("first_node_ever"):
        earned.append(_badge("first_node", why="pierwszy nod, gdy sieć była pusta"))

    return earned


def badge_panel(ledger, wallet: str, stats: dict | None = None,
                now_ts: int | None = None) -> dict:
    """Dane pod panel GUI: zdobyte + zablokowane (do podglądu „czego mi brakuje")."""
    earned = evaluate_badges(ledger, wallet, stats=stats, now_ts=now_ts)
    have = {b["code"] for b in earned}
    locked = [dict({"code": c}, **m) for c, m in BADGE_CATALOG.items() if c not in have]
    return {"earned": earned, "locked": locked}


# -------------------------------------------------------------------------- selftest E2E
if __name__ == "__main__":
    from chain.block import Tx, TX_TRANSFER, TX_DONATE, TX_BAN_EVT
    from chain.ledger import Ledger
    from chain.miner import mine
    from chain import ban_evt as bevt
    from core.identity import Identity

    print("chain/badges.py — selftest: odznaki liczone z faktów, nie wklejane (D52)\n")

    TRE = "FNX1" + "b" * 32
    L = Ledger(TRE)
    ala = Identity.generate("ala_badge")

    def kop(miner: str, tag: str):
        t = L.block_template(miner, zbits=2)
        w = mine(t, max_tries=300_000)
        assert w is not None, f"kopanie padło: {tag}"
        L.apply_block(w)

    # 0) świeży wallet = ZERO odznak (nawet early_bird — nie było tx)
    p0 = badge_panel(L, ala.wallet)
    assert p0["earned"] == [] and len(p0["locked"]) == len(BADGE_CATALOG)
    print(f"  [OK] 0. świeży profil: 0 zdobytych / {len(BADGE_CATALOG)} do odblokowania "
          "(panel pokazuje cel)")

    # 1) early_bird: coinbase na wallet ali (blok #1 = debiut ≤ EARLY_HEIGHT)
    kop(ala.wallet, "pierwszy")
    got = {b["code"] for b in evaluate_badges(L, ala.wallet)}
    assert "early_bird" in got, got
    print("  [OK] 1. Ptak Wczesny: coinbase w bloku #1 = debiut ≤1000 → odznaka z chain")

    # 2) donor I/II: datki kumulują się (D50); progi przyznają się kaskadowo
    for i in range(30):                                  # fundusz: 150 FNX z coinbase
        kop(ala.wallet, f"fund{i}")
    L.add_tx(Tx.build_signed(TX_DONATE, ala, TRE, 60 * ISKRA, nonce=0)); kop(ala.wallet, "d1")
    got = {b["code"] for b in evaluate_badges(L, ala.wallet)}
    assert "donor_t1" in got and "donor_t2" not in got, got
    L.add_tx(Tx.build_signed(TX_DONATE, ala, TRE, 50 * ISKRA, nonce=1)); kop(ala.wallet, "d2")
    got = {b["code"] for b in evaluate_badges(L, ala.wallet)}
    assert {"donor_t1", "donor_t2"} <= got and "donor_t3" not in got, got
    print("  [OK] 2. DONOR: 60 FNX→I; +50=110→II (kumulacja chain); III jeszcze zamknięte")

    # 3) miner_100: 100 bloków własnym coinbase (GRUBO — zbits=2 leci ekspresowo)
    import time as _t
    t0 = _t.time()
    while scan_chain(L, ala.wallet)["mined"] < 100:
        kop(ala.wallet, "m")
    sc = scan_chain(L, ala.wallet)
    got = {b["code"] for b in evaluate_badges(L, ala.wallet)}
    assert "miner_100" in got, got
    print(f"  [OK] 3. Górnik: {sc['mined']} bloków coinbase → odznaka ({_t.time()-t0:.1f}s kopania)")

    # 4) guardian: pełna kropka k-z-n 3/3 z podpisem ali (rejestr dev jak w D47)
    import chain.ban_evt as _pkg
    att_b, att_c = Identity.generate("att_bee"), Identity.generate("att_cee")
    for a in (ala, att_b, att_c):
        _pkg.register_dev_attestor(a)
    ofiara = Identity.generate("troll_farm")
    ev = _pkg.evidence_hash_of({"case": "flood", "n": 123})
    core = _pkg.ban_core(ofiara.wallet, "0x11", "Zalewał sieć.", "Flooded the network.", ev)
    entries = [_pkg.attest_entry(a, core) for a in (ala, att_b, att_c)]
    txb = Tx(type=TX_BAN_EVT, sender="", recipient="", amount=0,
             payload=_pkg.ban_payload(core, entries))
    L.add_tx(txb); kop(ala.wallet, "ban")
    assert _pkg.is_banned(L.bans, ofiara.wallet)
    got = {b["code"] for b in evaluate_badges(L, ala.wallet)}
    assert "guardian" in got, got
    print("  [OK] 4. Czuwający: podpisana kropka w TX_BAN_EVT → odznaka z chain")

    # 5) rank_owner: kupno vip (D46/D51); odznaka ŻYJE z rangą — wygaśnięcie = znika
    from chain.block import TX_RANK_UP
    from chain.ranks import rank_payload, RANK_PRICE
    L.add_tx(Tx.build_signed(TX_RANK_UP, ala, "FNX-RANKS", RANK_PRICE["vip"],
                             nonce=L.nonce_of(ala.wallet), payload=rank_payload("vip")))
    kop(ala.wallet, "vip")
    for _ in range(5):
        kop(ala.wallet, "conf")
    got = {b["code"] for b in evaluate_badges(L, ala.wallet)}
    assert "rank_owner" in got, got
    b_rank = next(b for b in evaluate_badges(L, ala.wallet) if b["code"] == "rank_owner")
    assert b_rank["tier"] == "vip", b_rank
    L.ranks[ala.wallet]["until"] = L.tip().timestamp - 1            # upływ terminu (D51)
    got2 = {b["code"] for b in evaluate_badges(L, ala.wallet, now_ts=L.tip().timestamp)}
    assert "rank_owner" not in got2, "odznaka rangi przeżyła wygaśnięcie rangi!"
    print("  [OK] 5. Właściciel Legitymacji: vip z chain; po wygaśnięciu 30d odznaka gaśnie")

    # 6) local: uptime/webmaster/first_node z stats.json (oznaczone verify=local)
    st = {"uptime_hours": 1200.0, "site_created": True, "first_node_ever": True}
    gotl = {b["code"]: b for b in evaluate_badges(L, ala.wallet, stats=st)}
    assert {"host_100h", "host_1000h", "webmaster", "first_node"} <= set(gotl), set(gotl)
    assert "host_10kh" not in gotl
    assert all(gotl[c]["verify"] == "local" for c in
               ("host_100h", "host_1000h", "webmaster", "first_node"))
    gotn = {b["code"] for b in evaluate_badges(L, ala.wallet, stats=None)}
    assert not ({"host_100h", "webmaster", "first_node"} & gotn), "local bez stats ≠ odznaki"
    print("  [OK] 6. Strażnik Czasu I+II, Architekt, Założyciel = licznik lokalny "
          "(bez stats znikają — zero ściemy)")

    # 7) panel: zdobyte + zablokowane sumują się do katalogu; katalog ma grafiki i PL/EN
    pan = badge_panel(L, ala.wallet, stats=st)
    assert len(pan["earned"]) + len(pan["locked"]) == len(BADGE_CATALOG)
    for c, m in BADGE_CATALOG.items():
        assert m["icon"].endswith(".png") and m["name"] and m["en"], c
    print(f"  [OK] 7. panel: {len(pan['earned'])} zdobytych + {len(pan['locked'])} "
          "zablokowanych = cały katalog; ikony+PL/EN kompletne")

    print("\nSELFTEST: PASS ✅  chain/badges.py — odznaki D52:\n"
          "chain (ranga/donor/górnik/czuwający/ptak) liczone bit-w-bit; local (godziny,\n"
          "strona, pierwszy nod) uczciwie oznaczone; panel zdobyte+cele; zero fotoszopa.")
