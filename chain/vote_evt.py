# chain/vote_evt.py — VOTE_EVT 0x07: głos on-chain WYŁĄCZNIE dla statusu VOTER (D60)
"""
Analogia: urna przy bramie fabryki. Wpisać się do dziennika obecności (PoU, D58)
może każdy — ale do URNY podchodzi tylko ten, kto ma legitymację GŁOSUJĄCEGO:
30 dni obecności bez przerwy >72 h, pokrycie ≥80% dni, obecność świeża ≤72 h.
Legitymacji NIE kupuje się za FNX (fnx_spec §13: „głosu nie kupuje się",
„node nie wykopie reputacji szybciej niż zegar PoU") — zdobywa się ją zegarem.

Co ten plik WDROWAŻY (P25):
  • format + walidacja TX_VOTE_EVT (rezerwa spec §tx: 0x07),
  • rejestr ledger.votes: topic -> wallet -> choice (replay bit-w-bit),
  • JEDEN głos na temat na wallet — zmiana/duble = odrzut (MVP: głos trwały),
  • fee płaska antyspamowa (ROBOCZA — fnx_spec §12/P5), ppm-owner → skarbiec.

Czego ten plik NIE robi (uczciwie):
  • NIE weryfikuje „czy VOTER jest online" — głos podpisuje konto, nie obecność;
    status VOTER liczy się z rejestru PoU w chwili BLOKU (konsensus deterministyczny),
  • temat (topic) jest dowolnym hex64 — REJESTRACJA tematów (kto otwiera głosowanie,
    kiedy je zamyka, quorum k-z-n) to osobny kamień (P10 multi-sentinel i referenda
    dostaną tu rurę; MVP liczy jedynie samą bramkę VOTER + księgę głosów).
"""
from __future__ import annotations

import json
import re
import sys
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

# --- parametry konsensusu (fnx_spec §6/§13; fee = §12) ---
VOTE_FEE_ISKRY = 100                  # płaska fee antyspamowa (⚠️ ROBOCZA — fnx_spec §12/P5)
TOPIC_RE = re.compile(r"^[0-9a-f]{64}$")      # topic = zawsze hash (propozycja ban/nazwa…)
_CHOICE_MAX = 64


class VoteError(Exception):
    """Błędy głosu — jedna klasa, czytelne komunikaty po polsku."""


# ---------------------------------------------------------------- core / payload
def vote_core(topic: str, choice: str) -> dict:
    return {"v": 1, "op": "vote", "topic": topic, "choice": choice}


def _validate_core(core: dict) -> None:
    if not isinstance(core, dict) or core.get("v") != 1 or core.get("op") != "vote":
        raise VoteError("core: brak v=1/op=vote")
    t = core.get("topic")
    if not isinstance(t, str) or not TOPIC_RE.match(t):
        raise VoteError("topic ma być hex64 (hash tematu — nie dowolny napis)")
    c = core.get("choice")
    if not isinstance(c, str) or not (1 <= len(c) <= _CHOICE_MAX) or \
            any(ord(ch) < 32 for ch in c):
        raise VoteError(f"choice: 1..{_CHOICE_MAX} znaków, bez znaków sterujących")


def vote_payload(topic: str, choice: str) -> str:
    core = vote_core(topic, choice)
    _validate_core(core)
    from chain.block import canon
    return canon(core).decode()            # ten sam kanon co wszędzie (sort_keys, bytes)


def parse_payload(raw: str) -> dict:
    try:
        p = json.loads(raw)
    except (ValueError, TypeError):
        raise VoteError("payload: niepoprawny JSON") from None
    _validate_core(p)
    return p


def validate_vote_payload(raw: str, votes_reg: dict, sender: str) -> tuple[str, str]:
    """Mempool+blok: format + JEDEN głos na temat na wallet (dedup vs chain+mempool
    — rejestr wirtualny łączonego widoku przekazuje wołający). Zwraca (topic, choice)."""
    p = parse_payload(raw)
    if votes_reg.get(p["topic"], {}).get(sender) is not None:
        raise VoteError(f"topic {p['topic'][:12]}…: głos tego walletu już oddany "
                        "(1 głos / temat / wallet — MVP: głos trwały)")
    return p["topic"], p["choice"]


def apply_vote(votes_reg: dict, topic: str, wallet: str, choice: str) -> None:
    votes_reg.setdefault(topic, {})[wallet] = choice


def tally(votes_reg: dict, topic: str) -> dict:
    """Podliczenie tematu (podgląd deterministyczny — nie zmienia stanu)."""
    m = votes_reg.get(topic, {})
    out: dict = {}
    for w, c in m.items():
        out[c] = out.get(c, 0) + 1
    return {"topic": topic, "voters": len(m), "choices": out}


# ---------------------------------------------------------------- selftest
if __name__ == "__main__":
    import tempfile
    import time

    print("chain/vote_evt.py — selftest: VOTE_EVT 0x07 (D60) — urna tylko dla VOTER\n")
    from core.identity import Identity
    from chain.ledger import Ledger, BLOCK_REWARD
    from chain.block import Tx, TX_VOTE_EVT, fee_split as _fs
    from chain.miner import mine
    from chain import pou as _pou

    now = int(time.time())
    ida = Identity.generate("vote_ala")
    bob = Identity.generate("vote_bob")

    # 1) payload/core roundtrip + brudne wejścia odrzucane
    tp = "ab" * 32
    assert parse_payload(vote_payload(tp, "tak")) == vote_core(tp, "tak")
    for zle in ({"v": 2, "op": "vote", "topic": tp, "choice": "tak"},
                {"v": 1, "op": "ban", "topic": tp, "choice": "tak"},
                vote_core("to-nie-hex", "tak"),
                vote_core(tp, ""),
                vote_core(tp, "x" * 65),
                vote_core(tp, "zły\nwybór")):
        try:
            _validate_core(zle)
            raise SystemExit(f"brudne core przeszło: {zle}")
        except VoteError:
            pass
    print("  [OK] 1. core kanoniczne; brudne wejścia (v/op/topic/choice) odrzucone")

    # 2) dedup: drugi głos tego walletu w tym temacie = odmowa (chain ∪ mempool)
    reg: dict = {}
    t2, c2 = validate_vote_payload(vote_payload(tp, "tak"), reg, ida.wallet)
    apply_vote(reg, t2, ida.wallet, c2)
    try:
        validate_vote_payload(vote_payload(tp, "nie"), reg, ida.wallet)
        raise SystemExit("zmiana głosu przeszła!")
    except VoteError as e:
        assert "1 głos" in str(e)
    assert validate_vote_payload(vote_payload(tp, "nie"), reg, bob.wallet)[1] == "nie"  # inny wallet OK
    print("  [OK] 2. jeden głos/temat/wallet (MVP trwały); inny wallet głosuje normalnie")

    # 3) E2E łańcuch: GHOST nie głosuje (brama VOTER), zła fee = odmowa
    L = Ledger()
    won = mine(L.block_template(ida.wallet, zbits=2), max_tries=200_000)
    assert won
    L.apply_block(won)
    txv = Tx.build_signed(TX_VOTE_EVT, ida, "", VOTE_FEE_ISKRY, 0,
                          payload=vote_payload(tp, "tak"))
    try:
        L.add_tx(txv)
        raise SystemExit("GHOST zagłosował!")
    except Exception as e:
        assert "VOTER" in str(e), e
    print("  [OK] 3. brama VOTER: ghost odrzucony w mempoolu (PoU 30d albo nic)")

    # 4) VOTER (31 dni obecności w rejestrze) głosuje → blok → księga + fee→skarbiec
    wins = [(now - d * 86400) // _pou.WINDOW_S for d in range(31)]
    L.pou[ida.wallet] = {"w": sorted(wins), "last_ts": now}
    st = _pou.status_of(L.pou, ida.wallet, now)
    assert st["voter"], st
    tre0 = L.balance_of(L.treasury)
    L.add_tx(txv)
    won2 = mine(L.block_template(ida.wallet, zbits=2), max_tries=200_000)
    assert won2
    L.apply_block(won2)
    assert L.votes[tp][ida.wallet] == "tak"
    _b, _o, _t = _fs(VOTE_FEE_ISKRY)
    assert L.balance_of(L.treasury) == tre0 + _o, "ppm głosu nie trafiło do skarbca"
    assert won2.txs[0].amount == BLOCK_REWARD, "kopacz dostał fee z głosu — usługa rejestru!"
    assert tally(L.votes, tp) == {"topic": tp, "voters": 1, "choices": {"tak": 1}}
    print("  [OK] 4. VOTER głosuje: księga on-chain, tally deterministyczny, ppm→skarbiec, kopacz NIC")

    # 5) zła fee / dublet w bloku = odmowa
    tx_bad = Tx.build_signed(TX_VOTE_EVT, ida, "", VOTE_FEE_ISKRY + 1, 1,
                             payload=vote_payload("cd" * 32, "tak"))
    try:
        L.add_tx(tx_bad)
        raise SystemExit("głos ze złą fee przeszedł!")
    except Exception as e:
        assert "fee" in str(e)
    tx_dup = Tx.build_signed(TX_VOTE_EVT, ida, "", VOTE_FEE_ISKRY, 1,
                             payload=vote_payload(tp, "nie"))
    try:
        L.add_tx(tx_dup)
        raise SystemExit("dublet głosu przeszedł mempool!")
    except Exception as e:
        assert "1 głos" in str(e)
    print("  [OK] 5. zła fee = odmowa; dublet (chain∪mempool) = odmowa")

    # 6) tombstone: zbanowany VOTER nie głosuje (D18/D47 — martwy dla wszystkiego)
    import chain.ban_evt as _be
    from chain.ban_evt import ban_core, attest_entry as _att, ban_payload as _bp, \
        evidence_hash_of
    att_ids = [Identity.generate(f"vote_att{i}") for i in range(3)]
    for w in att_ids:
        _be.register_dev_attestor(w)
    bc = ban_core(ida.wallet, "0x11", "Test tombstone.", "Tombstone test.",
                  evidence_hash_of({"c": 60}))
    tx_ban = Tx(0x06, "", ida.wallet, 0, 0, payload=_bp(bc, [_att(w, bc) for w in att_ids]))
    L.add_tx(tx_ban)
    won3 = mine(L.block_template(bob.wallet, zbits=2), max_tries=200_000)
    assert won3
    L.apply_block(won3)
    assert _be.is_banned(L.bans, ida.wallet)
    tx9 = Tx.build_signed(TX_VOTE_EVT, ida, "", VOTE_FEE_ISKRY, 1,
                          payload=vote_payload("ef" * 32, "tak"))
    try:
        L.add_tx(tx9)
        raise SystemExit("ZBANOWANY voter zagłosował!")
    except Exception as e:
        assert "zbanowany" in str(e)
    print("  [OK] 6. tombstone: zbanowany VOTER martwy także dla urny (jedyna droga: wykup)")

    # 7) replay-strażnik: łańcuch z głosem BEZ historii attestation NIE jest ważny —
    # obcy węzeł odtwarza PoU z zerowych attests → brama VOTER zamknięta (anty-obchód)
    L7 = Ledger()
    try:
        L7.adopt_chain(L.chain)
        raise SystemExit("replay głosu bez historii PoU przeszedł!")
    except Exception as e:
        assert "VOTER" in str(e), f"inny powód: {e}"
    snap = L.snapshot()
    assert "votes" in snap and snap["votes"][tp][ida.wallet] == "tak"
    print("  [OK] 7. replay: syn-chirurgiczny register NIE przetrwa adopt_chain (brama liczy z chain)")
    print("           (w realu: 30 dni attests idzie W TX-ach 0x04 — replay odtwarza VOTER właściwie)")

    print("\nSELFTEST: PASS ✅  chain/vote_evt.py — VOTE_EVT 0x07 (D60):\n"
          "urna tylko dla VOTER (30 dni PoU), 1 głos/temat/wallet, fee ppm→skarbiec,\n"
          "kopacz NIC, tombstone martwy, replay-strażnik czujny. Rejestracja tematów +\n"
          "zamykanie głosowań = P10/multi-sentinel (rura gotowa).")
