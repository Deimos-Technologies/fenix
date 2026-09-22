# chain/contact_ref.py — USERNAME → KONTAKT FNXS1 ON-CHAIN (P21, TX_CONTACT_REF 0x13)
"""
Wymaganie użytkowe: w czacie wpisujesz NICK, nie wklejasz adresu FNXS1 z karteczki.
Łańcuch ma już mapowanie name → wallet (D28, usernames.py). Brakowało zamknięcia
pętli: wallet → JAWNY adres kontaktowy FNXS1 (sig‖x pub + checksum), żeby komunikator
mógł rozwiązać nick → adres i zaszyfrować E2E BEZ ręcznej wymiany adresów.

Model (analogia: tabliczka na skrzynce — właściciel sam ją wiesza i zdejmuje):
    TX_CONTACT_REF (0x13) — podpisany tx konta (sig = dowód własności walletu);
    payload: {"v":1,"op":"set|del","addr":"FNXS1…≈107 znaków"}
      set — publikuje/nadpisuje adres kontaktowy walletu (każda zmiana = nowy ref;
            STARY kontakt nie działa — to celowe: wypowiedź adresu jest jawna)
      del — zdejmuje tabliczkę (nick nadal Twój, ale kontaktu brak → resolve = None)
    Jeden wallet = MAKS jeden aktywny ref (nadpis jest tani, squatting nie istnieje —
    ref jest per-wallet, nie per-nazwa, więc NICZEGO nie można okupować).
    Fee: CONTACT_FEE (jak RENAME_FEE), split D15 → skarbiec (usługa rejestru;
    nie jest to praca kopacza — spójne z ID_DECLARE, D39).

PRYWATNOŚĆ uczciwie: publikacja ref jest JAWNA (każdy czyta mapowanie wallet→kontakt).
Kto chce prywatnego kontaktu — NIE publikuje ref i wymienia adres drugim kanałem
(tak jak dotychczas). Ref to WYGODA, nie obowiązek.

Rejestr w Ledger: contact_refs: {wallet: addr}. Replay/adopt odtwarza bit-w-bit.
Walidacja addr: decode_stealth_address z core.identity (jedno źródło codec FNXS1).
"""
from __future__ import annotations

import json
import sys
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from chain.block import ISKRA                          # noqa: E402
from core.identity import (IdentityError,               # noqa: E402
                           decode_stealth_address)

CONTACT_FEE = ISKRA // 10          # 0.1 FNX (jak RENAME_FEE; usługa rejestru → skarbiec)
OPS = ("set", "del")
ADDR_MAX = 160                     # FNXS1 + margines (codec ma ~141 zn.; twardy sufit)


class ContactRefError(Exception):
    """Naruszenie rejestru kontaktów — jeden typ."""


def contact_payload(op: str, addr: str = "") -> str:
    if op not in OPS:
        raise ContactRefError(f"op ∈ {OPS}")
    return json.dumps({"v": 1, "op": op, "addr": addr},
                      separators=(",", ":"), sort_keys=True)


def parse_contact_payload(raw: str) -> dict:
    try:
        p = json.loads(raw)
    except (ValueError, TypeError):
        raise ContactRefError("payload: niepoprawny JSON") from None
    if not isinstance(p, dict) or p.get("v") != 1:
        raise ContactRefError("payload: brak v=1")
    return p


def validate_contact_payload(raw: str, sender_wallet: str) -> tuple[str, str, int]:
    """Walidacja konsensusu. Zwraca (op, addr, fee_required).
    refs nie jest potrzebne: slot jest per-wallet (brak kolizji między walletami)."""
    p = parse_contact_payload(raw)
    op = p.get("op")
    addr = p.get("addr", "")
    if op not in OPS:
        raise ContactRefError(f"op musi być {OPS}")
    if op == "set":
        if not isinstance(addr, str) or not addr or len(addr) > ADDR_MAX:
            raise ContactRefError("addr: pusty albo ponad-wymiarowy")
        try:
            decode_stealth_address(addr)        # codec FNXS1 = jedyne źródło prawdy
        except IdentityError as e:
            raise ContactRefError(f"addr nie jest FNXS1: {e}") from None
    else:                                       # del: addr musi być PUSTY (bez półśrodków)
        if addr:
            raise ContactRefError("del: addr musi być pusty (zdejmujemy całość)")
    return op, addr if op == "set" else "", CONTACT_FEE


def apply_contact_ref(refs: dict, op: str, addr: str, sender_wallet: str) -> None:
    """Mutacja roboczego rejestru (walidacja MUSI przejść wcześniej)."""
    if op == "del":
        refs.pop(sender_wallet, None)
    else:
        refs[sender_wallet] = addr


# -------------------------------------------------------------------------- selftest E2E
if __name__ == "__main__":
    from core.identity import Identity, encode_stealth_address
    from chain.block import (Tx, TREASURY_WALLET_DEV, TX_CONTACT_REF, TX_TRANSFER)
    from chain.ledger import Ledger, ChainError
    from chain.miner import mine

    print("chain/contact_ref.py — selftest E2E: ref na prawdziwym ledgerze (P21)\n")
    TRE = TREASURY_WALLET_DEV
    L = Ledger(TRE)
    ala, bob, ceo = (Identity.generate(n) for n in ("ala_ref", "bob_ref", "ceo_ref"))

    def kop(tag: str):
        tmpl = L.block_template(ala.wallet, zbits=2)
        won = mine(tmpl, max_tries=200_000)
        assert won is not None, f"mining nie trafił ({tag})"
        L.apply_block(won)

    # 1) funding + claim username ali (pętla nick→wallet→kontakt!)
    for _ in range(6):
        kop("funding")
    from chain.usernames import username_payload
    L.add_tx(Tx.build_signed(0x03, ala, "FNX-NAMES", 1 * ISKRA, nonce=0,
                             payload=username_payload("claim", "ala_ludzka")))
    kop("claim")
    print("  [OK] 1. funding + username 'ala_ludzka' (pętla nick → wallet gotowa)")

    # 2) ala publikuje ref (wallet → FNXS1); resolve: nick → wallet → adres
    addr_ala = encode_stealth_address(ala.sig_pub_b, ala.x_pub_b)
    t_set = Tx.build_signed(TX_CONTACT_REF, ala, "FNX-CONTACT", CONTACT_FEE, nonce=1,
                            payload=contact_payload("set", addr_ala))
    L.add_tx(t_set)
    kop("set")
    assert L.contact_refs[ala.wallet] == addr_ala
    wallet_z_nicka = L.usernames["ala_ludzka"]
    assert L.contact_refs[wallet_z_nicka] == addr_ala, "pętla nick→wallet→kontakt zerwana"
    print("  [OK] 2. set: nick → wallet → FNXS1 działa on-chain (P21 zamknięte)")

    # 3) zła forma: nie-FNXS1 / ponadwymiar / del z adresem → mempool odrzuca
    roxy = [
        contact_payload("set", "FNX1a9f-to-nie-kontakt"),
        contact_payload("set", "F" * (ADDR_MAX + 1)),
        contact_payload("del", addr_ala),
        contact_payload("set", ""),
    ]
    for i, bad in enumerate(roxy):
        try:
            L.add_tx(Tx.build_signed(TX_CONTACT_REF, ala, "FNX-CONTACT", CONTACT_FEE,
                                     nonce=2 + i, payload=bad))
            raise SystemExit(f"zły payload przeszedł (#{i})!")
        except ChainError:
            pass
    print("  [OK] 3. nie-FNXS1 / ponadwymiar / del-z-adresem / pusty set → wszystko odrzucone")

    # 4) złe fee i zła sygnatura (kradzież cudzego walletu) → odrzuty
    try:
        L.add_tx(Tx.build_signed(TX_CONTACT_REF, ala, "FNX-CONTACT", CONTACT_FEE - 1,
                                 nonce=2, payload=contact_payload("set", addr_ala)))
        raise SystemExit("zaniżone fee przeszło!")
    except ChainError as e:
        assert "fee" in str(e)
    ceo_p = contact_payload("set", encode_stealth_address(ceo.sig_pub_b, ceo.x_pub_b))
    fake = Tx.build_signed(TX_CONTACT_REF, ceo, "FNX-CONTACT", CONTACT_FEE, nonce=0,
                           payload=ceo_p)
    fake.sender = ala.wallet                       # podstawiony wallet ≠ klucze
    try:
        L.add_tx(fake)
        raise SystemExit("kradzież tabliczki przeszła!")
    except ChainError as e:
        assert "podpis" in str(e)
    print("  [OK] 4. zaniżone fee + ref z podstawionym walletem (fałszywy sig) → odrzuty")

    # 5) nadpis (set na set) + del: stary kontakt przestaje działać Jawnie
    alt = Identity.generate("ala_ref_alt")
    addr_ala2 = encode_stealth_address(alt.sig_pub_b, alt.x_pub_b)   # nowa tabliczka
    L.add_tx(Tx.build_signed(TX_CONTACT_REF, ala, "FNX-CONTACT", CONTACT_FEE, nonce=2,
                             payload=contact_payload("set", addr_ala2)))
    kop("re-set")
    assert L.contact_refs[ala.wallet] == addr_ala2
    L.add_tx(Tx.build_signed(TX_CONTACT_REF, ala, "FNX-CONTACT", CONTACT_FEE, nonce=3,
                             payload=contact_payload("del")))
    kop("del")
    assert ala.wallet not in L.contact_refs, "del nie zdjął tabliczki"
    print("  [OK] 5. nadpis działa; del zdejmuje ref (nick zostaje, kontakt gaśnie)")

    # 6) ekonomia: fee z ref → skarbiec (jak ID_DECLARE), kopacz NIE dostaje (to usługa).
    #    Kontrolny TRANSFER nie zmienia skarbca (D39 — jego fee idzie do kopacza).
    tre_before = L.balance_of(TRE)
    t_xfer = Tx.build_signed(TX_TRANSFER, ala, bob.wallet, ISKRA, nonce=4)
    L.add_tx(t_xfer)
    kop("kontrolny-transfer")
    assert L.balance_of(TRE) == tre_before, \
        "skarbiec zmienił się od transferu (łamiemy D39!)"
    assert tre_before > 0, "skarbiec ma mieć fee z usług rejestru (claim+set+re-set+del)"
    print(f"  [OK] 6. skarbiec = tylko usługi rejestru ({tre_before} iskier); transfer = 0 (D39)")

    # 7) replay: świeży ledger odtwarza ref bit-w-bit
    L2 = Ledger(TRE)
    for b in L.chain[1:]:
        L2.apply_block(b)
    assert L2.contact_refs == L.contact_refs and L2.usernames == L.usernames
    print("  [OK] 7. replay/adopt: rejestr ref identyczny bit-w-bit")

    print("\nSELFTEST: PASS ✅  chain/contact_ref.py — nick→wallet→FNXS1 na-chain (P21),\n"
          "tabliczka = Twoja własność (sig), wypowiedź jawna, skarbiec z fee (D39-spójne)")
