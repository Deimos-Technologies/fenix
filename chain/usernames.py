# chain/usernames.py — USERNAME ON-CHAIN: identyfikacja ludzka zamiast walletów (D28, TX_ID_DECLARE 0x03)
"""
Wymaganie właściciela: „komunikacja nie przez wallet addr, tylko USERNAME — żeby każdego
dało się znaleźć w sieci". Filar nic niewart, jeśli user musi przepisywać FNX1a9f3… z karteczki.

Model (D28):
    TX_ID_DECLARE (0x03) — zwykły podpisany tx konta (sig z kluczy wallet = dowód własności);
    payload: {"v":1,"op":"claim|rename","name":"ala","avatar":"hex≤64B opcjonalnie"}
      claim  — rezerwuje username (pierwszy-come-first-served); koszt CLAIM_FEE (anty-squatting:
               kradzież wszystkich 3-literowych nazw musi KOSZTOWAĆ, inaczej boty zrobią to w dobę)
      rename — właściciel portfela zmienia nazwę (starą zwalnia NATYCHMIAST — ktoś inny może
               ją przejąć: to jest celowe, fair); koszt RENAME_FEE (taniej niż claim)
    Jeden wallet = JEDEN aktywny username (MVP; multi-alias = backlog).
    Regex = core.identity.valid_username (jedno źródło prawdy z fenix_boot — łańcuch i ISO
    nie mogą się rozjechać ani o znak).
    RANGA nie jest tu edytowalna (D28: tylko username+avatar user-side; rangi = TX_RANK_UP).
    TOFU anty-impersonacja = warstwa APP (messenger, M4); łańcuch daje tylko mapowanie.

Rejestr w Ledger: usernames: {name: wallet}. Replay/adopt_chain odtwarza jak pool.

Fee: amount = CLAIM_FEE/RENAME_FEE → standardowy split D15 (burn + skarbiec).
Selftest E2E: funding → claim → duplikat: odrzut → rename → stara nazwa wolna → obcy bierze
→ zła sygnatura/nazwa → regex-sync z core.identity → replay zachowuje rejestr.
"""
from __future__ import annotations

import json
import sys
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from chain.block import ISKRA                          # noqa: E402
from core.identity import valid_username               # noqa: E402

CLAIM_FEE = 1 * ISKRA              # 1 FNX (anty-squatting; dostroimy w M5 spec)
RENAME_FEE = ISKRA // 10           # 0.1 FNX
AVATAR_MAX_HEX = 128               # 64B — hash/off-chain ref avatara (D28); nie blob na-chain
OPS = ("claim", "rename")


class UsernameError(Exception):
    """Naruszenie rejestru nazw — jeden typ."""


def username_payload(op: str, name: str, avatar: str = "") -> str:
    if op not in OPS:
        raise UsernameError(f"op ∈ {OPS}")
    return json.dumps({"v": 1, "op": op, "name": name, "avatar": avatar},
                      separators=(",", ":"), sort_keys=True)


def parse_username_payload(raw: str) -> dict:
    try:
        p = json.loads(raw)
    except (ValueError, TypeError):
        raise UsernameError("payload: niepoprawny JSON") from None
    if not isinstance(p, dict) or p.get("v") != 1:
        raise UsernameError("payload: brak v=1")
    return p


def validate_username_payload(raw: str, names: dict, sender_wallet: str) -> tuple[str, str, str, int]:
    """Walidacja konsensusu. names: {name: wallet} (chain ∪ mempool, w tej kolejności).
    Zwraca (op, name, avatar, fee_required)."""
    p = parse_username_payload(raw)
    op = p.get("op")
    name = p.get("name")
    avatar = p.get("avatar", "")
    if op not in OPS:
        raise UsernameError(f"op musi być {OPS}")
    if not isinstance(name, str) or not valid_username(name):
        raise UsernameError("nazwa poza D28-regex (a-z0-9_- dł. 3-24, małe litery)")
    if not isinstance(avatar, str) or len(avatar) > AVATAR_MAX_HEX:
        raise UsernameError(f"avatar: hex ≤ {AVATAR_MAX_HEX} znaków (64B ref, nie obrazek!)")
    if avatar:
        try:
            bytes.fromhex(avatar)
        except ValueError:
            raise UsernameError("avatar: zły hex") from None
    owner_of_name = names.get(name)
    sender_has = [n for n, w in names.items() if w == sender_wallet]
    if op == "claim":
        if sender_has:
            raise UsernameError(f"wallet ma już username '{sender_has[0]}' (użyj rename)")
        if owner_of_name is not None:
            raise UsernameError(f"username '{name}' zajęty — pierwszy-come-first-served")
        return op, name, avatar, CLAIM_FEE
    # rename:
    if not sender_has:
        raise UsernameError("rename bez username — najpierw claim")
    if sender_has[0] == name:
        raise UsernameError("to już Twoja nazwa (rename na samą siebie)")
    if owner_of_name is not None and owner_of_name != sender_wallet:
        raise UsernameError(f"username '{name}' zajęty")
    return op, name, avatar, RENAME_FEE


def apply_username(names: dict, op: str, name: str, sender_wallet: str) -> None:
    """Mutacja roboczego rejestru (walidacja MUSI przejść wcześniej)."""
    if op == "rename":
        for n in [n for n, w in names.items() if w == sender_wallet]:
            del names[n]                      # stara nazwa wolna od razu (fair re-claim)
    names[name] = sender_wallet


# -------------------------------------------------------------------------- selftest E2E
if __name__ == "__main__":
    from core.identity import Identity
    from chain.ledger import Ledger, BLOCK_REWARD, ChainError
    from chain.block import Tx, TREASURY_WALLET_DEV, TX_ID_DECLARE, TX_TRANSFER, fee_split
    from chain.miner import mine

    print("chain/usernames.py — selftest E2E: rejestr username na prawdziwym ledgerze\n")
    TRE = TREASURY_WALLET_DEV
    L = Ledger(TRE)
    ala = Identity.generate("ala_unames")
    bob = Identity.generate("bob_unames")

    def kop(tag: str):
        tmpl = L.block_template(ala.wallet, zbits=2)
        won = mine(tmpl, max_tries=200_000)
        assert won is not None, f"mining nie trafił ({tag})"
        L.apply_block(won)

    # 1) funding + bob dostaje 3 FNX (potrzebne mu na claim później)
    for _ in range(4):
        kop("funding")
    t0 = Tx.build_signed(TX_TRANSFER, ala, bob.wallet, 3 * ISKRA, nonce=0)
    L.add_tx(t0)
    kop("fund-bob")
    assert L.balance_of(bob.wallet) == 3 * ISKRA
    print(f"  [OK] 1. funding: ala + bob 3 FNX na jego przyszły claim")

    # 2) claim "feniks-ala"
    tx = Tx.build_signed(TX_ID_DECLARE, ala, "FNX-NAMES", CLAIM_FEE, nonce=1,
                         payload=username_payload("claim", "feniks-ala", avatar="AB12CD"))
    L.add_tx(tx)
    assert "feniks-ala" not in L.usernames          # jeszcze w mempoolu
    kop("claim")
    assert L.usernames.get("feniks-ala") == ala.wallet
    print("  [OK] 2. claim: 'feniks-ala' → wallet ali (on-chain, po kopnięciu)")

    # 3) bob próbuje ukraść zajętą nazwę — odrzut w MEMPOOLU
    steal = Tx.build_signed(TX_ID_DECLARE, bob, "FNX-NAMES", CLAIM_FEE, nonce=0,
                            payload=username_payload("claim", "feniks-ala"))
    try:
        L.add_tx(steal)
        raise SystemExit("kradzież nazwy przeszła w mempoolu!")
    except ChainError as e:
        assert "zajęty" in str(e)
    print("  [OK] 3. kradzież zajętego username odrzucona (first-come-first-served)")

    # 4) drugi claim na TYM SAMYM walletcie = odrzut (jedno imię na wallet)
    again = Tx.build_signed(TX_ID_DECLARE, ala, "FNX-NAMES", CLAIM_FEE, nonce=2,
                            payload=username_payload("claim", "druga-nazwa"))
    try:
        L.add_tx(again)
        raise SystemExit("drugie imię na wallet przeszło!")
    except ChainError:
        pass
    print("  [OK] 4. drugi username na tym samym wallet odrzucony (użyj rename)")

    # 5) rename ali: feniks-ala → superala; stara nazwa natychmiast wolna
    ren = Tx.build_signed(TX_ID_DECLARE, ala, "FNX-NAMES", RENAME_FEE, nonce=2,
                          payload=username_payload("rename", "superala"))
    L.add_tx(ren)
    kop("rename")
    assert "feniks-ala" not in L.usernames and L.usernames.get("superala") == ala.wallet
    print("  [OK] 5. rename: feniks-ala → superala; stara nazwa zwolniona NATYCHMIAST")

    # 6) bob bierze zwolnioną "feniks-ala" — uczciwe przejęcie
    take = Tx.build_signed(TX_ID_DECLARE, bob, "FNX-NAMES", CLAIM_FEE, nonce=0,
                           payload=username_payload("claim", "feniks-ala"))
    L.add_tx(take)
    kop("re-claim")
    assert L.usernames.get("feniks-ala") == bob.wallet
    print("  [OK] 6. zwolniona nazwa uczciwie przejęta przez innego (fair)")

    # 7) karaluchy: złe op / zła nazwa / zły hex avatara / krzywy JSON
    for bad_pl, why in [
        (username_payload("claim", "ZlaNazwa"), "wielkie litery"),
        (username_payload("claim", "ab"), "za krótko"),
        (username_payload("claim", "x" * 25), "za długo"),
        ('{"v":1,"op":"hack","name":"okname"}', "zły op"),
        ('{"v":1,"op":"claim","name":"okname","avatar":"zz"}', "zły hex avatara"),
        ('not json', "krzywy JSON"),
    ]:
        try:
            validate_username_payload(bad_pl, L.usernames, bob.wallet)
            raise SystemExit(f"przeszło: {why}")
        except UsernameError:
            pass
    print("  [OK] 7. walidacja: wielkie litery/długość/op/hex/JSON — wszystko odrzucone")

    # 8) sync regex z core.identity (łańcuch i ISO nie mogą się rozjechać)
    import random, string
    rng = random.Random(7)
    for _ in range(300):
        s = "".join(rng.choice(string.ascii_letters + string.digits + "_-!@ ") for _ in range(rng.randint(0, 30)))
        try:
            validate_username_payload(username_payload("claim", s), {"taken_" + s: "W"}, "nowy-wallet-x")
            chain_ok = True
        except UsernameError as e:
            chain_ok = "zajęty" in str(e)
        assert chain_ok == valid_username(s) or (not valid_username(s) and not chain_ok), \
            f"rozjazd regexu dla {s!r}"
    print("  [OK] 8. fuzz 300 nazw: łańcuchowy regex ≡ core.identity (ani o znak rozjazdu)")

    # 9) salda: 8 bloków kopniętych przez alę; transfer 3 FNX do boba; claim+rename fee D15;
    #    D39: część „owner" fee transferu WRACA do ali (ona kopie bloki); fee ID_DECLARE
    #    (claim/rename) idzie do SKARBCA — kopacz go nie dostaje
    exp_ala = 8 * BLOCK_REWARD
    exp_ala -= 3 * ISKRA + fee_split(3 * ISKRA)[2]                        # transfer do boba
    exp_ala += fee_split(3 * ISKRA)[1]                                     # D39: kopacz odzyskuje
    exp_ala -= CLAIM_FEE + fee_split(CLAIM_FEE)[2]
    exp_ala -= RENAME_FEE + fee_split(RENAME_FEE)[2]
    assert L.balance_of(ala.wallet) == exp_ala, (L.balance_of(ala.wallet), exp_ala)
    exp_bob = 3 * ISKRA - CLAIM_FEE - fee_split(CLAIM_FEE)[2]
    assert L.balance_of(bob.wallet) == exp_bob, (L.balance_of(bob.wallet), exp_bob)
    print("  [OK] 9. ekonomia: CLAIM_FEE=1 FNX, RENAME_FEE=0.1 FNX rozliczone przez D15")

    # 10) replay: świeży ledger odtwarza rejestr identycznie
    L2 = Ledger(TRE)
    for b in L.chain[1:]:
        L2.apply_block(b)
    assert L2.usernames == L.usernames
    print("  [OK] 10. replay łańcucha: rejestr username bit-w-bit (fork/restart-safe)")

    print("\nSELFTEST: PASS ✅  username on-chain: claim/rename/re-claim/anty-squatting działają")
