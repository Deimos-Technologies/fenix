# chain/ban_evt.py — BANY ON-CHAIN z KONSENSUSEM k-z-n (TX_BAN_EVT 0x06; D18/D22/D30)
"""
Rejestr banów na łańcuchu (tombstone). Analogia: **czerwona plomba na drzwiach —
widują ją WSZYSCY węzły na zawsze**, a stawia ją wyłącznie „rada nadzorcza"
(k attestorów z n znanych), nigdy jeden człowiek i nigdy automat sam z siebie.

Model (ban_policy.md v1.0 + D18/D22/D30):
    TX_BAN_EVT (0x06) ma DWA tryby:
      op="ban"   — wpis tombstone. sender="" (wydarzenie systemowe jak TX_RING),
                   amount=0, podpis tx BRAK; moc dowodowa = KROPKA attestorów
                   w payload: ≥BAN_K różnych podpisów Ed25519 pod KANONICZNYM
                   core. Każdy wpis kropki jest samowystarczalny: {signer,
                   sig_pub, x_pub, sig} — węzeł sprawdza sig_pub‖x_pub → wallet
                   (ta sama wiązanka co Tx.verify_signature) + że signer ∈
                   ATTESTOR_WALLETS + że Ed25519 się zgadza. Bez kluczy
                   z kropki nikt nie sfałszuje bana (Filar 1).
      op="unban" — wykup. Jedyna sztuka: podpisuje GO ZBANOWANY wallet
                   (dowód, że właściciel kluczy wnioskuje), amount =
                   UNBAN_FEE_ISKRY → CAŁY do skarbca (D30). Jeden wykup na
                   wallet w całej historii; re-ban = już NA ZAWSZE (D18).
    Żadne żółte/pomarańczowe flagi NIE lądują na chain (ban_policy §3) —
    to jest rejestr WYŁĄCZNIE werdyktów red z k-z-n + hash dowodów.

Dlaczego k-z-n przez treasury-podpunkt DEV (ATTESTOR_WALLETS)?
    Registry attestorów MUSI być stałe konsensusu (jak genesis): inaczej dwa
    węzły spłacałyby różne bany. W tej wersji: pusta lista + dev-hook dla
    testów (moduł NIE przyjmie żadnego bana dopóki kropka nie zostanie
    zaszuta wydaniem). Prawdziwa kropka = zimne klucze ownera + rotacja
    k-z-n on-chain = backlog (P25, D14).

Wykup — uczciwe ograniczenia tej wersji (NIE ukrywamy):
    D30 każe 1 000 000 USD w FNX przez escrow multisig 2-z-3 + timelocki
    + 30 dni decyzji admina (odmowa/timeout = zwrot 99%). W tej wersji:
    UNBAN_FEE_ISKRY = stała ROBOCZA (§12 fnx_spec / P5 — jak ceny rang),
    płatność wprost do skarbca, bez escrow. Escrow + oracle kursu = backlog.

Anti-replay / anti-double-ban: bany trzymamy w rejestrze per wallet; drugi
ban aktywnego walletu lub powtórzony tx odpada (stan, nie pamięć txid).
"""
from __future__ import annotations

import hashlib
import json
import sys
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from chain.block import ISKRA, canon                     # noqa: E402
from core.crypto.fenix_crypto import wallet_address      # noqa: E402

BAN_K = 3                              # wymagane podpisy attestorów (k z n)
BAN_N = 5                              # wielkość kropki dev (fnx_spec §9)
ATTESTOR_WALLETS: set[str] = set()     # DEV-pusto; produkcja: zaszute wydaniem (P25)
UNBAN_FEE_ISKRY = 100 * ISKRA          # ⚠ ROBOCZA kwota wykupu (D30→oracle; §12/P5)
REASON_MAX = 280                       # PL i EN każde max tyle znaków (czytelny tombstone)
EVIDENCE_HEX = 64                      # blake2s-256 hex hash paczki dowodów

# Kody red z docs/ban_codes.txt (TAM jest rejestr żelazny; tu tylko kopia do
# konsensusu — zmiana kodu = nowa wersja ban_codes + 14 dni publikacji, ToS §11).
# code -> (nazwa, domyślne uzasadnienie PL, domyślne uzasadnienie EN);
# uzasadnienia w core MOGĄ być dłuższe/szczegółowe — te są minimem czytelności.
REASONS_RED: dict[str, tuple[str, str, str]] = {
    "0x11": ("PROTO_FLOOD",
             "Zalewanie sieci masowym ruchem (DoS wewnętrzny).",
             "Volumetric flooding of the network (internal DoS)."),
    "0x12": ("INVALIDTAG_STORM",
             "Masowe ramki z błędnymi podpisami/AEAD.",
             "Mass frames with invalid signatures/AEAD tags."),
    "0x15": ("REPLAY_ATTACK",
             "Odtwarzanie wcześniej zapisanych ramek.",
             "Replaying previously recorded frames."),
    "0x21": ("ROUTE_LEAKAGE",
             "Wyciąganie ruchu poza trasę Fenix (k≥3 potwierdzeń z regionów).",
             "Routing Fenix traffic outside the network (k≥3 region confirmations)."),
    "0x22": ("ONION_SKIPPING",
             "Pomijanie/zdejmowanie warstw cebuli niezgodnie z rolą hopa.",
             "Skipping/peeling onion layers beyond the hop's role."),
    "0x24": ("ECLIPSE_ATTEMPT",
             "Otoczenie ofiary samymi własnymi peerami (izolacja).",
             "Surrounding a victim with own peers (eclipse)."),
    "0x25": ("BOOTSTRAP_SPOOF",
             "Podszywanie pod seed/listy startowe sieci.",
             "Spoofing the network bootstrap/seeds."),
    "0x31": ("SYBIL_RING",
             "Pierścień skoordynowanych tożsamości (Sybil).",
             "Coordinated ring of identities (Sybil)."),
    "0x32": ("IDENTITY_THEFT",
             "Podszywanie pod cudzą tożsamość.",
             "Impersonating another identity."),
    "0x34": ("WITNESS_CARTEL",
             "Zmowa świadków PoU (wzajemne fałszerstwa attestation).",
             "Cartel of PoU witnesses (mutual attestation forgery)."),
    "0x42": ("DOUBLE_SPEND",
             "Próba podwójnego wydania tego samego wejścia (dowód matematyczny).",
             "Double-spend attempt of the same input (mathematical proof)."),
    "0x44": ("MINING_CLAIM_THEFT",
             "Przepisywanie cudzych bloków/nagród na siebie.",
             "Re-signing others' blocks/rewards to oneself."),
    "0x45": ("CHECKPOINT_FORGE",
             "Fałszowanie podpisów progowych checkpointów.",
             "Forging threshold checkpoint signatures."),
    "0x54": ("DOXXING",
             "Publikowanie danych osobowych (meta + zgłoszenia ofiar).",
             "Publishing personal data (meta pattern + victim reports)."),
    "0x55": ("CSAM_ALERT",
             "Dopasowanie z rejestru hashy (treści NIGDY nieotwierane).",
             "Hash-registry match (content NEVER opened)."),
    "0x56": ("MALWARE_SEEDING",
             "Dystrybucja binariów z rejestru hashy niebezpiecznych.",
             "Seeding binaries from the dangerous-hash registry."),
    "0x57": ("PHISH_KIT",
             "Wzorzec kampanii phishingowej (meta; treść nieotwierana).",
             "Phishing campaign pattern (meta; content never opened)."),
    "0x63": ("FAKE_ADMIN",
             "Podszywanie pod Administrację (podpisy, kanały).",
             "Impersonating the Administration (signatures, channels)."),
}
OPS = ("ban", "unban")


class BanEvtError(Exception):
    """Naruszenie rejestru banów — jeden typ (jak UsernameError/ContactRefError)."""


# ---------------------------------------------------------------- dev-hook (P25)
def register_dev_attestor(identity) -> str:
    """Rejestruje wallet jako attestora k-z-n. WYŁĄCZNIE dev/test — produkcja
    ma listę zaszutą wydaniem (P25/D14); hook zostawiamy, by selftest E2E
    mógł zbudować kropkę na świeżych tożsamościach."""
    ATTESTOR_WALLETS.add(identity.wallet)
    return identity.wallet


def register_dev_attestor_wallet(wallet: str) -> str:
    """Jak wyżej, ale z SAMEGO adresu publicznego (D55): demon przy starcie zna
    wyłącznie wallet Deimosa z publicznego pliku admin_attestor.json — klucz
    prywatny śpi zaszyfrowany w admin.ks i demona nie dotyczy. Samo członkostwo
    w rosterze NIE daje władzy: kropka liczy podpisy Ed25519 k-z-n, więc wpis
    bez klucza prywatnego jest martwy (jak tabliczka z cudzym nazwiskiem przy
    skrzynce — listonosz i tak sprawdza podpis, nie napis)."""
    if not (isinstance(wallet, str) and wallet.startswith("FNX1") and len(wallet) >= 30):
        raise BanEvtError("register_dev_attestor_wallet: to nie wygląda na wallet FNX")
    ATTESTOR_WALLETS.add(wallet)
    return wallet


# ---------------------------------------------------------------- dowody
def evidence_hash_of(bundle: dict) -> str:
    """Hash paczki dowodów (karty zdarzeń wg D5 — meta, nie treści!). Na chain
    trafia WYŁĄCZNIE ten hash; pełna paczka zostaje u attestorów/operatora."""
    return hashlib.blake2s(canon(bundle)).hexdigest()


# ---------------------------------------------------------------- core + podpisy
def ban_core(wallet: str, code: str, reason_pl: str, reason_en: str,
             evidence: str) -> dict:
    """Kanoniczny rdzeń werdyktu — DOKŁADNIE ten obiekt podpisują attestorzy i
    DOKŁADNIE ten waliduje konsensus (jeden ciąg bajtów w całej sieci)."""
    _validate_core_fields({"v": 1, "op": "ban", "wallet": wallet, "code": code,
                           "reason_pl": reason_pl, "reason_en": reason_en,
                           "evidence": evidence})
    return {"v": 1, "op": "ban", "wallet": wallet, "code": code,
            "reason_pl": reason_pl, "reason_en": reason_en, "evidence": evidence}


def _validate_core_fields(core: dict) -> None:
    if not isinstance(core, dict):
        raise BanEvtError("core: ma być obiektem")
    if core.get("v") != 1 or core.get("op") != "ban":
        raise BanEvtError("core: brak v=1/op=ban")
    w = core.get("wallet")
    if not isinstance(w, str) or not w.startswith("FNX1"):
        raise BanEvtError("core: wallet ma zaczynać się od FNX1")
    if core.get("code") not in REASONS_RED:
        raise BanEvtError(f"core: kod musi być red z ban_codes ({core.get('code')!r} nie jest)")
    for k in ("reason_pl", "reason_en"):
        r = core.get(k)
        if not isinstance(r, str) or not r or len(r) > REASON_MAX:
            raise BanEvtError(f"core: {k} puste albo > {REASON_MAX} znaków")
    ev = core.get("evidence")
    if not isinstance(ev, str) or len(ev) != EVIDENCE_HEX or not all(
            c in "0123456789abcdef" for c in ev):
        raise BanEvtError("core: evidence ma być 64-hex (blake2s paczki dowodów)")


def attest_entry(identity, core: dict) -> dict:
    """Wpis kropki: podpis attestora nad kanonicznym core + JAWNE klucze pub
    (węzeł sam wiąże sig_pub‖x_pub → wallet, jak w Tx.verify_signature)."""
    _validate_core_fields(core)
    return {"signer": identity.wallet,
            "sig_pub": identity.sig_pub_b.hex(),
            "x_pub": identity.x_pub_b.hex(),
            "sig": identity.sign(canon(core)).hex()}


def ban_payload(core: dict, entries: list[dict]) -> str:
    _validate_core_fields(core)
    if not isinstance(entries, list) or not entries:
        raise BanEvtError("payload: potrzebna lista wpisów kropki")
    return json.dumps({"v": 1, "op": "ban", "core": core, "sigs": entries},
                      separators=(",", ":"), sort_keys=True)


def unban_payload() -> str:
    """Wykup podpisuje sam zbanowany wallet (sender = dowód własności kluczy)."""
    return json.dumps({"v": 1, "op": "unban"}, separators=(",", ":"), sort_keys=True)


def parse_ban_payload(raw: str) -> dict:
    try:
        p = json.loads(raw)
    except (ValueError, TypeError):
        raise BanEvtError("payload: niepoprawny JSON") from None
    if not isinstance(p, dict) or p.get("v") != 1:
        raise BanEvtError("payload: brak v=1")
    return p


def verify_entry(entry: dict, core: dict) -> bool:
    """Jeden wpis kropki: wiązanka kluczy do walletu + podpis Ed25519 pod core."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        if wallet_address(bytes.fromhex(entry["sig_pub"]),
                          bytes.fromhex(entry["x_pub"])) != entry["signer"]:
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["sig_pub"])) \
            .verify(bytes.fromhex(entry["sig"]), canon(core))
        return True
    except (ValueError, InvalidSignature, KeyError, TypeError):
        return False


def validate_ban_payload(raw: str, bans: dict, sender: str = "",
                         attestors: set[str] | None = None) -> tuple[str, str]:
    """Walidacja konsensusu przeciw roboczemu rejestrowi `bans`.
    Zwraca (op, wallet-cełu). Dla op='unban' sender MUSI być podany = wallet
    płacący (weryfikacja podpisu tx robi resztę w ledgerze)."""
    roster = ATTESTOR_WALLETS if attestors is None else attestors
    p = parse_ban_payload(raw)
    op = p.get("op")
    if op not in OPS:
        raise BanEvtError(f"op musi być {OPS}")
    if op == "unban":
        if not sender:
            raise BanEvtError("unban: wymagany sender (wykup podpisuje właściciel)")
        e = bans.get(sender)
        if not e or not e.get("active"):
            raise BanEvtError("unban: ten wallet nie jest zbanowany (nie ma czego wykupić)")
        if e.get("unban_used"):
            raise BanEvtError("unban: wykup już wykorzystany — re-ban jest NA ZAWSZE (D18)")
        return "unban", sender
    # ---------------- op == "ban": weryfikacja kropki k-z-n ----------------
    core = p.get("core")
    _validate_core_fields(core)
    wallet = core["wallet"]
    if bans.get(wallet, {}).get("active"):
        raise BanEvtError("wallet już jest zbanowany (anti-replay / anti-double-ban)")
    sigs = p.get("sigs")
    if not isinstance(sigs, list):
        raise BanEvtError("payload: brak listy sigs")
    ok: set[str] = set()
    for entry in sigs:
        if not isinstance(entry, dict):
            continue
        signer = entry.get("signer", "")
        if signer in ok or signer not in roster:
            continue                                # obcy albo powtórzony — nie liczymy
        if verify_entry(entry, core):
            ok.add(signer)
    if len(ok) < BAN_K:
        raise BanEvtError(f"kropka za mała: {len(ok)}/{BAN_K} ważnych podpisów attestorów")
    return "ban", wallet


# ---------------------------------------------------------------- mutacje rejestru
def apply_ban(bans: dict, core: dict, height: int) -> None:
    """Tombstone ON (walidacja MUSI przejść wcześniej). unban_used przeżywa
    nawet gdyby wpis kiedyś nadpisano — historia jest wieczna (D18)."""
    prev = bans.get(core["wallet"], {})
    bans[core["wallet"]] = {"active": True, "height": height,
                            "code": core["code"], "evidence": core["evidence"],
                            "unban_used": bool(prev.get("unban_used", False))}


def apply_unban(bans: dict, wallet: str, height: int) -> None:
    e = bans.get(wallet)
    if not e:                                    # walidacja już pilnuje — twardy assert
        raise BanEvtError("unban bez bana (błąd wewnętrzny kolejności)")
    e["active"] = False
    e["unban_used"] = True
    e["unban_height"] = height


def is_banned(bans: dict, wallet: str) -> bool:
    """Tombstone AKTYWNY? (używane w add_tx/_validate_economics/coinbase)."""
    return bool(wallet and bans.get(wallet, {}).get("active"))


# -------------------------------------------------------------------------- widok dla człowieka (D66)
def ban_view(bans: dict, wallet: str | None) -> dict:
    """Status banu DO POKAZANIA człowiekowi (D66 — „widać go"): ta sama prawda
    co tombstone (is_banned), zero nowego prawa, zero zdjętego prawa. Zwraca
    czytelny obiekt: czy zbanowany, kod + etykieta + powód PL/EN (z REASONS_RED),
    wysokość plomby i jaka jest jedyna furtka (wykup D30 — albo brak, D18)."""
    e = bans.get(wallet or "") or {}
    if not (wallet and e):
        return {"banned": False, "wallet": wallet or "", "history": False}
    if not e.get("active"):                            # wykupany: wpis-historia został
        return {"banned": False, "wallet": wallet, "history": True,
                "code": e.get("code", "?"),
                "unban_used": bool(e.get("unban_used")),
                "unban_height": e.get("unban_height")}
    slug, rpl, ren = REASONS_RED.get(e.get("code", "?"), ("UNKNOWN", "—", "—"))
    furtka = ("wykup = jednorazowy TX_BAN_EVT do skarbca (D30)"
              if not e.get("unban_used") else
              "wykup już zużyty w przeszłości — re-ban obowiązuje NA ZAWSZE (D18)")
    return {"banned": True, "wallet": wallet, "history": True,
            "code": e.get("code", "?"), "slug": slug,
            "reason_pl": rpl, "reason_en": ren,
            "since_height": e.get("height"),
            "unban_used": bool(e.get("unban_used")), "unban_path": furtka}


def ban_banner_pl(view: dict) -> str:
    """Jednolinijkowy baner PL (D66) dla GUI/IPC/CLI — bez skrótów myślowych."""
    if not view.get("banned"):
        if view.get("history"):
            return ("wallet NIE jest zbanowany (aktualna plomba zdjęta — "
                    "w historii był ban, wykup odbył się zgodnie z D30)")
        return "wallet NIE jest zbanowany (brak wpisu w rejestrze tombstone)"
    return (f"⛔ ZBANOWANY — {view['code']} {view['slug']}: {view['reason_pl']} "
            f"[EN: {view['reason_en']}] Plomba od bloku {view['since_height']}. "
            f"Jedyna furtka: {view['unban_path']}.")


# -------------------------------------------------------------------------- selftest E2E
if __name__ == "__main__":
    from core.identity import Identity
    from chain.block import (Tx, TREASURY_WALLET_DEV, TX_BAN_EVT, TX_TRANSFER)
    from chain.ledger import Ledger, ChainError
    from chain.miner import mine

    print("chain/ban_evt.py — selftest E2E: tombstone k-z-n na prawdziwym ledgerze\n")
    TRE = TREASURY_WALLET_DEV
    L = Ledger(TRE)
    ala = Identity.generate("ala_cel")
    attestors = [Identity.generate(f"att_{i}") for i in range(BAN_N)]
    import chain.ban_evt as _pkg          # UWAGA: plik odpalony jako __main__ ma OSOBNY
    for a in attestors:                   # moduł — kropkę rejestrujemy w instancji pakietu,
        _pkg.register_dev_attestor(a)     # bo TEJ używa ledger (inaczej kropka=∅ → 0/3)

    _kop_n = [0]

    def kop(tag: str):
        _kop_n[0] += 1
        tmpl = L.block_template(Identity.generate(f"miner_{_kop_n[0]}").wallet, zbits=2)
        won = mine(tmpl, max_tries=200_000)
        assert won is not None, f"mining nie trafił ({tag})"
        L.apply_block(won)

    # --- funding ali (żeby miała czym płacić transfery i wykup) -------------
    kop("rozruch")
    # funding ali: kopiemy prosto na jej wallet (24×5 FNX = 120 > wykup 100 FNX)
    for _ in range(24):
        tmpl = L.block_template(ala.wallet, zbits=2)
        won = mine(tmpl, max_tries=200_000)
        assert won is not None
        L.apply_block(won)
    saldo0 = L.balance_of(ala.wallet)
    assert saldo0 > UNBAN_FEE_ISKRY, f"ala potrzebuje środków na wykup ({saldo0}=)"
    print(f"  [OK] 0. funding: ala ma {saldo0} iskier (kropka {BAN_K}-z-{BAN_N} zarejestrowana dev)")

    # --- 1) ban: za mało podpisów / obcy podpis / zły kod / zły evidence ----
    core = ban_core(ala.wallet, "0x11", *REASONS_RED["0x11"][1:],
                    evidence_hash_of({"cards": 1234, "kind": "msg_flood"}))
    e3 = [attest_entry(a, core) for a in attestors[:3]]
    try:
        L.add_tx(Tx(type=TX_BAN_EVT, sender="", recipient="", amount=0,
                    payload=ban_payload(core, e3[:2])))        # tylko 2 z 3!
        raise SystemExit("kropka 2<3 przeszła!")
    except ChainError as e_:
        assert "kropka" in str(e_)
    obcy = attest_entry(Identity.generate("nie_attestor"), core)
    try:
        L.add_tx(Tx(type=TX_BAN_EVT, sender="", recipient="", amount=0,
                    payload=ban_payload(core, e3[:2] + [obcy])))
        raise SystemExit("obcy podpis policzony!")
    except ChainError:
        pass
    # złe CORE: budujemy surowy JSON (ban_core słusznie odmawia błędu już przy budowie)
    import json as _js

    def raw_payload(core_d: dict, entries: list) -> str:
        return _js.dumps({"v": 1, "op": "ban", "core": core_d, "sigs": entries},
                         separators=(",", ":"), sort_keys=True)

    core_kod = dict(core, code="0x99")                       # kod spoza ban_codes
    core_evid = dict(core, evidence="zz" + "0" * 62)         # evidence nie-hex
    core_dlug = dict(core, reason_pl="x" * (REASON_MAX + 1))  # uzasadnienie > 280 znaków
    for bad in (
        raw_payload(core_kod, e3),
        raw_payload(core_evid, e3),
        raw_payload(core_dlug, e3),
        # 2 attestorów + duplikat jednego: duplikat NIE dolicza się do kworum
        # (test łapał błąd: e3+[e3[0]] to LEGALNA kropka 3-różnych+echo!)
        ban_payload(core, e3[:2] + [e3[0]]),
    ):
        try:
            L.add_tx(Tx(type=TX_BAN_EVT, sender="", recipient="", amount=0, payload=bad))
            raise SystemExit("zły payload ban przeszedł!")
        except (ChainError, BanEvtError):
            pass
    print("  [OK] 1. kropka<BAN_K / obcy / zły kod / zły evidence / za długi powód / "
          "duplikat attestora → odrzuty")

    # --- 2) poprawny ban: ledger stosuje tombstone --------------------------
    t_ban = Tx(type=TX_BAN_EVT, sender="", recipient="", amount=0,
               payload=ban_payload(core, e3))
    L.add_tx(t_ban)
    kop("ban")
    assert is_banned(L.bans, ala.wallet) and L.bans[ala.wallet]["code"] == "0x11"
    print("  [OK] 2. ban k-z-n NA CHAIN: rejestr tombstone aktywny (kod 0x11 + hash dowodów)")

    # --- 3) zbanowana ala jest MARTWA: mempool i blok odrzucają jej tx ------
    try:
        L.add_tx(Tx.build_signed(TX_TRANSFER, ala, TRE, ISKRA, nonce=0))
        raise SystemExit("zbanowany transfer przeszedł do mempoola!")
    except ChainError as e_:
        assert "zbanowan" in str(e_)
    # bestia: ręcznie wkopany blok z jej tx też ma odpaść (konsensus, nie mempool)
    evil = Tx.build_signed(TX_TRANSFER, ala, TRE, ISKRA, nonce=0)
    tmpl = L.block_template(TRE, zbits=2)
    tmpl.txs.append(evil)
    won = mine(tmpl, max_tries=300_000)
    try:
        L.apply_block(won)
        raise SystemExit("blok z tx zbanowanego przeszedł!")
    except ChainError as e_:
        assert "zbanowan" in str(e_)
    print("  [OK] 3. mempool I blok odrzucają tx zbanowanego walletu (tombstone działa)")

    # --- 4) kopanie dla zbanowanego walletu = blok nieważny -------------------
    tmpl = L.block_template(ala.wallet, zbits=2)
    won = mine(tmpl, max_tries=200_000)
    try:
        L.apply_block(won)
        raise SystemExit("kopanie na zbanowany przeszło!")
    except ChainError as e_:
        assert "kopacz" in str(e_)
    print("  [OK] 4. coinbase do zbanowanego → blok odrzucony (martwy kopacz nie zarabia)")

    # --- 5) double-ban / replay tego samego tx → odrzut ----------------------
    try:
        L.add_tx(Tx(type=TX_BAN_EVT, sender="", recipient="", amount=0,
                    payload=ban_payload(core, e3)))
        raise SystemExit("double-ban przeszedł!")
    except ChainError as e_:
        assert "już jest zbanowany" in str(e_)
    print("  [OK] 5. drugi ban tego samego walletu (i replay tx) → odrzut")

    # --- 6) wykup: zła kwota / cudzy wykup / poprawny wykup → skarbiec -------
    try:
        L.add_tx(Tx.build_signed(TX_BAN_EVT, ala, TRE, UNBAN_FEE_ISKRY - 1, nonce=0,
                                 payload=unban_payload()))
        raise SystemExit("zaniżony wykup przeszedł!")
    except ChainError as e_:
        assert "wykup" in str(e_)
    try:
        L.add_tx(Tx.build_signed(TX_BAN_EVT, Identity.generate("dobry_samaritanin"),
                                 TRE, UNBAN_FEE_ISKRY, nonce=0, payload=unban_payload()))
        raise SystemExit("wykup za kogoś przeszedł!")
    except ChainError as e_:
        assert "nie jest zbanowany" in str(e_)
    tre0 = L.balance_of(TRE)
    L.add_tx(Tx.build_signed(TX_BAN_EVT, ala, TRE, UNBAN_FEE_ISKRY, nonce=0,
                             payload=unban_payload()))   # pierwszy tx ali = nonce 0!
    kop("unban")
    assert not is_banned(L.bans, ala.wallet) and L.bans[ala.wallet]["unban_used"]
    assert L.balance_of(TRE) == tre0 + UNBAN_FEE_ISKRY + \
        (UNBAN_FEE_ISKRY * 550 // 10 ** 6), "skarbiec ma dostać wykup + ppm (D30/D15)"
    print("  [OK] 6. wykup: kwota/cudzy wykup odrzucone; poprawny → skarbiec, plomba zdjęta")

    # --- 7) po wykupie ala żyje; drugi ban OK; DRUGI wykup = NIGDY -----------
    L.add_tx(Tx.build_signed(TX_TRANSFER, ala, TRE, ISKRA, nonce=1))
    kop("ala-zyje")
    core2 = ban_core(ala.wallet, "0x15", *REASONS_RED["0x15"][1:],
                     evidence_hash_of({"cards": 77, "kind": "replay"}))
    e3b = [attest_entry(a, core2) for a in attestors[:3]]
    L.add_tx(Tx(type=TX_BAN_EVT, sender="", recipient="", amount=0,
                payload=ban_payload(core2, e3b)))
    kop("re-ban")
    assert is_banned(L.bans, ala.wallet)
    try:
        L.add_tx(Tx.build_signed(TX_BAN_EVT, ala, TRE, UNBAN_FEE_ISKRY, nonce=2,
                                 payload=unban_payload()))
        raise SystemExit("drugi wykup przeszedł!")
    except ChainError as e_:
        assert "NA ZAWSZE" in str(e_)
    print("  [OK] 7. wykup=1/historia: po re-banie drugi wykup odrzucony — re-ban na zawsze (D18)")

    # --- 8) replay na świeżym ledgerze: rejestr banów bit-w-bit --------------
    L2 = Ledger(TRE)
    for b in L.chain[1:]:
        L2.apply_block(b)
    assert L2.bans == L.bans, "replay nie odtworzył rejestru banów bit-w-bit"
    print("  [OK] 8. replay/adopt: rejestr tombstone identyczny bit-w-bit")

    # --- 9) D66: status banu WIDOCZNY — widać go, z powodem i furtką ---------
    v9 = ban_view(L.bans, ala.wallet)
    assert v9["banned"] and v9["code"] == "0x15" and v9["slug"] == "REPLAY_ATTACK"
    assert v9["since_height"] is not None and v9["unban_used"], \
        "widok: kod, etykieta, wysokość, historia wykupu — komplet"
    b9 = ban_banner_pl(v9)
    assert "ZBANOWANY" in b9 and "0x15" in b9 and "NA ZAWSZE" in b9, \
        "baner mówi: co, dlaczego (PL+EN), od kiedy, jaka furtka"
    assert ban_view(L2.bans, ala.wallet) == v9, "widok z klona replay = identyczny (konsensus!)"
    v_clean = ban_view(L.bans, TRE)
    assert not v_clean["banned"] and not v_clean["history"]
    assert "NIE jest zbanowany" in ban_banner_pl(v_clean) and "brak wpisu" in ban_banner_pl(v_clean)
    v_hist = {"banned": False, "wallet": ala.wallet, "history": True,
              "code": "0x11", "unban_used": True, "unban_height": 5}
    assert "wykup" in ban_banner_pl(v_hist) and "NIE jest zbanowany" in ban_banner_pl(v_hist)
    print("  [OK] 9. D66: status banu czytelny dla człowieka (kod+powód PL/EN+blok+furtką),"
          "\n            klon replay pokazuje IDENTYCZNIE; czysty i wykupany rozróżnione")

    print("\nSELFTEST: PASS ✅  chain/ban_evt.py — tombstone k-z-n (0x06):\n"
          "kropka Ed25519≥3, martwy wallet (tx+kopanie), wykup 1/historia do skarbca,\n"
          "anti-replay na rejestrze, replay łańcucha odtwarza plomby bit-w-bit (D18/D22/D30),\n"
          "D66: status banu pokazywany człowiekowi (ban_view/baner PL)")
