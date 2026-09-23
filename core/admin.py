# core/admin.py — KONTO ADMINA „Deimos" (D53): kapitan okrętu, nie wujek z kamery
"""
Zasada systemu (decyzja właściciela 2026-08-06): istnieje JEDNO konto admina —
operatorskie konto właściciela. Analogia: kapitan okrętu. Kapitan ma mapę maszynowni
(diagnostyka noda, widoki D17) i klucz do kajuty ratunkowej (dev-attestor k-z-n,
D47 — do czasu głosowań VOTER/PoU, P25). Czego kapitan NIE MA: przycisku ban
(ban_policy §zero ludzkich banów — werdykt red wymaga kropki 3-z-5, nigdy jednej
ręki) i czytnika treści (E2E: node fizycznie nie ma czego czytać).

Konto:
    username on-chain : „deimos"  (regex core.identity: małe litery — twardo)
    display           : „Deimos"
    plik              : <data_dir>/admin.ks  (Keystore KS1, Argon2id + AEAD, D24)
    hasło startowe    : ⚠️ DEV-DEFAULT „Anon123!"  (na życzenie właściciela;
                       ZMIEŃ przy pierwszym starcie — unlock_admin(...)+
                       change_admin_password(); dopóki default aktywny, każdy
                       pomocniczy napis w GUI melduje to czerwienią)
    panika startowa   : ⚠️ DEV-DEFAULT „Anon123!-panic" (musi być INNE niż hasło, D3)

Uprawnienia (biała lista, jawna):
    attest_ban_dev — podpisuje kropki k-z-n jako DEV-attestor (chain/ban_evt;
                     rejestr żyje w procesie noda — produkcja: zaszute wydaniem, P25)
    node_diagnostics / peers_view — widoki owner-admina (D17; IPC sentinel_*, status)
To wszystko. Żadnego backdoora do wiadomości, haseł ani cudzych środków — admin
podlega temu samemu konsensusowi co ghost.
"""
from __future__ import annotations

import os
import sys
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from core.keystore import Keystore, KDFParams, KeystoreError   # noqa: E402

ADMIN_USERNAME = "deimos"                    # on-chain regex: ^[a-z0-9_][a-z0-9_-]{2,23}$
ADMIN_DISPLAY = "Deimos"                     # etykieta GUI/profilu
ADMIN_FILENAME = "admin.ks"
# ⚠️ DEV-DEFAULT (decyzja właściciela). Jawne w repo = każdy je zna: traktuj jak
# hasło fabryczne routera — PIERWSZA czynność po starcie to jego zmiana.
DEFAULT_ADMIN_PASSWORD = "Anon123!"
DEFAULT_ADMIN_PANIC = "Anon123!-panic"

ADMIN_RIGHTS = ("attest_ban_dev", "node_diagnostics", "peers_view")

# D55: publiczna „wizytówka" attesta — demon przy starcie zna TYLKO ten plik
# (wallet publiczny; hasła nigdy). Jak legitymacja w okienku: każdy może ją
# przeczytać, ale bez klucza prywatnego ze skarbca KS1 nikt nią nie „wejdzie"
# (kropka k-z-n liczy podpisy Ed25519, nie wpisy w rosterze — ban_evt D47).
ATTESTOR_PUB_FILENAME = "admin_attestor.json"


class AdminError(Exception):
    """Błędy konta admina — jeden typ."""


def admin_path(data_dir: str) -> str:
    return os.path.join(data_dir, ADMIN_FILENAME)


def attestor_pub_path(data_dir: str) -> str:
    return os.path.join(data_dir, ATTESTOR_PUB_FILENAME)


def _write_attestor_pub(data_dir: str, wallet: str) -> None:
    """Zapis atomowy wizytówki attesta (0600). Dane PUBLICZNE — bez kluczy."""
    import json
    import tempfile
    os.makedirs(data_dir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=data_dir, prefix=".attest-", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"v": 1, "app": "fenix-admin-attestor", "username": ADMIN_USERNAME,
                   "display": ADMIN_DISPLAY, "wallet": wallet}, f,
                  ensure_ascii=False, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, attestor_pub_path(data_dir))


def attestor_wallet(data_dir: str) -> str | None:
    """Wallet Deimosa z wizytówki (BEZ odblokowywania keystora). Brak → None."""
    import json
    try:
        with open(attestor_pub_path(data_dir), "r", encoding="utf-8") as f:
            d = json.load(f)
        w = d.get("wallet")
        return w if isinstance(w, str) and w.startswith("FNX1") else None
    except (OSError, ValueError):
        return None


def register_admin_attestor_boot(data_dir: str, kdf: KDFParams | None = None) -> str:
    """Start DEMONA (D55): wpiąć attesta Deimosa do procesu (roster k-z-n, dev P25).
    - brak admin.ks → ensure_admin stawia konto (hasło fabryczne — ONB w GUI je
      zmieni; wallet zostaje ten sam na zawsze) i wypisuje wizytówkę,
    - jest admin.ks → czytamy wallet z wizytówki (hasło demona NIE interesuje).
    Zwraca wallet. Rzuca AdminError, gdy nie ma skąd wziąć walleta."""
    ks = ensure_admin(data_dir, kdf=kdf)
    if ks.is_unlocked:                       # świeżo utworzone konto — mamy tożsamość
        wallet = ks.identity.wallet
        _write_attestor_pub(data_dir, wallet)
    else:
        wallet = attestor_wallet(data_dir)
    if not wallet:
        raise AdminError("brak wizytówki attesta (admin_attestor.json) — odblokuj "
                         "admina raz w GUI (login/ONB), wizytówka się odtworzy")
    import chain.ban_evt as bevt             # instancja PAKIETU — ta, z której liczy ledger
    return bevt.register_dev_attestor_wallet(wallet)


def ensure_admin(data_dir: str, kdf: KDFParams | None = None) -> Keystore:
    """Istnieje → Keystore.load; brak → tworzy z hasłem DEV-DEFAULT (⚠️ zmień!)."""
    os.makedirs(data_dir, exist_ok=True)
    path = admin_path(data_dir)
    if os.path.exists(path):
        return Keystore.load(path)
    ks = Keystore.create(path, ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD.encode(),
                         DEFAULT_ADMIN_PANIC.encode(), kdf=kdf)
    _write_attestor_pub(data_dir, ks.identity.wallet)   # D55: wizytówka dla demona
    return ks


def unlock_admin(data_dir: str, passkey: str | bytes,
                 kdf: KDFParams | None = None) -> Keystore:
    """Logowanie admina. Złe hasło → AdminError (keystore ma backoff, D24).
    data_dir bez admin.ks → tworzy domyślne (pierwszy start systemu)."""
    ks = ensure_admin(data_dir, kdf=kdf)
    pw = passkey.encode() if isinstance(passkey, str) else bytes(passkey)
    try:
        ks.unlock(pw)
    except KeystoreError as e:
        raise AdminError(f"logowanie admina: {e}") from None
    if ks.identity.username != ADMIN_USERNAME:
        raise AdminError("plik admin.ks nie jest kontem 'deimos' (podmiana?)")
    _write_attestor_pub(data_dir, ks.identity.wallet)   # D55: odśwież wizytówkę
    return ks


def is_default_password(data_dir: str, kdf: KDFParams | None = None) -> bool:
    """Czy dalej wisi hasło fabryczne? (GUI: czerwony pasek „ZMIEŃ HASŁO")."""
    try:
        ks = ensure_admin(data_dir, kdf=kdf)
        ks.unlock(DEFAULT_ADMIN_PASSWORD.encode())
        ks.lock()
        return True
    except (AdminError, KeystoreError):
        return False


def change_admin_password(ks: Keystore, new_passkey: str | bytes,
                          new_panic: str | bytes | None = None) -> None:
    """Zmiana hasła (keystore musi być odblokowany). Format KS1 wymaga pary
    hasło+panika: new_panic=None → panika ustawiana na DEV-DEFAULT — jeśli
    zmieniałeś ją wcześniej, podaj jawnie (MUSI być inna niż hasło, D3)."""
    if not ks.is_unlocked:
        raise AdminError("zmiana hasła: najpierw unlock_admin")
    pw = new_passkey.encode() if isinstance(new_passkey, str) else bytes(new_passkey)
    if len(pw) < 8:
        raise AdminError("nowe hasło: min. 8 znaków")
    pn = (new_panic.encode() if isinstance(new_panic, str)
          else new_panic) if new_panic is not None else DEFAULT_ADMIN_PANIC.encode()
    ks.change_password(pw, pn)
    _write_attestor_pub(os.path.dirname(ks.path) or ".",
                        ks.identity.wallet)          # D55: wizytówka świeża po zmianie


def register_admin_attestor(ks: Keystore) -> str:
    """Wpisuje wallet admina jako DEV-attestora k-z-n (chain/ban_evt D47).
    Uprawnienie żyje w procesie noda (rejestr w RAM) — produkcja: zimna kropka
    zaszuta wydaniem + rotacja (P25). Zwraca wallet."""
    import chain.ban_evt as bevt
    return bevt.register_dev_attestor(ks.identity)


def admin_status(data_dir: str, kdf: KDFParams | None = None) -> dict:
    """Widok bezpieczny (bez odblokowywania na stałe): istnieje? default? prawa."""
    exists = os.path.exists(admin_path(data_dir))
    return {"exists": exists,
            "username": ADMIN_USERNAME, "display": ADMIN_DISPLAY,
            "default_password": is_default_password(data_dir, kdf=kdf) if exists else None,
            "rights": list(ADMIN_RIGHTS)}


# -------------------------------------------------------------------------- selftest
if __name__ == "__main__":
    import shutil
    import tempfile

    print("core/admin.py — selftest: konto Deimos (D53)\n")
    d = tempfile.mkdtemp(prefix="fenix-admin-")
    fast = KDFParams.fast_for_tests()

    # 1) pierwszy start: tworzy admin.ks z defaultem; status uczciwie melduje default
    ks = ensure_admin(d, kdf=fast)
    assert os.path.exists(admin_path(d))
    st = admin_status(d, kdf=fast)
    assert st["exists"] and st["default_password"] is True, st
    assert st["username"] == "deimos" and st["display"] == "Deimos"
    print("  [OK] 1. pierwszy start: admin.ks powstaje; status melduje hasło fabryczne")

    # 2) logowanie dobrym defaultem OK; złym hasłem = AdminError; tożsamość stabilna
    ks2 = unlock_admin(d, "Anon123!", kdf=fast)
    w0 = ks2.identity.wallet
    assert w0.startswith("FNX1") and ks2.identity.username == "deimos"
    try:
        unlock_admin(d, "ZleHaslo123", kdf=fast)
        raise SystemExit("admin wszedł złym hasłem!")
    except AdminError as e:
        assert "logowanie" in str(e)
    ks3 = unlock_admin(d, b"Anon123!", kdf=fast)
    assert ks3.identity.wallet == w0, "wallet admina się ROZJECHAŁ między restartami!"
    print("  [OK] 2. login: default działa, złe hasło odrzucone; wallet stabilny po restarcie")

    # 3) dev-attestor: wallet admina potrafi podpisać kropkę k-z-n (D47 E2E)
    w = register_admin_attestor(ks3)
    import chain.ban_evt as _pkg
    assert w in _pkg.ATTESTOR_WALLETS
    from chain.ban_evt import ban_core, attest_entry, evidence_hash_of
    core = ban_core("FNX1" + "0" * 32, "0x11", "Zalewał.", "Flooded.", evidence_hash_of({"c": 1}))
    ent = attest_entry(ks3.identity, core)
    assert _pkg.verify_entry(ent, core), "kropka admina nie przechodzi verify_entry!"
    print("  [OK] 3. attest_ban_dev: Deimos podpisuje kropkę k-z-n (verify_entry✓)")

    # 4) zmiana hasła: stara przestaje działać, nowa wchodzi; status melduje czysto
    change_admin_password(ks3, "NoweHaslo!9", new_panic="Panika!77-ine")
    ks3.lock()
    try:
        unlock_admin(d, "Anon123!", kdf=fast)
        raise SystemExit("stare hasło admina dalej działa po zmianie!")
    except AdminError:
        pass
    ks4 = unlock_admin(d, "NoweHaslo!9", kdf=fast)
    assert ks4.identity.wallet == w0, "zmiana hasła ZMIENIŁA wallet (tożsamość uciekła!)"
    st2 = admin_status(d, kdf=fast)
    assert st2["default_password"] is False, st2
    print("  [OK] 4. change_password: stare martwe, nowe działa, wallet ten sam, status czysty")

    # 5) złe zmiany odrzucane: za krótkie hasło; zmiana na zamkniętym keystore
    try:
        change_admin_password(ks4, "krotkie")
        raise SystemExit("za krótkie hasło przeszło!")
    except AdminError as e:
        assert "8 znaków" in str(e)
    ks4.lock()
    try:
        change_admin_password(ks4, "JeszczeInne!1")
        raise SystemExit("zmiana na zamkniętym keystore przeszła!")
    except AdminError:
        pass
    print("  [OK] 5. strażnicy: min. 8 znaków; zmiana tylko na odblokowanym keystore")

    # 6) D55: wizytówka attesta + boot demona. Wallet publiczny w admin_attestor.json;
    #    demon rejestruje z SAMEGO pliku (bez hasła); złe w takim pliku = roster bez
    #    władzy (kropka liczy podpisy, nie wpisy); SNAPSHOT-heal: kolejny ONB/login
    #    nadpisuje wizytówkę prawidłowym walletem.
    assert attestor_wallet(d) == w0, "wizytówka nie powstała przy ensure/unlock/change"
    d2 = tempfile.mkdtemp(prefix="fenix-admin-boot-")
    wb = register_admin_attestor_boot(d2, kdf=fast)     # symulacja startu demona
    import chain.ban_evt as _pkg2
    assert wb in _pkg2.ATTESTOR_WALLETS and wb == attestor_wallet(d2)
    ks5 = unlock_admin(d2, "Anon123!", kdf=fast)
    assert ks5.identity.wallet == wb, "wallet z wizytówki ≠ wallet w admin.ks!"
    # SPOOF: Eve podmienia wizytówkę na SWÓJ wallet → demon wpisze obcy wallet do
    # dev-rosteru (przejrzyste: wpis ≠ klucz, kropki dalej nie podpisze; P25 mówi
    # wprost: docelowy roster = zimna kropka wydania). Login admina LECZY plik:
    from core.identity import Identity as _Id
    eve_w = _Id.generate("eve_spoof").wallet
    _write_attestor_pub(d2, eve_w)
    assert attestor_wallet(d2) == eve_w
    ks5.lock()
    unlock_admin(d2, "Anon123!", kdf=fast)              # zwykły login…
    assert attestor_wallet(d2) == wb, "login admina NIE wyleczył sfałszowanej wizytówki!"
    shutil.rmtree(d, ignore_errors=True)
    shutil.rmtree(d2, ignore_errors=True)
    print("  [OK] 6. D55: boot demona rejestruje attesta z wizytówki (bez hasła);")
    print("           spoof wizytówki = martwy wpis; login admina leczy plik")

    print("\nSELFTEST: PASS ✅  core/admin.py — Deimos:\n"
          "konto tworzy się raz, hasło fabryczne jawnie oznaczone i wymienne,\n"
          "wallet stabilny, kropka k-z-n działa; ZERO backdoora (ta sama matematyka co ghost).")
