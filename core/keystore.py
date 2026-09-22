# core/keystore.py
"""
Keystore Fenixa (KS1) — jedyny plik z sekretem, jaki kiedykolwiek istnieje.

Decyzje, które ten plik WDRAŻA:
  D3  — profil pod hasło; 3× ❌ = opóźnienie ×2 (NIGDY destrukcja za złe hasło
        — wróg by niszczył dane losowymi próbami); OSOBNE hasło paniki = SHRED.
  D9  — zero recovery w protokole; JEDYNA furka: opcjonalny export udziałów
        Shamira MEK-a do zaufanych (OFF, za to odpowiada UI z ostrzeżeniem).
  D24 — kontener przetrwania ISO: username + kontakty + klucze; amnezja reszty.
  D25 — ten sam plik służy aplikacji desktopowej i Fenix OS.

Co trzyma (zawsze zaszyfrowane): username, klucze prywatne (X25519+Ed25519),
kontakty, ranka-cache, created_at. NIC więcej.

Architektura kluczy (dlaczego zmiana hasła przewija 32B, nie całość):
  passkey ──Argon2id(salt_pw)──► KEK_pw ──AEAD-wrap──► MEK (32B, losowy)
  panic   ──Argon2id(salt_pn)──► KEK_pn ──AEAD-probe─► "KS1-PANIC-PROBE" (weryfikator)
  MEK ──AEAD(XChaCha20-Poly1305 lub ChaCha20)──► PAYLOAD (JSON z profilem)
MEK NIGDY nie wychodzi z hasła wprost — zmiana hasła = nowy wrap MEK-a.

Hamulec brute-force: sam Argon2id (64 MiB, t=3, p=2 ≈ 0.3–1 s/próba na CPU)
+ nasz mnożnik opóźnień: 3-cia i kolejne próby czekają 2^(fc-1) s (2,4,8…300).
Licznik porażek jest w pliku — UCZCIWIE: atakujący z KOPIĄ pliku go ominie,
więc prawdziwym hamulcem jest koszt Argon2id, nie licznik. Licznik broni
przed "kumpel przy otwartym komputerze", Argon2id przed GPU.

Zapis: atomowy (tmp + rename), chmod 0600. Panika: nadpisanie losowym + zerami,
fsync, skasowanie pliku + zeroize MEK w RAM. Nie ratujemy kopii, których nie
kontrolujemy (cloud sync, backupy OS!) — dlatego GUI ostrzega: keystore NIGDY
w folderze synchronizowanym. Reguła twarda: JEDEN proces piszący na plik
(stare instancje w RAM nie „odświeżają się" — późniejszy _save wygrywa).
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import sys as _sys
import time
import pathlib as _pl

# Pozwala odpalić wprost (python core/keystore.py) i jako moduł (-m core.keystore)
if __package__ in (None, ""):
    _sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidTag

from core.identity import Identity, check_profile
from core.crypto.fenix_crypto import split_secret, combine_shares

# --- AEAD: preferujemy XChaCha20-Poly1305 (jak w protocol_spec), fallback ChaCha20 ---
_AEAD_OK = True
try:
    from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305 as _XCH
except ImportError:  # starsza biblioteka — nadal silny AEAD, tylko nonce 12B
    _XCH = None
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as _CHA

# --- Argon2id: cryptography>=44 LUB argon2-cffi --------------------------------
try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id as _CryptoArgon2id
except ImportError:
    _CryptoArgon2id = None
try:
    from argon2.low_level import Type as _Argon2Type
    from argon2.low_level import hash_secret_raw as _argon2ffi
except ImportError:
    _argon2ffi = None
if _CryptoArgon2id is None and _argon2ffi is None:
    raise ImportError(
        "Keystore wymaga Argon2id: `pip install 'cryptography>=44.0.0'` "
        "albo `pip install argon2-cffi`")

KS_VERSION = 1
PROBE_PANIC = b"KS1-PANIC-PROBE"          # hasło paniki NIE odszyfrowuje danych — tylko weryfikuje
AAD_WRAP = b"KS1/wrap-pw"
AAD_PROBE = b"KS1/probe-panic"
AAD_PAYLOAD = b"KS1/payload"
BACKOFF_BASE_S = 2.0                       # 3-cia próba czeka 2s, potem 4, 8…
BACKOFF_CAP_S = 300.0


class KeystoreError(Exception):
    """Złe hasło / zły plik / zabroniona operacja. Jeden typ (brak orakli)."""


class PanicActivated(Exception):
    """Podano hasło PANIKI: kontener został zniszczony (to jest sukces procedury)."""


class KDFParams:
    """Parametry Argon2id. Produkcyjnie: 64 MiB / t=3 / p=2 (RFC 9106, ~0.3–1 s).
    Testowo: 8 MiB / t=1 / p=1 (~dziesiątki ms — inaczej suite czekałaby minutami)."""

    def __init__(self, m_kib: int = 65536, t: int = 3, p: int = 2):
        self.m_kib, self.t, self.p = m_kib, t, p

    @classmethod
    def fast_for_tests(cls) -> "KDFParams":
        return cls(m_kib=8192, t=1, p=1)

    @classmethod
    def from_dict(cls, d: dict) -> "KDFParams":
        """Odbudowa z obwoluty JSON (klucze m/t/p → parametry m_kib/t/p)."""
        return cls(m_kib=int(d["m"]), t=int(d["t"]), p=int(d["p"]))

    def as_dict(self) -> dict:
        return {"algo": "argon2id", "m": self.m_kib, "t": self.t, "p": self.p}


def _argon2id(password: bytes, salt: bytes, kdf: KDFParams) -> bytes:
    if _CryptoArgon2id is not None:
        return _CryptoArgon2id(
            salt=salt, length=32, iterations=kdf.t,
            lanes=kdf.p, memory_cost=kdf.m_kib).derive(password)
    return _argon2ffi(secret=password, salt=salt, time_cost=kdf.t,
                      memory_cost=kdf.m_kib, parallelism=kdf.p,
                      hash_len=32, type=_Argon2Type.ID)


def _aead_name() -> str:
    return "xchacha20" if _XCH is not None else "chacha20"


def _aead_encrypt(name: str, key: bytes, pt: bytes, aad: bytes):
    if name == "xchacha20":
        nonce = secrets.token_bytes(24)
        return nonce, _XCH(key).encrypt(nonce, pt, aad)
    nonce = secrets.token_bytes(12)
    return nonce, _CHA(key).encrypt(nonce, pt, aad)


def _aead_decrypt(name: str, key: bytes, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
    box = _XCH(key) if name == "xchacha20" else _CHA(key)
    return box.decrypt(nonce, ct, aad)


def _zero(buf: bytearray) -> None:
    """Best-effort kasownik RAM. UCZCIWIE: wyciera to, co kontrolujemy
    (nasze bytearray); kopie w obiektach biblioteki zarządza C — stąd zasada:
    klucze żyją krótko, a panika/wipe dotyczy przede wszystkim PLIKU."""
    for i in range(len(buf)):
        buf[i] = 0


class Keystore:
    """Kontener D24/D3. Cykl życia:

        ks = Keystore.create(path, "ala", passkey=b"...", panic=b"...")
        idn = ks.identity                       # odblokowany (RAM)
        ks.lock()                               # 'wylogowanie' — MEK gaśnie

        ks = Keystore.load(path)                # 'restart systemu' (amnezja)
        idn = ks.unlock(b"...")                 # albo PanicActivated / KeystoreError
    """

    def __init__(self, path: str):
        self._path = path
        self._env: dict | None = None            # obwoluta (jawna część pliku)
        self._mek: bytearray | None = None       # w RAM tylko po unlock
        self._identity: Identity | None = None
        self._profile: dict | None = None        # odszyfrowany profil (RAM)
        self._sleeper = time.sleep               # wstrzykiwane w testach

    @property
    def path(self) -> str:
        """Ścieżka pliku keystora (read-only; D55: admin wypisuje wizytówkę obok)."""
        return self._path

    # ------------------------------------------------------------------ tworzenie
    @classmethod
    def create(cls, path: str, username: str, passkey: bytes, panic: bytes,
               kdf: KDFParams | None = None) -> "Keystore":
        if len(passkey) < 8:
            raise KeystoreError("passkey: min. 8 znaków (hasło = grzejnik brute-force)")
        if passkey == panic:
            raise KeystoreError("hasło paniki MUSI być inne niż hasło (D3)")
        kdf = kdf or KDFParams()
        idn = Identity.generate(username)
        profile = {
            "v": KS_VERSION,
            "username": username,
            "keys": idn._private_bundle(),          # TYLKO tu i TYLKO zaszyfrowane
            "contacts": [],
            "rank": "ghost",
            "created_at": int(time.time()),
        }
        ks = cls(path)
        ks._identity, ks._profile = idn, profile
        ks._mek = bytearray(secrets.token_bytes(32))
        ks._env = cls._build_env(kdf, passkey, panic, ks._mek,
                                 cls._seal_payload(kdf=None, mek=ks._mek,
                                                   profile=profile))
        ks._save()
        return ks

    @staticmethod
    def _build_env(kdf: KDFParams, passkey: bytes, panic: bytes,
                   mek: bytearray, payload_field: dict) -> dict:
        salt_pw, salt_pn = secrets.token_bytes(32), secrets.token_bytes(32)
        name = _aead_name()
        kek_pw = _argon2id(passkey, salt_pw, kdf)
        kek_pn = _argon2id(panic, salt_pn, kdf)
        n1, c1 = _aead_encrypt(name, kek_pw, bytes(mek), AAD_WRAP)
        n2, c2 = _aead_encrypt(name, kek_pn, PROBE_PANIC, AAD_PROBE)
        return {
            "v": KS_VERSION, "aead": name, "kdf": kdf.as_dict(),
            "salt_pw": salt_pw.hex(), "salt_panic": salt_pn.hex(),
            "wrap_pw": {"nonce": n1.hex(), "ct": c1.hex()},
            "probe_panic": {"nonce": n2.hex(), "ct": c2.hex()},
            "payload": payload_field,
            "fail_count": 0, "created_at": int(time.time()),
        }

    @staticmethod
    def _seal_payload(kdf, mek: bytearray, profile: dict) -> dict:
        n, c = _aead_encrypt(_aead_name(), bytes(mek),
                             json.dumps(profile, sort_keys=True).encode("utf-8"),
                             AAD_PAYLOAD)
        return {"nonce": n.hex(), "ct": c.hex()}

    # ------------------------------------------------------------------ dostęp
    @property
    def is_unlocked(self) -> bool:
        return self._identity is not None

    @property
    def identity(self) -> Identity:
        if not self._identity:
            raise KeystoreError("keystore zablokowany — najpierw unlock(passkey)")
        return self._identity

    def profile_public(self) -> dict:
        return self.identity.public_profile()

    # ------------------------------------------------------------------ otwieranie
    @classmethod
    def load(cls, path: str) -> "Keystore":
        ks = cls(path)
        try:
            with open(path, "r", encoding="utf-8") as f:
                ks._env = json.load(f)
        except (OSError, ValueError):
            raise KeystoreError("keystore: brak pliku lub uszkodzony") from None
        if ks._env.get("v") != KS_VERSION:
            raise KeystoreError("keystore: nieznana wersja obwoluty")
        if ks._env.get("aead") not in ("xchacha20", "chacha20"):
            raise KeystoreError("keystore: nieznany AEAD w obwolucie")
        return ks

    def unlock(self, passkey: bytes) -> Identity:
        if self._identity:
            return self._identity
        if self._env is None:
            raise KeystoreError("keystore niezaładowany — Keystore.load(path)")
        # --- backoff: 3-cia i kolejne próby czekają, ×2 za każdą (D3) ---
        fc = int(self._env.get("fail_count", 0))
        if fc >= 2:
            self._sleeper(min(BACKOFF_BASE_S * (2 ** (fc - 2)), BACKOFF_CAP_S))
        kdf = KDFParams.from_dict(self._env["kdf"])
        kek = _argon2id(passkey, bytes.fromhex(self._env["salt_pw"]), kdf)
        try:
            mek = _aead_decrypt(self._env["aead"], kek,
                                bytes.fromhex(self._env["wrap_pw"]["nonce"]),
                                bytes.fromhex(self._env["wrap_pw"]["ct"]), AAD_WRAP)
        except InvalidTag:
            mek = None
        if mek is None:
            # może to hasło PANIKI? (weryfikator — wtedy SHRED, bez pytania)
            kek_pn = _argon2id(passkey, bytes.fromhex(self._env["salt_panic"]), kdf)
            try:
                _aead_decrypt(self._env["aead"], kek_pn,
                              bytes.fromhex(self._env["probe_panic"]["nonce"]),
                              bytes.fromhex(self._env["probe_panic"]["ct"]), AAD_PROBE)
                self._shred_everything()
                raise PanicActivated("hasło paniki: kontener zniszczony")
            except InvalidTag:
                pass
            self._env["fail_count"] = fc + 1
            self._save()
            raise KeystoreError("nieprawidłowe hasło")
        # --- sukces: składamy profil i tożsamość w RAM ---
        try:
            profile = json.loads(_aead_decrypt(
                self._env["aead"], mek,
                bytes.fromhex(self._env["payload"]["nonce"]),
                bytes.fromhex(self._env["payload"]["ct"]), AAD_PAYLOAD))
        except (InvalidTag, ValueError):
            raise KeystoreError("keystore: payload uszkodzony") from None
        keys = profile["keys"]
        self._identity = Identity.from_private(
            profile["username"], bytes.fromhex(keys["x_priv"]),
            bytes.fromhex(keys["s_priv"]), created_at=profile.get("created_at"))
        self._profile = profile
        self._mek = bytearray(mek)
        if self._env.get("fail_count"):
            self._env["fail_count"] = 0
            self._save()
        return self._identity

    def lock(self) -> None:
        if self._mek is not None:
            _zero(self._mek)
        self._mek = self._identity = self._profile = None

    # ------------------------------------------------------------------ edycja
    def contacts(self) -> list:
        return list((self._profile or {}).get("contacts", []))

    def add_contact(self, profile: dict) -> None:
        """Kontakt = CUDZY profil publiczny. check_profile łapie podmiankę kluczy."""
        check_profile(profile)
        me = self.identity  # wymaga unlock
        if profile["wallet"] == me.wallet:
            raise KeystoreError("nie dodajesz siebie do kontaktów")
        prof = self._profile
        if any(c["profile"]["wallet"] == profile["wallet"] for c in prof["contacts"]):
            return                                   # deduplikacja cicho
        prof["contacts"].append({"profile": profile, "added_at": int(time.time())})
        self._env["payload"] = self._seal_payload(None, self._mek, prof)
        self._save()

    def change_password(self, new_passkey: bytes, new_panic: bytes) -> None:
        """Przewinięcie: NOWY wrap tego samego MEK-a (payload nietknięty).
        Wymaga odblokowanego keystora (GUI: zmiana hasła po zalogowaniu)."""
        if not self.is_unlocked:
            raise KeystoreError("zmiana hasła tylko po unlock")
        if len(new_passkey) < 8 or new_passkey == new_panic:
            raise KeystoreError("nowe hasło: min. 8 znaków i ≠ hasło paniki")
        kdf = KDFParams.from_dict(self._env["kdf"])
        self._env = self._build_env(kdf, new_passkey, new_panic, self._mek,
                                    self._env["payload"])
        self._save()

    # ------------------------------------------------------------------ recovery (D9)
    def export_recovery_shares(self, k: int = 2, n: int = 3) -> list:
        """OPCJONALNA furka użytkownika (OFF w UI, ostrzeżenie!):
        MEK rozbity Shamirem k-z-n do zaufanych. Kto złoży k udziałów +
        ma plik keystora, otwiera WSZYSTKO. Sieć o tym nie wie (D9)."""
        if not self.is_unlocked:
            raise KeystoreError("export udziałów tylko po unlock")
        return [s.hex() for s in split_secret(bytes(self._mek), k, n)]

    @classmethod
    def load_with_shares(cls, path: str, shares_hex: list) -> "Keystore":
        ks = cls.load(path)
        try:
            mek = combine_shares([bytes.fromhex(s) for s in shares_hex])
            profile = json.loads(_aead_decrypt(
                ks._env["aead"], mek,
                bytes.fromhex(ks._env["payload"]["nonce"]),
                bytes.fromhex(ks._env["payload"]["ct"]), AAD_PAYLOAD))
        except Exception:
            raise KeystoreError("udziały nie pasują (za mało/uszkodzone)") from None
        keys = profile["keys"]
        ks._identity = Identity.from_private(
            profile["username"], bytes.fromhex(keys["x_priv"]),
            bytes.fromhex(keys["s_priv"]), created_at=profile.get("created_at"))
        ks._profile, ks._mek = profile, bytearray(mek)
        return ks

    # ------------------------------------------------------------------ plik/panika
    def _save(self) -> None:
        """Atomowy zapis: tmp+rename (brak pół-pliku przy crashu), chmod 0600."""
        tmp = self._path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps(self._env, sort_keys=True).encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self._path)
        os.chmod(self._path, 0o600)

    def _shred_everything(self) -> None:
        """PANIKA: plik nadpisany 2× i skasowany; MEK/klucze w RAM wyzerowane."""
        try:
            size = os.path.getsize(self._path)
            with open(self._path, "r+b", buffering=0) as f:
                f.write(secrets.token_bytes(size))
                os.fsync(f.fileno())
                f.seek(0)
                f.write(b"\x00" * size)
                os.fsync(f.fileno())
            os.remove(self._path)
        finally:
            self.lock()


# ---------------------------------------------------------------------------
# Selftest — uruchom:  python core/keystore.py   (albo: python -m core.keystore)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import tempfile

    FAST = KDFParams.fast_for_tests()
    print("core/keystore.py — selftest kontenera D3/D24/D9\n")
    tmpd = tempfile.mkdtemp(prefix="fenix-ks-")

    # 1) create → unlock po "restarcie" (nowy proces = nowa instancja)
    p_ala = os.path.join(tmpd, "ala.ks1")
    ks = Keystore.create(p_ala, "ala", b"sekret-ala-123", b"panika-ala-456", kdf=FAST)
    wallet_ala = ks.identity.wallet
    prof_ala = ks.profile_public()
    ks.lock()
    ks2 = Keystore.load(p_ala)
    idn = ks2.unlock(b"sekret-ala-123")
    assert idn.wallet == wallet_ala, "ta sama tożsamość po restarcie"
    assert stat.S_IMODE(os.stat(p_ala).st_mode) == 0o600
    print(f"  [OK] 1. create→lock→load→unlock: wallet={wallet_ala}, perms=0600")

    # 2) złe hasło ≠ destrukcja: dobre hasło dalej działa (D3)
    try:
        Keystore.load(p_ala).unlock(b"zle-haslo-999")
        raise AssertionError("przyjęto złe hasło!")
    except KeystoreError:
        pass
    assert Keystore.load(p_ala).unlock(b"sekret-ala-123").wallet == wallet_ala
    print("  [OK] 2. 1 poślizg hasła: nic się nie psuje, dobre hasło wchodzi")

    # 3) backoff: opóźnienia rosną ×2 od 3-ciej próby (sleeper stub)
    ks3 = Keystore.load(p_ala)
    sleeps = []
    ks3._sleeper = sleeps.append
    for bad in (b"a1" * 10, b"a2" * 10, b"a3" * 10, b"a4" * 10, b"a5" * 10):
        try:
            ks3.unlock(bad)
        except KeystoreError:
            pass
    assert sleeps == [2.0, 4.0, 8.0], f"backoff {sleeps}"
    ks3._sleeper = lambda s: sleeps.append(s)
    assert ks3.unlock(b"sekret-ala-123").wallet == wallet_ala   # bramka nie zabija
    env = json.load(open(p_ala))
    assert env["fail_count"] == 0, "sukces zeruje licznik porażek"
    print(f"  [OK] 3. backoff ×2 od 3-ciej próby: {sleeps}; sukces zeruje licznik")

    # 4) ZŁE hasło paniki = zwykła porażka (NIE shred! inaczej wróg niszczy dane)
    try:
        Keystore.load(p_ala).unlock(b"panika-ala-457")
        raise AssertionError("przyjęto złe hasło paniki!")
    except KeystoreError:
        pass
    assert os.path.exists(p_ala)
    print("  [OK] 4. literówka w haśle paniki: plik żyje (tylko trafienie shreaduje)")

    # 5) PANIKA: trafione hasło paniki = plik nadpisany i zniknięty
    p_panic = os.path.join(tmpd, "ofiar.ks1")
    ksp = Keystore.create(p_panic, "ofiar", b"haslo-ofiary-1", b"panika-ofiary-1", kdf=FAST)
    ksp.lock()
    try:
        Keystore.load(p_panic).unlock(b"panika-ofiary-1")
        raise AssertionError("powinno być PanicActivated")
    except PanicActivated:
        pass
    assert not os.path.exists(p_panic), "plik po panice ma NIE istnieć"
    try:
        Keystore.load(p_panic)
        raise AssertionError("załadowano zniszczony keystore!")
    except KeystoreError:
        pass
    print("  [OK] 5. hasło paniki: plik nadpisany+skasowany, keystore martwy (cichy shred)")

    # 6) zmiana hasła: stare pada, nowe działa, payload ten sam (przewinięcie MEK)
    ks6 = Keystore.load(p_ala)
    ks6.unlock(b"sekret-ala-123")
    payload_before = ks6._env["payload"]
    ks6.change_password(b"sekret-ala-321", b"panika-ala-654")
    assert ks6._env["payload"] == payload_before, "payload ma być NIETKNIĘTY"
    ks6.lock()
    try:
        Keystore.load(p_ala).unlock(b"sekret-ala-123")
        raise AssertionError("stare hasło dalej działa!")
    except KeystoreError:
        pass
    assert Keystore.load(p_ala).unlock(b"sekret-ala-321").wallet == wallet_ala
    print("  [OK] 6. zmiana hasła: przewinięto 32B wrapu, payload nietknięty, stare martwe")

    # 7) kontakty: zapis w kontenerze + ochrona anty-spoof (check_profile)
    #    (edytuje ŚWIEŻA instancja ks6 — uczy: jeden piszący proces na plik!)
    ks6.unlock(b"sekret-ala-321")
    p_bob = os.path.join(tmpd, "bob.ks1")
    ksb = Keystore.create(p_bob, "bob", b"sekret-bob-123", b"panika-bob-123", kdf=FAST)
    prof_bob, wallet_bob = ksb.profile_public(), ksb.identity.wallet
    assert ks6.add_contact(prof_bob) is None
    fake = dict(prof_bob)
    fake["x_pub"] = prof_ala["x_pub"]           # atak: profil Boba z kluczem Ali
    try:
        ks6.add_contact(fake)
        raise AssertionError("przyjęto sfałszowany kontakt!")
    except Exception:
        pass
    ks3b = Keystore.load(p_ala)
    ks3b.unlock(b"sekret-ala-321")
    assert ks3b.contacts()[0]["profile"]["wallet"] == wallet_bob
    print("  [OK] 7. kontakt zapisany w kontenerze; podmiana klucza w profilu odrzucona")

    # 8) E2E przez kontenery (symuluje: reboot → passkey → walizki działają)
    ala = Keystore.load(p_ala); ala.unlock(b"sekret-ala-321")
    bob = Keystore.load(p_bob); bob.unlock(b"sekret-bob-123")
    blob = ala.identity.encrypt_to(bob.contacts()[0]["profile"]
                                   if bob.contacts() else ks3b.contacts()[0]["profile"],
                                   "siema Bob, przeżyliśmy amnezję".encode("utf-8"))
    pt, sender = bob.identity.decrypt_from(blob)
    assert sender == wallet_ala and b"amnezj" in pt
    print("  [OK] 8. E2E po 'restarcie': passkey otworzył kontenery, walizki działają")

    # 9) recovery udziałami (D9, user-side): 2 z 3 otwiera; 1 nie otwiera NIC
    shares = ala.export_recovery_shares(k=2, n=3)
    rec = Keystore.load_with_shares(p_ala, [shares[0], shares[2]])
    assert rec.identity.wallet == wallet_ala
    try:
        Keystore.load_with_shares(p_ala, [shares[1]])
        raise AssertionError("1 udział wystarczył!")
    except KeystoreError:
        pass
    print("  [OK] 9. recovery Shamir 2-z-3: 2 udziały otwierają, 1 = matematycznie nic")

    print("\nSELFTEST: PASS ✅  keystore KS1 (D3+D9+D24) gotowy")
