# core/identity.py
"""
Tożsamość Fenixa = Wallet Address + Username + UID + Ranga  (Filar 1, D16).

JEDYNY identyfikator w całej sieci. Nie istnieje IP, MAC, email, telefon —
istnieje TO: para kluczy, z której liczony jest wallet, plus etykiety.

Kluczowa granica (serce bezpieczeństwa):
  ┌────────────────────────────────────────────────────────────┐
  │ PRIVATE (Identity)          │ PUBLIC (profil)              │
  │  klucze prywatne X25519     │  wallet FNX1… (z pubkluczy)  │
  │  + Ed25519 — TYLKO RAM,     │  username, uid, ranga        │
  │  nigdy dysk bez keystora    │  pubklucze (do walizek E2E)  │
  │  (plik core/keystore.py),   │  → to leci do sieci; z tego  │
  │  nigdy sieć                 │    każdy może Ci szyfrować   │
  └────────────────────────────────────────────────────────────┘

Profil publiczny jest jak tabliczka na drzwiach z adresem: dzięki niej każdy
może zrobić dla Ciebie zaszyfrowaną "walizkę" (E2E), ale otworzysz ją TYLKO Ty —
bo klucz od walizki (prywatny X25519) nigdy nie opuszcza Twojego RAM-u.
Odszyfrowanie dzieje się wyłącznie na Twojej maszynie, w momencie czytania.

Username: 3–24 znaki [a-z0-9_-], lowercase. Ograniczenie celowe: brak
wielkich liter i "klonów" (0 vs O, l vs I) = obrona przed podszywaniem
się pod podobne nicki. Unikalność egzekwuje dopiero łańcuch (ID_DECLARE, M5).

Ranga: startuje zawsze jako "ghost", jest CACHE — prawdą jest łańcuch
(RANK_UP, 6 potwierdzeń, D16). Ranga nigdy nie daje głosu/danych/władzy.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys as _sys
import time
import pathlib as _pl

# Pozwala odpalić plik wprost (python core/identity.py) i jako moduł (-m core.identity)
if __package__ in (None, ""):
    _sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from core.crypto.fenix_crypto import Identity as _CryptoIdentity
from core.crypto.fenix_crypto import encrypt_message, decrypt_message, wallet_address

_RAW = serialization.Encoding.Raw
_RAWP = serialization.PublicFormat.Raw

PROFILE_VERSION = 1

# --- Username: małe litery, cyfry, _ i - ; 3–24 znaki -------------------------
_USERNAME_RE = re.compile(r"^[a-z0-9_][a-z0-9_-]{2,23}$")

# --- Rangi wg D16 (kolejność = tier QoS 0–7) ----------------------------------
RANKS = ("ghost", "donor", "vip", "vip+", "svip", "elite", "selite", "fenix")


class IdentityError(Exception):
    """Błędy tożsamości (zły username, zła ranga, sfabrykowany profil)."""


def valid_username(name: str) -> bool:
    return bool(_USERNAME_RE.match(name))


def rank_tier(rank: str) -> int:
    """ghost→0 … fenix→7 (tier QoS, D16). Nieznana ranga = wyjątek, nie cicho 0."""
    if rank not in RANKS:
        raise IdentityError(f"nieznana ranga: {rank!r}")
    return RANKS.index(rank)


class Identity:
    """Pełna tożsamość (część prywatna + publiczna). Tworzenie:

        me = Identity.generate("neo")
        me.wallet           # 'FNX1…' — Twój adres w sieci
        me.uid              # 'a1b2-c3d4' — krótki identyfikator do GUI
        me.public_profile() # to można pokazać światu / wysłać w HELLO

    UWAGA: ten obiekt trzyma klucze prywatne w RAM. Zapis na dysk =
    WYŁĄCZNIE przez core/keystore.py (hasło, Argon2id, D3). Nigdy json/pickle
    tego obiektu na dysk.
    """

    def __init__(self, username: str):
        if not valid_username(username):
            raise IdentityError(
                "username: 3–24 znaki [a-z0-9_-], małe litery, pierwszy znak nie '-'")
        self.username = username
        # rdzeń krypto generuje/obchodzi klucze (core/crypto/fenix_crypto.py)
        self._core = _CryptoIdentity.generate(username)
        self.rank = "ghost"                 # każdy startuje jako duch (D16)
        self.created_at = int(time.time())  # lokalna notatka; NIGDY nie wysyłamy

    # --- fabryka --------------------------------------------------------------
    @classmethod
    def generate(cls, username: str) -> "Identity":
        return cls(username)

    @classmethod
    def from_private(cls, username: str, x_priv_b: bytes, s_priv_b: bytes,
                     created_at: int | None = None) -> "Identity":
        """Odbudowa tożsamości z surowych kluczy (32B X25519 + 32B Ed25519).

        Wywołuje ją WYŁĄCZNIE core/keystore.py przy każdym unlock — ta sama
        para kluczy MUSI dawać ten sam wallet/UID (inaczej tożsamość byłaby
        'co restart inna'). Budujemy przez __new__, bo rdzeń krypto zna tylko
        generate(); przy przeglądzie M1 fenix_crypto dostanie czystszy konstruktor.
        """
        if len(x_priv_b) != 32 or len(s_priv_b) != 32:
            raise IdentityError("klucze prywatne: dokładnie 32B każdy")
        if not valid_username(username):
            raise IdentityError("username z keystora nie przechodzi walidacji")
        self = cls.__new__(cls)
        self.username = username
        crypto = _CryptoIdentity.__new__(_CryptoIdentity)
        crypto.username = username
        crypto._x_priv = X25519PrivateKey.from_private_bytes(x_priv_b)
        crypto._s_priv = Ed25519PrivateKey.from_private_bytes(s_priv_b)
        crypto.sig_pub_b = crypto._s_priv.public_key().public_bytes(_RAW, _RAWP)
        crypto.x_pub_b = crypto._x_priv.public_key().public_bytes(_RAW, _RAWP)
        crypto.wallet = wallet_address(crypto.sig_pub_b, crypto.x_pub_b)
        crypto.uid = hashlib.blake2s(crypto.x_pub_b, digest_size=4).hexdigest()
        self._core = crypto
        self.rank = "ghost"
        self.created_at = created_at if created_at else int(time.time())
        return self

    def _private_bundle(self) -> dict:
        """SUROWE klucze prywatne jako hex. *** TYLKO dla core/keystore.py ***
        (trafiają wyłącznie do zaszyfrowanego payloadu KS1). Nigdzie indziej
        NIE eksportować — to jest 'serce' tożsamości."""
        return {
            "x_priv": self._core._x_priv.private_bytes(
                _RAW, PrivateFormat.Raw, NoEncryption()).hex(),
            "s_priv": self._core._s_priv.private_bytes(
                _RAW, PrivateFormat.Raw, NoEncryption()).hex(),
        }

    # --- identyfikatory publiczne (delegacje do rdzenia krypto) ---------------
    @property
    def wallet(self) -> str:
        return self._core.wallet

    @property
    def uid(self) -> str:
        """Czytelny UID '####-####' — deterministyczny z klucza (ta sama
        tożsamość = ten sam UID wszędzie)."""
        raw = self._core.uid
        return f"{raw[:4]}-{raw[4:]}"

    @property
    def x_pub_b(self) -> bytes:
        """Publiczny klucz do SZYFROWANIA do mnie (walizki E2E)."""
        return self._core.x_pub_b

    @property
    def sig_pub_b(self) -> bytes:
        """Publiczny klucz do WERYFIKACJI moich podpisów."""
        return self._core.sig_pub_b

    # --- ranga (lokalny cache — prawda jest na łańcuchu) ----------------------
    def set_rank(self, rank: str) -> None:
        rank_tier(rank)  # walidacja rzuci wyjątek przy literówce
        self.rank = rank

    @property
    def tier(self) -> int:
        return rank_tier(self.rank)

    # --- PROFIL PUBLICZNY -----------------------------------------------------
    def public_profile(self) -> dict:
        """Jedyne, co wolno wysłać do sieci / pokazać kontaktom.

        Zero prywatności: same klucze PUBLICZNE + etykiety. Z tego profilu
        każdy może: (a) szyfrować do Ciebie E2E, (b) sprawdzić Twoje podpisy,
        (c) przeliczyć sobie wallet i upewnić się, że klucze do niego pasują.
        """
        return {
            "pv": PROFILE_VERSION,
            "wallet": self.wallet,
            "username": self.username,
            "uid": self.uid,
            "rank": self.rank,
            "sig_pub": self.sig_pub_b.hex(),
            "x_pub": self.x_pub_b.hex(),
        }

    def profile_json(self) -> str:
        return json.dumps(self.public_profile(), sort_keys=True, separators=(",", ":"))

    def sign(self, data: bytes) -> bytes:
        """Podpis Ed25519 — dowód 'to naprawdę ja' bez ujawniania klucza."""
        return self._core._s_priv.sign(data)

    def x25519_shared(self, peer_x_pub: bytes) -> bytes:
        """Współdzielony sekret X25519 z MOICH kluczy statycznych i jego x_pub
        (32 B) — do warstw na kanale (FNX64 D70). To NIE jest eksport klucza:
        wraca 32-bajtowy wynik DH, z którego priv nie wychodzi."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        if len(peer_x_pub) != 32:
            raise IdentityError("peer_x_pub musi mieć 32 B (raw X25519)")
        return self._core._x_priv.exchange(
            X25519PublicKey.from_public_bytes(peer_x_pub))

    # --- E2E w skrócie (most do core/crypto/fenix_crypto.py) -------------------
    def encrypt_to(self, recipient_profile: dict, plaintext: bytes) -> bytes:
        """Szyfruj DO właściciela profilu. Wystarczy jego część publiczna —
        walizkę otworzy tylko on, na swojej maszynie."""
        rec_x = bytes.fromhex(recipient_profile["x_pub"])
        return encrypt_message(self._core, rec_x, plaintext)

    def decrypt_from(self, blob: bytes):
        """Odszyfruj walizkę adresowaną do mnie. Działa TYLKO tutaj, bo tylko
        tutaj jest klucz prywatny. Zwraca (plaintext, wallet_nadawcy)."""
        return decrypt_message(self._core, blob)


# --- weryfikacja CUDZYCH profili (anty-podmianka) ------------------------------
def check_profile(profile: dict) -> None:
    """Rzuca IdentityError, gdy profil jest spreparowany.

    Atak, który to łapie: ktoś wysyła CIĘBIE podmieniony profil ofiary
    z JEJ walletem, ale SWOIMI kluczami → czytałby Twoje "walizki" do niej.
    Obrona: wallet MUSI wychodzić z kluczy w profilu (przeliczamy lokalnie).
    """
    try:
        sig_pub = bytes.fromhex(profile["sig_pub"])
        x_pub = bytes.fromhex(profile["x_pub"])
    except (KeyError, ValueError):
        raise IdentityError("profil: brak/złe klucze publiczne") from None
    if not valid_username(profile.get("username", "")):
        raise IdentityError("profil: zły username")
    if wallet_address(sig_pub, x_pub) != profile.get("wallet"):
        raise IdentityError("profil: klucze NIE pasują do walleta (podmianka!)")
    uid_raw = hashlib.blake2s(x_pub, digest_size=4).hexdigest()
    if profile.get("uid") != f"{uid_raw[:4]}-{uid_raw[4:]}":
        raise IdentityError("profil: UID nie pasuje do kluczy")
    rank_tier(profile.get("rank", ""))  # nieznana ranga → wyjątek


def verify_signed(profile: dict, signature: bytes, data: bytes) -> bool:
    """Sprawdź podpis 'profile' pod danymi, używając klucza Z profilu
    (po check_profile!). False = nie weryfikuje się; nigdy wyjątek w API GUI."""
    check_profile(profile)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(profile["sig_pub"])) \
            .verify(signature, data)
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# ADRES KONTAKTOWY / STEALTH (FNXS1) — jedynym źródłem jest core (D28/D31a)
# Używają go: gui/pool_panel.py (adres prywatny portfela) i app/messenger.py
# (kontakt do szyfrowanej rozmowy) — TEN SAM pakiet kluczy sig_pub‖x_pub.
# ---------------------------------------------------------------------------
STEALTH_ADDR_PREFIX = "FNXS1"
STEALTH_ADDR_BODY = 128          # 64B kluczy publicznych hex
STEALTH_ADDR_CHECKSUM = 8        # 4B blake2s hex (anty-literówka)


def encode_stealth_address(sig_pub_b: bytes, x_pub_b: bytes) -> str:
    raw = bytes(sig_pub_b) + bytes(x_pub_b)
    if len(raw) != 64:
        raise IdentityError("adres FNXS1: klucze publiczne muszą mieć po 32B")
    chk = hashlib.blake2s(raw, digest_size=4).hexdigest()
    return STEALTH_ADDR_PREFIX + raw.hex() + chk


def decode_stealth_address(addr: str) -> tuple[bytes, bytes]:
    """→ (sig_pub_b, x_pub_b); błąd → IdentityError z ludzkim opisem."""
    a = (addr or "").strip()
    if not a.startswith(STEALTH_ADDR_PREFIX):
        raise IdentityError(f"adres zaczyna się od {STEALTH_ADDR_PREFIX}…")
    body = a[len(STEALTH_ADDR_PREFIX):]
    want = STEALTH_ADDR_BODY + STEALTH_ADDR_CHECKSUM
    if len(body) != want:
        raise IdentityError(f"adres ma {len(body)} znaków, a ma mieć {want}")
    try:
        raw = bytes.fromhex(body)
    except ValueError:
        raise IdentityError("adres: dozwolone tylko znaki hex (0-9 a-f)") from None
    keys, chk = raw[:64], raw[64:]
    if hashlib.blake2s(keys, digest_size=4).digest() != chk:
        raise IdentityError("checksum się nie zgadza — literówka w adresie?")
    return keys[:32], keys[32:]


def contact_fingerprint(sig_pub_b: bytes, x_pub_b: bytes, grouped: bool = True) -> str:
    """TOFU-odcisk kontaktu (16 hex znaków): porównujesz DRUGIM kanałem
    przy pierwszym kontakcie — anty-impersonacja (D28)."""
    fp = hashlib.blake2s(bytes(sig_pub_b) + bytes(x_pub_b), digest_size=8).hexdigest()
    return "-".join(fp[i:i + 4] for i in range(0, 16, 4)) if grouped else fp


# ---------------------------------------------------------------------------
# Selftest — uruchom:  python core/identity.py   (albo: python -m core.identity)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("core/identity.py — selftest tożsamości (Filar 1)\n")

    # 1) dwie tożsamości; format identyfikatorów
    ala = Identity.generate("ala")
    bob = Identity.generate("bob_kopie")
    assert ala.wallet.startswith("FNX1") and len(ala.wallet) == 36
    assert re.match(r"^[0-9a-f]{4}-[0-9a-f]{4}$", ala.uid)
    print(f"  [OK] 1. ala:  {ala.wallet}  uid={ala.uid}  ranga={ala.rank}")
    print(f"  [OK]    bob:  {bob.wallet}  uid={bob.uid}  ranga={bob.rank}")

    # 2) walidacja username (obrona przed klonami „Admin" vs „adm1n")
    for bad in ("Alice", "a", "admin root", "łukasz", "-mafia", "x" * 25):
        try:
            Identity.generate(bad)
            raise AssertionError(f"przyjęto zły username: {bad!r}")
        except IdentityError:
            pass
    print("  [OK] 2. złe username'y odrzucone (wielkie litery, spacje, klony)")

    # 3) ranga: start = ghost; literówka = wyjątek; tier działa
    assert ala.rank == "ghost" and ala.tier == 0
    ala.set_rank("vip")
    assert ala.tier == 2 and rank_tier("fenix") == 7
    try:
        ala.set_rank("root")
        raise AssertionError("przyjęto zmyśloną rangę!")
    except IdentityError:
        pass
    ala.set_rank("ghost")
    print("  [OK] 3. ranga: ghost startuje, 'root' nie istnieje, tier QoS 0–7 (D16)")

    # 4) profil publiczny = same dane publiczne (nie ma czego ukraść)
    p_ala = ala.public_profile()
    p_bob = bob.public_profile()
    assert set(p_ala) == {"pv", "wallet", "username", "uid", "rank", "sig_pub", "x_pub"}
    check_profile(p_ala)
    print(f"  [OK] 4. profil publiczny OK: {json.dumps(p_ala)[:70]}…")

    # 5) E2E przez profil: Ala szyfruje do Boba znając TYLKO jego profil;
    #    odszyfrować może WYŁĄCZNIE maszyna Boba (tam jest klucz prywatny)
    blob = ala.encrypt_to(p_bob, "cześć Bob, koniec maila — początek walizki".encode("utf-8"))
    pt, sender = bob.decrypt_from(blob)
    assert pt.startswith(b"cze") and sender == ala.wallet
    print("  [OK] 5. E2E: profil wystarcza do walizki; czyta tylko Bob")

    # 6) Eve ma profil Boba (publiczny!) i nadal NIE odczyta walizki
    eve = Identity.generate("eve")
    check_profile(p_bob)          # profil może mieć każdy — to tabliczka adresowa
    try:
        eve.decrypt_from(blob)
        raise AssertionError("Eve odczytała!")
    except Exception:
        print("  [OK] 6. Eve z profilem Boba: nadal losowy szum (E2E trzyma)")

    # 7) podmianka kluczy w profilu = wykryta (wallet nie pasuje do kluczy)
    fake = dict(p_bob)
    fake["x_pub"] = ala.x_pub_b.hex()       # atakujący podkłada SWÓJ klucz
    try:
        check_profile(fake)
        raise AssertionError("profile swap przeszedł!")
    except IdentityError:
        print("  [OK] 7. podmiana klucza w profilu = wykryta (MITM PROFILE SWAP)")

    # 8) podpis + weryfikacja z profilu (u odbiorcy, bez zaufania do transportu)
    sig = ala.sign(b"ID_DECLARE ala")
    assert verify_signed(p_ala, sig, b"ID_DECLARE ala") is True
    assert verify_signed(p_ala, sig, b"ID_DECLARE admin") is False
    print("  [OK] 8. podpis: dobry przechodzi, zmieniona treść = False")

    # 9) adres FNXS1 jako rdzeń core (używany przez pool i messengera)
    addr = encode_stealth_address(ala.sig_pub_b, ala.x_pub_b)
    assert addr.startswith("FNXS1")
    sb, xb = decode_stealth_address(addr)
    assert sb == ala.sig_pub_b and xb == ala.x_pub_b
    for bad in (addr[1:], addr[:-2] + "00", addr + "ff", "FNX1" + addr[5:]):
        try:
            decode_stealth_address(bad)
            raise AssertionError(f"zły adres przeszedł: {bad[:14]}…")
        except IdentityError:
            pass
    fp = contact_fingerprint(ala.sig_pub_b, ala.x_pub_b)
    assert re.match(r"^[0-9a-f]{4}(-[0-9a-f]{4}){3}$", fp)
    assert contact_fingerprint(bob.sig_pub_b, bob.x_pub_b) != fp
    print("  [OK] 9. FNXS1 rdzeń core: round-trip + checksum; fingerprint TOFU 4-4-4-4")

    print("\nSELFTEST: PASS ✅  tożsamość = Wallet + Username + UID + Ranga")
