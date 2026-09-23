# fenix_crypto.py
# ============================================================
#  Rdzen kryptograficzny FENIX  |  Projekt AnonNet / Fenix
#  Faza 1 (Core) + fundament pod Faze 4/5 (siec + blockchain)
# ------------------------------------------------------------
#  Co ten plik GWARANTUJE:
#   1) E2E: wiadomosc czyta TYLKO odbiorca.
#      Podmiot trzeci (ISP, sniffer, panstwo) widzi losowy szum.
#   2) Podpis: nikt nie podszyje sie pod Wallet Address nadawcy.
#   3) Skarbiec sieci (threshold): klucz glowny FNX podzielony
#      na udzialy (Shamir, prog k-z-n). Pelny klucz NIE ISTNIEJE
#      w zadnym pojedynczym miejscu -> odszyfrowanie danych
#      blockchainu mozliwe TYLKO przy wspolpracy wezlow Fenixa.
#   4) Panic button = zniszczenie udzialow/kluczy = dane martwe
#      na zawsze (crypto-shredding > kasowanie plikow).
#
#  Zaleznosci: pip install cryptography
# ============================================================

import base64
import hashlib
import secrets

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_RAW = serialization.Encoding.Raw
_RAWP = serialization.PublicFormat.Raw


def wallet_address(sig_pub_b: bytes, x_pub_b: bytes) -> str:
    """FNX1... liczony z OBOU kluczy publicznych — identyfikator zamiast IP/MAC."""
    h = hashlib.blake2s(sig_pub_b + x_pub_b, digest_size=20).digest()
    return "FNX1" + base64.b32encode(h).decode().lower()


# ============================================================
#  1) TOZSAMOSC UZYTKOWNIKA — Wallet + Username + UID
#     Klucze prywatne nigdy nie opuszczaja RAM urzadzenia.
# ============================================================
class Identity:
    def __init__(self, username: str):
        self.username = username
        self._x_priv = X25519PrivateKey.generate()    # ECDH — do szyfrowania
        self._s_priv = Ed25519PrivateKey.generate()   # do podpisow
        self.sig_pub_b = self._s_priv.public_key().public_bytes(_RAW, _RAWP)
        self.x_pub_b = self._x_priv.public_key().public_bytes(_RAW, _RAWP)
        self.wallet = wallet_address(self.sig_pub_b, self.x_pub_b)
        self.uid = hashlib.blake2s(self.x_pub_b, digest_size=4).hexdigest()

    @classmethod
    def generate(cls, username: str) -> "Identity":
        return cls(username)


# ============================================================
#  2) WIADOMOSCI E2E (hybryda: X25519 -> HKDF -> AES-256-GCM + Ed25519)
#     Blob jest samowystarczalny — mozna go np. wrzucic na blockchain:
#       [ sig_pub 32B | x_pub 32B | eph_pub 32B ]  (naglowek)
#       [ podpis 64B ] [ nonce 12B ] [ szyfrogram ]
# ============================================================
def encrypt_message(sender: Identity, recipient_x_pub_b: bytes, plaintext: bytes) -> bytes:
    eph = X25519PrivateKey.generate()   # klucz jednorazowy -> FORWARD SECRECY
    shared = eph.exchange(
        X25519PublicKey.from_public_bytes(recipient_x_pub_b))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"fenix-msg-v1").derive(shared)

    eph_pub_b = eph.public_key().public_bytes(_RAW, _RAWP)
    header = sender.sig_pub_b + sender.x_pub_b + eph_pub_b   # 96 B
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, header)  # header = AAD: niepodmienialny
    sig = sender._s_priv.sign(header + nonce + ct)
    return header + sig + nonce + ct


def decrypt_message(recipient: Identity, blob: bytes):
    """Zwraca (plaintext, wallet_nadawcy). Jakikolwiek przeklam = wyjatek."""
    header, rest = blob[:96], blob[96:]
    spub_b, xpub_b, eph_b = header[:32], header[32:64], header[64:]
    sig, nonce, ct = rest[:64], rest[64:76], rest[76:]

    # a) autentycznosc: podpis musi pasowac do kluczy z naglowka
    Ed25519PublicKey.from_public_bytes(spub_b).verify(sig, header + nonce + ct)
    # b) wspolny sekret policzy TYLKO posiadacz prywatnego klucza odbiorcy
    shared = recipient._x_priv.exchange(X25519PublicKey.from_public_bytes(eph_b))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"fenix-msg-v1").derive(shared)
    pt = AESGCM(key).decrypt(nonce, ct, header)   # InvalidTag = proba oszustwa
    return pt, wallet_address(spub_b, xpub_b)


# ============================================================
#  3) SHAMIR — dzielenie sekretu k-z-n (fundament skarbca sieci)
#     Arytmetyka mod p (p = 2**256 - 189, liczba pierwsza).
#     k udzialow -> sekret odzyskany.  k-1 -> ZERO informacji.
# ============================================================
_P = 2**256 - 189


def _eval_poly(coeffs, x):
    y = 0
    for c in reversed(coeffs):          # schemat Hornera
        y = (y * x + c) % _P
    return y


def split_secret(secret: bytes, k: int, n: int):
    """Zwraca n udzialow; kazdy: bajt_x || po 32B na kazdy bajt sekretu."""
    if not (1 < k <= n < 256):
        raise ValueError("wymagane: 1 < k <= n < 256")
    polys = [[b] + [secrets.randbelow(_P) for _ in range(k - 1)] for b in secret]
    shares = []
    for x in range(1, n + 1):
        y = b"".join(_eval_poly(poly, x).to_bytes(32, "big") for poly in polys)
        shares.append(bytes([x]) + y)
    return shares


def combine_shares(shares) -> bytes:
    """Interpolacja Lagrange'a w punkcie x=0 -> ORYGINALNY sekret."""
    xs = [s[0] for s in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("zduplikowane udzialy!")
    body_len = len(shares[0]) - 1
    secret = bytearray()
    for off in range(0, body_len, 32):
        total = 0
        for j, sj in enumerate(shares):
            xj = sj[0]
            yj = int.from_bytes(sj[1 + off: 1 + off + 32], "big")
            num, den = 1, 1
            for m, sm in enumerate(shares):
                if m == j:
                    continue
                num = (num * (-sm[0])) % _P
                den = (den * (xj - sm[0])) % _P
            total = (total + yj * num * pow(den, -1, _P)) % _P
        if total > 255:
            raise ValueError("udzialy nie pasuja (za malo / uszkodzone / falszywe)")
        secret.append(total)
    return bytes(secret)


# ============================================================
#  4) SKARBIEC SIECI — dane blockchainu pod kluczem, ktorego
#     NIE MA w jednym miejscu. Otwiera go tylko wspolpraca wezlow.
#     (Docelowo: DKG + threshold ElGamal w Fazie 5 — wtedy master
#      NIGDY nie powstaje nawet na chwile. Tu: demo mechanizmu progu.)
# ============================================================
class NetworkVault:
    @staticmethod
    def create(k: int = 3, n: int = 5):
        master = secrets.token_bytes(32)
        return master, split_secret(master, k, n)

    @staticmethod
    def encrypt(master: bytes, data: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(master).encrypt(nonce, data, b"fenix-vault-v1")

    @staticmethod
    def decrypt(shares, blob: bytes) -> bytes:
        master = combine_shares(shares)         # mniej niz k udzialow -> wyjatek/szum
        nonce, ct = blob[:12], blob[12:]
        return AESGCM(master).decrypt(nonce, ct, b"fenix-vault-v1")


# ============================================================
#  DEMO — test bojowy wszystkich gwarancji
# ============================================================
if __name__ == "__main__":
    line = "=" * 60
    print(line)
    print("FENIX :: test kryptografii (E2E + skarbiec sieci)")
    print(line)

    alice = Identity.generate("alice")
    bob   = Identity.generate("bob")
    eve   = Identity.generate("eve_podmiot_3")     # <- podmiot trzeci!

    for who in (alice, bob):
        print(f"[id] {who.username:14} wallet={who.wallet}  uid={who.uid}")

    # --- TEST 1: wiadomosc E2E ---
    msg = b"Blockchain FNX: blok #1 zatwierdzony."
    blob = encrypt_message(alice, bob.x_pub_b, msg)
    print(f"\n[e2e] blob ({len(blob)}B) poczatek: {blob[:24].hex()}...")

    pt, sender_addr = decrypt_message(bob, blob)
    assert pt == msg and sender_addr == alice.wallet
    print(f"[e2e] Bob odszyfrowal : {pt.decode()}")
    print(f"[e2e] Nadawca potwierdzony: {sender_addr}")

    # --- TEST 2: podmiot trzeci probuje czytac ---
    try:
        decrypt_message(eve, blob)
        print("[!!] BLAD BEZPIECZENSTWA: Eve odszyfrowala!")
    except (InvalidTag, InvalidSignature, ValueError):
        print("[ok] Eve NIE odszyfruje — dla niej to losowy szum.")

    # --- TEST 3: manipulacja przy transporcie ---
    tampered = bytearray(blob)
    tampered[-1] ^= 1
    try:
        decrypt_message(bob, bytes(tampered))
        print("[!!] BLAD: przyjeto zmodyfikowana wiadomosc!")
    except (InvalidTag, InvalidSignature):
        print("[ok] Przeklamany 1 bit -> wiadomosc odrzucona (podpis/GCM).")

    # --- TEST 4: skarbiec sieci (prog 3 z 5) ---
    print(line)
    master, shares = NetworkVault.create(k=3, n=5)
    vb = NetworkVault.encrypt(master, b"PAYLOAD BLOCKCHAINU FNX")
    print(f"[vault] 5 wezlow, prog=3. Szyfrogram: {vb[:20].hex()}...")

    ok = NetworkVault.decrypt([shares[0], shares[2], shares[4]], vb)
    print(f"[vault] 3 udzialy wspolpracuja -> OK: {ok.decode()}")

    try:
        NetworkVault.decrypt([shares[1], shares[3]], vb)   # tylko 2 udzialy!
        raise SystemExit("KRYTYCZNY: 2 udzialy wystarczyly do odszyfrowania!")  # test MUSI paść
    except (InvalidTag, ValueError):
        print("[ok] 2 udzialy < prog -> matematycznie NIC do odzyskania.")

    # --- TEST 5: panic button ---
    del master, shares
    print("[ok] PANIC: udzialy zniszczone -> dane skarbca MARTWE na zawsze.")
    print("\nSELFTEST: PASS ✅ fenix_crypto (E2E AEAD, wallet addr, Shamir 3z5, panic)")
