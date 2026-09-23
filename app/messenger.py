# app/messenger.py — rdzeń komunikatora FNX (M4): kontakt FNXS1 (D28), E2E, TOFU
"""
Model (analogia „sejf z dwiema skrytkami i odciskiem palca na drzwiach"):
  KONTAKT = adres FNXS1 (sig_pub‖x_pub + checksum — TEN SAM format co adres
  prywatny portfela z gui/pool_panel; rdzeń codec w core/identity.py).
  Username jest etykietą WYŚWIETLANĄ, nie dowodem tożsamości — dowód to
  podpis ed25519 pod wiadomością + odcisk TOFU (porównany drugim kanałem).

KANAŁ E2E — dwa protokoły na jednym drucie:
  v1 (legacy, czytany dalej): eph X25519 per wiadomość; „from" na jawie.
  v2 = FNX-R1 RATCHET (D43, domyślny): nadawca ukryty (brak from/eph na jawie),
  klucz wiadomości mk = HMAC(ck) zużyty RAZ i wymazywany; ck postępuje tylko
  naprzód; przy każdej zmianie kierunku rozmowy nowa para X25519 (kick):
  root' = HMAC(root, DH(nowy, ich_pub)). Skradziony długi klucz tożsamości
  NIE odszyfruje starych rozmów po pierwszym kicku (PFS udowodniony testem 9:
  „złodziej z x_priv" czyta co najwyżej do pierwnego kicka, dalej już nie).
  Kolejność/replay: seq wewnętrzny TOFU jak w v1 + okno skip ≤ 32 (mesh lubi
  przestawiać); stragglers z poprzedniej rundy odszyfrowalne (prev, 1 poziom).
  Desync po utracie ramki = resync przy kolejnym kicku (kick daje świeży łańcuch
  od aktualnego roota — utrata N kopnięcia go nie psuje).
  Concurrent-init (D57, P24): gdy OBYDWIE strony napiszą pierwsze „na krzyż",
  kanonem jest root0 strony o MNIEJSZYM x_pub (obie liczą identycznie z adresów
  FNXS1); skrzyżowany łańcuch drugiej strony = kanał-czytanka cand (≤4, FIFO) —
  żadna ramka krzyżówki nie ginie; sesja zbiega w 1 RTT (test 13/14). Sesja już
  grająca jest NIETYKALNA dla „nowego nadawcy" pod tożsamość kontaktu (multi-
  device bez linku = uczciwy drop; link urządzeń = M4c).

TRANSPORT (D37): rdzeń nie zależy od transportu — duck-type send_env/poll_envs.
  LocalTransport = szyna w procesie (testy/dev). MESH = net/fenix_node T_MSG:
  gossip {v:1, ttl, env} po peerach (plasterki T_SYNC_PART dla dużych), dedup
  blake2s(canon(env)), ttl=5, skrzynka odbiorcy TYLKO w RAM demona (amnezja),
  zero zapisu na chain. Most do demona = gui/backend_ipc.MsgIpcTransport
  (opy msg_sub/msg_send/msg_poll, IPC /run/fenix/node.ipc).

GRANICE uczciwie: ratchet PFS = FNX-R1 (D43, ping-pong jak w Signal; pełne PFS po
pierwszej wymianie „tam i z powrotem" — przed nią root0 da się odtworzyć z długiego
klucza; uczciwie w teście), kolejka offline = spool TTL na relayu (D44), kontakty
on-chain (username→FNXS1) = backlog P21. Anti-forensic: TofuStore dla my[()] ma
shred 2× nadpis jak wszędzie w projekcie; stan ratchetu trzyma się w RAM (amnezja)
albo pod walizką TF1 — NIGDY w jawnym tofu na dysku.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import sys
import time
import pathlib as _pl
from dataclasses import dataclass, field

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidSignature, InvalidTag                  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey    # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import (                    # noqa: E402
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305          # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF                          # noqa: E402
from cryptography.hazmat.primitives.hashes import SHA256                          # noqa: E402
from cryptography.hazmat.primitives.serialization import (                        # noqa: E402
    Encoding, PublicFormat, PrivateFormat, NoEncryption)

from chain.block import canon                                                     # noqa: E402
from core.identity import (IdentityError, encode_stealth_address,                 # noqa: E402
                           decode_stealth_address, contact_fingerprint)
from core.keystore import KDFParams, _argon2id                                    # noqa: E402

MAX_TEXT = 4096                 # znaków na wiadomość (tekst, nie tunel FTP)
MAX_ENV = 16384                 # bajtów na całą kopertę JSON (anty-DoS)
_PROTO = 1
_PROTO2 = 2                     # FNX-R1 ratchet (D43): domyślny od M4b
_RK_CAP_SKIP = 32               # okno zamieszania mesh (pozakolejności/powtórki)
_RK_CAP_CAND = 4                # D57: kanały-czytanki skrzyżowanych łańcuchów per kontakt
_RK_CAP_TRIES = 64              # prób kick przy nieznanym pub (anty-CPU-DoS)


def _h256(k: bytes, tag: bytes) -> bytes:
    return _hmac.new(k, tag, hashlib.sha256).digest()


class MessengerError(Exception):
    """Błędy komunikatora — jeden typ (GUI pokazuje bez zgadywania)."""


# -------------------------------------------------------------------------- TOFU store
_TF1_MAGIC = b"TF1"          # kontener tofu szyfrowany hasłem (KS1-wrap, D40)
_TF1_AAD = b"TF1/tofu"


class TofuStore:
    """Trust-On-First-Use: fp → {addr, name, seq, first_ts, last_ts}.
    path=None → tylko RAM (amnezja/selftest); z path → zapis 0600 + shred(D9).

    WALIZKA TF1 (KS1-wrap): protect(hasło) → plik na dysku to ZAMKNIĘTA walizka:
    b"TF1" + ver(1) + m(4 LE) + t(1) + p(1) + salt(16) + nonce(12) + ChaCha20-
    Poly1305(json, KEK=Argon2id(hasło, salt, m/t/p z nagłówka), AAD=b"TF1/tofu").
    Złodziej z plikiem bez hasła widzi martwy szum (adresy/piny kontaktów
    są w środku szyfru). Złe hasło = MessengerError. Legacy plaintext JSON
    (tymczasowe/dev) nadal się czyta — unprotect() wraca do jawnego zapisu."""

    def __init__(self, path: str | None = None, passkey: str | bytes | None = None,
                 kdf: KDFParams | None = None):
        self.path = path
        self.pin: dict[str, dict] = {}
        self._passkey: bytes | None = None
        self._kdf = kdf
        if path and os.path.exists(path):
            with open(path, "rb") as f:
                raw = f.read()
            if raw.startswith(_TF1_MAGIC):
                if passkey is None:
                    raise MessengerError(
                        "kontakty szyfrowane hasłem (TF1) — najpierw odblokuj podając hasło")
                self._load_tf1(raw, passkey)
            else:
                self._load(raw)

    @staticmethod
    def is_encrypted(path: str) -> bool:
        """Czy plik na dysku to zamknięta walizka TF1 (peek po magii, bez otwierania)."""
        try:
            with open(path, "rb") as f:
                return f.read(3) == _TF1_MAGIC
        except OSError:
            return False

    def _pw(self, passkey: str | bytes) -> bytes:
        return passkey.encode("utf-8") if isinstance(passkey, str) else bytes(passkey)

    def _load(self, raw: bytes):
        try:
            data = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError, UnicodeDecodeError) as e:
            raise MessengerError(f"tofu-store uszkodzony: {e}") from None
        if not isinstance(data, dict) or data.get("v") != 1 or not isinstance(data.get("pin"), dict):
            raise MessengerError("tofu-store: zły format")
        self.pin = data["pin"]

    def _load_tf1(self, raw: bytes, passkey: str | bytes):
        if len(raw) < 3 + 1 + 4 + 1 + 1 + 16 + 12 + 16:
            raise MessengerError("tofu TF1: plik ucięty")
        if raw[3] != 1:
            raise MessengerError("tofu TF1: nieznana wersja kontenera")
        m_kib = int.from_bytes(raw[4:8], "little")
        kdf = KDFParams(m_kib=m_kib, t=raw[8], p=raw[9])
        salt, nonce, ct = raw[10:26], raw[26:38], raw[38:]
        pw = self._pw(passkey)
        try:
            pt = ChaCha20Poly1305(_argon2id(pw, salt, kdf)).decrypt(nonce, ct, _TF1_AAD)
        except InvalidTag:
            raise MessengerError("złe hasło do kontaktów (TF1) albo plik nadpisany") from None
        self._load(pt)
        self._passkey, self._kdf = pw, kdf          # kolejne save() zostają w walizce

    def protect(self, passkey: str | bytes, kdf: KDFParams | None = None):
        """Włącz szyfrowanie pliku TYM hasłem (od najbliższego save — robimy go od razu)."""
        pw = self._pw(passkey)
        if len(pw) < 6:
            raise MessengerError("hasło do kontaktów: min. 6 znaków (walizka z zasuwką to nie sejf)")
        self._passkey, self._kdf = pw, (kdf or KDFParams())
        self.save()

    def unprotect(self):
        """ŚWIADOMA decyzja: wracamy do jawnego JSON na dysku (RAM bez zmian)."""
        self._passkey = None
        self.save()

    @property
    def encrypted(self) -> bool:
        """Czy save() pisze walizką TF1 (passkey jest w RAM)."""
        return self._passkey is not None

    def save(self):
        if not self.path:
            return
        tmp = self.path + ".tmp"
        if self._passkey is not None:                     # WALIZKA TF1 (D40)
            kdf = self._kdf or KDFParams()
            salt = os.urandom(16)
            nonce = os.urandom(12)
            pt = json.dumps({"v": 1, "pin": self.pin},
                            ensure_ascii=False, sort_keys=True).encode("utf-8")
            ct = ChaCha20Poly1305(_argon2id(self._passkey, salt, kdf)).encrypt(
                nonce, pt, _TF1_AAD)
            blob = (_TF1_MAGIC + bytes([1]) + kdf.m_kib.to_bytes(4, "little")
                    + bytes([kdf.t, kdf.p]) + salt + nonce + ct)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
        else:                                              # legacy plaintext (dev)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"v": 1, "pin": self.pin}, f, ensure_ascii=False, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o600)

    def shred(self) -> bool:
        """2× nadpis (losowe + zera) + rm — wzorzec D9 z keystore/panicd."""
        if not self.path or not os.path.exists(self.path):
            return False
        size = os.path.getsize(self.path)
        for payload in (os.urandom, lambda n: b"\x00" * n):
            with open(self.path, "r+b", buffering=0) as f:
                left = size
                while left > 0:
                    chunk = payload(min(left, 1 << 20))
                    f.write(chunk)
                    left -= len(chunk)
                f.flush()
                os.fsync(f.fileno())
        os.remove(self.path)
        self.pin.clear()
        return True


# -------------------------------------------------------------------------- transport
class LocalTransport:
    """Szyna LOCAL: wspólny registry fp → [env-dict…] (testy/dev-demo w procesie).
    To MOST testowy, nie sieć — mesh T_MSG = net/fenix_node (D37, patrz docstring modułu)."""

    def __init__(self, registry: dict[str, list], my_fp: str):
        self.registry = registry
        self.my_fp = my_fp

    def send_env(self, env: dict) -> None:
        self.registry.setdefault(env["to_fp"], []).append(env)

    def poll_envs(self) -> list[dict]:
        q = self.registry.setdefault(self.my_fp, [])   # tworzę kolejkę, zanim ktokolwiek pisze
        return [q.pop(0) for _ in range(len(q))]


# -------------------------------------------------------------------------- wiadomość przychodząca
@dataclass
class Incoming:
    from_addr: str
    fp: str                     # grouped (4-4-4-4) — do wyświetlenia/porównania
    name: str                   # username NADAWCY (etykieta, NIE dowód!)
    text: str
    seq: int
    ts: int
    new_contact: bool           # True = pierwszy raz: PORÓWNAJ fp drugim kanałem!


# -------------------------------------------------------------------------- rdzeń
class Messenger:
    """E2E po FNXS1. identity: core.identity.Identity; tofu/transport/clock wstrzykiwalne."""

    def __init__(self, identity, tofu: TofuStore | None = None,
                 transport: LocalTransport | None = None, clock=time.time):
        self.identity = identity
        self.tofu = tofu or TofuStore()
        self._clock = clock
        self._out_seq: dict[str, int] = {}          # per-odbiorca licznik (RAM)
        self.stats = {"delivered": 0, "for_other": 0, "bad_env": 0,
                      "bad_aead": 0, "bad_sig": 0, "replay": 0}
        self.my_fp = contact_fingerprint(identity.sig_pub_b, identity.x_pub_b,
                                         grouped=False)
        self.transport = transport or LocalTransport({self.my_fp: []}, self.my_fp)
        # FNX-R1 (D43): stan ratchetu per fp kontaktu; mapa rk_pub→fp (nadawca
        # jest UKRYTY w v2 — rozpoznajemy go dopiero po stronie szyfru)
        self.ratchets: dict[str, dict] = {}
        self._rk_by_pub: dict[str, str] = {}
        for fp, e in self.tofu.pin.items():          # powrót z walizki TF1 (D40)
            rk = e.get("rk")
            if isinstance(rk, dict) and rk.get("my_priv") is not None:
                self.ratchets[fp] = rk

    def sync_ratchets_to_tofu(self) -> int:
        """Stan ratchetu → wpisy tofu (TYLKO gdy tofu jest walizką TF1! jawny
        plik NIGDY nie dostaje kluczy sesyjnych). Zwraca liczbę zsyncowanych."""
        if not self.tofu.encrypted:
            return 0
        n = 0
        for fp, rk in self.ratchets.items():
            if fp in self.tofu.pin:
                self.tofu.pin[fp]["rk"] = rk
                n += 1
        return n

    # ---------------- moje dane ----------------
    def my_address(self) -> str:
        return encode_stealth_address(self.identity.sig_pub_b, self.identity.x_pub_b)

    def my_fingerprint(self, grouped: bool = True) -> str:
        return contact_fingerprint(self.identity.sig_pub_b, self.identity.x_pub_b, grouped)

    def contacts(self) -> list[dict]:
        out = []
        for fp, e in self.tofu.pin.items():
            out.append({"fp": fp, "name": e.get("name") or "—",
                        "addr": e["addr"], "msgs": e["seq"], "last_ts": e.get("last_ts", 0)})
        return sorted(out, key=lambda e: -e["last_ts"])

    # ---------------- krypto E2E ----------------
    @staticmethod
    def _msg_key(shared: bytes) -> bytes:
        return HKDF(algorithm=SHA256(), length=32, salt=b"FNXM1",
                    info=b"msg").derive(shared)

    def _seal(self, contact_addr: str, from_addr: str, inner: dict) -> dict:
        # DH z kluczem publicznym ODBIORCY (nie nadawcy!) — inaczej nikt nie odszyfruje
        _sb, x_pub_b = decode_stealth_address(contact_addr)
        contact_fp = contact_fingerprint(_sb, x_pub_b, grouped=False)
        eph = X25519PrivateKey.generate()
        shared = eph.exchange(X25519PublicKey.from_public_bytes(x_pub_b))
        eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        nonce = os.urandom(12)
        aad = (contact_fp + from_addr).encode()
        ct = ChaCha20Poly1305(self._msg_key(shared)).encrypt(nonce, canon(inner), aad)
        return {"v": _PROTO, "to_fp": contact_fp, "from": from_addr,
                "eph": eph_pub.hex(), "n": nonce.hex(), "ct": ct.hex()}

    def _open(self, env: dict) -> dict | None:
        shared = self.identity._core._x_priv.exchange(
            X25519PublicKey.from_public_bytes(bytes.fromhex(env["eph"])))
        aad = (env["to_fp"] + env["from"]).encode()
        try:
            raw = ChaCha20Poly1305(self._msg_key(shared)).decrypt(
                bytes.fromhex(env["n"]), bytes.fromhex(env["ct"]), aad)
        except Exception:
            return None
        try:
            inner = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
        return inner if isinstance(inner, dict) else None

    # ---------------- FNX-R1 ratchet (D43) ----------------
    @staticmethod
    def _x_priv_of(identity):
        return identity._core._x_priv

    @staticmethod
    def _x_pub_of(priv_b: bytes) -> bytes:
        return X25519PrivateKey.from_private_bytes(priv_b).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)

    @staticmethod
    def _rk_root0(dh: bytes) -> tuple[bytes, bytes]:
        """(root0, ck0) z pierwszego DH (iniciator ↔ tożsamość odbiorcy)."""
        root = _h256(dh, b"FNXR1/root")
        return root, _h256(root, b"ck")

    @staticmethod
    def _rk_kick(root: bytes, dh: bytes) -> tuple[bytes, bytes]:
        """(root', ck') — nowa runda DH: root' = HMAC(root, DH‖tag)."""
        root2 = _h256(root, dh + b"FNXR1/rk")
        return root2, _h256(root2, b"ck")

    def _seal_rk(self, fp: str, contact_x_pub_b: bytes, inner: dict) -> dict:
        """v2: nadawca niewidoczny; mk jednorazowy; kick przy zmianie kierunku."""
        rk = self.ratchets.get(fp)
        if rk is None:                                   # pierwsza ramka do kontaktu
            kp = X25519PrivateKey.generate()
            dh = kp.exchange(X25519PublicKey.from_public_bytes(contact_x_pub_b))
            root, ck = self._rk_root0(dh)
            rk = {"root": root.hex(), "ck_s": ck.hex(), "ck_r": None,
                  "my_priv": kp.private_bytes(Encoding.Raw, PrivateFormat.Raw,
                                              NoEncryption()).hex(),
                  "their_pub": None, "kicked": None,
                  "seq_s": 0, "seq_r": 0, "skip": {}, "prev": None, "cand": {}}
            self.ratchets[fp] = rk
        elif rk["ck_s"] is None or \
                (rk["their_pub"] is not None and rk.get("kicked") != rk["their_pub"]):
            # nowa runda: świeża para + root' (tylko gdy ZNAM ich pub — inaczej ck by istniał)
            kp = X25519PrivateKey.generate()
            dh = kp.exchange(X25519PublicKey.from_public_bytes(
                bytes.fromhex(rk["their_pub"])))
            root, ck = self._rk_kick(bytes.fromhex(rk["root"]), dh)
            rk["root"], rk["ck_s"] = root.hex(), ck.hex()
            rk["my_priv"] = kp.private_bytes(Encoding.Raw, PrivateFormat.Raw,
                                             NoEncryption()).hex()
            rk["kicked"], rk["seq_s"] = rk["their_pub"], 0
        my_pub = self._x_pub_of(bytes.fromhex(rk["my_priv"])).hex()
        ck = bytes.fromhex(rk["ck_s"])
        seq = int(rk["seq_s"])
        mk = _h256(ck, b"mk")
        rk["ck_s"] = _h256(ck, b"ck").hex()              # ck idzie tylko NAPRZÓD
        rk["seq_s"] = seq + 1
        nonce = os.urandom(12)
        aad = b"FNXR1|" + fp.encode() + b"|" + my_pub.encode() + b"|" + str(seq).encode()
        ct = ChaCha20Poly1305(mk).encrypt(nonce, canon(inner), aad)
        try:
            mk_b = bytearray(mk)
            for i in range(len(mk_b)):
                mk_b[i] = 0                              # mk umiera od razu (best-effort)
        except Exception:       # noqa: BLE001 — wymazanie jest higieną, nie warunkiem
            pass
        return {"v": _PROTO2, "to_fp": fp, "rk_pub": my_pub,
                "seq": seq, "n": nonce.hex(), "ct": ct.hex()}

    @staticmethod
    def _mk_at(st: dict, target: int) -> bytes | None:
        """mk dla seq=target w ŁAŃCUCHU odbiorczym st (mutuje st); mki pominiętych
        seq lądują w skip (cap _RK_CAP_SKIP); target < seq_r → pobiera ze skip."""
        if target < 0:
            return None
        seq_r = int(st["seq_r"])
        if target < seq_r:
            got = st["skip"].pop(str(target), None)
            return bytes.fromhex(got) if got else None
        ck = bytes.fromhex(st["ck_r"])
        while seq_r < target:
            if len(st["skip"]) >= _RK_CAP_SKIP:
                return None                              # za dużo zamieszania → odrzut
            st["skip"][str(seq_r)] = _h256(ck, b"mk").hex()
            ck = _h256(ck, b"ck")
            seq_r += 1
        mk = _h256(ck, b"mk")
        st["ck_r"] = _h256(ck, b"ck").hex()
        st["seq_r"] = seq_r + 1
        return mk

    def _rk_decrypt(self, env: dict, st: dict, mk_ck_state: bool = True) -> dict | None:
        """Wspólna próba AEAD dla znanych parametrów st (bez mutowania rk na zewnątrz —
        st jest kopią roboczą albo żywym stanem)."""
        mk = self._mk_at(st, int(env["seq"]))
        if mk is None:
            return None
        aad = b"FNXR1|" + env["to_fp"].encode() + b"|" + env["rk_pub"].encode() \
            + b"|" + str(env["seq"]).encode()
        try:
            raw = ChaCha20Poly1305(mk).decrypt(
                bytes.fromhex(env["n"]), bytes.fromhex(env["ct"]), aad)
        except Exception:
            return None
        try:
            inner = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
        return inner if isinstance(inner, dict) else None

    def _rk_bind(self, fp: str, pub: str):
        self._rk_by_pub[pub] = fp

    @staticmethod
    def _rk_cand_put(rk: dict, pub: str, st: dict) -> None:
        """D57: zapis kanału-czytanki skrzyżowanego łańcucha (concurrent-init).
        Okno ≤_RK_CAP_CAND, FIFO: najstarszy wylatuje. Kanał = tylko ODCZYT
        (ck_r/seq_r/skip) — wysyłka zawsze idzie kanonicznym rootem."""
        cand = rk.setdefault("cand", {})
        if pub in cand:
            cand[pub].update(st)
            return
        while len(cand) >= _RK_CAP_CAND:
            cand.pop(next(iter(cand)))
        cand[pub] = st

    def _open_rk(self, env: dict) -> dict | None:
        """Odszyfruj ramkę v2 → inner (z „from" w środku szyfru) albo None.
        Rozpoznanie nadawcy po stronie szyfru: znany pub → jego łańcuch; nieznany
        pub → kick znanego kontaktu (próby ≤64) → zupełnie nowy kontakt (root0 z
        moją tożsamością). Stan ratchetu mutuje TYLKO po udanym AEAD (tu próbujemy
        na kopiach; commit po sukcesie)."""
        pub = env["rk_pub"]
        # 1) znany pub → znany fp (kontynuacja łańcucha lub straggler z poprzedniej rundy)
        fp = self._rk_by_pub.get(pub)
        if fp is not None and fp in self.ratchets:
            rk = self.ratchets[fp]
            # D57: NAJPIERW kanały-czytanki (skrzyżowane łańcuchy concurrent-init) —
            # pub jest kluczem jednoznacznym łańcucha; bez tego ramka z krzyżówki
            # trafiałaby w kanoniczny stan i umierała na AEAD
            _cand = rk.get("cand", {}).get(pub)
            if _cand is not None:
                trial = {**_cand, "skip": dict(_cand["skip"])}
                inner = self._rk_decrypt(env, trial)
                if inner is not None:
                    _cand.update({k: trial[k] for k in ("ck_r", "seq_r", "skip")})
                    return inner
                return None
            if rk.get("their_pub") == pub:
                trial = {**rk, "skip": dict(rk["skip"])}
                inner = self._rk_decrypt(env, trial)
                if inner is not None:
                    rk.update({k: trial[k] for k in ("ck_r", "seq_r", "skip")})
                    return inner
                return None
            prev = rk.get("prev")
            if prev and prev.get("pub") == pub:
                trial = {"ck_r": prev["ck_r"], "seq_r": prev["seq_r"],
                         "skip": dict(prev["skip"])}
                inner = self._rk_decrypt(env, trial)
                if inner is not None:
                    prev.update({k: trial[k] for k in ("ck_r", "seq_r", "skip")})
                    return inner
            return None                      # pub sprzed 2 rund = za stary → odrzut
        # 2) nieznany pub (np. świeży proces: mapa _rk_by_pub jest RAM-only):
        #    NAJPIERW kontynuacja AKTUALNEGO łańcucha każdego kontaktu, potem kick
        try:
            their_k = X25519PublicKey.from_public_bytes(bytes.fromhex(pub))
        except ValueError:
            return None
        for fp2, rk in list(self.ratchets.items()):
            if rk.get("their_pub") != pub:
                continue
            trial = {**rk, "skip": dict(rk["skip"])}
            inner = self._rk_decrypt(env, trial)
            if inner is not None:
                rk.update({k: trial[k] for k in ("ck_r", "seq_r", "skip")})
                self._rk_bind(fp2, pub)
                return inner
        tries = 0
        for fp2, rk in list(self.ratchets.items()):
            if tries >= _RK_CAP_TRIES:
                break
            if rk.get("their_pub") == pub or not rk.get("my_priv"):
                continue
            tries += 1
            trial = {"root": rk["root"], "ck_r": None, "seq_r": 0, "skip": {}}
            # kick = DH(MÓJ ratchet-priv tej rundy, ich NOWY pub) — NIE długi klucz!
            dh = X25519PrivateKey.from_private_bytes(
                bytes.fromhex(rk["my_priv"])).exchange(their_k)
            root2, ck2 = self._rk_kick(bytes.fromhex(rk["root"]), dh)
            trial["root"], trial["ck_r"] = root2.hex(), ck2.hex()
            inner = self._rk_decrypt(env, trial)
            if inner is not None:
                rk["prev"] = ({"pub": rk["their_pub"], "ck_r": rk["ck_r"],
                               "seq_r": rk["seq_r"], "skip": rk["skip"]}
                              if rk.get("their_pub") else None)
                rk.update({"root": trial["root"], "their_pub": pub, "ck_r": trial["ck_r"],
                           "seq_r": trial["seq_r"], "skip": trial["skip"], "kicked": None})
                self._rk_bind(fp2, pub)
                return inner
        # 3) zupełnie nowy nadawca: root0 = DH(mój x_priv, jego pub)
        trial = {"seq_r": 0, "skip": {}}
        dh = self._x_priv_of(self.identity).exchange(their_k)
        root0, ck0 = self._rk_root0(dh)
        trial["ck_r"] = ck0.hex()
        inner = self._rk_decrypt(env, trial)
        if inner is None:
            return None
        try:
            _sb, _xb = decode_stealth_address(str(inner.get("from", "")))
            fp3 = contact_fingerprint(_sb, _xb, grouped=False)
        except (IdentityError, ValueError):
            return None
        # ---- D57: skrzyżowane pierwsze wiadomości (concurrent-init, P24) ----
        # Obie strony napisały PIERWSZE zanim cokolwiek przeczytały: istnieją DWA
        # root0 (po jednym na parę efemeryczną). Stara ścieżka NADPISYWAŁA stan →
        # każda strona brała root0 drugiej i sesje goniły się w nieskończoność
        # (permanentny deadlock — złapane analizą + testem 13). Reguła kanonu:
        # INICJATOR = właściciel MNIEJSZEGO x_pub (identycznie liczą obie strony,
        # bo obie znają oba x_pub z adresów FNXS1).
        old = self.ratchets.get(fp3)
        if old is not None:
            if old.get("my_priv") and not old.get("their_pub"):
                if self.identity.x_pub_b < _xb:        # JA jestem inicjatorem
                    # mój root0 (z mojej pierwszej pary) = kanon; ICH łańcuch → cand
                    self._rk_cand_put(old, pub, {"root": root0.hex(),
                                                 "ck_r": trial["ck_r"],
                                                 "seq_r": trial["seq_r"],
                                                 "skip": trial["skip"]})
                    old["their_pub"] = pub             # mój kick pójdzie po ich pub
                    self._rk_bind(fp3, pub)
                    return inner
                # JA nie jestem inicjatorem → kanonem jest ICH root0 (ten z trial):
                # przepinam sesję na kanon; mój pierwszy łańcuch zostaje czytelny
                # u nich (są inicjatorem → mają swój cand — matematyka symetryczna)
                old.update({"root": root0.hex(), "ck_s": None,
                            "ck_r": trial["ck_r"], "seq_r": trial["seq_r"],
                            "skip": trial["skip"], "their_pub": pub,
                            "kicked": None, "cand": {}})
                self._rk_bind(fp3, pub)
                return inner
            # sesja już gra (their_pub ustawione), a „nowy nadawca" udaje TEN kontakt
            # (np. to samo konto na drugim urządzeniu — multi-device bez linku, M4c):
            # ODRZUT bez niszczenia stanu — dawne nadpisanie zabijałoby sesję (P24)
            self.stats["bad_env"] += 1
            return None
        # ---- naprawdę nowy kontakt (jak dotychczas) ----
        self.ratchets[fp3] = {"root": root0.hex(), "ck_s": None,
                              "ck_r": trial["ck_r"], "my_priv": None,
                              "their_pub": pub, "kicked": None,
                              "seq_s": 0, "seq_r": trial["seq_r"],
                              "skip": trial["skip"], "prev": None, "cand": {}}
        self._rk_bind(fp3, pub)
        return inner

    # ---------------- wysyłka ----------------
    def send_text(self, contact_addr: str, text: str) -> dict:
        sig_pub_b, x_pub_b = decode_stealth_address(contact_addr)   # walidacja z core
        if not text or len(text) > MAX_TEXT:
            raise MessengerError(f"tekst: 1..{MAX_TEXT} znaków")
        fp = contact_fingerprint(sig_pub_b, x_pub_b, grouped=False)
        seq = self._out_seq.get(fp, 0) + 1
        self._out_seq[fp] = seq
        mine = {"v": _PROTO, "seq": seq, "ts": int(self._clock()),
                "name": self.identity.username, "text": text}
        # v2 (FNX-R1): „from" chowa się do środka szyfru — relay nie widzi nadawcy
        inner = {**mine, "sig": self.identity.sign(canon(mine)).hex(),
                 "from": self.my_address()}
        env = self._seal_rk(fp, x_pub_b, inner)
        if len(json.dumps(env)) > MAX_ENV:
            raise MessengerError("koperta przekracza MAX_ENV (za długa wiadomość?)")
        self.transport.send_env(env)
        return env

    def send_text_v1(self, contact_addr: str, text: str) -> dict:
        """Legacy v1 (kompat wstecz / debug): eph-DH per wiadomość, „from" na jawie."""
        sig_pub_b, x_pub_b = decode_stealth_address(contact_addr)
        if not text or len(text) > MAX_TEXT:
            raise MessengerError(f"tekst: 1..{MAX_TEXT} znaków")
        fp = contact_fingerprint(sig_pub_b, x_pub_b, grouped=False)
        seq = self._out_seq.get(fp, 0) + 1
        self._out_seq[fp] = seq
        mine = {"v": _PROTO, "seq": seq, "ts": int(self._clock()),
                "name": self.identity.username, "text": text}
        inner = {**mine, "sig": self.identity.sign(canon(mine)).hex()}
        env = self._seal(contact_addr, self.my_address(), inner)
        if len(json.dumps(env)) > MAX_ENV:
            raise MessengerError("koperta przekracza MAX_ENV (za długa wiadomość?)")
        self.transport.send_env(env)
        return env

    # ---------------- odbiór ----------------
    def poll(self) -> list[Incoming]:
        got: list[Incoming] = []
        for env in self.transport.poll_envs():
            try:
                v = env.get("v") if isinstance(env, dict) else None
                if v not in (_PROTO, _PROTO2):
                    self.stats["bad_env"] += 1
                    continue
                if env.get("to_fp") != self.my_fp:
                    self.stats["for_other"] += 1
                    continue
                if len(json.dumps(env)) > MAX_ENV:
                    raise MessengerError("env za duże")
                if v == _PROTO:                            # legacy: nadawca na jawie
                    for k in ("from", "eph", "n", "ct"):
                        if not isinstance(env.get(k), str):
                            raise MessengerError(f"env.{k} nie-str")
                    from_addr = env["from"]
                    sig_pub_b, _xb = decode_stealth_address(from_addr)
                    fp = contact_fingerprint(sig_pub_b, _xb, grouped=False)
                    inner = self._open(env)
                else:                                      # v2 ratchet: nadawca z szyfru
                    if not (isinstance(env.get("rk_pub"), str)
                            and len(env["rk_pub"]) == 64
                            and all(c in "0123456789abcdef" for c in env["rk_pub"])):
                        raise MessengerError("env.rk_pub zły")
                    if not isinstance(env.get("seq"), int) or isinstance(env.get("seq"), bool):
                        raise MessengerError("env.seq nie-int")
                    for k in ("n", "ct"):
                        if not isinstance(env.get(k), str):
                            raise MessengerError(f"env.{k} nie-str")
                    inner = self._open_rk(env)
                    from_addr = str(inner.get("from", "")) if inner else ""
                    if inner is not None:
                        sig_pub_b, _xb = decode_stealth_address(from_addr)
                        fp = contact_fingerprint(sig_pub_b, _xb, grouped=False)
                if inner is None:
                    self.stats["bad_aead"] += 1
                    continue
                for k in ("v", "seq", "ts", "name", "text", "sig"):
                    if k not in inner:
                        raise MessengerError(f"inner.{k} brak")
                core = {"v": inner["v"], "seq": inner["seq"], "ts": inner["ts"],
                        "name": inner["name"], "text": inner["text"]}
                try:
                    Ed25519PublicKey.from_public_bytes(sig_pub_b).verify(
                        bytes.fromhex(inner["sig"]), canon(core))
                except (InvalidSignature, ValueError):
                    self.stats["bad_sig"] += 1
                    continue
                seq = int(inner["seq"])
                ent = self.tofu.pin.get(fp)
                new_contact = ent is None
                # Anty-replay: v1 = surowy licznik inner.seq; v2 = dedup ROBI ŁAŃCUCH
                # (zużyty mk), więc zamieszanie mesh (starsza seq po nowszej) jest LEGALNE
                if v == _PROTO and ent is not None and seq <= int(ent["seq"]):
                    self.stats["replay"] += 1
                    continue
                name = str(inner["name"])[:32]
                if new_contact:
                    self.tofu.pin[fp] = {"addr": from_addr, "name": name,
                                         "seq": seq, "first_ts": int(inner["ts"]),
                                         "last_ts": int(inner["ts"])}
                else:
                    ent["seq"] = max(seq, int(ent.get("seq", 0)))   # high-water (UI)
                    ent["name"] = name or ent.get("name")
                    ent["last_ts"] = max(int(inner["ts"]), int(ent.get("last_ts", 0)))
                self.sync_ratchets_to_tofu()               # rk zapisuje się TYLKO pod TF1
                self.tofu.save()
                self.stats["delivered"] += 1
                got.append(Incoming(from_addr=from_addr, fp="-".join(
                    fp[i:i + 4] for i in range(0, 16, 4)), name=name,
                    text=inner["text"], seq=seq, ts=int(inner["ts"]),
                    new_contact=new_contact))
            except MessengerError:
                self.stats["bad_env"] += 1
            except IdentityError:
                self.stats["bad_env"] += 1
            except ValueError:
                self.stats["bad_env"] += 1
        return got


# -------------------------------------------------------------------------- CLI demo
def _demo():
    print("app/messenger.py — demo: ala ↔ bob przez wspólną szynę (LocalTransport)\n")
    from core.identity import Identity
    bus: dict[str, list] = {}
    ala = Identity.generate("alicja")
    bob = Identity.generate("bobas")
    ma = Messenger(ala, transport=LocalTransport(bus, contact_fingerprint(
        ala.sig_pub_b, ala.x_pub_b, grouped=False)))
    mb = Messenger(bob, transport=LocalTransport(bus, contact_fingerprint(
        bob.sig_pub_b, bob.x_pub_b, grouped=False)))
    ma.send_text(mb.my_address(), "cześć bobas, tu alicja — odcisk mego klucza: "
                 + ma.my_fingerprint())
    mb.send_text(ma.my_address(), "witaj! sprawdziłem odcisk drugim kanałem ✅")
    for who, m in (("bobas", mb), ("alicja", ma)):
        for inc in m.poll():
            tag = " 🆕 NOWY KONTAKT" if inc.new_contact else ""
            print(f"[{who}] ⬅ {inc.name} (fp {inc.fp}){tag}: {inc.text}")
    print("\nkontakty bobasa:", json.dumps(mb.contacts(), ensure_ascii=False))


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--demo":
    _demo()
    sys.exit(0)


# -------------------------------------------------------------------------- selftest
if __name__ == "__main__":
    import os as _os
    import tempfile as _tf

    print("app/messenger.py — selftest: E2E, TOFU, replay, impersonacja, shred\n")

    from core.identity import Identity

    bus: dict[str, list] = {}
    ala = Identity.generate("alicja_m")
    bob = Identity.generate("bob_m")
    ceo = Identity.generate("ceo_m")
    eve = Identity.generate("alicja_m")          # UWAGA: eve bierze TEN SAM username!

    def mk(who):
        return Messenger(who, transport=LocalTransport(bus, contact_fingerprint(
            who.sig_pub_b, who.x_pub_b, grouped=False)))

    ma, mb, mc, me = mk(ala), mk(bob), mk(ceo), mk(eve)

    # 1) adres/fingerprint: round-trip + odciski różne
    assert mb.my_address().startswith("FNXS1")
    assert ma.my_fingerprint() != mb.my_fingerprint() != me.my_fingerprint()
    print("  [OK] 1. FNXS1+fingerprint: unikalne odciski (eve ≠ ala mimo tego samego username)")

    # 2) dostawa: bob dostaje CAŁY tekst; new_contact=True; kontakty zapisane
    env1 = ma.send_text(mb.my_address(), "hasło na dziś: feniks")
    got = mb.poll()
    assert len(got) == 1
    inc = got[0]
    assert inc.text == "hasło na dziś: feniks" and inc.new_contact is True
    assert inc.name == "alicja_m" and inc.seq == 1
    assert mb.tofu.pin[next(iter(mb.tofu.pin))]["seq"] == 1
    print("  [OK] 2. E2E: bob odczytał; TOFU pin przy 1. kontakcie (new_contact=True)")

    # 3) odpowiedź + seq rosnące; REPLAY koperty = pominięta + licznik
    mb.send_text(ma.my_address(), "potwierdzam ✅")
    got2 = ma.poll()
    assert len(got2) == 1 and got2[0].text == "potwierdzam ✅" and got2[0].seq == 1
    ma.send_text(mb.my_address(), "druga wiadomość")
    mb.poll()
    bus[mb.my_fp].append(dict(env1))             # replay starej koperty!
    got3 = mb.poll()
    assert got3 == [] and mb.stats["replay"] + mb.stats["bad_aead"] >= 1, \
        "powtórzona koperta nie została zignorowana"
    print("  [OK] 3. seq ściśle rosnący; powtórzona koperta = drop (v2: łapie ją już") 
    print("         ŁAŃCUCH ratchetu — zużyty mk, zanim ktokolwiek zobaczy inner.seq)")

    # 4) manipulacja szyfrogramem (1 bajt) → AEAD odrzuca. ŚWIEŻA ramka (mk jeszcze
    #    niezużyty — dedup jej nie łapie), Poly1305 nad zepsutym ct MUSI zatrąbić
    b4 = mb.stats["bad_aead"]
    ma.send_text(mb.my_address(), "oryginał, którego nie wolno dostarczyć")
    tf4 = json.loads(json.dumps(bus[mb.my_fp][-1]))
    ct4 = bytearray.fromhex(tf4["ct"])
    ct4[0] ^= 0x01
    tf4["ct"] = ct4.hex()
    bus[mb.my_fp][-1] = tf4
    assert mb.poll() == [] and mb.stats["bad_aead"] == b4 + 1
    print("  [OK] 4. flip bitu w ct → AEAD: bad_aead, zero tekstu (bezpieczny FAIL)")

    # 5) impersonacja: eve podszywa się pod username ali, ale ma SWOJE klucze
    #    → NIE wpada do wątku ali (fp jest tożsamością, nie username!)
    me.send_text(mb.my_address(), "to ja alicja, wyślij mi seed")
    got4 = mb.poll()
    assert len(got4) == 1 and got4[0].new_contact is True
    assert got4[0].fp == me.my_fingerprint() != ma.my_fingerprint()
    contacts = mb.contacts()
    assert len(contacts) == 2 and contacts[0]["name"] == "alicja_m"
    #    oraz: eve NIE MOŻE podpisać się kluczem ali (podpisna podróbka = drop)
    my_core = {"v": 1, "seq": 1, "ts": 1, "name": "alicja_m", "text": "x"}
    fake_sig = eve.sign(canon(my_core)).hex()
    inner_fake = {**my_core, "sig": fake_sig}
    env_fake = me._seal(mb.my_address(), ma.my_address(), inner_fake)  # from=ala, sig=eve!
    bus[mb.my_fp].append(env_fake)
    assert mb.poll() == [] and mb.stats["bad_sig"] >= 1
    print("  [OK] 5. impersonacja: ten sam username = OSOBNY kontakt (fp); "
          "fałszywy podpis kluczem ali → bad_sig")

  # 6) tofu plikowo: save 0600, load, SHRED
    d6 = _tf.mkdtemp(prefix="fenix-tofu-")
    path6 = _os.path.join(d6, "tofu.json")
    ts6 = TofuStore(path6)
    ts6.pin["deadbeef00000000"] = {"addr": mb.my_address(), "name": "bob_m",
                                   "seq": 3, "first_ts": 1, "last_ts": 2}
    ts6.save()
    assert _os.stat(path6).st_mode & 0o777 == 0o600
    ts6b = TofuStore(path6)
    assert ts6b.pin["deadbeef00000000"]["seq"] == 3
    assert ts6b.shred() is True and not _os.path.exists(path6) and ts6b.pin == {}
    _os.rmdir(d6)
    print("  [OK] 6. tofu-plik: 0600 + atomowy save + shred 2× nadpis (D9)")

  # 6b) WALIZKA TF1 (KS1-wrap, D40): protect(hasło) → plik = martwy szum;
    #     brak/złe hasło → odmowa; po unlock save() ZOSTAJE szyfrowany; unprotect → jawny
    d6b = _tf.mkdtemp(prefix="fenix-tofu1-")
    p6b = _os.path.join(d6b, "tofu.tf1")
    tsw = TofuStore(p6b)
    tsw.pin["cafe000000000001"] = {"addr": mc.my_address(), "name": "ceo_m",
                                   "seq": 7, "first_ts": 1, "last_ts": 2}
    tsw.protect("moje-haslo-123", kdf=KDFParams.fast_for_tests())
    raw6b = open(p6b, "rb").read()
    assert raw6b.startswith(b"TF1") and TofuStore.is_encrypted(p6b)
    assert (b"cafe000000000001" not in raw6b and "ceo_m".encode() not in raw6b
            and mc.my_address().encode() not in raw6b), "walizka TF1 przecieka kontakt!"
    try:
        TofuStore(p6b)
        raise SystemExit("TF1 bez hasła się otworzył!")
    except MessengerError as e:
        assert "odblokuj" in str(e)
    try:
        TofuStore(p6b, passkey="zle-haslo!!!")
        raise SystemExit("TF1 ze złym hasłem się otworzył!")
    except MessengerError as e:
        assert "złe hasło" in str(e)
    tsw2 = TofuStore(p6b, passkey="moje-haslo-123")
    assert tsw2.pin["cafe000000000001"]["seq"] == 7 and tsw2.encrypted
    tsw2.pin["cafe000000000001"]["seq"] = 8
    tsw2.save()                                          # wciąż TF1 (passkey żyje w RAM)
    assert TofuStore.is_encrypted(p6b)
    tsw2.unprotect()
    assert not TofuStore.is_encrypted(p6b)
    assert TofuStore(p6b).pin["cafe000000000001"]["seq"] == 8   # plaintext znowu czytelny
    try:
        TofuStore(p6b + ".x").protect("abc")             # zbyt krótkie hasło → odmowa
        raise SystemExit("krótkie hasło do walizki przeszło!")
    except MessengerError:
        pass
    import shutil as _sh
    _sh.rmtree(d6b, ignore_errors=True)
    print("  [OK] 6b. WALIZKA TF1: plik = szum wobec złodzieja; brak/złe hasło → odmowa;")
    print("           unlock trzyma szyfr przy save; unprotect() = świadomy powrót do jawa (D40)")

    # 7) for_other: mesh-broadcast (symulowany ręcznie) — ceo widzi kopertę boba,
    #    ale ją pomija (to_fp ≠ jego fp); routing po fp w LocalTransport w ogóle
    #    jej nie doręcza — obie warstwy zgodne
    env7 = me.send_text(mb.my_address(), "jj")
    assert mc.poll() == []                          # routing: u ceo pusto (tak ma być)
    bus[mc.my_fp].append(dict(env7))                # symulacja relay mesh T_MSG (D37)
    assert mc.poll() == [] and mc.stats["for_other"] == 1
    mb.poll()                                       # bob pobiera żeby bus nie rósł
    print("  [OK] 7. routing po fp + for_other przy broadcastzie (mesh T_MSG simulation)")

    # 8) limity: za długi tekst odrzucony; zła koperta (v≠1) liczona
    try:
        ma.send_text(mb.my_address(), "x" * (MAX_TEXT + 1))
        raise SystemExit("za długi tekst przeszedł!")
    except MessengerError as e:
        assert "1.." in str(e)
    bus[mb.my_fp].append({"v": 99, "to_fp": mb.my_fp})
    mb.poll()
    assert mb.stats["bad_env"] >= 1
    print("  [OK] 8. MAX_TEXT + walidacja koperty (v/to_fp/typy) = bad_env, bez wyjątków")

    # 9) FNX-R1 RATCHET (D43): v2 = domyślny; nadawca ukryty; kick co zmiana kierunku;
    #    skip-okwo ratuje zamieszanie; PFS testowany ZŁODZIEJEM z długim kluczem;
    #    stan ratchetu: RAM (amnezja) lub pod walizką TF1 — NIGDY jawnie na dysku
    ida2, idb2 = Identity.generate("rk_ala"), Identity.generate("rk_bob")
    ma2, mb2 = Messenger(ida2), Messenger(idb2)
    bus2: dict[str, list] = {}
    ma2.transport = LocalTransport(bus2, ma2.my_fp)
    mb2.transport = LocalTransport(bus2, mb2.my_fp)
    wire: list[dict] = []                                   # podsłuch całego drutu

    e1 = ma2.send_text(mb2.my_address(), "jeden")
    wire.append(dict(e1))
    assert e1["v"] == 2 and "from" not in e1 and "eph" not in e1, \
        "v2 zdradza nadawcę na drucie (from/eph na jawie)!"
    g1 = mb2.poll()
    assert len(g1) == 1 and g1[0].text == "jeden" and g1[0].name == "rk_ala"
    e2 = mb2.send_text(ma2.my_address(), "dwa")
    wire.append(dict(e2))
    assert e2["rk_pub"] != e1["rk_pub"], "kick przy zmianie kierunku NIE podmienił pub!"
    g2 = ma2.poll()
    assert len(g2) == 1 and g2[0].text == "dwa"
    fpa2, fpb2 = ma2.my_fp, mb2.my_fp
    assert ma2.ratchets[fpb2]["root"] == mb2.ratchets[fpa2]["root"], \
        "rozjazd rootów ratchetu po 2 kickach (matematyka rozłączna?)"
    print("  [OK] 9a. v2: nadawca niewidoczny na drucie; kick co kierunek; rooty zbieżne")
    e3 = ma2.send_text(mb2.my_address(), "trzy")            # znowu zmiana kierunku → kick
    e4 = ma2.send_text(mb2.my_address(), "cztery")          # ta sama runda → ten sam pub
    wire.extend([dict(e3), dict(e4)])
    assert e4["rk_pub"] == e3["rk_pub"] and e3["rk_pub"] != e1["rk_pub"]
    bus2[fpb2].reverse()                                    # mesh przestawił kolejność!
    g34 = mb2.poll()
    assert sorted(m.text for m in g34) == ["cztery", "trzy"], \
        f"skip-okno nie uratowało zamieszania: {[m.text for m in g34]}"
    bus2[fpb2].append(dict(e3))                             # powtórka (relay duplikuje)
    mb2.poll()
    assert mb2.stats["delivered"] == 3 and mb2.stats["bad_aead"] >= 1, \
        f"duplikat koperty v2 nie został zignorowany: {mb2.stats}"
    print("  [OK] 9b. zamieszanie mesh (4 przed 3) odczytane przez skip-okno; duplikat zignorowany")
    # ZŁODZIEJ Z DŁUGIM KLUCZEM: kradnie x_priv BOBA (odpowiadającego) + ma cały drut
    stolen_x = idb2._core._x_priv

    def crack(env: dict):
        """Ile złodziej odczyta znając TYLKO długi klucz + drut (bez privów ratchetu)."""
        try:
            dh0 = stolen_x.exchange(X25519PublicKey.from_public_bytes(
                bytes.fromhex(env["rk_pub"])))
            root0, ck0 = Messenger._rk_root0(dh0)
            st = {"ck_r": ck0.hex(), "seq_r": 0, "skip": {}}
            mk = Messenger._mk_at(st, env["seq"])
            aad = b"FNXR1|" + env["to_fp"].encode() + b"|" + env["rk_pub"].encode() \
                + b"|" + str(env["seq"]).encode()
            raw = ChaCha20Poly1305(mk).decrypt(
                bytes.fromhex(env["n"]), bytes.fromhex(env["ct"]), aad)
            import json as _jc
            return _jc.loads(raw.decode())["text"]
        except Exception:
            return None

    assert crack(wire[0]) == "jeden", \
        "UCZCIWIE: 1. wiadomość przed pierwszym kickiem pada przy skradzionym x_priv"
    assert crack(wire[1]) is None and crack(wire[2]) is None and crack(wire[3]) is None, \
        "PFS złamany: wiadomości PO kicku czytelne z samego długiego klucza!"
    print("  [OK] 9c. PFS: złodziej z x_priv czyta co najwyżej 1. ramkę przed kickiem;")
    print("           po wymianie tam↔z_powrotem drut + długi klucz = NIC (klucze ratchetu umarły)")
    # TF1 sync: stan ratchetu persystuje TYLKO pod hasłem; w RAM domyślnie umiera
    d9 = _tf.mkdtemp(prefix="fenix-rk-")
    p9 = _os.path.join(d9, "tofu-rk.tf1")
    mb2.tofu.path = p9
    mb2.tofu.protect("haslo-rk-998", kdf=KDFParams.fast_for_tests())
    mb2.sync_ratchets_to_tofu()
    mb2.tofu.save()
    raw9 = open(p9, "rb").read()
    assert b"my_priv" not in raw9 and mb2.ratchets[fpa2]["root"].encode() not in raw9, \
        "klucz sesyjny ratchetu przeciekł do pliku TF1!"
    mb3 = Messenger(idb2, tofu=TofuStore(p9, passkey="haslo-rk-998"))
    assert fpa2 in mb3.ratchets, "ratchet nie wstał z walizki TF1"
    mb3.transport = LocalTransport(bus2, mb3.my_fp)
    e5 = ma2.send_text(mb3.my_address(), "pięć po restarcie")
    g5 = mb3.poll()
    assert len(g5) == 1 and g5[0].text == "pięć po restarcie", \
        "rozmowa po restarcie (ratchet z TF1) nie zbiegła się bez resyncu"
    # jawny tofu (bez TF1): ratchet NIGDY nie ląduje w pliku
    p91 = _os.path.join(d9, "plain.json")
    ts91 = TofuStore(p91)
    ms91 = Messenger(ida2, tofu=ts91)
    ms91.tofu.pin["beef" + "0" * 12] = {"addr": mb3.my_address(), "name": "x",
                                        "seq": 1, "first_ts": 1, "last_ts": 1}
    ms91.ratchets["beef" + "0" * 12] = dict(ma2.ratchets[fpb2])
    assert ms91.sync_ratchets_to_tofu() == 0, "rk zapisany pod JAWNYM tofu!"
    ts91.save()
    raw91 = open(p91, "rb").read()
    assert b"my_priv" not in raw91 and b'"rk"' not in raw91, \
        "klucz sesyjny w jawnym tofu — złamana polityka (tylko TF1)!"
    import shutil as _sh9
    _sh9.rmtree(d9, ignore_errors=True)
    print("  [OK] 9d. TF1: ratchet przetrwał restart (pięć odczytane); jawny tofu = bez kluczy")

    # 13) D57/P24: CONCURRENT-INIT — obie strony piszą PIERWSZE „na krzyż" (cross-first)
    bus13: dict[str, list] = {}
    ida13, idb13 = Identity.generate("ala_cross13"), Identity.generate("bob_cross13")
    ma13, mb13 = Messenger(ida13), Messenger(idb13)
    ma13.transport = LocalTransport(bus13, ma13.my_fp)
    mb13.transport = LocalTransport(bus13, mb13.my_fp)
    ma13.send_text(mb13.my_address(), "cześć bob, ja ala (krzyż)")
    mb13.send_text(ma13.my_address(), "cześć ala, ja bob (krzyż)")   # przed JAKIMKOLWIEK poll!
    gA = ma13.poll()
    gB = mb13.poll()
    assert [m.text for m in gA] == ["cześć ala, ja bob (krzyż)"], gA
    assert [m.text for m in gB] == ["cześć bob, ja ala (krzyż)"], gB
    # po krzyżówce sesja musi być ZDROWA: pełny ping-pong (kicki w obie strony)
    ma13.send_text(mb13.my_address(), "drugie A→B")
    assert [m.text for m in mb13.poll()] == ["drugie A→B"]
    mb13.send_text(ma13.my_address(), "trzecie B→A")
    assert [m.text for m in ma13.poll()] == ["trzecie B→A"]
    # KONWERGENCJA: root identyczny po obu stronach (dowód JEDNEJ sesji, nie dwóch)
    fpb13 = contact_fingerprint(idb13.sig_pub_b, idb13.x_pub_b, grouped=False)
    fpa13 = contact_fingerprint(ida13.sig_pub_b, ida13.x_pub_b, grouped=False)
    assert ma13.ratchets[fpb13]["root"] == mb13.ratchets[fpa13]["root"], \
        "sesje po cross-first ROZJECHANE na dwa różne rooty (P24!)!"
    print("  [OK] 13. D57 cross-first: obie strony piszą pierwsze „na krzyż”; kanon")
    print("           mniejszego x_pub; po 1 RTT sesje ZBIEŻNE (root identyczny)")

    # 14) D57: spóźnione ramki skrzyżowanego łańcucha (kanał-czytanka cand) — żadna
    #     ramka krzyżówki nie ginie, niezależnie która strona wylosuje rolę inicjatora
    bus14: dict[str, list] = {}
    ida14, idb14 = Identity.generate("ala_cross14"), Identity.generate("bob_cross14")
    ma14, mb14 = Messenger(ida14), Messenger(idb14)
    ma14.transport = LocalTransport(bus14, ma14.my_fp)
    mb14.transport = LocalTransport(bus14, mb14.my_fp)
    mb14.send_text(ma14.my_address(), "B: pierwsza!")
    mb14.send_text(ma14.my_address(), "B: i od razu druga (ta sama runda)")
    ma14.send_text(mb14.my_address(), "A: też pierwsza!")
    gA14 = ma14.poll()                 # ala czyta OBYDWIE ramki b-łańcucha (cross-first)
    assert [m.text for m in gA14] == ["B: pierwsza!", "B: i od razu druga (ta sama runda)"], gA14
    assert [m.text for m in mb14.poll()] == ["A: też pierwsza!"]
    ma14.send_text(mb14.my_address(), "A: już normalnie")
    assert [m.text for m in mb14.poll()] == ["A: już normalnie"]
    mb14.send_text(ma14.my_address(), "B: też normalnie")
    assert [m.text for m in ma14.poll()] == ["B: też normalnie"]
    fpb14 = contact_fingerprint(idb14.sig_pub_b, idb14.x_pub_b, grouped=False)
    fpa14 = contact_fingerprint(ida14.sig_pub_b, ida14.x_pub_b, grouped=False)
    assert ma14.ratchets[fpb14]["root"] == mb14.ratchets[fpa14]["root"], \
        "po stragglerach rooty ROZJECHANE (P24!)"
    print("  [OK] 14. D57 cand: spóźnione ramki krzyżówki dochodzą (kanał-czytanka);")
    print("           role inicjator/odpowiedź z losowych x_pub — obie strony zbieżne")

    # 15) D57: sesja grająca NIETYKALNA dla „nowego nadawcy" pod tożsamość kontaktu —
    #     to samo konto na DRUGIM urządzeniu (multi-device bez linku = uczciwy drop),
    #     a oryginalna rozmowa żyje dalej (dawniej: nadpisanie = śmierć sesji)
    root15 = mb14.ratchets[fpa14]["root"]
    ma14_dev2 = Messenger(ida14)       # to samo konto, „drugi proces" (bez linku M4c)
    ma14_dev2.transport = LocalTransport(bus14, ma14_dev2.my_fp)
    ma14_dev2.send_text(mb14.my_address(), "A z drugiego urządzenia")
    assert mb14.poll() == [], "drugie urządzenie bez linku weszło w obcą sesję!"
    assert mb14.ratchets[fpa14]["root"] == root15, "stan sesji NADPISANY przez obcy wjazd!"
    ma14.send_text(mb14.my_address(), "A: sesja żyje?")
    assert [m.text for m in mb14.poll()] == ["A: sesja żyje?"]
    assert ma14.ratchets[fpb14]["root"] == mb14.ratchets[fpa14]["root"]
    print("  [OK] 15. D57: multi-device bez linku = drop + bad_env; sesja NIETKNIĘTA")
    print("           (regresja: dawniej case3 nadpisywał stan — rozmowa umierała)")

    print("\nSELFTEST: PASS ✅  app/messenger.py — E2E ChaCha/X25519/HKDF + podpis ed25519,\n"
          "TOFU+replay, impersonacja wykryta, transport-mesh T_MSG = net/fenix_node (D37),\n"
          "FNX-R1 ratchet PFS (D43), walizka TF1 na kontaktach+kluczach (D40)")
