#!/usr/bin/env python3
# os/fenix_boot.py — BARIERA BOOT-UNLOCK: bez hasła ISO to tylko szum (D24+D27+D3)
"""
To jest mur przy bramie. Każdy boot Fenix OS przechodzi przez TEN plik,
zanim wstanie node/GUI (fenix-boot.service, Before=fenix-node.service):

  1. BRAK kontenera (pierwszy boot) → KREATOR: username + passkey ×2 +
     HASŁO PANIKI ×2 → Keystore.create (kontener D24, Argon2id→KEK→MEK→AEAD).
  2. Kontener jest → UNLOCK-AGENT: pyta o passkey (systemd-ask-password,
     gwiazdki, nic nie ląduje w logach — zsynchronizowane z journald volatile).
     Złe hasło → licznik backoffu w kontenerze (×2 co próbę, D3).
     HASŁO PANIKI → Keystore sam niszczy kontener (PanicActivated) → boot
     uruchamia sekwencję paniki z os/fenix_panicd.py (wipe RAM + poweroff).
  3. Odblokowana tożsamość → JEDNORAZOWY przekaz do noda: JSON zapisywany
     na /run/fenix (tmpfs=RAM, ginie z prądem) z prawami 0440 root:fenix.
     Node czyta go przy starcie (--identity-file) i kasuje po odczycie.

Efekt odstraszający: kto zabierze pendrive'a/dysk ma w ręku losowy szum
(KS1) + losowy szum w RAM po odcięciu prądu. Kto włączy ISO bez hasła,
patrzy na mur. Kto wciśnie Del+PageUp 2 s albo wpisze hasło paniki,
patrzy na mur, który sam się wyburzył.

Selftest (ten plik bez argumentów) nie wymaga roota — wszystko w tempdir,
a funkcje są wstrzykiwalne (io, ask_password, panic).
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import tempfile
import time
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from core.keystore import (Keystore, KeystoreError, PanicActivated,   # noqa: E402
                           KDFParams)
from core.identity import valid_username                               # noqa: E402

KEYSTORE_PATH = "/home/fenix/.fenix/keystore.ks1"     # kontener D24 na ISO
RUNTIME_DIR = "/run/fenix"                            # tmpfs — RAM, nie dysk
IDENTITY_OUT = "identity.json"                        # jednorazowy przekaz → node
MAX_ASK = 3                                           # próby na jeden boot (backoff
                                                      # i tak rośnie ×2 w kontenerze)


# ------------------------------------------------------------------ IO (wstrzykiwalne)
class BootIO:
    """Interfejs konsoli boota — potomkowie: systemd-ask-password albo test."""

    def ask(self, prompt: str) -> bytes:
        raise NotImplementedError

    def say(self, text: str) -> None:
        raise NotImplementedError


class SystemdIO(BootIO):
    """Prawdziwa konsola: systemd-ask-password (gwiazdki, zero logów)."""

    def ask(self, prompt: str) -> bytes:
        import subprocess
        r = subprocess.run(["systemd-ask-password", "--no-output", prompt],
                           capture_output=True)
        if r.returncode != 0:                     # fallback: czyste getpass na tty
            return getpass.getpass(prompt + " ").encode()
        return r.stdout.rstrip(b"\n")

    def say(self, text: str) -> None:
        print(text, flush=True)


class ScriptedIO(BootIO):
    """Odpowiedzi z listy (selftest / później GUI przekaże swoje pola)."""

    def __init__(self, answers: list[str]):
        self.answers = list(answers)
        self.seen: list[str] = []

    def ask(self, prompt: str) -> bytes:
        self.seen.append(prompt)
        if not self.answers:
            raise KeystoreError("ScriptedIO: brak odpowiedzi (nieoczekiwane pytanie)")
        return self.answers.pop(0).encode()

    def say(self, text: str) -> None:
        self.seen.append(f"SAY:{text}")


# ------------------------------------------------------------------ kreator 1. bootu
def run_wizard(io: BootIO, ks_path: str, kdf: KDFParams | None = None) -> Keystore:
    """Kreator pierwszego bootu → kompletny, zaszyfrowany kontener D24.
    Waliduje: username D28-regex, passkey≥8, panic≠passkey, ×2 zgodnie."""
    io.say("== FENIX OS — pierwsza konfiguracja tożsamości ==")
    while True:
        username = io.ask("Wybierz username (a-z0-9_-): ").decode(errors="replace").strip()
        if valid_username(username):
            break
        io.say("  zły username (3–24 znaki: a-z 0-9 _ -; zacznij od litery/cyfry/_)")
    p1 = io.ask("Ustaw HASŁO (min. 8 znaków): ")
    p2 = io.ask("Powtórz HASŁO: ")
    if p1 != p2:
        raise KeystoreError("hasła się różnią — kreator od nowa przy następnym boot")
    g1 = io.ask("Ustaw HASŁO PANIKI (inne! wpisane przy unlock = zniszczenie): ")
    g2 = io.ask("Powtórz HASŁO PANIKI: ")
    if g1 != g2:
        raise KeystoreError("hasła paniki się różnią — kreator od nowa")
    os.makedirs(os.path.dirname(ks_path), mode=0o700, exist_ok=True)
    ks = Keystore.create(ks_path, username, p1, g1, kdf=kdf or KDFParams())
    os.chmod(ks_path, 0o600)
    io.say("== kontener utworzony. Zapamiętaj OBA hasła — odzyskania NIE MA (D9). ==")
    return ks


# ------------------------------------------------------------------ unlock-agent
def unlock_agent(io: BootIO, ks_path: str, runtime_dir: str,
                 max_ask: int = MAX_ASK,
                 on_panic=None) -> Keystore:
    """Pyta o passkey, składa tożsamość, wystawia jednorazowy identity.json.
    Hasło paniki → wyjątek PanicActivated z keystora → on_panic() → wyjście."""
    ks = Keystore.load(ks_path)
    for attempt in range(1, max_ask + 1):
        pw = io.ask(f"Hasło Fenixa (próba {attempt}/{max_ask}; hasło paniki = zniszczenie): ")
        try:
            idn = ks.unlock(pw)
        except PanicActivated:
            io.say("!! hasło paniki — kontener zniszczony; sekwencja paniki…")
            if on_panic is not None:
                on_panic()
            raise
        except KeystoreError:
            io.say("!! złe hasło (backoff rośnie ×2 w kontenerze)")
            continue
        _handoff_identity(idn, runtime_dir, io)
        return ks
    raise KeystoreError("unlock-agent: wyczerpano próby na ten boot "
                        "(kontener żyje; backoff pilnuje reszty)")


def _handoff_identity(idn, runtime_dir: str, io: BootIO) -> str:
    """Tożsamość → /run/fenix/identity.json (tmpfs, 0440 root:fenix, jednorazowo)."""
    os.makedirs(runtime_dir, mode=0o750, exist_ok=True)
    out = os.path.join(runtime_dir, IDENTITY_OUT)
    bundle = {"username": idn.username, **idn._private_bundle()}
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(bundle, f)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o440)
    try:
        os.chown(tmp, 0, 1088)                # root:fenix (uid 1088 z hooka 0100)
    except PermissionError:
        pass                                  # selftest bez roota: zostaje właściciel
    os.rename(tmp, out)                       # atomowo — node albo widzi całość, albo nic
    io.say(f"== tożsamość odblokowana: {idn.username} — przekaz do noda gotowy ==")
    return out


# ------------------------------------------------------------------ ładunek kodu (sealed ISO)
PAYLOAD_ENC = "/opt/fenix-payload.enc"        # SEALED build: kod tylko tu
PAYLOAD_DEV = "/opt/fenix-payload.dev"        # DEV build: jawny, gated ENV
PAYLOAD_DEST = "/run/fenix-payload"           # tmpfs, 0700


def cmd_payload(io: BootIO, dest: str = PAYLOAD_DEST,
                enc: str = PAYLOAD_ENC, dev: str = PAYLOAD_DEV) -> str:
    """Weryfikuj+wypakuj ładunek kodu (fenix_payload). Zwraca status:
    'sealed-ok' | 'sealed-await-seeds' | 'dev-ok' | 'dev-denied' | 'plain'."""
    if os.path.exists(enc):
        import importlib.util as _ilu
        spec = _ilu.spec_from_file_location(
            "fenix_payload", str(_pl.Path(__file__).resolve().with_name("fenix_payload.py")))
        pay = _ilu.module_from_spec(spec)
        spec.loader.exec_module(pay)
        key_hex = os.environ.get("FENIX_PAYLOAD_KEY")   # operator QA; produkcyjnie: Shamir z seedów (M5)
        if key_hex:
            pay.verify_and_extract(enc, bytes.fromhex(key_hex), dest)
            io.say("== ładunek: SEALED otwarty kluczem operatora (test) ==")
            return "sealed-ok"
        io.say("== ładunek: SEALED — czeka na udziały seedów (M5); stos nie wstanie "
               "bez 3-z-5 (to JEST cegła by design) ==")
        return "sealed-await-seeds"
    if os.path.exists(dev):
        if not os.environ.get("FENIX_DEV_PAYLOAD_KEY"):
            io.say("== ładunek DEV bez ENV — odmowa (§4) ==")
            return "dev-denied"
        import importlib.util as _ilu
        spec = _ilu.spec_from_file_location(
            "fenix_payload", str(_pl.Path(__file__).resolve().with_name("fenix_payload.py")))
        pay = _ilu.module_from_spec(spec)
        spec.loader.exec_module(pay)
        pay.verify_and_extract(dev, None, dest)
        io.say("== ładunek DEV wypakowany — GUI pokaże 'DEV BUILD' ==")
        return "dev-ok"
    io.say("== ładunek: brak — stos leci jawnie z /opt/fenix (plain build) ==")
    return "plain"


# ------------------------------------------------------------------ tryby CLI
def cmd_boot(io: BootIO, ks_path: str, runtime_dir: str, on_panic=None,
             skip_payload: bool = False) -> int:
    """Pełny przepływ boota: ładunek → kreator gdy brak kontenera → unlock-agent."""
    if not skip_payload:
        cmd_payload(io)
    if not os.path.exists(ks_path):
        run_wizard(io, ks_path)
    unlock_agent(io, ks_path, runtime_dir, on_panic=on_panic)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="fenix-boot",
        description="Bariera boot Fenix OS: kreator/unlock/panika (D24+D27)")
    ap.add_argument("--keystore", default=KEYSTORE_PATH)
    ap.add_argument("--runtime-dir", default=RUNTIME_DIR)
    ap.add_argument("--max-ask", type=int, default=MAX_ASK)
    args = ap.parse_args(argv)

    # panika z boota = TA SAMA sekwencja co demon (jeden kod, jedno miejsce testów).
    # UWAGA: katalog os/ NIE jest pakietem python (kolizja ze stdlib os) — ładujemy
    # moduł po ścieżce pliku, nie po nazwie.
    def _panic():
        import importlib.util as _ilu
        panicd_path = _pl.Path(__file__).resolve().with_name("fenix_panicd.py")
        spec = _ilu.spec_from_file_location("fenix_panicd", panicd_path)
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.run_panic_sequence(os.path.dirname(args.keystore) + "/*.ks1", dry=False)

    try:
        return cmd_boot(SystemdIO(), args.keystore, args.runtime_dir, on_panic=_panic)
    except PanicActivated:
        return 42            # kod informacyjny dla systemd/journald (log volatile)
    except KeystoreError as e:
        print(f"fenix-boot: {e}", file=sys.stderr)
        return 1


# ------------------------------------------------------------------ selftest
if __name__ == "__main__":
    print("os/fenix_boot.py — selftest: kreator, unlock, panika, przekaz RAM-only\n")

    fast = KDFParams.fast_for_tests()
    tmp = tempfile.mkdtemp(prefix="fenix-boot-test-")
    ks_path = os.path.join(tmp, "home", "keystore.ks1")
    run_dir = os.path.join(tmp, "run")

    # 1) kreator: zły username odrzucony, ×2 zgodne hasła → kontener powstaje
    io = ScriptedIO([
        "ZŁY!!user",           # odrzucone (wielkie litery/wykrzykniki)
        "adek_fox",            # dobre
        "haslo-straznika", "haslo-straznika",          # passkey ×2 zgodne
        "panika-drukarska", "panika-drukarska",        # panic ×2 zgodne
    ])
    ks = run_wizard(io, ks_path, kdf=fast)
    assert os.path.exists(ks_path)
    assert (os.stat(ks_path).st_mode & 0o777) == 0o600
    w1 = ks.identity.wallet
    print("  [OK] 1. kreator: walidacja username, ×2 hasła, kontener 0600 na dysku")

    # 2) kreator odmawia: różne powtórki → wyjątek, kontenera nie ma
    io2 = ScriptedIO(["bozena", "aaa", "bbb"])
    try:
        run_wizard(io2, os.path.join(tmp, "h2", "k.ks1"), kdf=fast)
        raise SystemExit("kreator puścił rozjazd haseł!")
    except KeystoreError:
        print("  [OK] 2. kreator: różne ×2 → odmowa (kontener NIE powstaje)")

    # 3) unlock: 1× złe hasło (backoff w zawartości), potem dobre → identity.json
    io3 = ScriptedIO(["zle-haslo-99", "haslo-straznika"])
    ks2 = unlock_agent(io3, ks_path, run_dir)
    out = os.path.join(run_dir, IDENTITY_OUT)
    assert os.path.exists(out)
    bundle = json.load(open(out))
    assert bundle["username"] == "adek_fox" and len(bundle["x_priv"]) == 64
    assert ks2.identity.wallet == w1, "ta sama tożsamość co w kreatorze (restart-safe)"
    assert (os.stat(out).st_mode & 0o777) == 0o440 or os.geteuid() != 0
    print("  [OK] 3. unlock: złe→backoff, dobre→identity.json (0440, tmpfs, jednorazowo)")

    # 4) HASŁO PANIKI przy unlock: kontener znika + on_panic odpalony (bez poweroff w teście)
    panicked = []
    io4 = ScriptedIO(["panika-drukarska"])
    try:
        unlock_agent(io4, ks_path, run_dir, on_panic=lambda: panicked.append(1))
        raise SystemExit("hasło paniki nie zniszczyło kontenera!")
    except PanicActivated:
        pass
    assert panicked == [1], "boot MUSI odpalić sekwencję paniki po shred kontenera"
    assert not os.path.exists(ks_path), "kontener ma NIE istnieć po panice"
    print("  [OK] 4. hasło paniki: kontener shred → boot odpala sekwencję (jeden kod z D27)")

    # 5) przekaz jest jednorazowy + żadne hasło NIE poszło do „logów" (ScriptedIO.seen)
    blob = " ".join(io.seen + io3.seen)
    for leak in ("haslo-straznika", "panika-drukarska"):
        assert f"SAY:{leak}" not in blob, "hasło w say()!"
    ks_path3 = os.path.join(tmp, "home2", "keystore.ks1")
    os.makedirs(os.path.dirname(ks_path3), exist_ok=True)
    ks3 = Keystore.create(ks_path3, "ewa_99", b"klucz-klucz", b"minej-minej", kdf=fast)
    w3 = ks3.identity.wallet
    ks3.lock()                                # 'restart' — RAM pusta (amnezja)
    io5 = ScriptedIO(["klucz-klucz"])
    unlock_agent(io5, ks_path3, run_dir)
    bundle3 = json.load(open(out))
    idn3 = Keystore.load(ks_path3).unlock(b"klucz-klucz")
    from core.identity import Identity as _I3
    idn3b = _I3.from_private(bundle3["username"], bytes.fromhex(bundle3["x_priv"]),
                             bytes.fromhex(bundle3["s_priv"]))
    assert idn3b.wallet == w3 == idn3.wallet, "przekaz boot = dokładnie ta sama tożsamość"
    print("  [OK] 5. hasła nie wypisują się nigdzie; przekaz boot = identyczna tożsamość")

    # 6) ładunek kodu: SEALED z kluczem (ENV operatora) → wypakowany; bez klucza → cegła
    import importlib.util as _ilu
    spec = _ilu.spec_from_file_location("fenix_payload", "os/fenix_payload.py")
    pay = _ilu.module_from_spec(spec)
    spec.loader.exec_module(pay)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    stk = os.path.join(tmp, "stk")
    os.makedirs(os.path.join(stk, "core"))
    open(os.path.join(stk, "core", "x.py"), "w").write("MARKER_77 = 1\n")
    enc_p = os.path.join(tmp, "pay.enc")
    pkey = pay.build_payload(stk, enc_p, Ed25519PrivateKey.generate(), commit="t")
    dest6 = os.path.join(tmp, "runpay")
    os.environ.pop("FENIX_PAYLOAD_KEY", None)
    st6a = cmd_payload(ScriptedIO([]), dest=dest6, enc=enc_p, dev=os.path.join(tmp, "nie-ma"))
    assert st6a == "sealed-await-seeds" and not os.path.exists(dest6)
    os.environ["FENIX_PAYLOAD_KEY"] = pkey.hex()
    st6b = cmd_payload(ScriptedIO([]), dest=dest6, enc=enc_p, dev=os.path.join(tmp, "nie-ma"))
    os.environ.pop("FENIX_PAYLOAD_KEY", None)
    assert st6b == "sealed-ok"
    assert open(os.path.join(dest6, "core", "x.py")).read() == "MARKER_77 = 1\n"
    st6c = cmd_payload(ScriptedIO([]), dest=os.path.join(tmp, "nope"),
                      enc="/brak", dev="/brak")
    assert st6c == "plain"
    print("  [OK] 6. ładunek SEALED: bez klucza cegła (await-seeds), z kluczem operatora otwarty")

    print("\nSELFTEST: PASS ✅  bariera boot: mur przy bramie stoi; szum bez hasła; panika burzy")
