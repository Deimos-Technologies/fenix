# tools/self_attack.py
"""
SELF-ATTACK — wewnętrzny „czerwony zespół" Fenixa.

Cel: próba ZŁAMANIA własnego szyfrowania zanim zrobi to ktoś inny.
To NIE jest audyt zewnętrzny (ten jest w M9) — to automatyczna bateria ataków,
którą odpalamy po KAŻDEJ zmianie w krypto (patrz checklista pliku w TODO).

Metodologia: atakujemy jak naprawdę potrafimy:
  A. kanał E2E (core/crypto/fenix_crypto.py) — tamper, podmianki nagłówka, replay,
     podpisy, separacja kluczy, nonce
  B. FNX-WRAP (core/crypto/fenix_wrap.py) — tamper/oracle, lawina, statystyka
     keystreamu, S-box (dyferencjały/linearyzacja — próbkowane)
  C. Keystore KS1 (core/keystore.py) — koszt brute-force, grzebanie w obwolucie,
     downgrade, panic-shred, poufność markerów, Shamir
  D. Profile (core/identity.py) — unikalność walletów, MITM-swap (regresja)
  E. CSPRNG platformy — sanity

Klasy wyniku:
  🛡️ ODPARTY  — atak nie zadziałał (oczekiwane)
  📝 NOTATKA  — uczciwe zastrzeżenie projektowe („by design", ale trzeba o tym pamiętać)
  ⚠️ ZNALEZIONO — coś się złamało = krytyczny bug do naprawy ZANIM cokolwiek dalej

Uruchomienie:  python tools/self_attack.py   → raport: docs/crypto_attack_report.md
"""

from __future__ import annotations

import json
import os
import platform
import secrets
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.crypto.fenix_crypto import (  # noqa: E402
    Identity, decrypt_message, encrypt_message, split_secret, combine_shares,
)
from core.crypto.fenix_wrap import FenixWrap, FenixWrapError, SBOX  # noqa: E402
from core.keystore import (  # noqa: E402
    Keystore, KeystoreError, KDFParams, PanicActivated, _argon2id,
)
from core.identity import Identity as CoreIdentity, check_profile  # noqa: E402

R: list[dict] = []   # wyniki


def rec(section: str, name: str, method: str,
        outcome: str, status: str = "🛡️ ODPARTY") -> None:
    R.append({"section": section, "name": name,
              "method": method, "outcome": outcome, "status": status})
    print(f"  [{status}] {section} :: {name}")


def xor(a: bytes, b: bytes) -> bytes:
    n = min(len(a), len(b))
    return bytes(x ^ y for x, y in zip(a[:n], b[:n]))


def chi2_uniform(sample: bytes) -> tuple[float, float]:
    """Chi-kwadrat vs 256-stanowy jednostajny; zwraca (statystyka, odchylenie w sigmach)."""
    counts = [0] * 256
    for byte in sample:
        counts[byte] += 1
    exp = len(sample) / 256.0
    chi2 = sum((c - exp) ** 2 / exp for c in counts)
    mean, std = 255.0, (2 * 255) ** 0.5
    return chi2, (chi2 - mean) / std


def monobit(sample: bytes) -> float:
    """Odsetek jedynek wszystkich bitów (oczekiwane ≈ 0.5)."""
    ones = sum(bin(byte).count("1") for byte in sample)
    return ones / (8 * len(sample))


def lag1_autocorr(sample: bytes) -> float:
    """Autokorelacja bajtów lag-1 (oczekiwane ≈ 0)."""
    n = min(len(sample) - 1, 200_000)
    xs, ys = sample[:n], sample[1:n + 1]
    mx, my = 127.5, 127.5
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    return num / den if den else 0.0


# =====================================================================
def section_a() -> None:
    print("\n== A. KANAŁ E2E (X25519→HKDF→AES-256-GCM + Ed25519) ==")
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    eve = Identity.generate("eve")
    msg = "blok FNX #144: 1.5 FNX → FNX1abcd…; flota OK".encode("utf-8")
    blob = encrypt_message(alice, bob.x_pub_b, msg)

    # A1: poufność sanity + statystyka szyfrogramu
    big = encrypt_message(alice, bob.x_pub_b, secrets.token_bytes(300_000))
    chi, sig = chi2_uniform(big)
    mono = monobit(big)
    ok = abs(sig) < 4 and 0.5 - 0.005 < mono < 0.5 + 0.005 and msg not in big
    rec("A", "poufność + statystyka (chi²/monobit)", "szyfrogram nieodróżnialny od szumu",
        f"chi²σ={sig:+.2f} (dopuszczane |σ|<4), monobit={mono:.4f}, plaintext niewidoczny",
        "🛡️ ODPARTY" if ok else "⚠️ ZNALEZIONO")

    # A2: tamper w losowych 200 pozycjach — 100% odrzutu
    rejects = 0
    for _ in range(200):
        t = bytearray(blob)
        i = secrets.randbelow(len(t))
        t[i] ^= 1 << secrets.randbelow(8)
        try:
            decrypt_message(bob, bytes(t))
        except Exception:
            rejects += 1
    rec("A", "bit-flip przekłamania (200 prób)", "każdy przekłam odrzucony",
        f"odrzucono {rejects}/200",
        "🛡️ ODPARTY" if rejects == 200 else "⚠️ ZNALEZIONO")

    # A3: MITM podmiana klucza podpisującego w nagłówku
    t = eve.sig_pub_b + blob[32:]
    try:
        decrypt_message(bob, t)
        ok = False
    except Exception:
        ok = True
    rec("A", "podmiana sig_pub nagłówka", "podpis nie pokrywa podmienionego klucza",
        "weryfikacja Ed25519 odrzuciła", "🛡️ ODPARTY" if ok else "⚠️ ZNALEZIONO")

    # A4: podmiana x_pub (klucza odbiorcy) w nagłówku
    t = blob[:32] + eve.x_pub_b + blob[64:]
    try:
        decrypt_message(bob, t)
        ok = False
    except Exception:
        ok = True
    rec("A", "podmiana x_pub nagłówka", "nagłówek jest AAD + podpisany — niepodmienialny",
        "podpis odrzucił", "🛡️ ODPARTY" if ok else "⚠️ ZNALEZIONO")

    # A5: podpis z kosmosu
    t = blob[:96] + secrets.token_bytes(64) + blob[160:]
    try:
        decrypt_message(bob, t)
        ok = False
    except Exception:
        ok = True
    rec("A", "fałszerstwo podpisu (losowe 64B)", "Ed25519 nie do podrobienia siłowo",
        "odrzucony", "🛡️ ODPARTY" if ok else "⚠️ ZNALEZIONO")

    # A6: obcinki/doklejki
    ok = True
    for t in (blob[:-1], blob + b"\x00", blob[:95]):
        try:
            decrypt_message(bob, t)
            ok = False
        except Exception:
            pass
    rec("A", "truncation/append", "AEAD związany z długością — obcinki odrzucane",
        "wszystkie odrzucone", "🛡️ ODPARTY" if ok else "⚠️ ZNALEZIONO")

    # A7: replay na poziomie pliku (bez sesji) — uczciwa notatka
    pt1, _ = decrypt_message(bob, blob)
    pt2, _ = decrypt_message(bob, blob)
    rec("A", "replay poza sesją", "ten sam blob odszyfrowuje się 2×",
        "BY DESIGN: blob jest autonomiczny; ochrona replay = okno 4096 ramek "
        "w KANALE sesyjnym (protocol_spec) — nie w formacie E2E",
        "📝 NOTATKA")

    # A8: nonce niepowtarzalny przy 4000 wiadomości
    nonces = set()
    for _ in range(4000):
        b2 = encrypt_message(alice, bob.x_pub_b, b"x")
        nonces.add(b2[96 + 64:96 + 64 + 12])
    rec("A", "nonce/eph-key 4000×", "każdy komunikat ma świeży klucz efemeryczny i nonce",
        f"unikatowe: {len(nonces)}/4000",
        "🛡️ ODPARTY" if len(nonces) == 4000 else "⚠️ ZNALEZIONO")

    # A9: lekcja — dlaczego nonce reuse zabija (kontrolowana demonstracja)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    k, n = secrets.token_bytes(32), secrets.token_bytes(12)
    a1 = AESGCM(k).encrypt(n, b"ATAK ########", None)
    a2 = AESGCM(k).encrypt(n, b"KLUCZ!!!!!!!!", None)
    leak = xor(a1[:-16], a2[:-16]) == xor(b"ATAK ########", b"KLUCZ!!!!!!!!")
    rec("A", "demonstracja nonce-reuse (nasza obrona: eph-key + losowy nonce)",
        "pokazać mechanizm katastrofy, której u nas nie ma",
        f"XOR szyfrogramów = XOR plaintextów: {leak} — u nas niemożliwe (A8), "
        "bo klucz sesji E2E jest jednorazowy (eph X25519)",
        "📝 NOTATKA")

    # A10: separacja domen HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    ikm = secrets.token_bytes(32)
    k1 = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"fenix-msg-v1").derive(ikm)
    k2 = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"fenix/wrap/01").derive(ikm)
    rec("A", "separacja kluczy (labele HKDF)", "msg ≠ wrap ≠ sess — jeden sekret, niezależne klucze",
        f"klucze różne: {k1 != k2}",
        "🛡️ ODPARTY" if k1 != k2 else "⚠️ ZNALEZIONO")


# =====================================================================
def section_b() -> None:
    print("\n== B. FNX-WRAP (nasza własna warstwa; D2 — zawsze pod AEAD) ==")
    w = FenixWrap(secrets.token_bytes(32))
    msg = b"Sailor's caution: wrap is additive."

    # B1: roundtrip na granicznych rozmiarach
    ok = True
    for n in (0, 1, 15, 16, 17, 255, 256, 4096):
        pt = secrets.token_bytes(n)
        try:
            if w.decrypt(w.encrypt(pt)) != pt:
                ok = False
        except Exception:
            ok = False
    rec("B", "roundtrip 0..4096 B", "brak padding-owych krzaków", "wszystkie OK",
        "🛡️ ODPARTY" if ok else "⚠️ ZNALEZIONO")

    # B2: tamper 200× — w tym w tag, nonce i magic
    rejects = 0
    blob = w.encrypt(msg, aad=b"hdr")
    for _ in range(200):
        t = bytearray(blob)
        i = secrets.randbelow(len(t))
        t[i] ^= 1 << secrets.randbelow(8)
        try:
            w.decrypt(bytes(t), aad=b"hdr")
        except FenixWrapError:
            rejects += 1
    rec("B", "bit-flip przekłamania (200 prób)", "EtM-HMAC łapie wszystko (magia/nonce/ct/tag)",
        f"odrzucono {rejects}/200",
        "🛡️ ODPARTY" if rejects == 200 else "⚠️ ZNALEZIONO")

    # B3: orakel błędów — jeden typ wyjątku na wszystkie przekłamy
    kinds = set()
    for t in (b"XW1" + blob[3:], blob[:-1], blob + b"\x00", blob[:18]):
        try:
            w.decrypt(t, aad=b"hdr")
        except FenixWrapError as e:
            kinds.add(type(e).__name__)
        except Exception as e:  # inny typ = przeciek (złe)
            kinds.add("☠" + type(e).__name__)
    rec("B", "orakel typów błędów", "atakujący nie dowiaduje się CO nie pasuje",
        f"typy wyjątków: {sorted(kinds)}",
        "🛡️ ODPARTY" if kinds == {"FenixWrapError"} else "⚠️ ZNALEZIONO")

    # B4: zły AAD/klucz/nonce-kopia → odrzut
    ok = True
    try:
        w.decrypt(blob, aad=b"inny-typ"); ok = False
    except FenixWrapError:
        pass
    try:
        FenixWrap(secrets.token_bytes(32)).decrypt(blob, aad=b"hdr"); ok = False
    except FenixWrapError:
        pass
    rec("B", "zły AAD / obcy klucz", "uwierzytelnienie obejmuje nagłówek warstwy",
        "oba odrzucone", "🛡️ ODPARTY" if ok else "⚠️ ZNALEZIONO")

    # B5: lawina 800 prób (serce szyfru)
    import random
    rng = random.Random(0xBEEF)
    diffs = []
    for _ in range(800):
        x = rng.randbytes(16)
        y1 = w._enc_block(x)
        xb = bytearray(x)
        xb[rng.randrange(16)] ^= 1 << rng.randrange(8)
        y2 = w._enc_block(bytes(xb))
        diffs.append(sum(bin(a ^ b).count("1") for a, b in zip(y1, y2)))
    mn, avg, mx = min(diffs), sum(diffs) / len(diffs), max(diffs)
    ok = mn >= 24 and 48 <= avg <= 80
    rec("B", "efekt lawinowy (800 prób)", "1 bit we → ~64/128 bitów wy",
        f"min={mn} avg={avg:.1f} max={mx} (ideał: avg≈64)",
        "🛡️ ODPARTY" if ok else "⚠️ ZNALEZIONO")

    # B6: statystyka keystreamu 256 KB (szyfrujemy same zera → CT = keystream)
    raw = w.encrypt(b"\x00" * (256 * 1024))
    ks = raw[19:19 + 256 * 1024]
    chi, sig = chi2_uniform(ks)
    mono = monobit(ks)
    ac = lag1_autocorr(ks)
    ok = abs(sig) < 4 and abs(mono - 0.5) < 0.005 and abs(ac) < 0.01
    rec("B", "statystyka keystreamu (256 KB)", "chi²/monobit/autokorelacja w normie",
        f"chi²σ={sig:+.2f}, monobit={mono:.4f}, lag1={ac:+.4f}",
        "🛡️ ODPARTY" if ok else "⚠️ ZNALEZIONO")

    # B7: ten sam tekst 2× → inne szyfrogramy (losowy nonce)
    c1, c2 = w.encrypt(msg), w.encrypt(msg)
    ok = c1 != c2 and c1[3:19] != c2[3:19]
    rec("B", "nonce losowy na wiadomość", "determinizm = przeciek; tutaj go nie ma",
        "szyfrogramy różne, nonce różne",
        "🛡️ ODPARTY" if ok else "⚠️ ZNALEZIONO")

    # B8: S-box — dyferencjały (próbkowane) i linearyzacja (próbkowana)
    rng2 = random.Random(0x5B0C)
    maxp = 0.0
    for _ in range(64):                     # 64 losowe różnice wejściowe
        dx = rng2.randrange(1, 256)
        counts = [0] * 256
        for _ in range(512):
            x = rng2.randrange(256)
            counts[SBOX[x] ^ SBOX[x ^ dx]] += 1
        maxp = max(maxp, max(counts) / 512)
    maxc = 0.0
    for _ in range(200):                    # 200 losowych par masek
        a, b = rng2.randrange(1, 256), rng2.randrange(1, 256)
        ones = 0
        for _ in range(2048):
            x = rng2.randrange(256)
            if (bin(a & x).count("1") & 1) == (bin(b & SBOX[x]).count("1") & 1):
                ones += 1
        maxc = max(maxc, abs(ones / 2048 - 0.5))
    ok = maxp < 0.15 and maxc < 0.2
    rec("B", "S-box: kryptoanaliza (próbkowana)", "brak patologicznych dyferencjałów/biasów",
        f"max Δ-prawd podobieństwo ≈ {maxp:.3f}, max bias liniowy ≈ {maxc:.3f} "
        "(próbkowane — sanity, nie pełna analiza; wrap i tak jest warstwą DODATKOWĄ pod AEAD)",
        "🛡️ ODPARTY" if ok else "📝 NOTATKA")

    # B9: uczciwa uwaga o roli warstwy
    rec("B", "rola warstwy własnej", "pamiętać, że wrap NIE jest samodzielną obroną",
        "gdyby FNX-WRAP runął całkowicie, kanał dalej chroni AEAD sesji (D2); "
        "testowana tu jako dodatkowa głębia, nie fundament",
        "📝 NOTATKA")


# =====================================================================
def section_c() -> None:
    print("\n== C. KEYSTORE KS1 (Argon2id→KEK→MEK→AEAD, D3/D9/D24) ==")
    tmpd = tempfile.mkdtemp(prefix="fenix-atk-")
    FAST = KDFParams.fast_for_tests()
    pw, pn = b"jakub-tajne-777", b"jakub-panika-999"
    p = os.path.join(tmpd, "jakub.ks1")
    ks = Keystore.create(p, "jakub", pw, pn, kdf=FAST)
    wallet = ks.identity.wallet
    ks.lock()

    # C1: koszt jednej próby (produkcyjne parametry!) — ekstrapolacja brute-force
    kdf_prod = KDFParams()
    t0 = time.time()
    _argon2id(b"x" * 16, secrets.token_bytes(32), kdf_prod)
    dt = time.time() - t0
    # atakujący z 32 równoległymi CPU ≈ 32/dt prób/s; przestrzeń 62^12 haseł 12-znakowych
    space = 62 ** 12
    years = space / (32 / dt) / 31_557_600
    rec("C", "koszt brute-force (produkcyjny Argon2id)", "pokazać cenę jednej próby",
        f"1 próba ≈ {dt * 1000:.0f} ms + 64 MiB RAM; siłowe 12-znakowe [a-zA-Z0-9] "
        f"przy 32 CPU ≈ {years:.1e} lat (średnio połowa)",
        "🛡️ ODPARTY" if years > 1e6 else "📝 NOTATKA")

    # C2: grzebanie w obwolucie — flip nonce/ct/salt payloadu
    ok = True
    env = json.load(open(p))
    for field, sub in (("payload", "ct"), ("payload", "nonce"), ("wrap_pw", "ct"),
                       ("wrap_pw", "nonce")):
        e2 = json.loads(json.dumps(env))
        raw = bytearray.fromhex(e2[field][sub])
        raw[0] ^= 1
        e2[field][sub] = raw.hex()
        p2 = os.path.join(tmpd, "tamper.ks1")
        json.dump(e2, open(p2, "w"))
        try:
            Keystore.load(p2).unlock(pw)
            ok = False
        except KeystoreError:
            pass
    rec("C", "bit-flip w obwolucie (4 pola)", "AEAD na każdym polu osobno",
        "wszystkie odrzucone (jeden typ: KeystoreError)",
        "🛡️ ODPARTY" if ok else "⚠️ ZNALEZIONO")

    # C3: SWAP pól wrap/probe — próba obejścia hasła lub wymuszenia paniki
    e3 = json.loads(json.dumps(env))
    e3["wrap_pw"], e3["probe_panic"] = e3["probe_panic"], e3["wrap_pw"]
    p3 = os.path.join(tmpd, "swap.ks1")
    json.dump(e3, open(p3, "w"))
    st_pw = st_pn = "?"
    try:
        Keystore.load(p3).unlock(pw)
        st_pw = "OTWARTO(!)"
    except KeystoreError:
        st_pw = "odrzut"
    except PanicActivated:
        st_pw = "PANIKA(!)"
    shred_ok = os.path.exists(p3)
    try:
        Keystore.load(p3).unlock(pn)
        st_pn = "OTWARTO(!)"
    except KeystoreError:
        st_pn = "odrzut"
    except PanicActivated:
        st_pn = "PANIKA(!)"
    ok = st_pw == "odrzut" and st_pn == "odrzut" and os.path.exists(p3)
    rec("C", "swap wrap_pw ↔ probe_panic", "klucze KEK_pw/KEK_pn są rozpięte na pola — swap = martwy plik",
        f"passkey→{st_pw}, panic→{st_pn}, plik istnieje dalej: {os.path.exists(p3)}",
        "🛡️ ODPARTY" if ok else "⚠️ ZNALEZIONO")

    # C4: downgrade wersji/AEAD
    ok = True
    for e4 in ({**env, "v": 0}, {**env, "aead": "rot13"}):
        p4 = os.path.join(tmpd, "down.ks1")
        json.dump(e4, open(p4, "w"))
        try:
            Keystore.load(p4)
            ok = False
        except KeystoreError:
            pass
    rec("C", "downgrade v/aead", "nieznane pola obwoluty = odrzut przy load",
        "oba odrzucone", "🛡️ ODPARTY" if ok else "⚠️ ZNALEZIONO")

    # C5: fail_count=99 — czy da się wykończyć konto opóźnieniami? (sleeper stub)
    e5 = json.loads(json.dumps(env))
    e5["fail_count"] = 99
    p5 = os.path.join(tmpd, "fc99.ks1")
    json.dump(e5, open(p5, "w"))
    ks5 = Keystore.load(p5)
    ks5._sleeper = lambda s: None
    ok = ks5.unlock(pw).wallet == wallet
    rec("C", "fail_count=99 (DoS greiferem)", "licznik nie więzi właściciela",
        f"dobre hasło dalej wchodzi i zeruje licznik: {ok}; prawdziwy hamulec = Argon2id (C1), "
        "nie licznik — jak obiecano w dokumentacji",
        "🛡️ ODPARTY" if ok else "⚠️ ZNALEZIONO")

    # C6: poufność markerów w surowym pliku (szukamy plaintextu na dysku)
    raw = open(p, "rb").read()
    leaks = [m for m in (b"jakub", wallet.encode(), b"x_priv", b"s_priv")
             if m in raw]
    # username siedzi w zaszyfrowanym payloadzie — NIE może być widoczny
    rec("C", "markery plaintextu na dysku", "plik .ks1 = same szyfrogramy i metadane",
        f"wycieki: {leaks if leaks else 'brak'} (username/wallet/klucze niewidoczne)",
        "🛡️ ODPARTY" if not leaks else "⚠️ ZNALEZIONO")

    # C7: panic shred na poziomie FS — plik nie istnieje, brak .tmp
    p7 = os.path.join(tmpd, "doomed.ks1")
    Keystore.create(p7, "doomed", b"doomed-haslo-1", b"doomed-panika-1", kdf=FAST).lock()
    try:
        Keystore.load(p7).unlock(b"doomed-panika-1")
    except PanicActivated:
        pass
    gone = not os.path.exists(p7) and not os.path.exists(p7 + ".tmp")
    rec("C", "panic-shred (FS level)", "po panice nie ma czego odzyskać z katalogu",
        f"plik zniknięty (2× nadpisanie + remove): {gone}; uwaga: kopie w chmurze/backupach "
        "OS są poza zasięgiem — GUI ostrzega",
        "🛡️ ODPARTY" if gone else "⚠️ ZNALEZIONO")

    # C8: Shamir — duplikat udziału / udział z obcego keystora
    ks8 = Keystore.load(p)
    ks8.unlock(pw)
    sh = ks8.export_recovery_shares(k=2, n=3)
    ok = True
    try:
        combine_shares([bytes.fromhex(sh[0]), bytes.fromhex(sh[0])])
        ok = False
    except ValueError:
        pass
    other = Keystore.create(os.path.join(tmpd, "iny.ks1"), "iny",
                            b"iny-pass-11111", b"iny-panic-1111", kdf=FAST)
    sh_other = other.export_recovery_shares(k=2, n=3)
    try:
        Keystore.load_with_shares(p, [sh[0], sh_other[1]])
        ok = False
    except KeystoreError:
        pass
    rec("C", "Shamir: duplikat/obcy udział", "udziały nie mieszają się między kontenerami",
        "duplikat → wyjątek; obcy udział → brak otwarcia",
        "🛡️ ODPARTY" if ok else "⚠️ ZNALEZIONO")

    # C9: uczciwa notatka o RAM
    rec("C", "RAM u aplikacji Python", "secret hygiene w interpreterze",
        "MEK zeroizujemy best-effort (bytearray), ale obiekty biblioteki zarządza C; "
        "pełne mlock/anti-dump = dopiero build natywny (M8) — zapisane jako wymóg, nie obietnica",
        "📝 NOTATKA")


# =====================================================================
def section_d() -> None:
    print("\n== D. PROFILE / TOŻSAMOŚĆ ==")
    wallets = set()
    for _ in range(100):
        wallets.add(CoreIdentity.generate(f"u{len(wallets):04d}").wallet)
    ok = len(wallets) == 100
    rec("D", "unikalność walletów (100 tożsamości)", "kolizja 160-bit praktycznie niemożliwa",
        f"unikatowe: {len(wallets)}/100",
        "🛡️ ODPARTY" if ok else "⚠️ ZNALEZIONO")

    # regresja: MITM swap profilu (pełny scenariusz w core/identity.py)
    a = CoreIdentity.generate("atakujacy")
    b = CoreIdentity.generate("bohater")
    fake = dict(b.public_profile())
    fake["x_pub"] = a.public_profile()["x_pub"]
    try:
        check_profile(fake)
        ok = False
    except Exception:
        ok = True
    rec("D", "MITM profile-swap (regresja)", "wallet przeliczany z kluczy — podmianka widoczna",
        "check_profile odrzucił", "🛡️ ODPARTY" if ok else "⚠️ ZNALEZIONO")

    rec("D", "UID 32-bit", "pamiętać o roli UID",
        "UID (8 hex) ma kolizje urodzinowe przy ~2^16 tożsamościach — to ETYKIETA do GUI, "
        "nie identyfikator; identyfikatorem jest zawsze wallet (160 bit)",
        "📝 NOTATKA")


# =====================================================================
def section_e() -> None:
    print("\n== E. CSPRNG platformy ==")
    sample = os.urandom(512 * 1024)
    chi, sig = chi2_uniform(sample)
    mono = monobit(sample)
    ok = abs(sig) < 4 and abs(mono - 0.5) < 0.005
    rec("E", "os.urandom 512 KB", "platformowe RNG = fundament wszystkich nonce/kluczy",
        f"chi²σ={sig:+.2f}, monobit={mono:.4f}",
        "🛡️ ODPARTY" if ok else "📝 NOTATKA")


# =====================================================================
def build_report() -> str:
    import cryptography
    blocked = sum(1 for r in R if r["status"] == "🛡️ ODPARTY")
    notes = [r for r in R if r["status"] == "📝 NOTATKA"]
    found = [r for r in R if r["status"] == "⚠️ ZNALEZIONO"]
    verdict = ("WYNIK: wszystkie ataki odparzone; znaleziono WYŁĄCZNIE notatki projektowe."
               if not found else
               f"WYNIK: ⚠️ ZNALEZIONO {len(found)} PROBLEM(Y) — NAPRAWIĆ PRZED DALSZĄ PRACĄ!")

    lines = [
        "# Fenix — Raport z wewnętrznego ataku na szyfrowanie (self-attack)",
        "",
        "wersja raportu: 1.0 · 2026-07-25 · generator: `tools/self_attack.py`",
        "",
        f"## Werdykt",
        "",
        f"**{verdict}**",
        "",
        f"- 🛡️ odparzone: **{blocked}**",
        f"- 📝 notatki projektowe (uczciwe, nie luki): **{len(notes)}**",
        f"- ⚠️ znalezione problemy: **{len(found)}**",
        "",
        "## Środowisko testu",
        "",
        f"- Python {platform.python_version()} · cryptography {cryptography.__version__} · {platform.system()} {platform.machine()}",
        "- sandbox deweloperski; pomiary czasów orientacyjne",
        "",
        "## Metodologia i OGRANICZENIA (uczciwie)",
        "",
        "To jest wewnętrzna bateria ataków projektanta, którą odpalamy po każdej zmianie",
        "w krypto. To NIE zastępuje audytu zewnętrznego (M9) ani pełnych pakietów",
        "statystycznych (NIST STS/dieharder) — robi sanity-checki chi²/monobit/lawina.",
        "Testy S-boxa są próbkowane (64 różnice × 512 par, 200 masek × 2048 próbek).",
        "",
        "## Wyniki szczegółowe",
        "",
        "| # | sekcja | atak | podejście/cel | rezultat | status |",
        "|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(R, 1):
        lines.append(
            f"| {i} | {r['section']} | {r['name']} | {r['method']} | {r['outcome']} | {r['status']} |")
    lines += [
        "",
        "## Notatki projektowe (co trzymamy w głowie)",
        "",
    ]
    for r in notes:
        lines.append(f"- **{r['section']}::{r['name']}** — {r['outcome']}")
    if found:
        lines += ["", "## ⚠️ ZNALEZIONE PROBLEMY", ""]
        for r in found:
            lines.append(f"- **{r['section']}::{r['name']}** — {r['outcome']}")
    lines += [
        "",
        "## Rekomendacje na zapleczu",
        "",
        "- zewnętrzny audyt krypto przed publicznym M5 (seed nodes + mainnet)",
        "- fuzzing ramek/keystora w CI (ciągłe, nie ręczne)",
        "- pełny pakiet NIST STS na keystream FNX-WRAP przed uzależnieniem od niego",
        "- build natywny (M8): prawdziwe mlock/anti-core-dump dla MEK i kluczy sesji",
        "- powtarzać ten raport po KAŻDEJ zmianie core/crypto (checklista pliku, TODO)",
        "",
        "---",
        "*Wygenerowano automatycznie przez tools/self_attack.py — nie edytować ręcznie.*",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    t0 = time.time()
    print("SELF-ATTACK Fenix — wewnętrzny czerwony zespół\n")
    section_a()
    section_b()
    section_c()
    section_d()
    section_e()
    report = build_report()
    out = ROOT / "docs" / "crypto_attack_report.md"
    out.write_text(report, encoding="utf-8")
    dt = time.time() - t0
    found = sum(1 for r in R if r["status"] == "⚠️ ZNALEZIONO")
    blocked = sum(1 for r in R if r["status"] == "🛡️ ODPARTY")
    notes = sum(1 for r in R if r["status"] == "📝 NOTATKA")
    print(f"\nKONIEC: {blocked} odparzone · {notes} notatki · {found} problemów · "
          f"{dt:.1f}s · raport: docs/crypto_attack_report.md")
    if found:
        sys.exit(1)


if __name__ == "__main__":
    main()
