# gui/settings_admin.py — ONB ADMINA (D55): pierwsza czynność = zedrzyj hasło fabryczne
"""
Analogia dla każdego: kupujesz router — na spodzie naklejka „admin / admin123".
Porządny instalator NIE pyta „chcesz zmienić?" — każe zedrzeć naklejkę i wpisać
własne hasło, ZANIM puszcza Cię dalej. Fenix robi dokładnie to z kontem Deimos
(D53): hasło fabryczne „Anon123!" jest JAWNE w repo (na życzenie właściciela),
więc traktujemy je jak naklejkę ze spodu routera — działa raz, po to, by wejść
i ją wymienić.

„Wymuszone" znaczy: dialog ONB nie ma przycisku „pomiń", a kontroler melduje
stan czerwienią, dopóki `is_default_password` mówi True. Kodowo ONB to zwykła
zmiana hasła (unlock aktualnym + change_password pary hasło+panika, KS1/D3),
ale z TRZEMA strażnikami, których nie ma ręczna zmiana z konsoli:

    1. walidacja LUDZKA (min. długość, nie-fabryczne, nie-oczywiste, panika ≠ hasło),
    2. dowód posessionu: trzeba znać AKTUALNE hasło (fabryczne liczy się raz),
    3. WERYFIKACJA po fakcie (nie wierz — sprawdź): fabryczne martwe? nowe otwiera?
       wallet TEN SAM? wizytówka attesta (D55, core/admin) odświeżona?

Po udanym ONB ta sama funkcja służy jako zwykłe „Zmień hasło admina" —
aktualne hasło jest wtedy Twoim własnym, nie fabrycznym.
"""
from __future__ import annotations

import os
import sys
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from core.admin import (admin_path, unlock_admin, is_default_password,       # noqa: E402
                        change_admin_password, attestor_wallet, AdminError,
                        DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_PANIC, ADMIN_USERNAME)
from core.keystore import KDFParams                                          # noqa: E402

# ONB = konto kapitana okrętu: mocniej niż zwykłe 8 znaków (min. z core/keystore).
MIN_PASS = 10
MIN_PANIC = 8
# hasła-oczywiste: mała lista „naklejkowych" pomysłów, nie słownik hakerski
OBVIOUS = {ADMIN_USERNAME, "admin", "deimos", "haslo", "hasło", "password",
           "qwerty", "fenix", "anon", "letmein"}


class OnboardingError(Exception):
    """Odmowa ONB — jeden typ; komunikat zawsze po polsku, dla człowieka."""


def needs_onboarding(data_dir: str, kdf: KDFParams | None = None) -> bool:
    """Czy trzeba przejść ONB? True: brak admin.ks ALBO fabryczne hasło dalej żyje."""
    if not os.path.exists(admin_path(data_dir)):
        return True
    return is_default_password(data_dir, kdf=kdf)


def validate_new_credentials(new_pass: str, new_panic: str) -> list[str]:
    """Lista powodów odrzucenia (PUSTA = można zmieniać). Każdy powód po polsku."""
    bad: list[str] = []
    pw, pn = new_pass or "", new_panic or ""
    if len(pw) < MIN_PASS:
        bad.append(f"nowe hasło: min. {MIN_PASS} znaków (podano {len(pw)})")
    if pw == DEFAULT_ADMIN_PASSWORD:
        bad.append("nowe hasło = FABRYCZNE — to jest właśnie ta dziura, którą latamy")
    if pw.strip().lower() in OBVIOUS:
        bad.append("nowe hasło zbyt oczywiste (nazwa konta / klasyk z naklejki)")
    if len(pn) < MIN_PANIC:
        bad.append(f"hasło paniki: min. {MIN_PANIC} znaków (podano {len(pn)})")
    if pn == DEFAULT_ADMIN_PANIC:
        bad.append("hasło paniki = FABRYCZNE — panika to wabik, musi być własna (D3)")
    if pw and pn and pw == pn:
        bad.append("hasło paniki MUSI być inne niż hasło (D3: inaczej wabik nie istnieje)")
    return bad


def run_onboarding(data_dir: str, current_pass: str, new_pass: str,
                   new_panic: str, kdf: KDFParams | None = None) -> str:
    """Pełna ścieżka ONB / zmiany hasła admina. Sukces = komunikat; błąd = OnboardingError.

    Kolejność jest częścią bezpieczeństwa: NAJPIERW walidacja (nic nie jest pisane),
    POTEM dowód aktualnego hasła, POTEM zmiana pary (hasło+panika, KS1), NA KOŃCU
    weryfikacja trzech faktów z dysku, nie z pamięci."""
    bad = validate_new_credentials(new_pass, new_panic)
    if bad:
        raise OnboardingError("; ".join(bad))
    try:
        ks = unlock_admin(data_dir, current_pass, kdf=kdf)   # dowód: znasz aktualne
    except AdminError as e:
        raise OnboardingError(f"aktualne hasło admina nie pasuje ({e})") from None
    # UCZCIWY DOWÓD (złapane selftestem): gdy admin.ks powstał PRZED CHWILĄ w tym
    # procesie, Keystore.create zostawia go OTWARTEGO, a unlock() zwraca tożsamość
    # bez patrzenia na hasło — „aktualne hasło" byłoby teatrem. Domykamy i otwieramy
    # PODANYM hasłem: teraz złe hasło NAPRAWDĘ odpada (Argon2id liczy się z dysku).
    ks.lock()
    try:
        ks = unlock_admin(data_dir, current_pass, kdf=kdf)
    except AdminError as e:
        raise OnboardingError(f"aktualne hasło admina nie pasuje ({e})") from None
    w0 = ks.identity.wallet                                  # tożsamość = święta
    try:
        change_admin_password(ks, new_pass, new_panic)       # KS1: para hasło+panika
    except AdminError as e:
        raise OnboardingError(str(e)) from None
    ks.lock()
    # --- WERYFIKACJA (zamykamy pętlę jak w full_audit: nie wierz — sprawdź) ---
    if is_default_password(data_dir, kdf=kdf):
        raise OnboardingError("po zmianie DALEJ działa hasło fabryczne — przerwano")
    ks2 = unlock_admin(data_dir, new_pass, kdf=kdf)
    if ks2.identity.wallet != w0:
        raise OnboardingError("wallet po zmianie inny niż przed — tożsamość uciekła!")
    ks2.lock()
    return ("hasło admina ZMIENIONE ✓ — fabryczne martwe, panika własna, "
            "wallet bez zmian, wizytówka attesta odświeżona (demon zarejestruje "
            "przy starcie, D55)")


# -------------------------------------------------------------------------- selftest
if __name__ == "__main__":
    import shutil
    import tempfile

    print("gui/settings_admin.py — selftest: ONB Deimosa (D55)\n")
    d = tempfile.mkdtemp(prefix="fenix-onb-")
    fast = KDFParams.fast_for_tests()

    # 1) świeży katalog: ONB potrzebny (nim cokolwiek istnieje)
    assert needs_onboarding(d, kdf=fast) is True
    print("  [OK] 1. pusty data_dir → ONB potrzebny (konto stanie się przy pierwszym użyciu)")

    # 2) walidacja łapie WSZYSTKIE szkolne błędy naraz (i nic nie zapisuje)
    bad = validate_new_credentials(DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_PANIC)
    assert any("FABRYCZNE" in b for b in bad) and any("paniki" in b for b in bad), bad
    bad2 = validate_new_credentials("deimos", "x")          # oczywiste = dop. dokładne
    assert any("oczywiste" in b for b in bad2) and any(f"min. {MIN_PANIC}" in b for b in bad2), bad2
    bad3 = validate_new_credentials("TakieSame!Haslo1", "TakieSame!Haslo1")
    assert any("inne niż hasło" in b for b in bad3), bad3
    assert validate_new_credentials("Kredens!Dobre-88", "Panika!Inna-77") == []
    print("  [OK] 2. walidacja: fabryczne/oczywiste/panika=hasło/za krótkie — odrzucone z powodami")

    # 3) pełny ONB: fabrycznym wchodzimy, własnym wychodzimy; wallet TEN SAM
    w_before = None
    try:
        run_onboarding(d, "ZleFabryczne!1", "Kredens!Dobre-88", "Panika!Inna-77", kdf=fast)
        raise SystemExit("ONB przeszedł ze ZŁYM aktualnym hasłem!")
    except OnboardingError as e:
        assert "nie pasuje" in str(e), e
    # wallet bez odblokowywania: z wizytówki D55 (admin.ks po odrzuconej próbie
    # już ISTNIEJE i jest ZAMKNIĘTY — Keystore.load trzyma go pod kluczem)
    w_before = attestor_wallet(d)
    assert w_before and w_before.startswith("FNX1")
    msg = run_onboarding(d, DEFAULT_ADMIN_PASSWORD, "Kredens!Dobre-88", "Panika!Inna-77", kdf=fast)
    assert "ZMIENIONE" in msg, msg
    assert needs_onboarding(d, kdf=fast) is False
    assert is_default_password(d, kdf=fast) is False
    assert attestor_wallet(d) == w_before, "wizytówka attesta nie zgadza się z walletem"
    print("  [OK] 3. ONB: złe aktualne odrzucone; fabryczne→własne OK; wallet stabilny; wizytówka ✓")

    # 4) po ONB: fabryczne MARTWE, własne żywe (weryfikacja z dysku, nie z pamięci)
    try:
        unlock_admin(d, DEFAULT_ADMIN_PASSWORD, kdf=fast)
        raise SystemExit("fabryczne hasło dalej działa po ONB!")
    except AdminError:
        pass
    ks = unlock_admin(d, "Kredens!Dobre-88", kdf=fast)
    assert ks.identity.wallet == w_before
    ks.lock()
    print("  [OK] 4. weryfikacja: fabryczne martwe, własne otwiera, wallet bez zmian")

    # 5) ONB jako zwykłe „zmień hasło" (drugi raz — aktualne jest już własne)
    msg2 = run_onboarding(d, "Kredens!Dobre-88", "Nowsze!Haslo-999", "Panika!Nowsza-11", kdf=fast)
    assert "ZMIENIONE" in msg2
    ks = unlock_admin(d, "Nowsze!Haslo-999", kdf=fast)
    assert ks.identity.wallet == w_before
    ks.lock()
    assert needs_onboarding(d, kdf=fast) is False
    print("  [OK] 5. druga zmiana działa tą samą ścieżką (GNIAZDO 'ustawienia admina')")

    # 6) boot demona po ONB: attest rejestruje się z wizytówki (bez hasła)
    from core.admin import register_admin_attestor_boot
    import chain.ban_evt as _pkg
    wb = register_admin_attestor_boot(d, kdf=fast)
    assert wb == w_before and wb in _pkg.ATTESTOR_WALLETS
    shutil.rmtree(d, ignore_errors=True)
    print("  [OK] 6. po ONB demon rejestruje attesta Deimosa z wizytówki (hasło nietknięte)")

    print("\nSELFTEST: PASS ✅  gui/settings_admin.py — ONB (D55):\n"
          "naklejka z routera zdjęta przy pierwszej okazji, z dowodem posiadania,\n"
          "z walidacją dla człowieka i z weryfikacją faktów z dysku.")
