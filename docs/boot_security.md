# Fenix — Boot Security i ochrona kodu (boot_security.md)

wersja 0.1 · 2026-07-25 · status: SPEC WIĄZĄCA dla budowy ISO (os/) i pakowania aplikacji
powiązane: D3 (keystore/panika) · D8 (strategia ISO) · D9 (zero recovery) · D11 (zastrzeżenie obfuskacja)
           D14 (podpisy) · D18/D21 (bany=egzekucja) · D24 (kontener) · D25 (tryby wdrożenia)

---

## 0. Zasada zerowa (przeczytaj dwa razy)

**Kod NIE jest sekretem. Sekretem są klucze.** (Kerckhoffs, Filar 3)

Każdy kod — Python, C, cokolwiek — musi być jawnie czytelny na maszynie, która go
wykonuje (CPU nie wykonuje zaszyfrowanych instrukcji). Nie istnieje technologia
„działa u Ciebie, ale jest przed Tobą ukryte w 100%". Cel projektu NIE brzmi więc
„kod nieczytelny", tylko trzy mierzalne właściwości:

1. **Kod jest BEZUŻYTECZNY bez ważnego właściciela** (ładunek szyfrowany kluczem zbiorczym).
2. **Kod jest NIEPODMIENIALNY** (podpisy + weryfikacja na każdym poziomie, dm-verity).
3. **Kod NIE PRZETRWA zasilania** (payload żyje tylko w tmpfs/RAM, amnezja, panic).

Jeśli cały ten dokument straci — kod źródłowy może być jawny i audytowany, a bezpieczeństwo
użytkowników STOI. To jest test Kerckhoffsa, który przechodzimy założeniowo.

---

## 1. Sześć ataków typu „przejęcie kodu" → sześć obron (MATRYCA)

| # | atak | jak to wygląda w realu | nasza obrona | decyzja/plik |
|---|---|---|---|---|
| 1 | kradzież/wyciek źródeł | „mają wasz kod!" | nic do stracenia: bez kluczy kod jest martwy; protokół i specy są jawne z założenia | Filar 3 |
| 2 | podmiana obrazu przed pobraniem (supply chain) | fałszywe ISO na mirroringu | podpis ISO kluczem ownera offline + publikacja SHA256; `os/verify_iso.sh` przed nagraniem | D14 |
| 3 | grzebanie przy nośniku („evil maid") | ktoś modyfikuje pliki na pendrive | główny system plików = **squashfs read-only** + **dm-verity** (drzewo hashy: każda zmiana bloku = boot zatrzymany) + manifest payloadu podpisany | §3, os/build |
| 4 | podmiana kodu w RAM podczas sesji | rootkit / złośliwy proces | kernel `lockdown=integrity` (odrzuca niepodpisane moduły), AppArmor profil `fenix`, brak sudo w live, self-check hashy payloadu przy starcie stosu | iso_plan §B3 |
| 5 | odczyt kodu z RAM po przejęciu działającego sprzętu | analiza forenzyczna | kod jawny *w RAM* — tak, ale **zero sekretów w kodzie**; klucze trzymane w mlock z wyłączonymi core dumpami; panic = wipe; RAM ginie z zasilaniem | D3, D24 |
| 6 | zbanowany / wrogi użytkownik odpala własną kopię stosu | bootleg klon kopii | ładunek zaszyfrowany kluczem zbiorczym; seed-y wydają udziały Shamira tylko niezabanowanym walletom (challenge-response); brak udziałów = cegła | §3–§4, D18/D21 |

Wniosek: nie istnieje JEDNA obrona „na przejęcie kodu". Istnieje warstwowość, w której
każdy z sześciu scenariuszy kończy się dla atakującego: cegłą, porażką płyty głównej
albo zdobyczą pozbawioną wartości.

---

## 2. Dwa kształty produktu (zgodnie z D25)

### Fenix App (pulbit, poziom 1 ochrony kodu)
Musi działać OFFLINE, więc uczciwe szyfrowanie payloadu nie ma tam sensu (kto szyfruje
i wydaje klucz na tej samej maszynie, teatruje). Dlatego w apce:
- pakiet **podpisany kluczem build** (weryfikacja przy starcie i aktualizacji, D14),
- **Nuitka** (kompilacja do natywnego): podnosi poprzeczkę reverse-engineeringu —
  to HIGIENA, nie security (zastrzeżenie D11 obowiązuje),
- sekretów w kodzie: zero. Keystore (D24) = jedyny plik z sekretem, chroniony passkey.
Uczciwie w GUI: „poziom 1 — ochrona treści, nie systemu".

### Fenix OS ISO (poziom 3 — zapieczętowany ładunek)
Tu mamy to, czego apka nie może mieć: boot jest ONLINE do seed nodes (poza trybem
szkieletowym, który stosu Fenixa nie ładuje). To pozwala na schemat z §3.

---

## 3. Zapieczętowany ładunek na ISO — PIPELINE

### 3.1 Na hoście build (offline, Debian, klucze ownera poza maszyną)
1. zebranie stosu: `core/ net/ transport/ app/ gui/` (z repo, ten sam commit co tag wersji)
2. `manifest_payload.json` = {wersja, commit, [sha256 każdego pliku]}
3. podpis manifestu **hot-podkluczem build** (D14) → `manifest_payload.sig`
4. losowy **klucz_ładunku (32 B)**; `payload.enc` = XChaCha20-Poly1305(klucz_ładunku, stos + manifest)
5. klucz_ładunku → **Shamir 3-z-5** (mod 2^256−189, core.crypto.fenix_crypto) → po udziale
   na każdy seed node (szyfrowany kanałem do klucza seeda); **klucz NIGDY nie trafia na ISO**
6. ISO = squashfs(Debian live + `payload.enc` + manifest + sig + pubkey build + pubkey seedów)
   → podpis całości kluczem ownera (D14) → publikacja SHA256

### 3.2 Boot na maszynie użytkownika (timeline)
1. UEFI → kernel+initramfs → spoof (D6) → firewall FAIL-CLOSED → wipe hooks (iso_plan §B)
2. VERIFY: podpis manifestu (wbudowany pubkey build) + SHA256(payload.enc) zgodne z manifestem
   — niezgodność = stop, komunikat integralności, zero ładowania
3. kreator: passkey → otwarcie kontenera D24 (keystore) → tożsamość/wallet
   (3× ❌ = opóźnienie ×2; hasło paniki = cichy shred kontenera i wyjście)
4. do ≥3 seed nodes: **challenge-response** — klient podpisuje wyzwanie Ed25519 walletem
   (+ PoW-ticket hashcash z protocol_spec przeciw farmom)
5. każdy seed sprawdza: wallet NIE jest tombstone (ban) → wydaje swój udział, szyfrowany
   efemerycznym X25519 do klucza klienta (forward secrecy na czas odpowiedzi)
6. klient: ≥3 udziałów → **składa klucz_ładunku W RAM** (nigdy na dysk) →
   AEAD-decrypt `payload.enc` → `/run/fenix-payload` (tmpfs, 0700)
7. SELF-CHECK: hash każdego pliku payloadu vs manifest — dopiero potem import/start stosu
8. wylogowanie / wyłączenie / kill switch / panic: wipe tmpfs + zeroize mlock kluczy

### 3.3 Co dostaje wróg (scenariusze)
- skradzione ISO, bez passkey → cegła (kontener D24 zamknięty, payload.enc martwy)
- passkey znany, wallet ZBANOWANY → seed-y odmawiają udziałów → cegła; działa tylko tryb szkieletowy
- podmiana 1 bajta `payload.enc` lub manifestu → błąd integralności w kroku 2/7, zero startu
- podsłuch sieci w kroku 4–5 → podpisane wyzwania + X25519: dla podsłuchu losowy szum
- fizyczne przejęcie W TRAKCIE sesji → payload czytelny w RAM (UCZCIWIE: tak), ale zero
  kluczy użytkownika poza mlock; panic/kill-switch zamykają scenę w sekundy

---

## 4. Parametry (wiążące, zmiana = wersja tego dokumentu)

- AEAD ładunku: **XChaCha20-Poly1305**, nonce losowy na build
- Shamir: **k=3, n=5**, ciało mod 2^256−189 (implementacja: core.crypto.fenix_crypto)
- klucz_ładunku: 32 B, losowy; bytowo NIGDY na dysku maszyny podłączonej do sieci
- wydawanie udziału: max **1 / wallet / doba** na seed (anti-oracle); odmowa gdy tombstone
- Dev-mode przy pracach: `FENIX_DEV_PAYLOAD_KEY` z ENV — payload DEV jawny, GUI pokazuje
  wielkie „DEV BUILD"; produkcyjny build bez tej zmiennej NIE MA innej drogi niż seed-y
- seed pubkeys i seed listy: podpisane w ISO (aktualizacja = nowy ISO, D14)

---

## 5. Zastrzeżenie D11 — STAN

Obfuskacja „dla bezpieczeństwa" (pyarmor i podobne): **nie** — teatr + flagi AV + utrudniony
audyt. Kompilacja Nuitka w apce: **tak, jako higiena**. Cała realna ochrona z tego
dokumentu działałaby identycznie przy 100% jawnym kodzie — i to jest nasz dowód jakości.

---

## 6. QA przed wydaniem (checkboxy)

- [x] tag-test: 1 bajt zmieniony w `payload.enc` → boot wykrywa i odmawia startu ✅ (`os/fenix_payload.py` selftest #3)
- [x] manifest-test: podmiana manifestu/podpisu → verify fail w kroku 2 ✅ (selftest #7)
- [ ] banned-test (testnet): wallet z tombstone → seed-y odmawiają, stos nie startuje, tryb szkieletowy OK
- [ ] key-hygiene: po sesji, zrzut dysku/nośnika nie zawiera klucza_ładunku (RAM-only potwierdzone narzędziem)
- [x] dev-mode: bez ENV payload DEV = cegła; z ENV startuje + banner DEV ✅ (selftest #6; banner GUI ← M7)
- [ ] konsystencja z `core/keystore.py` (passkey, panika) i `os/verify_iso.sh` (D14)

---
---

## 7. CHANGELOG
- v0.1 (2026-07-25): spec pierwszy.
- v0.2 (2026-08-04): implementacja ładunku: `os/fenix_payload.py` (FNXPAYL1: chunked AEAD +
  manifest podpisany D14 + Shamir 3-z-5 gotowe przez fenix_crypto; runtime bez XChaCha →
  ChaCha20Poly1305 z nonce derywowanym per chunk, zapisane w nagłówku `aead`);
  `os/fenix_boot.py::cmd_payload` (sealed: ENV operatora → test / bez klucza = cegła by design,
  udziały od seedów ← M5); `os/build_iso.sh` tryby plain/dev/sealed (SEALED: kod NIE leży
  jawnie na ISO poza loaderem os/); launcher fenix-node: cwd `/opt/fenix` + PYTHONPATH na
  `/run/fenix-payload` (fix: stos na module path).

*boot_security.md v0.2 — egzekwowalne od momentu powstania os/build_iso.sh.*
