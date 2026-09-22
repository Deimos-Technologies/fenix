# Fenix — Raport z wewnętrznego ataku na szyfrowanie (self-attack)

wersja raportu: 1.0 · 2026-07-25 · generator: `tools/self_attack.py`

## Werdykt

**WYNIK: wszystkie ataki odparzone; znaleziono WYŁĄCZNIE notatki projektowe.**

- 🛡️ odparzone: **27**
- 📝 notatki projektowe (uczciwe, nie luki): **5**
- ⚠️ znalezione problemy: **0**

## Środowisko testu

- Python 3.11.2 · cryptography 50.0.1 · Linux x86_64
- sandbox deweloperski; pomiary czasów orientacyjne

## Metodologia i OGRANICZENIA (uczciwie)

To jest wewnętrzna bateria ataków projektanta, którą odpalamy po każdej zmianie
w krypto. To NIE zastępuje audytu zewnętrznego (M9) ani pełnych pakietów
statystycznych (NIST STS/dieharder) — robi sanity-checki chi²/monobit/lawina.
Testy S-boxa są próbkowane (64 różnice × 512 par, 200 masek × 2048 próbek).

## Wyniki szczegółowe

| # | sekcja | atak | podejście/cel | rezultat | status |
|---|---|---|---|---|---|
| 1 | A | poufność + statystyka (chi²/monobit) | szyfrogram nieodróżnialny od szumu | chi²σ=+0.56 (dopuszczane |σ|<4), monobit=0.5005, plaintext niewidoczny | 🛡️ ODPARTY |
| 2 | A | bit-flip przekłamania (200 prób) | każdy przekłam odrzucony | odrzucono 200/200 | 🛡️ ODPARTY |
| 3 | A | podmiana sig_pub nagłówka | podpis nie pokrywa podmienionego klucza | weryfikacja Ed25519 odrzuciła | 🛡️ ODPARTY |
| 4 | A | podmiana x_pub nagłówka | nagłówek jest AAD + podpisany — niepodmienialny | podpis odrzucił | 🛡️ ODPARTY |
| 5 | A | fałszerstwo podpisu (losowe 64B) | Ed25519 nie do podrobienia siłowo | odrzucony | 🛡️ ODPARTY |
| 6 | A | truncation/append | AEAD związany z długością — obcinki odrzucane | wszystkie odrzucone | 🛡️ ODPARTY |
| 7 | A | replay poza sesją | ten sam blob odszyfrowuje się 2× | BY DESIGN: blob jest autonomiczny; ochrona replay = okno 4096 ramek w KANALE sesyjnym (protocol_spec) — nie w formacie E2E | 📝 NOTATKA |
| 8 | A | nonce/eph-key 4000× | każdy komunikat ma świeży klucz efemeryczny i nonce | unikatowe: 4000/4000 | 🛡️ ODPARTY |
| 9 | A | demonstracja nonce-reuse (nasza obrona: eph-key + losowy nonce) | pokazać mechanizm katastrofy, której u nas nie ma | XOR szyfrogramów = XOR plaintextów: True — u nas niemożliwe (A8), bo klucz sesji E2E jest jednorazowy (eph X25519) | 📝 NOTATKA |
| 10 | A | separacja kluczy (labele HKDF) | msg ≠ wrap ≠ sess — jeden sekret, niezależne klucze | klucze różne: True | 🛡️ ODPARTY |
| 11 | B | roundtrip 0..4096 B | brak padding-owych krzaków | wszystkie OK | 🛡️ ODPARTY |
| 12 | B | bit-flip przekłamania (200 prób) | EtM-HMAC łapie wszystko (magia/nonce/ct/tag) | odrzucono 200/200 | 🛡️ ODPARTY |
| 13 | B | orakel typów błędów | atakujący nie dowiaduje się CO nie pasuje | typy wyjątków: ['FenixWrapError'] | 🛡️ ODPARTY |
| 14 | B | zły AAD / obcy klucz | uwierzytelnienie obejmuje nagłówek warstwy | oba odrzucone | 🛡️ ODPARTY |
| 15 | B | efekt lawinowy (800 prób) | 1 bit we → ~64/128 bitów wy | min=47 avg=64.0 max=82 (ideał: avg≈64) | 🛡️ ODPARTY |
| 16 | B | statystyka keystreamu (256 KB) | chi²/monobit/autokorelacja w normie | chi²σ=+1.46, monobit=0.4994, lag1=+0.0002 | 🛡️ ODPARTY |
| 17 | B | nonce losowy na wiadomość | determinizm = przeciek; tutaj go nie ma | szyfrogramy różne, nonce różne | 🛡️ ODPARTY |
| 18 | B | S-box: kryptoanaliza (próbkowana) | brak patologicznych dyferencjałów/biasów | max Δ-prawd podobieństwo ≈ 0.047, max bias liniowy ≈ 0.097 (próbkowane — sanity, nie pełna analiza; wrap i tak jest warstwą DODATKOWĄ pod AEAD) | 🛡️ ODPARTY |
| 19 | B | rola warstwy własnej | pamiętać, że wrap NIE jest samodzielną obroną | gdyby FNX-WRAP runął całkowicie, kanał dalej chroni AEAD sesji (D2); testowana tu jako dodatkowa głębia, nie fundament | 📝 NOTATKA |
| 20 | C | koszt brute-force (produkcyjny Argon2id) | pokazać cenę jednej próby | 1 próba ≈ 124 ms + 64 MiB RAM; siłowe 12-znakowe [a-zA-Z0-9] przy 32 CPU ≈ 4.0e+11 lat (średnio połowa) | 🛡️ ODPARTY |
| 21 | C | bit-flip w obwolucie (4 pola) | AEAD na każdym polu osobno | wszystkie odrzucone (jeden typ: KeystoreError) | 🛡️ ODPARTY |
| 22 | C | swap wrap_pw ↔ probe_panic | klucze KEK_pw/KEK_pn są rozpięte na pola — swap = martwy plik | passkey→odrzut, panic→odrzut, plik istnieje dalej: True | 🛡️ ODPARTY |
| 23 | C | downgrade v/aead | nieznane pola obwoluty = odrzut przy load | oba odrzucone | 🛡️ ODPARTY |
| 24 | C | fail_count=99 (DoS greiferem) | licznik nie więzi właściciela | dobre hasło dalej wchodzi i zeruje licznik: True; prawdziwy hamulec = Argon2id (C1), nie licznik — jak obiecano w dokumentacji | 🛡️ ODPARTY |
| 25 | C | markery plaintextu na dysku | plik .ks1 = same szyfrogramy i metadane | wycieki: brak (username/wallet/klucze niewidoczne) | 🛡️ ODPARTY |
| 26 | C | panic-shred (FS level) | po panice nie ma czego odzyskać z katalogu | plik zniknięty (2× nadpisanie + remove): True; uwaga: kopie w chmurze/backupach OS są poza zasięgiem — GUI ostrzega | 🛡️ ODPARTY |
| 27 | C | Shamir: duplikat/obcy udział | udziały nie mieszają się między kontenerami | duplikat → wyjątek; obcy udział → brak otwarcia | 🛡️ ODPARTY |
| 28 | C | RAM u aplikacji Python | secret hygiene w interpreterze | MEK zeroizujemy best-effort (bytearray), ale obiekty biblioteki zarządza C; pełne mlock/anti-dump = dopiero build natywny (M8) — zapisane jako wymóg, nie obietnica | 📝 NOTATKA |
| 29 | D | unikalność walletów (100 tożsamości) | kolizja 160-bit praktycznie niemożliwa | unikatowe: 100/100 | 🛡️ ODPARTY |
| 30 | D | MITM profile-swap (regresja) | wallet przeliczany z kluczy — podmianka widoczna | check_profile odrzucił | 🛡️ ODPARTY |
| 31 | D | UID 32-bit | pamiętać o roli UID | UID (8 hex) ma kolizje urodzinowe przy ~2^16 tożsamościach — to ETYKIETA do GUI, nie identyfikator; identyfikatorem jest zawsze wallet (160 bit) | 📝 NOTATKA |
| 32 | E | os.urandom 512 KB | platformowe RNG = fundament wszystkich nonce/kluczy | chi²σ=-0.29, monobit=0.5003 | 🛡️ ODPARTY |

## Notatki projektowe (co trzymamy w głowie)

- **A::replay poza sesją** — BY DESIGN: blob jest autonomiczny; ochrona replay = okno 4096 ramek w KANALE sesyjnym (protocol_spec) — nie w formacie E2E
- **A::demonstracja nonce-reuse (nasza obrona: eph-key + losowy nonce)** — XOR szyfrogramów = XOR plaintextów: True — u nas niemożliwe (A8), bo klucz sesji E2E jest jednorazowy (eph X25519)
- **B::rola warstwy własnej** — gdyby FNX-WRAP runął całkowicie, kanał dalej chroni AEAD sesji (D2); testowana tu jako dodatkowa głębia, nie fundament
- **C::RAM u aplikacji Python** — MEK zeroizujemy best-effort (bytearray), ale obiekty biblioteki zarządza C; pełne mlock/anti-dump = dopiero build natywny (M8) — zapisane jako wymóg, nie obietnica
- **D::UID 32-bit** — UID (8 hex) ma kolizje urodzinowe przy ~2^16 tożsamościach — to ETYKIETA do GUI, nie identyfikator; identyfikatorem jest zawsze wallet (160 bit)

## Rekomendacje na zapleczu

- zewnętrzny audyt krypto przed publicznym M5 (seed nodes + mainnet)
- fuzzing ramek/keystora w CI (ciągłe, nie ręczne)
- pełny pakiet NIST STS na keystream FNX-WRAP przed uzależnieniem od niego
- build natywny (M8): prawdziwe mlock/anti-core-dump dla MEK i kluczy sesji
- powtarzać ten raport po KAŻDEJ zmianie core/crypto (checklista pliku, TODO)

---
*Wygenerowano automatycznie przez tools/self_attack.py — nie edytować ręcznie.*
