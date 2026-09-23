# Fenix / AnonNet — Rejestr Decyzji Architektonicznych
Data aktualizacji: 2026-08-06

## Filary (nie do ruszenia)
1. Identyfikacja: Wallet Address + Username + UID + Ranga. Zero IP/MAC/fingerprintów w logice sieci.
2. Krypto produkcyjna: tylko sprawdzone algorytmy (X25519, Ed25519, AES-256-GCM, HKDF, ChaCha20).
3. Zasada Kerckhoffsa: bezpieczeństwo NIGDY nie opiera się na tajności kodu.
4. Dane wrażliwe, które nie istnieją, nie mogą wyciec (minimalizacja > zabezpieczanie).

## Podjęte decyzje

### D1. Kryptografia (Faza 1) — ZATWIERDZONE
- E2E hybrydowe: X25519 (ephemeral → forward secrecy) → HKDF → AES-256-GCM, podpis Ed25519.
- Wallet liczony z OBOU kluczy publicznych (blake2s → base32, prefix FNX1).
- Shamir k-z-n (mod p = 2^256−189) jako fundament konsensusów progowych.
- Plik: `crypto/fenix_crypto.py` (przetestowany).

### D2. Własny szyfr — TYLKO WARSTWA DODATKOWA
- Bez publicznej kryptoanalizy własny algorytm nie może być jedyną obroną.
- Edukacyjny Feistel: `crypto/fenix_cipher_demo.py`. Może szyfrować PO AES-256 (defense in depth).

### D3. Self-destruct i logowanie — TAK, z hasłem paniki
- 3× błędne hasło → opóźnienie ×2 (nie destrukcja — inaczej wróg niszczy nam dane przez 3 próby).
- OSOBNE hasło paniki → cichy crypto-shred (spalenie kluczy, nadpisanie, wymazanie RAM).
- Zawsze istnieje zaszyfrowany backup/seed odzysku (offline).

### D4. AI-Sentry (Faza 6/7) — TAK, jako radar (nie grabarz)
- 4 warstwy: twarde reguły → statystyka → lokalny ML → federacja (wagi, nie dane).
- Reakcje schodkowe: throttle → ban peera → rotacja trasy → lockdown.
- AI NIGDY samo nie odpala self-destruct (atakujący wymusiłby autodestrukcję).
- Obrona modelu: federated learning + agregacja bizantyjsko-odporna (mediana, reputacja).

### D5. Telemetria zbiorcza — "KAPSUŁY SESYJNE" (kompromis po burzy mózgów) — ZATWIERDZONE
- Surowe logi NIGDY nie opuszczają node'a i NIGDY nie trafiają na dysk.
- Kapsuła sesyjna: bufor RAM zdarzeń BEZPIECZEŃSTWA (nie treści wiadomości!),
  szyfrowana jednorazowym kluczem sesji; wylogowanie = SPALENIE klucza
  → kapsuła martwa nawet gdy ktoś skopiował szyfrogram (crypto-shredding).
- Do sieci lecą tylko karty zdarzeń <100 B: {typ, siła 0–10, sygnatura wzorca} —
  bez dokładnych czasów/rozmiarów, losowe okno 20–40 min (anti corelacja czasowa), transport mixnetem.
- Werdykt o złośliwym node: konsensus k-z-n niezależnych zgłoszeń, podpis progowy.
  AI ocenia ZACHOWANIE NODE'A, nie człowieka.
- Eskalacja (rzadka): odszyfrowanie kapsuły przez konsensus k-z-n, analiza w RAM,
  każda taka operacja = podpisane zdarzenie audytowe.
- Użytkownik ma suwak telemetrii: off / minimal / full.

### D6. Spoofing MAC/IP (Faza 2) — TAK, ale uczciwie
- Chroni przed LAN/trackerami lokalnymi. NIE ukrywa przed ISP — to załatwia Faza 4 (mixnet/onion).

### D7. Blockchain FNX (Faza 5) — kierunek
- PoW CPU-friendly (RandomX-like), trudność adaptacyjna; decyzja ostateczna w Fazie 5.
- Dane blockchainu/finne pod skarbcem progowym (D1).

### D8. Fenix OS ISO (Faza 3) — strategia MVP
- Od podstaw C/ASM: `boot/boot.asm` = artefakt edukacyjny (działa: tryb chroniony, keystore).
- Wersja produkcyjna ISO: REMASTER live-build (Debian) z autostartem Fenixa,
  skryptami spoof + self-destruct + amnezja RAM. Powód: 90% wartości za 5% pracy.

### D9. Brak recovery w protokole — "Zero tylnych drzwi, nawet dla nas" (decyzja właściciela)
- Protokół nie zna odzyskiwania: zgubione hasło = tożsamość nieodwracalnie martwa.
- Cel: ochrona administracji i użytkowników przed przymusem — nie ma czego wydać.
- Furka WYŁĄCZNIE user-side (off, UI ostrzega): użytkownik sam może wyeksportować
  udziały Shamira swojego klucza do zaufanych — sieć o tym nie wie.

### D10. Kamuflaż transportowy anty-DPI — pluggable transports
- `transport/camo.py`: Profil A (losowy szum, obfs4-style), Profil B (mimikra
  HTTPS/WebRTC), Profil C (decoy routing — research).
- Maskujemy sprawdzony transport własnymi profilami; DPI to wyścig zbrojeń
  (JA3/JA4, rozmiary, timing, active probing) — profile wymagają utrzymania.

### D11. Kod źródłowy — ZASTRZEŻENIE INŻYNIERA (notka odхана)
- Właściciel zdecydował: obfuskacja kodu ISO i aplikacji.
- Zastrzeżenie: obfuskacja ≠ zabezpieczenie (CPU widzi kod jawny w momencie
  wykonania; dump możliwy), blokuje audyt i zaufanie, binarki obfuskowane bywają
  flagowane przez AV (odwrotność stealth). Rekomendacja: core open + hardened;
  ukrywamy DANE i UŻYTKOWNIKÓW, nie kod. Release: bez symboli/debug (higiena).

### D12. Proof-of-Uptime 30 dni = prawo głosu (VOTER) (decyzja właściciela)
- Podpisane zaświadczenia obecności on-chain; heartbeat w LOSOWYCH oknach
  (anti korelacja). 30 dni udowodnionej obecności = status VOTER.
- GUI: pasek postępu + licznik do VOTER (gamifikacja). Ranga rośnie z uptime.

### D13. Protokół suwerenny (decyzja właściciela) + NOTA INŻYNIERA
- Fenix NIE działa na znanych protokołach/Tor; własny protokół z `protocol_spec.md`,
  wersjonowanie ramek od dnia 0, modułowy transport (podmienialny).
- Nota: własny protokół w małej sieci jest ROZPOZNAWALNY przez DPI → warstwa camo
  (D10) staje się WARUNKIEM startu sieci (patrz lista NIGDY w TODO).

### D14. Aktualizacje: tylko podpis ownera + wzmocnienie klucza (decyzja właściciela)
- Kluczem ownera podpisane release; klient weryfikuje przed instalacją.
- Master key OFFLINE: Shamir 2-z-3 na 3 zimnych nośnikach; podklucz "hot" do buildów;
  protokół rewokacji podklucza przez master. Paranoid-mode: aktualizacje ręczne.

### D15. Tokenomia FNX (decyzja właściciela)
- Opłata: 0.001% BURN + 0.055% → skarbiec ownera (zapis w protokole od genesis).
- Podzielność 8 miejsc: 1 FNX = 10^8 iskier. Kopanie: PoW CPU-friendly,
  trudność adaptacyjna (celowo "ciężko"). Blockchain = node'y (kopie=hostujesz):
  górnik + proof-of-storage w jednym. Skarbiec: adres ownera (multisig — backlog).
- OTWARTE: emisja/limit podaży, halvingi.

### D16. Rangi 7-tier (decyzja właściciela, cenik w TODO sekcja RANGI)
- ghost(darmowa)/Donor/VIP/VIP+/SVIP/ELITE/SELITE/FENIX; ceny 0.000001 → 100.1 FNX.
- Perki: bandwidth QoS (tiery), hosting stron (1 → fair-use), kosmetyka (avatar, ramki, motywy, odznaki), storage, beta/RC, vanity wallet, ekskluzywne limity (SELITE 10/rok, FENIX 21 w historii).
- OGRANICZENIA TWARDE: ranga ≠ prawo głosu (tylko PoU 30d), ≠ dostęp do danych,
  ≠ władza nad protokołem, ≠ odkupienie bana. Registry on-chain, upgrade = dopłata.
- Filtr bezpieczeństwa zadań AI niezależny od rangi.

### D17. AI = wyłącznie narzędzie owner/admin (decyzja właściciela)
- System ochrony sieci (AI-Sentry) operowany wyłącznie przez Administrację.
- Użytkownicy NIE mogą się z AI komunikować, sterować nią ani żądać jej działań.
- Werdykty są jawne (kod powodu + wyjaśnienie), ale sterowanie pozostaje zamknięte.

### D18. Polityka banów i unbana (decyzja właściciela)
- Auto-ban = konsensus AI + wpis on-chain: kod powodu + wyjaśnienie PL/EN + hash dowodów.
- UNBAN: jedyna droga = 1 000 000 USD w XMR, jednorazowo; escrow multisig 2-z-3 + timelock.
- Admin: 30 dni decyzji; odmowa/timeout → zwrot 99% (1% anti-spam).
- Unban resetuje reputację/PoU (VOTER od zera); 1 wykup na wallet w historii; re-ban = permanentny.

### D19. Egzekucja sprzętowa — ODRZUCONE: "CPU fuse"
- Pomysł: wbudowane w CPU blokowanie zbanowanych tożsamości. Brak API dla stron
  trzecich; egzekwowanie czegokolwiek na sprzęcie przeciwnika jest fizycznie niewykonalne.
- Zamiast: **tombstone tożsamości on-chain** (wallet martwy, widoczny publicznie).

### D20. Anti-VM — miękki sygnał, nie zakaz
- VM = sygnał ryzyka + asymetria kosztów: PoW-ticket ×N, PoU ×0.5 w VM.
- Bare-metal wymagany TYLKO dla: seed-host, admin, podpisów (D14).
- Qubes/VM to legalni użytkownicy prywatności — nie karzemy za higienę.

### D21. HWID-ban — ODRZUCONE; kara krypto-ekonomiczna
- HWID-ban: spoofowalny, wymagałby fingerprintingu sprzętu (łamie Filar 1), wątpliwy prawnie.
- Zamiast: kara krypto-ekonomiczna — tombstone + identity bond + slash + utrata rangi (D16/D18).

### D22 (2026-07-25). Tryb FAIL-OPEN: maksymalna ochrona przed błędnym banem (decyzja właściciela)
- Bo D9 czyni błąd nieodwracalnym: system minimalizuje FALSE POSITIVES, kosztem false negatives.
  Atakujący zdradzi się wzorcem jutro; niewinny zbanowany dziś nie wróci nigdy.
- Cel projektowy: FPR (błędne werdykty) < 0,1%/rok; w zdrowej sieci < 0,01% użytkowników
  kiedykolwiek zobaczy yellow.
- Zasady twarde:
  * wzorce, NIE zdarzenia — żaden kod nie odpala się od 1 zdarzenia;
  * decay/auto-reset — flagi gasną same; żółte nie kumulują się do czerwieni;
  * **Safe Harbor** — jawna lista niewinnych zachowań (wolny net, restarty Live OS,
    stary klient w grace period, wiele walletów z jednego domu ≠ Sybil, 3×❌ hasło = D3 lokalnie);
  * 🟥 red WYŁĄCZNIE konsensusem k-z-n (k≥3) + hash dowodów + wyjaśnienie PL/EN (D18);
  * symetria kosztów — bezpodstawny wniosek red kosztuje wnioskodawcę bond;
  * okres nowicjusza 7 dni — błędy techniczne = komunikat edukacyjny, zero wpisów;
  * test sygnatury celowości — bug klienta = kanał CLIENT_BUG + wymuszony update, nie kara;
  * auto-kalibracja — FPR powyżej celu → progi kat. A/E same się luzują (fail-open).
- Szczegóły wykonawcze: `docs/ban_policy.md` v1.0 — WIĄZĄCE dla implementacji od M1.

### D23 (2026-07-25). ISO i Secure Boot — instrukcja „wyłącz Secure Boot" (MVP) (decyzja właściciela)
- Zero kosztów/formalności; standard wśród live-OS prywatności (Tails-model).
- Instrukcja instalacji: krok BIOS ze zrzutami dla popularnych UEFI.
- Backlog M9: własny klucz MOK enrollowany; docelowo shim z podpisem Microsoft.

### D24 (2026-07-25). Persistence ISO = minimalny zaszyfrowany kontener (decyzja właściciela)
- Amnezja jak Tails dla WSZYSTKIEGO poza kontenerem: username + kontakty + owinięte klucze.
- Kontener = keystore wg D3: Argon2id(passkey) → KEK → MEK → AEAD; passkey przy każdym boot.
- PANIC = crypto-shred kontenera (nadpisanie + skasowanie pliku) + wipe RAM + poweroff —
  ginie wszystko, co przetrwało reboot. Brak recovery (D9): zgubiony passkey = kontener martwy.
- Jeden kod dla aplikacji i ISO: `core/keystore.py` (M1).

### D25 (2026-07-25). Tryby wdrożenia: Fenix App standalone = oficjalna ścieżka obok ISO (decyzja właściciela)
- Live ISO NIE jest wymagany: Fenix działa jako zwykła aplikacja (Python portable;
  docelowo PyInstaller: .exe / .AppImage) na Windows/Linux/macOS.
- Protokół i krypto IDENTYCZNE — sieć nie rozróżnia trybu w warstwie treści.
- 3 poziomy ochrony: App (dostępność) → App w VM (izolacja) → Fenix OS Live ISO (paranoia).
- W trybie App ZOSTAJE: E2E, wallet/tożsamość/rangi, blockchain, camo (ochrona przed ISP),
  keystore/kontener D24.
- W trybie App SŁABNIE: amnezja (swap/logi/miniatury OS), spoofing lokalny (zwłaszcza
  Windows), panika nie cofa tego, co OS zrzucił na dysk; wrogły OS może czytać RAM procesu.
- GUI MUSI pokazywać poziom ochrony i uczciwe ostrzeżenie („apka = dobre, ISO = zbroja").

### D26 (2026-08-03). Ramka sieciowa MUSI szyfrować payload (fix po złapanym przecieku; reguła procesu)- Wykryte przez selftest mesh: pierwsza iteracja `net/frame.py` liczyła AEAD „na pusto"
  (czysty MAC nad ramką) i payload leciał JAWNIE — test drutu złapał b\"amount\" na wiresie.
  Dokładnie po to był test prywatności: czujnik dymu zadziałał zanim ktokolwiek ugotował obiad.
- Fix: VER=2, CT = AEAD(PAYLOAD+PAD, AAD=nagłówek) — pełne szyfrowanie + integralność jednym
  prymitywem; handshake tylko-efemeryczny (na drucie czyste 32B szumu), profile sygnowane
  lecą POD kluczem (spec §4 doprecyzowany w v0.2 protocol_spec).
- **Reguła procesu:** każda warstwa sieciowa dostaje selftest drutu (tap bajtów + asercja
  „zero markerów treści"). Test, który złapał bug, zostaje w repo na zawsze (regresja).

### D27 (2026-08-04). PANIC = sekwencja klawiszowa Del+PageUp przez 2 s (decyzja właściciela)
- Wyzwalacz: **DEL + PAGEUP trzymane RAZEM ≥ 2 sekundy** (klawiatura działa na laptopie
  i w ISO; USB kill switch zostaje jako opcja dodatkowa, nie jedyna droga).
- Skutek: „usuwa wszystko" = crypto-shred kontenera D24 (2×nadpis+fsync+remove) +
  wipe poświadczeń RAM (mlock zeroize) + drop_caches + natychmiastowy poweroff.
  System live i tak żyje w tmpfs — po odcięciu prądu RAM jest martwy.
- Realizacja: `os/fenix_panicd.py` (evdev /dev/input, root, systemd) + wielki czerwony
  przycisk w GUI (M7) woła TEN SAM kod paniki (jedna ścieżka = jedno miejsce do testów).
- To działanie jest NIEODWRACALNE (D9). Sekwencja 2-klawiszowa 2 s to próg celowości —
  przypadkowe trafienie jednego klawisza nic nie robi.

### D28 (2026-08-04). Addressowanie = USERNAME; wallet/UID pod spodem (decyzja właściciela)
- Użytkownika znajduje się w sieci po **username** (nie po wallet address).
- Rejestr username: **on-chain** (tx `USERNAME_CLAIM`/`USERNAME_RENAME`, first-come-first-serve,
  zmiana MUSI być podpisana kluczem właściciela — profiling przechodzi, tożsamość kotwiczy KLUCZ).
- W GUI: **username wyświetlany BEZ UID**; UID/wallet = rzeczy techniczne pod spodem.
- Profil edytowalny: username (zajętość z rejestru on-chain) + **avatar** (mały, podpisany;
  w sieci leci hash + dane w profilu E2E), badge rangi.
- **Zastrzeżenie inżynierskie:** ranga NIE MOŻE być samo-edytowalna — gdyby była,
  każdy ustawiłby sobie FENIX i ranga przestałaby cokolwiek znaczyć (jak oceny wystawiane
  sobie samemu). Ranga = wyliczana z on-chain (PoU/kopanie/rejestr) — GUI ją POKAZUJE ładnie,
  nie edytuje. Edycja rang = wyłącznie przez konsensus protokołu.
- Anty-impersonacja: kontakt zapamiętuje pierwszy username danej tożsamości (TOFU);
  zmiana username u kogoś z listy = wyraźne ostrzeżenie w GUI.

### D29 (2026-08-04). Poziom paranoii w GUI + własny snowflake_fnx (decyzja właściciela)
- Ustawienia → suwak poziomu paranoii: A (szum obfs4-style) → B (mimikra HTTPS/WebRTC) →
  **SNOWFLAKE_FNX** — własny, nie zależny od Tora: wolontariusze-proxies, kanał WebRTC
  (DTLS-SRTP), brokery sygnalizacyjne on-chain + AMP-cache; cały strumień rekordów Fenixa
  płynie JAKO zwykła rozmowa wideo. Szybciej niż Snowflake (brak warstwy Tora — nasza
  warstwa anonimizacji jest protokołowa: cebula M2 + brak metadanych), trudniejszy do
  blokady niż statyczne bridge'e.
- Implementacja etapami (M3 profil B → M6 snowflake_fnx); GUI ZAWSZE pokazuje aktualny
  poziom i jego granice (uczciwość z D25).

### D30 (2026-08-04). Unban = 1 000 000 USD w FNX (aktualizacja D18: było XMR)
- Wykup = jednorazowo **1 000 000 USD liczone w FNX**, nie w Monero (ToS §8 zaktualizowane).
- **Problem inżynierski:** skąd kurs FNX/USD, skoro rynku jeszcze nie ma? Rozwiązanie MVP:
  **owner-oracle** — podpisany (D14) dokument kursowy z timelockiem, publikowany on-chain;
  przy starcie rynku escrow/idź na kurs z giełdy whitelistej (backlog M5+).
- Reszta procedury bez zmian: escrow 2-z-3, 30 dni decyzji adminów, odmowa → zwrot 99%,
  PoU/VOTER od zera, 1 wykup w historii, re-ban = permanentny.

### D31 (2026-08-04). FNX prywatny jak Monero — ROADMAP ETAPAMI (decyzja właściciela + zastrzeżenie)- Cel: blockchain FNX na zasadach prywatności Monero — własna, wewnętrzna, szyfrowana krypto.
- **Szczerze:** pełny RingCT + bulletproofs to w czystym Pythonie bardzo ciężki kawał
  kryptografii (udowodnienie bezpieczeństwa, wydajność weryfikacji na słabych CPU).
  Robimy to **etapami**, każdy z testami, zamiast jednego wielkiego skok w ciemność:
  1. **Stealth addresses** — odbiorca niewidoczny na-chain (jednorazowy klucz z DH nadawcy;
     blockchain nie wiąże tx z walletem) — pierwszy kamień, wraca PRYWATNOŚĆ ODBIORCY.
  2. **Ring signatures** — nadawca schowany w pierścieniu N wabików (niełączeniowość
     nadawca↔tx) — znany, udowodniony schemat (MLSAG/CLSAG-style na Ed25519).
  3. **Confidential amounts** — kwoty ukryte (zobowiązania Pedersena + prosty rangeproof;
     bulletproofs = backlog research).
- Transparentny tryb (obecny MVP) ZOSTAJE jako tryb dev/test; produkcja = prywatna domyślnie.
- Kamień milowy: `M5b — CHAIN PRIVACY (Monero-style)` w TODO.md.

### D32 (2026-08-04). Własna giełda FNX + monetyzacja + wpłaty PSC (decyzja właściciela + zastrzeżenia)
- **Giełda FNX**: wewnętrzny rynek FNX⇄gotówka/krypto — w aplikacji, notowania wpisane
  on-chain (orderbook na promarket-węzłach; każdy node może też prowadzić wymianę atomową).
- **Wpłata PSC (Paysafecard)**: voucher 16-cyfrowy z kiosku = częściowo-anonimowa gotówka
  → spełnia cel „bez banku/UI"; PSC realizowane PRZEZ MERCHANT ACCOUNT operatora
  (Paysafe API, MID) — po stronie operatora obowiązuje KYC/AML raportowanie (poza kodem).
- **Kurs FNX**: dzień 1 z D30 owner-oracle (podpisany, timelock) — giełda daje kurs rynkowy
  po starcie orderbooku; PSC ma opłatę realną 5% (koszt operatora), wpisana w ToS.
- **HIGIENA DANYCH (twarde):** 16-cyfrowy PIN PSC = gotówka — NIGDY w logach i plikach;
  po autoryzacji pamiętamy wyłącznie hash sha256(kod + dane rekomendowane przez Paysafe)
  jako proof-of-redemption; limit dzienny wymiany per wallet (anty-laundering pod progiem,
  właściciel definiuje w ToS); 1 voucher = 1 wykorzystanie (weryfikacja statusu merchant API).
- **ZASTRZEŻENIE PRAWNE (szczerze):** obrót krypto⇄fiat i przyjmowanie PSC to usługa
  finansowa = operator giełdy musi mieć rejestrację VASP/anti-laundering/gromadzenie danych
  do zeznań. KOD dostarcza warstwę techniczną; wymogi prawne = zadanie właściciela
  poza repo (od notowania kursu po deklaracje podatkowe). Giełda NIE jest non-custodial
  dla wpłat PSC (cash-in), ale portfele użytkowników ZOSTAJĄ u nich (wypłaty on-chain).
- Monetyzacja projektu: fee wymiany (np. 1% do skarbca operatora — jako osobne od D15 fee
  transakcyjne 0.001%/0.055%) + ranga market-maker (wymaga bond-u, zabezpiecza płynność).

### D33 (2026-08-04). Kamuflaż przez DNS (Profil D): Mullvad jako czysty pierwszy hop (decyzja właściciela)
- Nowy profil: **dns-camo** — kanał rezerwowy/bootstrap, gdy ISP blokuje protokół Fenixa.
  Ruch Fenixa po koderze w pakietach DNS (base32 w qname → bridge; TXT w odpowiedzi → klient),
  wysyłanych do publicznego resolvera **Mullvad** (194.242.2.2; DoT/DoH dns.mullvad.net) —
  ISP widzi zwykłe, legitne zapytania do znanego dostawcy prywatności (pojedyncza domena,
  losowe poddomeny — normalny obrazency DNS).
- **Wymagany własny bridge**: serwer autorytatywny dla domeny-mostu hostowany przez
  wolontariuszy/seed-y (domain+glue records poza repo; zadanie właściciela). Mullvad NIE
  tuneluje sam w sobie — to tylko pierwszy przeskok „czystego ruchu".
- **Uczciwe limity (nie obiecujemy gruszek na wierzbie):** przepustowość ~KB/s z latencją
  sekund → NADAJE SIĘ na: bootstrap, listę seedów, handoff ładunku, SOS; NIE na główny
  gossip/bloki (zostają na Profilu A/B/snowflake_fnx). Każde zapytanie z losowym nonce
  (cache public resolvery NIE zjadłby unikalności); EDNS0; rozmiar etykiety <64.
- Rate-limit: tunelowanie w dużej skali uruchomi ograniczenia u każdego resolvera — traktujemy
  Mullvada fair (małe ilości, retry z backoff, przemieszczanie między DoT/DoH/UDP).

### D34 (2026-08-04). Swap XMR → „świeży" FNX (wash-desk) (decyzja właściciela + zastrzeżenie)
- Przepływ: depozyt **XMR na jednorazowy subadres** → desk po potwierdzeniu wysyła FNX
  na wskazany wallet (docelowo stealth output z M5b) → użytkownik ma FNX bez historii
  łańcuchowej powiązanej z wejściem XMR (Monero z natury nie ujawnia źródła).
- **ZASADA ZEROWEGO LINKU (twarda):** rejestr depozyt↔wallet trzymany WYŁĄCZNIE w RAM,
  z TTL-shred 24 h po wypłacie (D9: kopia zapasowa linków NIE ISTNIEJE → nie da się jej
  wyciągnąć ani forenzycznie, ani na żądanie). Desk bez tej zasady byłby honeypotem.
- Anty-korelacja: losowe opóźnienie wypłaty 30–120 min (zegar wstrzykiwany), wspólne
  okna dzienne, fee 3% (prąd XMR + zmienność kursu; osobne od D32/PSC 5+1).
- **Zastrzeżenie szczere:** do czasu TTL-shred desk TECHNICZNIE widzi link (pełnego
  trustless atomic-swap XMR⇄FNX nie ma — XMR nie ma skryptów HTLC dla FNX). Roadmap:
  multi-desk (rotacja operatorów: minimalizacja tego, kto widzi) → w tle badanie adaptorów.
- Zasilanie oracle (D30) rozszerzone o XMR: usd_cents_per_fnx + usd_cents_per_xmr w jednym
  podpisanym dokumencie kursowym.

## D35 — Komunikator: kontakt = FNXS1, fp jest tożsamością, transport off-chain
- Kontakt komunikatora = adres **FNXS1** (sig_pub‖x_pub + checksum) — TEN SAM pakiet
  kluczy i TEN SAM codec co adres prywatny portfela (jedna implementacja w core/identity).
- Username jest WYŚWIETLONYM przydomkiem, NIE dowodem tożsamości: tożsamość =
  fingerprint TOFU (blake2s 8B, format 4-4-4-4, porównanie drugim kanałem przy 1. kontakcie)
  + podpis ed25519 pod każdą wersją wiadomości. (Eve z tym samym username = osobny kontakt.)
- E2E: efemeryczny X25519 per wiadomość → HKDF(„FNXM1"/„msg") → ChaCha20-Poly1305
  (AAD = to_fp‖from_addr); seq ściśle rosnący (anty-replay); koperta ≤16 KiB, tekst ≤4 KiB.
- Transport: off-chain epidemiczny **T_MSG** (jak T_TX_SUBMIT, bez mempoola i bez zapisu
  na chain — prywatność: nic nie zostaje w ledgerze). Na razie LocalTransport (rdzeń
  E2E gotowy i testowany), mesh-reléj T_MSG = kamień M2/M4.
- TofuStore: plik 0600 + atomowy rename + shred 2× nadpis (D9); opcja RAM-only (amnezja ISO).
- Zastrzeżenie szczere: brak double-ratchet/PFS (roadmap M4b), brak kolejkowania offline.

## D36 — Etap 3b: rdzeń ukrytych kwot (CLSAG) osobno od konsensusu
- Najpierw krypto-rdzeń `chain/clsag.py`, potem zmiana konsensusu (v=2) — NIGDY odwrotnie
  (zasada: nie wrzucamy nieprzetestowanej kryptografii do ledgera).
- MLSAG po dwóch kolumnach [(P_j),(D_j)] z D_j = C_j − (ΣC_out + fee·H): kolumna 1 = własność
  (priv_ot, key-image), kolumna 2 = bilans (Σin = Σout + fee bez ujawniania kwot).
  Konwencja c0/j = DOKŁADNIE ta z chain/ring_sig.py (jedna szkoła wyzwań w projekcie).
- Zobowiązania Pedersena + range proof Borromean 64-bit = chain/amount_hide.py (bez zmian).
- Blob kwotowy {a‖r}: AEAD ChaCha20-Poly1305, klucz HKDF(„FNXC1"/„amt") ze shared DH
  (ta sama para ep/x co stealth), AAD = C (blob sfałszowany ≠ C = odrzut już w skanie).
- Fee zostaje jawne (jak w Monero); ring/komplet decoys bez nominalizacji (kwoty ukryte
  → wabiki mogą mieć dowolne kwoty — pulary są większe niż w 3a).
- Konsensus v=2 (retencja C w poolu, rejestr ki, migracja istniejących outputów 3a) =
  następny kamień po 3b-rdzeniu.

## D37 — Transport messengera: mesh T_MSG w node (koperta E2E jak tx, ale bez zapisu)
- Nowy typ ramki **T_MSG 0x22** (`net/frame.py`): gossip wrappera `{v:1, ttl, env}` —
  koperta messengera (env z app/messenger) reléjowana jak T_TX_SUBMIT, ale **NIGDY**
  nie wpada do mempoola ani łańcucha (prywatność: zero śladu treści on-chain).
- **ttl=5** tłumi powódź gossip (jak hop-count); **dedup** = blake2s(canon(env)) 16 B
  (liczony z koperty, nie z ttl — ta sama przesyłka na innym ho pie to nadal ona);
  worki anty-echa czyszczone jak GOSSIP_SEEN_CAP.
- Node trzyma **skrzynkę TYLKO lokalnych subskrybentów** (watch: max 64 fp, kopert
  max 200/fp, deque) i TYLKO w RAM (amnezja ISO; drain przez IPC kasuje w demonie).
- Relay pośredni NICZEGO nie przechowuje (test 6 w fenix_node: środkowy node pusty).
- Duże koperty (>4063 B) lecą plasterkami **T_SYNC_PART** (istniejący chunking;
  sklejony T_MSG wraca do tego samego handlera). Sufit formatu: 16 384 B JSON env.
- Most GUI↔demon: opy IPC **msg_sub / msg_send / msg_poll** w gui/backend_ipc +
  klasa **MsgIpcTransport** (duck-type jak LocalTransport). FenixController.messenger()
  wybiera mesh, gdy demon ON-LINE; OFF-LINE → LocalTransport (etykieta w GUI uczciwa).
- Node NIE czyta kopert (tylko lekka walidacja kształtu: v, to_fp 16hex, pola str) —
  pełna walidacja E2E (AEAD+podpis+TOFU) wyłącznie u adresata.
- Pozostało (M4b/M5): ratchet PFS, kolejka offline dla nieobecnych, username→FNXS1 (P21).

## D38 — Konsensus v2 (3b): ledger przestaje znać kwoty
- Nowy moduł **`chain/tx_hidden.py`**: SHIELD v2 (payload `{v:2, mint:[…]}`) + wpięcie
  RING v2 (`chain/clsag.verify_hidden_tx`) do `add_tx` i `_validate_economics`.
- **Bramka (SHIELD v2) jak w Zcash (t→z):** kwota wejścia publiczna; nadawca publikuje
  `amt` + `r_pub` i każdy weryfikuje tanio `C == commit(amt, r_pub)`; **suma mintów ==
  tx.amount** (zamyka drukarnię na wejściu). Pool zapisuje TYLKO `{ep, C, blob, v:2}`
  — kwota znika za bramką (ledger nie trzyma `amt` dla v2, test 2 w tx_hidden).
- **Wnętrze (RING v2):** pełna mgła — MLSAG + Borromean RP + rejestr key-images
  (WSPÓLNY z v1, dedup mempoolowa też v2). Ring v2 bierze członków wyłącznie po C
  (lookup zwraca None dla wpisów v1 → odrzut „member spoza poola", test 8).
- **MIGRACJA 3a:** wpisy v1 (`{ep, amt}`) działają dalej przez v1-ściężkę (testowany
  spend ringiem 5×v1). v1-hardening: SHIELD v1 z >1 wyjściem odrzucany (złapana
  inflacja: każdemu wyjściu kredytowano pełne tx.amount).
- Wyjścia v2 konsensusu to MINIMUM `{sp, ep, C, blob, v:2}` (rp nie jest przechowywane
  po weryfikacji). IPC op pool zwraca marker `v` + C/blob dla v2 (scan GUI = M7d).
- Pozostało: UNSHIELD v2 (wyjście z mgły → konto), GUI pool v2, bulletproofs.

## D39 (2026-08-06). Fee 0.055% płynie do KOPACZA bloku (coinbase), nie do skarbca
- **Decyzja:** część „owner" każdego fee (`fee_split(amount)[1]`, 550 ppm) dostaje
  **kopacz bloku** w coinbase: `BLOCK_REWARD + Σ fee-owner z tx bloku`. Burn część
  (5 ppm) nadal nikomu. Do **skarbca** trafia już TYLKO fee z TX_ID_DECLARE
  (claim/rename username — usługa rejestru, nie przelew).
- **Dlaczego:** kopacz potwierdza transakcje innych — musi mieć z tego zarobek,
  inaczej nikt nie ma motywacji pakować cudzych tx do bloku (jak w Bitcoin: reward
  + fee). To zamyka pętlę „miner potwierdza transakcje → dostaje fee".
- **Implementacja:** `chain/ledger._miner_fees_of(txs)` — TRANSFER/SHIELD: split;
  RING v1: parse_payload; RING v2: `tx_hidden.parse_ring2` (fee jawne); UNSHIELD:
  `parse_unshield2`. `_validate_economics` pilnuje coinbase == BR + fees.
  `block_template` składa coinbase z tą sumą.
- **Fallout testowy (szczerze):** 2 stare suity (tx_ring, usernames) liczyły salda
  bez zwrotu fee do kopacza — złapane, aserty poprawione o „zwrot" kopaczowi.
- **UNSHIELD v2 (0x12)** wszedł razem z D39: wyjście z mgły na konto z jawną kwotą
  Y (public `Y·H`, jak z→t w Zcash). Konsensus: `Σ pseudoOut == ΣC_out + (Y+fee)·H`,
  key-image zamykane jak w ringu; reszta wraca do mgły wyjściem v2. Pętla wartości
  konto ↔ mgła zamknięta (testy 10-11 w tx_hidden, 9d w pool_panel).

## D40 (2026-08-06). Walizka TF1 — kontakty czatu szyfrowane hasłem właściciela
- **Problem:** TofuStore na dysku to jawny JSON z adresami/nazwami/seq kontaktów.
  Złodziej z laptopem czyta z kim rozmawiasz (metadane społeczne!).
- **Decyzja:** kontener **TF1** (jak KS1 na keystore, ten sam wzorzec):
  `b"TF1" + ver(1) + m(4 LE) + t(1) + p(1) + salt(16) + nonce(12) +
  ChaCha20-Poly1305(json, KEK=Argon2id(hasło, salt, m/t/p), AAD=b"TF1/tofu")`.
- **Zasady:** plik TF1 bez hasła → odmowa otwarcia; złe hasło → `InvalidTag` →
  polski błąd; po odblokowaniu `save()` ZOSTAJE szyfrowane (passkey w RAM);
  `unprotect()` = świadomy powrót do jawa; legacy plaintext dalej się czyta
  (dev/stare pliki); 0600 + shred 2× nadpis bez zmian; min. 6 znaków hasła.
- **GUI:** `msg_tofu_protect/unlock/status` na FenixController (test 19 w fenix_gui).

## D41 (2026-08-06). pseudoOut per wejście — naprawa MLSAG dla WIELU wejść
- **Bug (złapany testem M7d, 3-wejściowy hidden send):** konstrukcja „jedno z =
  r_in − Σr_out, D = C_in − COM" zamykała się bilansowo TYLKO dla jednego wejścia.
  Dla N wejść każde `D_i[idx_i]` wymagałoby `a_i == Σout + fee` — fałsz.
- **Fix (jak w Monero):** każde wejście publikuje **pseudoOut** `hC_i =
  commit(a_i, r_p_i)` z losowymi maskami `r_p`, ostatni domknięty tak, by
  `Σr_p == Σr_out` (unshield: `Σr_p == Σr_out`, a Y/fee jawnie w H). Podpis per
  wejście: `z_i = r_in_i − r_p_i`, kolumna `D_j = C_j − pseudo_i`. Konsensus:
  `Σ pseudo == ΣC_out + fee·H` (unshield: `+ (Y+fee)·H`).
- **Konsekwencja formatu:** build wymaga `"amt"` w spendach (portfel i tak zna
  kwoty); build dodatkowo sprawdza bilans JAWNIE liczbami (fail-fast przed
  podpisem) — test „zawyżone Y" to potwierdził po zmianie (pierwotny sanity
  na punktach stracił moc przy pseudoOut).

## D42 (2026-08-06). chain.dat — persystencja łańcucha z REPLAYEM konsensusu (P6)
- **Decyzja:** węzeł zrzuca CAŁY łańcuch do `chain.dat`: `b"FCD1" + blake2s(canon) +
  kanoniczny JSON {"v":1, "blocks":[…]}`; zapis atomowy (tmp+fsync+replace, 0600).
- **Zaufanie ZERO:** przy wczytaniu plik traktowany jak OBCY łańcuch z sieci —
  magia+digest pilnują bajtów, genesis musi być nasz, a KAŻDY blok przechodzi
  `apply_block` od zera (PoW, linki, ekonomia D39, ki, rp). Podmiana salda w pliku
  = błąd konsensusu, nigdy „fałszywy start". Test 8: złodziej „naprawia" digest po
  podmianie bloku → odpada na EKONOMII.
- **Skutek:** restart noda = minuty zamiast pełnego resyncu z sieci.

## D43 (2026-08-06). FNX-R1 — ratchet PFS dla komunikatora (M4b, P22)
- **Problem:** v1 (eph-DH per wiadomość) — skradziony długi klucz x odszyfrowuje
  WSZYSTKIE nagrane rozmowy wstecz. Brak PFS.
- **Konstrukcja (mini double-ratchet, szkoła Signal):** per kontakt root + łańcuchy
  ck_s/ck_r; mk = HMAC(ck,"mk") zużywany RAZ i wymazywany; ck tylko naprzód
  (HMAC(ck,"ck")). Zmiana kierunku rozmowy = nowa para X25519 (kick):
  `root' = HMAC(root, DH(nowy, ich_pub))`. Koperta v2: `{v,rk_pub,seq,n,ct}` —
  nadawca UKRYTY (brak from/eph na jawie; relay widzi mniej niż w v1).
- **Anty-replay:** dedup robi ŁAŃCUCH (zużyty mk), więc zamieszanie mesh jest
  legalne (skip-okno ≤32 + prev 1 runda wstecz); inner.seq = high-water dla UI.
- **PFS testowany ZŁODZIEJEM:** złodziej z długim kluczem + pełnym drutem odczytuje
  co najwyżej ramki sprzed pierwszego kicka (uczciwie pokazane w teście 9c);
  po wymianie tam↔z_powrotem — nic. Po drodze 3 prawdziwe bugi złapane testami:
  kick-trial brał x_priv zamiast ratchet-priv (DH się nie zgadzał), surowy anty-
  replay zabijał legalne zamieszanie, świeży proces nie rozpoznawał aktualnej
  rundy pub (mapa _rk_by_pub jest RAM-only → próba kontynuacji per kontakt).
- **Stan ratchetu:** RAM (amnezja) albo pod walizką TF1 — NIGDY w jawnym tofu
  (polityka pilniowana testem 9d). Desync po utracie ramki = resync przy kicku;
  pełny concurrent-sessions Signal = poza MVP (uczciwie).

## D44 (2026-08-06). Offline-buffer: spool RAM+TTL na relayu T_MSG
- **Problem:** koperta dla nieobecnego odbiorcy ginęła (skrzynka istnieje tylko
  dla lokalnie zapisanych fp).
- **Decyzja:** relay trzyma kopertę do nieznanego fp w ulotnym spoolu:
  RAM, TTL 1 h, ≤256 fp × ≤16 kopert (deque, anty-DoS), purge limityczny.
  Gdy odbiorca się zgłosi (msg_sub z IPC/GUI), spool przechodzi do skrzynki.
- **Prywatność:** relay widzi wciąż TYLKO szum + fp + czas śmierci — zero treści,
  zero zapisu na dysk/chain (amnezja ISO bez zmian). _env_ok przyjmuje v1 i v2.
- **Test 6b:** wtrysk → spool na n1/n2; powrót odbiorcy = zaległa poczta; zdychłęta
  kasowane; plaintext nie istnieje nawet w spoolu.

## D45 (2026-08-06). TX_CONTACT_REF 0x13 — pętla nick → wallet → kontakt FNXS1 on-chain (P21)
- **Problem:** czat wymagał wklejania adresu FNXS1 z karteczki; username (D28) wskazywał
  tylko wallet, a nie klucze X25519 do szyfru.
- **Decyzja:** `chain/contact_ref.py` — wallet publikuje swoją „tabliczkę" (adres FNXS1)
  podpisanym tx; rejestr `contact_refs {wallet: addr}`; op `set` (nadpis jawny) i `del`
  (zdjęcie). Rozwiązanie: nick → `usernames` → wallet → ref → E2E (GUI: pole „Do" w czacie
  bierze ADRES albo NICK, `msg_send_to` rozpoznaje auto).
- **Prywatność uczciwie:** publikacja jest jawna — kto chce prywatnego kontaktu, nie
  wiesza tabliczki (drugi kanał działa jak dawniej). Fee → skarbiec (usługa rejestru,
  jak ID_DECLARE, D39-spójne).
- **Testy 1-7:** nie-FNXS1/ponadwymiar/del-z-adresem odrzuty; podstawiony wallet
  (fałszywy sig) odrzut; nadpis+del; skarbiec tylko z usług; replay bit-w-bit. Złapane
  po drodze: FNXS1 ma ~141 zn. (sufit 128 pękał — ADDR_MAX=160) i funding testu
  (transfer mniejszy niż dotacja — uczony przez błąd „brak środków").

## D46 (2026-08-06). TX_RANK_UP — ranga pochodzi z konsensusu, nie z edycji profilu
- **Zasada (D28):** user edytuje username+avatar, ale NIGDY rangi („śćiernij fotoszopa").
  Dotąd ranga żyła tylko lokalnie; teraz: `chain/ranks.py` — wallet płaci TX_RANK_UP,
  zapis `{rank, height}`, **aktywna po 6 potwierdzeniach** (blok zakupu + 5 na szczycie,
  spójne z pending x/6).
- **Reguły:** BUYABLE = donor/vip/vip+/svip/elite (ceny ⚠️ ROBOCZE do decyzji przy §12/P5);
  **selite/fenix = systemowe — TX ich NIGDY nie nada** (strażnik w konsensusie, nie
  tylko w GUI); ghost darmowy; **upgrade = dopłata różnicy** (remis/downgrade/zaniżona
  dopłata = odrzut, nawet z mempool-overlajem); fee → skarbiec jak usługa rejestru.
- **GUI:** `profile()` pokazuje `onchain_rank` + `rank_pending`; `buy_rank_tx` waliduje
  cenę z chain/ranks (jedno źródło prawdy z core.identity RANKS).
- **Złapane testem:** „6 potwierdzeń" policzone off-by-one między active a pending —
  ujednolicone na standard „N confs" (blok zakupu + N−1).

## D47 (2026-08-06). TX_BAN_EVT 0x06 — tombstone k-z-n na łańcuchu (D18/D22/D30)
- **Zasada:** żaden człowiek ani automat nie banuje sam (ban_policy §9). Plombę
  stawia **kropka attestorów**: ≥BAN_K=3 podpisów Ed25519 z n=5 (progi dev;
  produkcja = zimne klucze k-z-n zaszute wydaniem — P25/D14). Na-chain wpis
  NIGDY nie zawiera dowodów, tylko **hash paczki** + kod z `ban_codes.txt` +
  uzasadnienie PL/EN ≤280 zn. (czytelny tombstone).
- **Format:** `chain/ban_evt.py` — op=`ban` to wydarzenie systemowe (sender="",
  amount=0, bez podpisu tx; moc = kropka w payload, każdy wpis niesie
  sig‖x pub → wallet bind jak Tx.verify_signature); op=`unban` podpisuje
  ZBANOWANY wallet, kwota = `UNBAN_FEE_ISKRY` (ROBOCZA — D30 każe 1 000 000 USD
  w FNX przez oracle + escrow 2-z-3 + 30 dni; to backlog, uczciwie oznaczone).
- **Egzekucja w konsensusie:** zbanowany wallet nie wysyła ŻADNEJ tx (wyjątek:
  wykup), nie dostaje coinbase (martwy kopacz), mempool czyszczony po plombie;
  wykup = 1 raz na wallet w historii, **re-ban = na zawsze** (D18).
- **Rejestr:** `bans {wallet: {active, height, code, evidence, unban_used}}`;
  replay/adopt/chain.dat odtwarzają bit-w-bit (stan wyprowadza się z bloków,
  więc format chain.dat nietknięty).
- **Złapane testem:** kropka 3+duplikat to LEGALNY kworum 3-różnych (test
  początkowo nazywał ją „duplikat nie liczy 2×" — błąd w TEŚCIE, nie w kodzie;
  prawdziwy przypadek = 2+duplikat); rejestracja kropki w `__main__` nie
  widniała ledgerowi (osobny moduł) — 0/3 podpisów (rejestracja w instancji
  pakietu, komentarz w selfteście); funding testu < wykup (uczone przez
  „brak środków", jak w D45).

## D48 (2026-08-06). AI-Sentry MVP (M6 start): radar fail-open, nigdy grabarz
- **Zasada (D4/D5/D17/D22):** `ai/ai_sentinel.py` patrzy wyłącznie na META
  (tempo, liczniki, wzorce) — karta zdarzenia z polami treści = `SentinelError`
  (zero-treści jest funkcją, nie obietnicą). Dostęp = wyłącznie owner/admin;
  interakcji z użytkownikiem brak (D17). Cel FPR <0,1%/rok: minimalizujemy
  fałszywe alarmy kosztem przeoczeń (ban_policy §0).
- **Detektory MVP (meta lokalne):** 0x11 PROTO_FLOOD (bieg zalewu >32 msg/s —
  najstarsze wypełnione wiaderko okna + strażnik anty-burst ostatnich 10 s),
  0x12 INVALIDTAG_STORM, 0x15 REPLAY_ATTACK (godziny-persist → red),
  0x16 HANDSHAKE_FARM (ORANGE: kanał red celowo wyłączony w MVP).
  Drabina none→watch→yellow(throttle 7 dni)→red(wniosek do kropki);
  **AI NIGDY nie banuje/destruuje** — sufit reakcji = `wniosek-do-kropki-k-z-n`.
- **Fail-open twarde:** Safe Harbor (sync/ping/hello_ok liczone osobno, score=0;
  rozjazd zegara ±5 min tolerowany), wzorce-nie-zdarzenia (bramki PATRZĘ),
  decay (throttle gaśnie po 7 dniach, wpis po 30; peer cichy+czysty znika
  z RAM po dobie — kapsuła sesyjna, `purge()` = spalenie klucza, zero dysku).
- **Zamknięte koło M6 (test 9):** zalew→red→`make_proposal` (core+hash dowodów)
  → kropka 3/5 → TX_BAN_EVT → tombstone — to jest DEMONTAŻ toru D18.
- **Granice (uczciwie):** radar JEDNEGO node'a (konsensus wielu sentineli i
  warstwa ML = P25/M6-skala), mapowanie fp→wallet = operator, node jeszcze nie
  karmi radaru żywym ruchem i nie apply-uje throttle do peerów (P26).
- **Złapane testem:** backdating biegu zalewu (watch schodził minutę za późno),
  burst vs sustained (hot-window 10 s), spacing replay 75 s nigdy nie dobija
  red (test, nie kod: 72/h wymusza drugą godzinę >50).

## D49 (2026-08-06). P26 — Sentinel karmi się żywym ruchem demona i egzekwuje throttle
- **Szwy karmienia (META, nigdy treść):** T_MSG → `msg` per wallet źródłowego
  peer-a (0x11 tempo kopert); kolizje ramek → `_sense_frame_error` mapuje
  FrameError: „AEAD"→`bad_tag` (0x12), „replay/okno SEQ"→`replay` (0x15);
  nieudane HELLO → `hello_fail` pod kluczem `addr:IP` (0x16 — farma jest
  adresem, nie tożsamością); T_SYNC_* → `sync` (Safe Harbor liczony osobno).
  Junk camo NIE jest kartą (normalny resync).
- **Egzekwowanie przez demon (reakcje ban_policy):** YELLOW → kubełek żetonów
  8 ramki/s (burst 16) na ramki PO poprawnym AEAD — połączenie żyje, nadmiar
  cicho ginie; TTL sam gaśnie (decay §7). RED → rozłączenie „u mnie" =
  OBRONA WŁASNA node'a, NIE ban (ban = tylko TX_BAN_EVT D47); demon sam
  przygotowuje szkic (`make_proposal` przy przejściu w red).
- **Mapowanie fp→wallet rozwiązane projektowo:** po handshake `peer.wallet`
  JEST walletem (podpisy HELLO + check_profile) — wniosek red z demona ma
  prawdziwy cel FNX1 bez dodatkowej mapy.
- **Widok (D17):** IPC `sentinel` / `sentinel_peer` / `sentinel_proposals`
  (gniazdo 0660, lokalny podmiot): same liczby/werdykty/szkice z hash
  dowodów; zero treści, zero przycisków sterowania — demon nie banuje.
- **CLI:** `--sentinel off|minimal|full` (suwak telemetrii D48).
- **Złapane testem:** szkice `proposals` puste po RED (make_proposal nie
  odpalał się automatycznie — rura rozerwana); farma 210 hello_fail w ułamku
  sekundy realnej → 1 ewaluacja (radar ocenia max 1/s/peer — oszczędność,
  test musiał rozwlec czas na zegarze fake; kod bez zmian).

## D50 (2026-08-06). TX_DONATE (0x14) — dobrowolny datek do skarbca ownera
- **Decyzja właściciela:** użytkownik donatuje FNX na skarbiec ownera,
  KWOTĘ WYBIERA SAM (≥1 iskry, bez progów). Recipient MUSI być skarbcem
  (datek komuś innemu = zwykły TX_TRANSFER — donate nie udaje transferu,
  bo karmi odznaki DONOR). CAŁY amount + fee ownerskie → skarbiec (kopacz
  nic nie dostaje z donate — „100% dla ownera" to matematyka, nie hasło).
- **Karteczka opcjonalna:** payload `{"v":1,"note":≤140 zn.}` — JAWNA na
  zawsze (GUI i spec ostrzegają: nic prywatnego).
- **Rejestr:** `ledger.donations {wallet: suma iskier}` — deterministyczny
  z replay/adopt bit-w-bit; napędza progi DONOR I/II/III (D52). Kontrola
  bilansu/nonce/podpisu dokładnie jak przy TRANSFER.
- **Prywatność uczciwie:** donate jest jawny (nadawca+kwota). Wersja
  „z mgły" = backlog (skarbiec-pool byłby niewidzialny).

## D51 (2026-08-06). Rangi wygasają po 30 dniach (miesięczna legitymacja)
- **Decyzja właściciela:** ranga kupiona TX_RANK_UP jest ważna 30 dni
  (`until = timestamp bloku + 30·86400`). Po terminie konsensus widzi ghost;
  wpis zostaje (historia), ale `active_rank` go ignoruje.
- **Determinizm:** ważność liczona z timestampów BLOKÓW, nie z zegara —
  replay/adopt liczą identycznie na każdym nodzie (bit-w-bit).
- **RENEW:** kupno TEJ SAMEJ żywej rangi = pełna cena, `until += 30d`,
  stos ważności max 60 dni (bez odkładania lat); renew NIE resetuje 6
  potwierdzeń (ranga nie gaśnie w trakcie przedłużania). Wygasła ranga:
  re-buy za pełną cenę (cena bazowa 0), downgrade po wygaśnięciu legalny.
- **Konsekwencja D52:** odznaka Właściciel Legitymacji gaśnie razem z rangą
  (nic nie udaje wieczności).

## D52 (2026-08-06). Odznaki profilu (badges) + grafiki
- **Przydział wg decyzji właściciela:** kupno rangi (Właściciel Legitymacji),
  czas hostowania noda — Strażnik Czasu I/II/III (100/1000/10000 h),
  stworzenie strony (Architekt, 1×), datki skarbcowi — Dobroczyńca I/II/III
  (≥1/≥100/≥1000 FNX), pierwszy nod sieci (Założyciel), ≥100 wykopanych
  bloków (Górnik), ≥1 podpisana kropka k-z-n (Czuwający), debiut w sieci
  ≤1000 bloku (Ptak Wczesny).
- **Dwie klasy prawdy, oznaczone przy każdej odznace:** `chain` (każdy nod
  liczy identycznie — rangi, donations, coinbase, kropki z TX_BAN_EVT,
  pierwszy tx) i `local` (licznik WŁASNEGO noda: uptime/strona/pierwszeństwo
  z stats.json D54 — GUI oznacza gwiazdką, bo sąsiad tego nie zweryfikuje).
  Odznaka NIE jest wklejanym stickerem: evaluate_badges liczy, nie słucha.
- **Grafiki:** `gui/assets/badges/*.png` (8 plików, 128 px; tiery widoczne
  w GUI gwiazdkami/etykietą, grafika = kategoria). Katalog = jedyne źródło
  prawdy (BADGE_CATALOG, PL+EN+opis+ikona).
- **Prywatność:** evaluate liczy lokalnie nad własnym ledgerem; nic nie
  wychodzi na drut. Panel IPC `profile` pokazuje same odznaki+liczniki.

## D53 (2026-08-06). Konto admina „Deimos"
- **Decyzja właściciela:** jedno konto operatorskie. on-chain `deimos`
  (regex identity: małe litery), display `Deimos`, plik `<data_dir>/admin.ks`
  (Keystore KS1: Argon2id+AEAD, panic osobny — D3). Hasło startowe `Anon123!`
  ⚠️ jawne DEV-DEFAULT w repo jak hasło fabryczne routera — `admin_status`
  melduje je czerwienią do czasu zmiany (`change_admin_password`).
- **Prawa (biała lista, jawna):** `attest_ban_dev` (podpis kropek k-z-n,
  D47 — do czasu zimnej kropki P25), `node_diagnostics`, `peers_view` (D17).
- **Czego admin NIE ma:** przycisku ban (ban_policy: red = kropka 3-z-5,
  nigdy jedna ręka) i dostępu do treści (E2E — node fizycznie nie ma czego
  czytać). Wallet admina stabilny między restartami (sealed w KS1).

## D54 (2026-08-06). Auto-discovery P2P + „pierwszy nod" + licznik profilu
- **Decyzja właściciela:** połączenia naprawiają się same. Demon (main)
  ma `discover=True`; biblioteka (NodeConfig wprost) domyślnie OFF — selftesty
  bez niespodzianek; testy 8-10 włączają jawnie.
- **Adresownia (analogia: notes listonosza):** kandydaci = seeds ∪ cache
  `peers.json` (atomowy zapis 0600) ∪ gossip T_ADDR (0x40 — wymiana przy
  handshake + co 2 min; max 32/ramkę, książka ≤256, walidacja portów).
  Pętla co 2 s dobija do `target_peers` (domyślnie 4) z backoffem per-adres
  (×2 do 300 s) i dedupem (in-flight + żywe dial_addr).
- **Pierwszy nod:** po `discover_grace` (45 s) ciszy node ogłasza
  „jestem PIERWSZYM NODEM" i słucha dalej (zostaje seedem sieci); gdy sieć
  się pojawi — tytuł oddaje. Claim trafia do stats.json (`first_node_ever`
  → odznaka Założyciel, uczciwie: verify=local).
- **stats.json:** `{uptime_hours, site_created, first_node_ever}` — licznik
  odznak „local" (atomowy zapis co 60 s + na stop; uptime kumuluje się
  między sesjami). `mark_site_created()` z IPC `site_created` (aplikacja
  melduje gotową stronę — odznaka Architekt).
- **Złapane testem:** `pack_frame` odrzucał T_ADDR (nieznany typ) i cicho
  zamykał handshake — mesh padał 0-peer; TYPES dopisane, selftest 1-7d+10 PASS.

## Następne kroki
→ patrz `TODO.md` (M0→M9) i `docs/plan_mvp.md`.

## D55 (2026-08-06). Łatanie dziur: ONB Deimosa + attest przy starcie demona + kontrakt seeds (P27 + P0)
- **Kontekst:** runda „zajmij się łataniem dziur". Dwie dziury zamknięte jednym
  zamkiem: P27 (hasło fabryczne Deimosa bez wymuszonej zmiany; attest nie wpięty
  w start demona) oraz P0-no.2 w klasie „demon na ISO nie wstaje"
  (`--seeds /etc/fenix/seeds.list` = ŚCIEŻKA, parser liczył `int('')`).
- **ONB (analogia: naklejka „admin/admin" na spodzie routera):**
  `gui/settings_admin.py` — `needs_onboarding` / `validate_new_credentials`
  (min. 10 znaków, ≠fabryczne, ≠oczywiste, panika ≠hasło i ≠fabryczna) /
  `run_onboarding` (walidacja → dowód aktualnego hasła → zmiana pary KS1 →
  WERYFIKACJA faktów z dysku: fabryczne martwe, nowe otwiera, wallet TEN SAM,
  wizytówka świeża). GUI: meldunek czerwony na Dashboardzie (D53 zapowiadał),
  karta w Ustawieniach, **modal bez „pomiń"** przy pierwszym starcie okna
  (`FenixApp(force_onboarding=True)` — demo/headless bez bramki).
- **Uczciwy dowód (złapane selftestem):** `Keystore.create` zostawia keystore
  OTWARTY i `unlock()` wtedy nie patrzy na hasło — `run_onboarding` domyka
  i otwiera PODANYM hasłem, inaczej „aktualne hasło" byłoby teatrem przy
  pierwszym starcie (gdy admin.ks powstaje w tej samej chwili).
- **Attest = legitymacja w okienku, nie klucz:** demon nie zna hasła admina.
  Publiczna wizytówka `admin_attestor.json` (wallet, 0600, zapis atomowy)
  powstaje przy create/unlock/zmianie hasła (core/admin). `net/fenix_node.main`
  woła `register_admin_attestor_boot(data_dir)`: pierwszy start → `ensure_admin`
  stawia admin.ks (hasło fabryczne — ONB je zmieni; wallet po zmianie TEN SAM)
  i wpisuje wallet do rosteru k-z-n (`ban_evt.register_dev_attestor_wallet`,
  instancja PAKIETU — lekcja v007). Fail-open: błąd attesta NIGDY nie zabija noda
  (spójne z ban_policy: kropka i tak wymaga podpisów k-z-n, wpis w rosterze
  bez klucza prywatnego jest martwy; docelowy roster = zimna kropka wydania, P25).
- **Spoof wizytówki:** lokalny Eve może podmienić plik → demon wpisze obcy wallet
  do dev-rosteru (przejrzyste, bez władzy). Leczenie: każdy login/ONB nadpisuje
  wizytówkę prawdziwym walletem (test w core/admin 6).
- **Kontrakt seeds:** `_parse_seeds` przyjmuje `ip:port,ip:port` ALBO plik
  (`#` = komentarz także inline — złapane testem 11 mesh); zły wpis = GŁOŚNY
  SystemExit z numerem linii (systemd Restart wskaże), nigdy ciche pominięcie.
  Strażnicy: os/build_iso.sh §7a (para service↔parser), tools/full_audit.py 2×add.
- **Keystore.path:** publiczna właściwość read-only (admin wypisuje wizytówkę
  obok admin.ks bez sięgania do prywatnego pola).

## D56 (2026-08-06). P20 zdjęte: żywy test demon↔klient GUI dwoma procesami
- **Decyzja:** każdy most IPC dostaje test z PRAWDZIWEGO argv w OSOBNYM procesie
  (lekcja „dispatch demona": selftesty w jednym procesie nie widzą argv/systemd).
- **Realizacja:** gui/backend_ipc.py selftest 13 — spawn `python3 -m net.fenix_node`
  (tmp data-dir, zbits=2, --ipc tmp.sock) → klient BackendIpc (ten sam co GUI) robi
  rundę opów: status/peers/netinfo/sentinel/msg sub+send+poll (roundtrip przez RAM
  demona)/donate z PRAWDZIWEGO salda (kopanie zbits=2; uczciwa odmowa „brak środków"
  złapana testem, gdy zapomniano doładować)/site_created → SIGINT = czyste zejście
  (rc=0, zero Traceback, log z attestem D55, pliki admin.ks/admin_attestor.json/
  stats.json na dysku). Znika punkt P20 z listy problemów otwartych.

## D57 (2026-08-06). P24: concurrent-init ratchetu (cross-first) — kanon x_pub + kanały cand
- **Dziura (analiza+test 13):** gdy OBYDWIE strony napiszą pierwsze wiadomości „na
  krzyż" (każda swoim root0 z własnej pary efemerycznej), stara ścieżka „nowy
  nadawca" NADPISYWAŁA stan ratchetu drugim root0 — sesje goniły się bez końca
  (permanentny deadlock rozmowy). Ta sama ścieżka pozwalała „nowemu nadawcy" pod
  cudzą tożsamość (np. to samo konto na drugim urządzeniu) zniszczyć grającą sesję.
- **Fix (jak w Signal, lecz MVP):** kanon = root0 strony o MNIEJSZYM x_pub — obie
  strony liczą identycznie, bo oba x_pub siedzą w adresach FNXS1. Inicjator zapisuje
  skrzyżowany łańcuch jako kanał-czytankę `cand` (≤4, FIFO, sam odczyt ck_r/seq_r/
  skip); odpowiedź przepina sesję na kanon. Zbieżność w 1 RTT, rooty identyczne
  (test 13/14 — rola z losowych x_pub, asercje neutralne). Grająca sesja =
  NIETYKALNA: „nowy nadawca" pod znany fp = drop + bad_env (multi-device bez linku;
  link urządzeń = M4c). Utrata ramki z kickiem go nie psuje (kick = świeży łańcuch
  od bieżącego roota); skip ≤32 i prev 1 poziom bez zmian; PFS nietknięty (cand =
  też łańcuchy naprzód, klucze umierają jak wszędzie).
- **Złapane samym testem (szczera kanapka):** P20 donate z demona bez środków =
  uczciwy IpcError — test musiał doczekać kopanie zbits=2 (produkcja czysta).

## D58 (2026-08-07). P25 fundament: PoU on-chain (TX_POU_ATTEST 0x04) + status VOTER
- **Decyzja:** PROOF-OF-UPTIME dostaje poparcie w konsensusie. Transakcja 0x04
  (rezerwa spec §tx) wpisuje wallet do `ledger.pou` — rejestru deterministycznego,
  replay bit-w-bit (wzorzec: walidacja najpierw, rejestr wirtualny w bloku,
  commit po całości — jak D50/D46/D47). Analogia właściciela: dziennik obecności
  przy wejściu do fabryki — sam wpis nie wystarczy, TRZECH kolegów z innych zmian
  musi potwierdzić „widziałem go na hali".
- **Format:** tx konto-podpisane (sender=wallet, fee POU_FEE_ISKRY — ⚠️ ROBOCZA,
  fnx_spec §12/P5), recipient pusty. Payload JSON: {v, op:"pou", window, sigs[]};
  świadkowie = {sig_pub, x_pub, sig} nad kanonicznym core {v,op,wallet,window}
  (jak ban_evt, lecz wpis świadka = `witness_entry`, NIE `attest_entry` —
  odrzuca cudze payloady ban). ≥3 RÓŻNYCH świadków, ≤8 (anty-bloat); świadek ≠
  wallet; każdy podpis wiąże się z (wallet, window) — podmianka okna/core = fałsz.
- **Okno-slot:** WINDOW_S = 30 min (spec §6 losowe 20–40; determinizm wybiera
  środek). Granice: okno nie z przyszłości (>600 s dryfu), nie starsze niż 4 doby
  (zaświadczamy ŚWIEŻĄ obecność, nie historię), 1 wpis/okno (dedup w rejestrze
  chain I w mempoolu — slot rezerwowany). Ref-czas: mempool = zegar lokalny
  (polityka), blok = b.timestamp (konsensus deterministyczny — jak rangi D51).
- **Rejestr + status:** apply_pou utrzymuje posortowane okna + last_ts; retencja
  kanoniczna 40 dni (decyduje BLOK, nie zegar — replay bit-w-bit). JEDNA funkcja
  prawdy `pou_status(entry, tip_ts)`: VOTER = streak ≥30 dni (odstępy między
  obecnościami NIGDY >72 h — spec §6 „przerwa >72 h = reset") ORAZ pokrycie ≥80%
  DNI streaka (≥1 okno/dzień; spec mówi „≥80% okien" → MVP: dni, losowe okna =
  warstwa sieci) ORAZ ostatnia obecność ≤72 h od tipu (żywy). Mnożnik §7 gotowy
  jako LICZBA: ghost 0.5 / VOTER 1.0 / VOTER+90d 1.25 — PODPIĘCIE do BLOCK_REWARD
  = osobna decyzja przy zamknięciu §12 (emisja), świadomie NIE tu.
- **Ekonomia:** fee = usługa rejestru (jak ID_DECLARE/CONTACT_REF/RANK_UP/DONATE):
  ppm-owner → skarbiec, kopacz NIC (coinbase = BLOCK_REWARD — asercja testu 8;
  `_miner_fees_of` dotyka wyłącznie TRANSFER/SHIELD/RING/UNSHIELD).
- **Tombstone:** zbanowany wallet martwy także dla PoU (gałąź globalna D18/D47 —
  test 9; jedyna droga = wykup TX_BAN_EVT).
- **Czego NIE zamyka (uczciwie, jak dev-hook D47):** losowość okien 20–40 min i
  „czy świadek REALNIE mnie widział" = warstwa SIECIOWA (M6c challenge-protocol);
  dziś sybil z 3 własnymi portfelami „udowodni" obecność. Docelowo: roster
  świadków gated (VOTER/reputacja) + losowanie świadków Z ŁAŃCUCHA + VOTE_EVT
  0x07 tylko dla VOTER + zimna kropka attestorów zamiast dev-hooka. Całość tej
  resztki = P25 w raporcie (przepisany tekst).
- **Złapane testem v012 (kanapka):** (a) parametr `pou` w _validate_economics
  przykrył import modułu pou → AttributeError (zmieniono na pou_reg + komentarz
  strażnika); (b) test budował tx „zła fee" ze świadkami podpisanymi pod STARE
  okno — walidacja słusznie odrzucała fałsz przed sprawdzeniem fee (test musiał
  dostać świadków pod nowe okno); (c) dziura 5-dniowa w danych synthetic dawała
  streak 1 dzień (nie 20) — oczekiwania testu liczone na piechotę były błędne,
  kod matematycznie rację miał; poprawiono dane testowe i asercje (55/55 nie 56/55).

## D59 (2026-08-07). P25: RING ŚWIADKÓW PoU losowany z łańcucha (sybil-hack zamknięty)
- **Dziura (przyznana w D58):** walidacja TX_POU_ATTEST brała DOWOLNYCH 3 świadków
  — sybil z 3 własnymi portfelami „udowadniał" obecność (świadek wybierał ZAWSZE
  on sam). To była najgroźniejsza z uczciwie otwartych dziur PoU.
- **Decyzja:** ring świadków wyznacza ŁAŃCUCH, nie nadawca: kandydaci = wallet-e
  z attestation w ostatnich 4 dobach vs okno (z REJESTRU — replay bit-w-bit,
  zegar nie gra roli), bez sendera; ring = do 8 wylosowanych deterministycznie
  z seedu blake2s(prev_hash ‖ window) (losowanie bez zwracania, rozszerzanie
  licznikiem). Nikt nie zna ringu przed wyjściem poprzedniego bloku, a i tak
  seed per-okno. Walidacja: każdy świadek ∈ ring (mempool: seed tip.hash(),
  blok: b.prev — te same, gdy łańcuch stał; szablon bloku filtruje tx-y PoU
  aktualnym ringiem, żeby kopacz nie budował nieważnego bloku po ruchu tipa).
- **Bootstrap jawnie:** gdy aktywnych kandydatów <3 → ring = dowolni (jak D58,
  flaga dokumentowana jak dev-hook D47). Sybil-wycena dziś: musisz wpisać ≥3
  własne portfele do dziennika i CZEKAĆ na losowanie hashu — drogo i bez kontroli.
- **Czego NIE zamyka:** „czy świadek REALNIE widział nadawcę" (challenge-
  reachability, kto realnie kopał odpowiedź) = warstwa sieci M6c. Ring to
  MATEMATYKA nad listą attesterów; fizyczna weryfikacja echo = osobny kamień.
- **Złapane przy tej robocie (kanapka):** — (raport v013: brak nowych defektów
  produkcyjnych; pętla losowania z cleanup-double-break uproszczona po przeglądzie).

## D60 (2026-08-07). P25: VOTE_EVT 0x07 — urna WYŁĄCZNIE dla statusu VOTER
- **Decyzja:** głos trafia na łańcuch jako TX_VOTE_EVT (rezerwa spec §tx). Tx jest
  konto-podpisane (sender podpisuje całość jak transfer — nonce/tombstone/fee
  działają same); payload: {v, op:"vote", topic: hex64, choice: ≤64 znaki}.
  Brama: sender MUSI być VOTERem liczonym z rejestru PoU w chwili BLOKU
  (pou_status(pou_reg, b.timestamp) — konsensus deterministyczny; mempool liczy
  zegarem lokalnym jako polityka). Rejestr ledger.votes: topic → wallet → choice.
- **Zasady:** JEDEN głos / temat / wallet (dedup chain ∪ mempool — wzorzec
  usernames; MVP: głos TRWAŁY, zmiana = odrzut); fee płaska 100 iskier (ROBOCZA
  §12/P5) jak usługa rejestru → ppm-owner do skarbca, kopacz NIC; tally()
  deterministyczne. fnx_spec §13 dotrzymane: głosu nie kupuje się za FNX.
- **Replay-strażnik (test 7):** łańcuch z głosem bez 30-dniowej historii
  attestation jest NIEWAŻNY przy adopt_chain (brama liczy z tx-ów 0x04, nie z
  „podrzuconego" rejestru) — anty-obchód chirurgicznej edycji snapshotu.
- **Czego NIE zamyka:** rejestracja tematów (kto otwiera głosowanie, zamykanie,
  quorum) = P10 multi-sentinel / referenda — rura gotowa, kierunek: topic =
  hash propozycji (np. ban-szkicu z D-P26).
- **Weryfikacja:** vote_evt selftest 7/7 (brama ghost, VOTER E2E, dedup, tombstone,
  replay-strażnik, ekonomia); pou 10/10 (z 2b ring D59); regresje pełne zielone.

## D61 (2026-08-07). LICZNIK SIECI: presence-beacon gossip (D61) — online/rejestr, ESTYMACJA nie cenzus
- **Życzenie właściciela:** track counter — ilu użytkowników zarejestrowanych, ilu
  node'ów online, zmiana płynąca online↔offline.
- **Decyzja:** kubła czasowe 5 min; każdy nod co <5 min rozgłasza PODPISANY beacon
  {wallet, bucket} (T_PRES 0x41, ttl 4, dedup (wallet,bucket), kubło = część podpisu,
  podmianka czasu bez sig = martwa). „Online" = sygnały z ostatnich 10 min — node
  milknie → spada SAM z licznika (offline/online płynie bez zawiadomień).
- **Dwie miary, zero udawania:** online_estimate = beacony (gossip-estymacja
  LOKALNA: partycja widzi swoją połowę — brak centrali = brak WIELKIEJ PRAWDY;
  pokazujemy z etykietą metody „estymacja"); registered = usernames on-chain
  (żywa metryka „użytkownik z nickiem"; anonimowego-gocha nie liczy — powiedziane).
- **Anty-spam (widoczne a nie niwelowalne):** sygnał wymaga prawdziwego klucza
  Ed25519 + wiązania pub‖x→wallet; farmę sygnałów odróżniamy od sygnałów farmy
  tylko żetonami czasu — jawne w raporcie (jak bootstrap D58).

## D62 (2026-08-07). AIRDROP kamienia milowego 1M (TX_AIRDROP 0x15) — maszyna losująca z hasha
- **Życzenie:** gdy Fenix NET urośnie do 1 000 000 użytkowników → airdrop FNX,
  losowy odbiorca (uuid), losowo 1–10 FNX.
- **Decyzja:** kamień milowy = licznik usernames on-chain (żywa metryka D61);
  ⚠️ ROBOCZE §12 — próg i lista progów = decyzja właściciela. Gdy count >= próg,
  szablon bloku wychwytuje JEDEN strzał: zdarzenie SYSTEMOWE (sender/sig puste),
  odbiorca = blake2s(prev‖milestone) % sorted(names) z pominięciem ZBANOWANYCH
  (przesuwanie w kolejce; cały zestaw banned → zdarzenie wstrzymane), kwota
  deterministyczna 1..10 FNX z osobnego labela. Każdy węzeł + replay liczy to samo
  (bit-w-bit — jak wszystko inne u nas). Emission-event: ⚠️ źródło FNX = §12
  (docelowo skarbiec / harmonogram emisji — uczciwie OTWARTE, nie skrywane).
- **Moc = zero:** nikt nie wybiera odbiorcy ani kwoty (wybiera blok poprzedni);
  kopacz może co najwyżej NIE włączyć strzału (przejdzie u następnego).

## D63 (2026-08-07). TRYB DUCHA (ghost) — mniej mówię o sobie, nie magia
- **Deklaracja bezpieczeństwa:** tryb ducha wzmacnia prywatność ADRESU/obecności:
  nod (a) NIE dokłada własnego host:port do T_ADDR (obstawia tylko obcymi),
  (b) NIE rozsyła beacona presence (nie liczy się w D61), (c) reszta bez zmian:
  AEAD, camo, gossip tx/bloków, kopanie. Toggle: --ghost flag demona + IPC op
  „ghost" (localhost 0660, jak mining) + node.set_ghost w locie (PRZYSZŁE
  ogłoszenia; już rozesłane nie zniknie).
- **Granice głośno (jak D31/P11):** duch ≠ invis — ISP widzi połączenia i timing;
  analiza ruchu/tor-to problem wyższych warstw (P12, Mullvad C); „bezpieczniejsze
  transakcje" finansowo = mgła v2 (już domyślna w panelu P12/M7d); duch dotyka
  tylko warstwy reklamy adresu/obecności.

## D64 (2026-08-07). tools/power_audit.py — stała kontrola „kto ma moc nad siecią"
- **Decyzja:** kryptografię atakuje self_attack; ZAMIAR (kto ma przyciski) pilnuje
  osobny statyczny audyt: kropka attestorów tylko z ban_evt/core-admin (produkcja,
  testy nad __main__ legalne), stała skarbca nigdzie w modułach D58/D60/D62,
  tx systemowe (coinbase/ban/airdrop) → sender/sig puste + matematyka, biała
  lista IPC = snapshot (nowy op = ludzkie oko; regex→AST po złapanym faluszu z
  komentarzem „(D17)"), zero sekretów w IPC, „przycisk ban" nie istnieje,
  ghost czysty z krypto, presence poza konsensusem, flagi DEV jawne.
- **Złapane własnym skanerem (kanapka):** 5 kontrolek początkowo czerwonych —
  test-sections settings_admin/ai_sentinel słusznie rejestrują kropki (dozwolone),
  selftesty pou/vote czytają saldo skarbca do ASERCJI (legalne), regex gryzł się
  na komentarzu w PROTO_OPS, słowo-ranga „ghost" w core — wszystko wyjaśnione
  i przełączone na część produkcyjną/AST. Skaner uczy tego samego co test: FAQ
  pisze się adresem bunkra, nie oczekiwaniem faktu.

## D65 (2026-08-08). GIEŁDA FNX-COIN (app/fnx_coin.py) — cena z łańcucha, nie z czyjejś ręki
- **Życzenie:** giełda kupna AND sprzedaży FNX, z ceną ZMIENNĄ zależną od
  wykopanej zebranej podaży i temu podobnych faktów sieci.
- **Decyzja:** desk market-maker (kupno+sprzedaż ze swojego magazynu, jak D32),
  ale KURS liczy wyłącznie krzywa z faktów łańcucha (int-only, każdy węzeł
  policzy identycznie bit-w-bit — replay klonów udowodnione testem):
    kapitał[¢] = FLOOR_CAP(100) + 100·usernames + 500·attesterzy_PoU
               + 1·głosy + 1·wysokość      (⚠️ ROBOCZE §12, głosowalne D60)
    cena[¢/FNX] = max(1¢, kapitał·ISKRA // max(Σsald, ISKRA))
  podaż (Σsald = ground truth — burn D15 nigdy nie był zaksięgowany) siedzi
  w MIANOWNIKU: więcej wykopanego przy tej samej aktywności = rozcieńczenie,
  cena ↓; users/attesterzy/głosy/wysokość w LICZNIKU: sieć żyje, cena ↑.
  Spread 2% każdą stronę = marża magazynu; ask > cena ≥ bid zawsze ≥ 1¢
  (podłoga, genesis i hiper-rozcieńczenie nie psują wzoru; potwór 10^18 = test).
- **Moc ZDJĘTA (kontynuacja D64):** D30 miał kurs PODPISYWANY przez ownera —
  jedna ręka na termostacie ceny. FNX-COIN ten przycisk usuwa: stałe są jawne,
  zmiana = VOTE_EVT (D60), nie podpis. Handel z desk nie rusza krzywej
  (transfer ≠ emisja; saldo desku ≠ fakt łańcuchowy) — nie da się pompować
  ceny kupując od samego kantora.
- **Twarde zasady desku:** NIGDY nie drukuje FNX (pusty magazyn = uczciwa
  odmowa; inwariant no-mint z pełnym księgowaniem podaży w teście); kurs
  sprzedaży z chwili KSIĘGOWANIA (settle), jak kantor „z chwili zaksięgowania";
  replay-stráżnik settled-txid; limity dzienne per wallet per kierunek (D32);
  rail płatności = świat zewnętrzny (FX PLN↔USD i kontrakt operatora = P7,
  zadanie właściciela — ProductionRail uczciwie odmawia jak D32).
- **Kupno:** rail.debit → tx desk→user (dokładnie kwota z kwotacji; fee bierze
  desk); łańcuch odrzucił = REFUND raila (pieniądz nigdy w powietrzu).
  **Sprzedaż:** user→desk transfer NA ŁAŃCUCHU → po potwierdzeniu settle wypłaca
  rail; mempool settle = odmowa (cena z księgowania, nie z wysłania).
- **NIE jest:** orderbookiem P2P (roadmapa D32 z rankami market-maker),
  ani fiat-out bez operatora (P7 otwarte), ani poradą inwestycyjną — LEGAL_NOTICE
  w pliku jak zawsze głośno.

## D66 (2026-08-08). STATUS BANU WIDOCZNY („widać go") — lusterko konsensusu, nie nowa władza
- **Życzenie właściciela:** bany na adres walleta mają być WIDOCZNE przy rejestracji.
- **Co już było (przypomnienie, testy 2–4 ban_evt):** tombstone D18/D47 egzekwuje
  to od dawna — zbanowany wallet NIE zarejestruje username, nie wyśle tx,
  nie skopie bloku (jedyna furtka: wykup D30, raz na historię).
- **Czego brakowało:** człowiek NIE WIDZIAŁ powodu — suche ChainError w logu
  konsensusu, a GUI mówiłoby ogólnym „błąd". To nieuczciwe UX wobec plomby.
- **Decyzja:** warstwa LUSTERKA (tylko odczyt, zero nowej władzy):
  * `chain/ban_evt.ban_view/ban_banner_pl` — status z rejestru: banned, kod +
    etykieta + powód PL/EN (REASONS_RED), wysokość plomby, furtka wykupu
    (albo „na zawsze" D18); rozróżnia: zbanowany / czysty / historia-wykupana;
    klon replay pokazuje IDENTYCZNIE (konsensus, bit-w-bit).
  * IPC op `ban_status` (localhost 0660; target = wallet/username/ja) +
    `node.ban_status_info` + klient GUI. Op READ-ONLY — power_audit dostał
    ludzkie oko: ban_status w dozwolonych (tymczasem: przycisk ban nadal
    NIE istnieje; kontrola twarda: handler bez mutacji rejestru).
  * GUI: `validate_username_edit` mówi CZEMU (baner z kodem/powodem/furtką
    PRZED kliknięciem „zarejestruj") + `ban_status_line` dla lookupu/dashboardu.
- **Czego to NIE jest:** nie egzekucja (jest w ledgerze), nie nowy ban,
  nie eksport danych treściowych (evidence = hash; powody = publiczne kody
  z ban_codes.txt). Ban_policy v1.0 nietknięta — nikt nie dostał przycisku.

## D67 (2026-08-08). POKÓJ CENOWY + KARTY SIECI w GUI — szyba wystawowa, nie kasa
- **Kontekst:** etap E1 planu dokończenia (docs/plan_do_konca.md) — GUI dostaje
  to, co backend już umie (D61/D63/D65/D66). Zasada etapu: TYLKO widoki
  read-only + lokalne toggl-e; żadnych opków handlu w IPC.
- **Decyzja:**
  * op IPC `price` (read-only): demon liczy krzywą D65 z własnego ledgera —
    karta w GUI pokazuje cena/ask/bid/podaż/users/attesterzy; źródło (demon vs
    dev-lokalny) nazwane na karcie; model + ROBOCZE §12 + LEGAL_NOTICE
    skrócone na szkle („handel = P7"). IPC NIE handluje: power_audit dostał
    twardą kontrolę (buy/sell/trade/swap_exec = zakazane opki; 20/20).
  * op `ghost` już istniał — GUI dostaje toggle na stronie Sieć + linijkę
    granic (routing/timing zostaje; duch ≠ tor) ZAWSZE pod przyciskiem.
  * karta Sieć: census z demona (online≈ ESTYMACJA, registered, attesterzy,
    kamień airdropu) — dev bez demona mówi uczciwie „sterowalne z żywym node".
  * Dashboard: CZERWONA KARTKA gdy mój wallet zbanowany (baner D66) — obok
    meldunku fabrycznego hasła; kadra kursu pod odznakami; obie „NIGDY nie
    wywracają dashboardu" (try/except jak admin-status).
- **Czego NIE zrobiono (jawnie):** przyciski Kup/Sprzedaj w GUI — wymagają desk
  w demonie + rail (P7, umowa operatora); szyba została read-only UMYŚLNIE,
  żeby nikt nie handlował „z GUI" bez prawnego gruntu (LEGAL_NOTICE).

## D68 (2026-08-09). REAL_E2E: brama funkcjonalna na ŻYWYCH procesach (koniec „printów")
- **Kontekst:** zarzut właściciela: „robota jest w printach — chcę realnego działania".
  Selftesty 1-procesowe pokrywają logikę; brakowało twardego dowodu, że DEMONY
  jako osobne procesy grają całość: TCP+AEAD, konsensus, tx, usługi IPC, dysk.
- **Decyzja:** `tools/real_e2e.py` — orkiestra 3 demonów (A seedless, B←A, C←B)
  sterowana przez IPC z czwartego procesu-klienta: mesh → kopanie staggered
  (DEV zbits=2; bloki produkują DWA RÓŻNE nody) → zbieg do TEGO SAMEGO tip-hash
  → DONATE 1 FNX przez gossip C→B→A (Δ skarbca i nadawcy liczone DO ISKRY wg
  D15/D50) → census/price/ban_status/ghost → SIGINT-restart z łańcuchem z DYSKU
  → rejoin do mesha → zero Traceback w logach. Każdy FAKT = artefakt z procesu
  (saldo, hash, licznik), nie napis „powinno działać".
- **Kanarek tej rury (w fixlogu raportu działania):** CLI domyślnie KOPJE od bootu;
  dwa minery dev (zbits=2 ≈ 400 blk/s) = wieczny storm forków i zbieg nigdy.
  Fix harnessu: `--no-mine` wszędzie + burst staggered + pigułka sync (op `sync`).
- **Czego to NIE jest:** dev-PoW i loopback; nie QA obciążeniowe (E7), nie
  multi-host (P2 — checklista właściciela). Ale to pierwszy raz, kiedy CAŁA
  mozaika (net/chain/app/IPC/dysk) gra w jednym scenariuszu na procesach.

## D69 (2026-08-09). AI-GRID v0: siatka obliczeniowa na drucie 0x42/0x43 — moc użytkowników
- **Kontekst:** „decentralizowana AI zasilana mocą obliczeniową użytkowników" ma
  być REALNĄ funkcją, nie slajdem. v0 buduje rurę, która musi być bezpieczna
  ZANIM wpuścimy ciężkie zadania: kernel deterministyczny (chain_hash) jako
  bieg próbny maszyny; wtyczka KERNELS otwarta na batch-verify CLSAG i embeddingi
  (dopiero z deterministycznym silnikiem — obiecujemy siatkę, nie cuda).
- **Decyzja:**
  * `ai/fnx_ai.py`: kernel + koperty sig-wire (sig_pub+x_pub w środku, wallet
    FNX1 wyliczany — wzór presence D61), JobCollector (dedup per wallet, kworum
    k-zbieżnych, FINALNY recompute PRZED płatnością), GridRegistry (rate-limit
    8/min/wallet — sybil zapieka się kubełkiem), budget z JAWNYM shortfall.
  * node: dispatch T_JOB/T_JOB_RES (+sense „grid" do radaru — KINDS_DATA),
    książka zadań FIFO, gossip jak tx; LICZENIE wyłącznie opt-in `--ai-grid`
    (sufit 250k iters na node; cięższe zadania = relay-only, uczciwie).
  * płatność: zamawiający po kworum robi recompute kernela i płaci każdemu
    zwycięzcy TX_TRANSFER z notą `fnx-ai-grid job …` (podpis W DEMONIE, jak
    donate). Fałszywe kworum / brak środków = jawny STOP — zero cichej emisji.
  * IPC: `grid_submit` / `grid_status` (power_audit: whitelist 22 opy, ludzkie
    oko nad D69 — pay to tx po dowodzie, NIE handel; NO-TRADE nietknięty).
  * dowód: `real_e2e` krok 3b — A ogłasza, B i C liczą WŁASNYM CPU w swoich
    procesach, wyniki wracają gosipem, kworum 2, `settle.truth` == NIEZALEŻNY
    recompute w harnessie, salda B/C rosną o DOKŁADNIE bounty (iskra-co-iskra).
- **Granice v0 (głośno, zgodnie z zasadą „obiecuj siatkę, nie cuda"):** pay =
  intent rozliczony tx-ami postera (escrow covenant = roadmap); `ms` jest
  self-reported (etykieta, nigdy premia); zero zmian emisji/konsensusu ledgera;
  zadania = jawne parametry publiczne (tajne wejście = MPC później); kanał
  „grid" w radarze liczony, ale WŁASNE progi detektorów = tuning P (progi msg
  się nie przenoszą automatycznie — inna charakterystyka ruchu).

## D70 (2026-08-09). FNX64 „x tetracja do 10" — właścicielska peleryna na drut (AEAD zostaje)
- **Kontekst:** życzenie właściciela: sieć P2P ma lecieć na WŁASNYM szyfrowaniu
  „FNX64 x tetracja do 10" i ten fakt ma być UDOWODNIONY bajtami, nie napisami.
- **Decyzja:**
  * `core/crypto/fnx64.py`: strumień XOR z tetracji — blok = (blake2s(k‖seq‖i)|1)↑↑10
    mod 2^64 (wieża przez łańcuch Carmichaela; baza WYMUSZANIE nieparzysta, bo
    parzysta zapada się do 0 — matematyka, nie bug). Złote wektory w selfteście.
  * `net/frame.py`: negocjacja pola „fx" w PODPISANYM HELLO_FIN; gdy obie strony
    je niosą, każdy CT ramki dostaje pelerynę XOR (po AEAD, przed drutem).
    Klucz peleryny = z (klucz sesji eph ⊕ DH STATYCZNYCH tożsamości) — obserwator
    po złamaniu SAMEJ efemeryki nadal ma czarny ekran (realny przyrost kosztu).
  * Kompatybilność: peer bez flagi = czysty AEAD (żadnego forka w protokole).
  * Nagłówki FN zostają jawne ZGODNIE ze specem (magic/typ/seq/len to meta);
    treść zawsze pod kluczem.
- **Czego to NIE jest:** to NIE zastępstwo ChaCha20-Poly1305/X25519/Ed25519
  (fundament nienaruszony — homebrew nigdy solo); tetracja mod 2^64 NIE jest
  audytowanym prymitywem światowym (warstwa właścicielska, statystyka dyfuzji
  to OBSERWACJA nie dowód); szybkość czystego Pythona ~0,08 MiB/s na wątek
  (dla ruchu mesh OK; port do C = roadmap, algorytm 1:1).
- **Dowód (artefakty, nie napis):** frame selftest kroki 7-8 (bez klucza fx ten
  sam klucz AEAD = czarny ekran); real_e2e kamera TcpSniffer na C↔B: 561 152 B
  ruchu, ZERO wystąpień markerów treści (label zadania, nota donate, „FNX1",
  amount, winner), 256/256 unikalnych bajtów, hex artefaktu w raporcie sieci.

## D71 (2026-08-09). Trwałość łańcucha u DEMONA (kanarek: „restart z dysku" był synciem!)
- **Kontekst (duża kanapka):** rozbudowa real_e2e zdemaskowała, że bogatszy
  scenariusz obnaża fakt z wcześniejszego raportu: demon w ogóle NIE zapisywał
  chain.dat (save/load istniały w ledgerze od D42, ale nikt ich nie wołał) —
  „wysokość po restarcie" wracała od peerów przez sync, nie z dysku. Errata
  dopisana do raportu z 2026-08-09.
- **Decyzja:** Node przy starcie robi `Ledger.load_chain(chain.dat)` (replay
  ZEROZUFANIOWY: magia+blake2s+apply_block od zera — podmiana salda = wyjątek,
  nie fałszywy start); `_flush_chain()` przy czystym stopie + co 60 s wraz z
  peers/stats (okno straty przy twardej śmierci ≤60 s — JAWNIE; zapis
  przyrostowy z kompaktacją = roadmap, bo zrzut pełny rośnie z łańcuchem).
- **Dowód:** real_e2e dwa restarty: A2 BEZ SEEDS → h odczytane natychmiast po
  starcie == h przed stopiem (5 426 B plik) = DYSK; A3 z seeds → rejoin+sync
  = SIECI. Dwa fakty, dwa różne mechanizmy, zero mieszania.

## D72 (2026-09-22). FNX64 — port wieży do C, bajt w bajt z Pythonem
- **Kontekst:** D70 zostawił tetrację w czystym Pythonie (~0,13 MiB/s). Koszt
  to `tower_mod`, nie blake2s. Sync większych ramek czekał na port 1:1.
- **Decyzja:** `core/crypto/fnx64_accel.c` liczy `a↑↑h mod 2^mb` hurtowo
  (`fnx64_tower_batch`). Wykładniki wysokości 10 mieszczą się w uint64;
  mnożenie uint64 + maska jest dokładne dla mod 2^mb przy mb≤64 (2^64 jest
  wielokrotnością 2^mb). Python włącza .so dopiero po złotym porównaniu
  (wektory wieży h=10 i h=2/3 oraz 20 B strumienia vs `_stream_py`). Rozjazd
  albo brak gcc = zostaje `tower_mod`. Bajty na drucie nie zależą od silnika.
- **Pomiar (ten sam interpreter, ten sam klucz):** 64 KiB strumienia 0,513 s →
  0,022 s (~23×); 1 MiB w selfteście 0,36 s (2,88 MiB/s). .so nie wchodzi do
  repo — buduje się przy imporcie, obok źródła albo w `~/.cache/fenix`.
- **Czego to NIE jest:** nie nowy prymityw, nie zamiana AEAD, nie przegląd
  kryptograficzny tetracji (ten punkt D70 zostaje otwarty).
