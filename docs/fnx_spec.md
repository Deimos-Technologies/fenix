# FNX CHAIN — Specyfikacja blockchainu FENIX v0.1 (2026-07-19)
> Święta księga ekonomii i konsensusu (D15, D12, D18 + mechanizmy egzekwowania A/B/C/D).
> Implementacja M4/M5 zaczyna się od tego pliku. Zmiana parametrów = wersja + konsensus.

## 1. JEDNOSTKI I OGÓLNE ZAŁOŻENIA
- **1 FNX = 10^8 iskier** (najmniejsza jednostka: 0.00000001 FNX = 1 iskra; D15)
- Łańcuch proof-of-work + proof-of-uptime: kopie = hostujesz (górnik utrzymuje też
  fragmenty danych — proof-of-storage per blok; decyzja wizji "kopie=hostujesz")
- Wszystkie salda, depozyty, werdykty, attestation i rangi = rejestr publiczny (bez treści!)
- Identyfikacja zawsze Wallet Address (D-rejestr); żadnych danych osobowych on-chain

## 2. STRUKTURA BLOKU
```
HEADER:
  ver(2B) | prev_hash(32B, BLAKE2s-256) | merkle_root(32B) |
  timestamp(4B, ±15min od mediany sieci) | target(4B) | nonce(8B) |
  miner_wallet(36B) | pou_proof_ref(32B) | storage_root(32B)
TXS: [ tx_1 ... tx_n ]  (max 1 MB na blok)
SIG:  podpis górnika (Ed25519) nad HEADER — czyli nie da się ukraść cudzego bloku
```
- Hash PoW: **BLAKE2s-mem(Argon2id-lite)** — propozycja CPU-friendly; cel: GPU/ASIC mało opłacalny.
  OSTATECZNY wybór funkcji: testy porównawcze w M4 (kandydaci: Argon2-lite, RandomX-port) — D7.

## 3. TRUDNOŚĆ I RYTM
- **Cel: blok co T = 60 s.** Retarget co **144 bloki (~1 doba)**: clamp zmiany do ×4/÷4 na epokę.
- Minimalna trudność chroniąca przed "podbiciem nowym botnetem w minutę": podłoga kalibrowana w M4.
- **Checkpoint:** co 100 bloków — podpis **progowy k-z-n** znanych seed-attestorów; łańcuch
  sprzeczny z ostatnim checkpointem = odrzucany (anti-51% przy małej sieci; do usunięcia przy skali).

## 4. TRANSAKCJE (typy)
| typ | kod | zawartość | notatki |
|---|---|---|---|
| TRANSFER | 0x01 | from→to, amount, fee | zwykły przelew |
| ID_DECLARE | 0x02 | wallet, username, UID | rejestracja tożsamości (fee antyspam) |
> ⚠️ Numery typów w tej tabeli są HISTORYCZNE (szkic v0.1); wiążące kody to
> `chain/block.py` (registry konsensusu): ID_DECLARE=0x03, POU_ATTEST=0x04,
> RANK_UP=0x05, BAN_EVT=0x06, VOTE_EVT=0x07, BLOB_REF=0x08, USERNAME_AVATAR=BLOB_REF.
> Zmiana numeru zaimplementowanego typu = hard-fork; tabela będzie zsynchronizowana
> przy zamknięciu §12 (emisja) w jednym dokumencie-wydaniu.

| POU_ATTEST | 0x04 | wallet, window_id, sygnatury świadków (≥3) | buduje Proof-of-Uptime (§6) |
| RANK_UP | 0x05 | wallet, rank_level, amount | cennik §8; aktywacja po 6 conf. |
| BAN_EVT | 0x06 | wallet, code, reason_hash, verdict_sig(k-z-n) | tombstone (§9, D18/D47) |
| DONATE | 0x14 | sender→skarbiec ownera, amount | dobrowolny datek (D50, §8a) |
| VOTE_EVT | 0x07 | voter_wallet, topic_id, choice, sig | tylko VOTER (PoU ≥30 dni) |
| BLOB_REF | 0x08 | fragment_hash, size_class, expiry | rejestr hostowanych fragmentów (bez treści) |
| BOND_LOCK / BOND_SLASH | 0x08/0x09 | depozyt / konfiskata | identity bond (§10) |
Walidacja każdej tx: podpis Ed25519 z klucza walleta + nonce sekwencyjny (anti-replay) + fee.

## 5. OPŁATY (D15 — nienaruszalne od genesis)
- **fee = 0.056%** z kwoty każdej TRANSFER, gdzie:
  - **0.001% → BURN** (niszczone na zawsze — deflacja przepisana do monet)
  - **0.055% → SKARBIEC OWNERA** (adres w genesis, publiczny, audytowalny)
- Pozostałe tx: płaskie opłaty antyspamowe w iskrach (ID_DECLARE, BLOB_REF — cennik w M4).
- Skarbiec po M5 transparentny na stronie/eksploratorze; planowany saldo-multisig: backlog.

## 6. PROOF-OF-UPTIME (PoU) I VOTER (D12)
- Losowe okna obserwacji 20–40 min (jitter obowiązkowy — lista NIGDY); w oknie wallet odpowiada
  na challenge od ≥3 losowych peerów (podpisy świadków do POU_ATTEST).
- **30 dni UDOWODNIONEJ obecności (≥80% okien) = status VOTER** (prawo głosu VOTE_EVT,
  prawo do ran sentinel, ścieżka do roli attestora).
- Przerwa > 72 h = reset progresu do zera (interrupt=death streaka; ban = także pełny reset, D18).
- **IMPLEMENTACJA MVP (D58, 2026-08-07, `chain/pou.py` + `ledger.pou`):** warstwa konsensusu
  gotowa — TX_POU_ATTEST 0x04 z ≥3 RÓŻNYMI świadkami (świadek ≠ wallet, podpis wiąże
  (wallet, window); ≤8 wpisów/payload), okno-slot 30 min (deterministyczny środek zakresu
  20–40; jitter/losowość = warstwa sieci), granice: nie z przyszłości + nie starsze niż 4 doby,
  1 wpis/okno (dedup chain+mempool), retencja kanoniczna 40 dni z timestampów BLOKÓW.
  VOTER w MVP = streak ≥30 dni (odstępy między obecnościami nigdy >72 h) **z pokryciem
  ≥80% DNI** (spec „≥80% okien" → uproszczenie MVP: ≥1 okno/dzień; pełne pokrycie okien
  wraca z challenge-protokołem M6c) **i żywą obecnością** ≤72 h od tipu. Mnożniki §7
  liczone jako LICZBA (0.5/1.0/1.25); podpięcie do reward_block = przy zamknięciu §12.
- **D59 (2026-08-07): RING ŚWIADKÓW LOSOWANY Z ŁAŃCUCHA.** Świadków NIE wybiera nadawca:
  kandydaci = wallet-e z attestation w ostatnich 4 dobach (z rejestru — replay bit-w-bit),
  bez sendera; ring = ≤8 wylosowanych deterministycznie z seedu blake2s(prev‖window).
  Walidacja wymaga świadków Z RINGU; szablon bloku filtruje tx-y PoU aktualnym ringiem.
  **BOOTSTRAP jawnie: kandydatów <3 → ring otwarty (jak w D58).** Sybil-wycena dziś:
  trzeba wpisać ≥3 własne portfele do dziennika i czekać na losowanie hashu bloku.
  (Otwarte: challenge-reachability — „czy świadek REALNIE odpowiedział” = warstwa sieci M6c.)
- **D60 (2026-08-07): VOTE_EVT 0x07 = urna on-chain WYŁĄCZNIE dla VOTERa** (§13 spełnione:
  głosu nie kupuje się za FNX). Payload {topic hex64, choice≤64}; 1 głos/temat/wallet
  (MVP trwały); brama = pou_status z b.timestamp (replay); fee ppm→skarbiec, kopacz NIC;
  rejestracja tematów/quorum = P10 (multi-sentinel dostaje rurę).

## 7. NAGRODY ZA BLOK I MNOŻNIKI (mechanizmy A1/A3 z projektu egzekwowania)
- reward_block = BASE × **mnożnik reputacji** górnika:
  - ghost 0-30 dni: ×0.5 • VOTER: ×1.0 • VOTER+90d: ×1.25 • attestor k-z-n: ×1.5
- **Streak lojalnościowy (A3):** za każdy KOMPLETNY czysty miesiąc attestation: +5% do nagród
  (maks. +50%). Ban/reset streaka → wracasz do zera. Emisja stanowi nagrodę "uczcie najlepiej".
- BASE i harmonogram emisji: OTWARTE (§12) — do decyzji właściciela przed M4.

## 7a. AIRDROP KAMIENIA MILOWEGO (D62, 2026-08-07 — ⚠️ ROBOCZE §12)
- Gdy licznik usernames on-chain osiągnie **1 000 000** (metryka żywa proxy
  „użytkowników"; anonimowych nie liczy — jawne), szablon bloku wychwytuje
  DOKŁADNIE JEDEN strzał TX_AIRDROP 0x15: odbiorca = blake2s(prev‖kamień) %
  sorted(rejestr) z pominięciem zbanowanych (tombstone wygrywa, D18), kwota
  deterministyczna 1..10 FNX z osobnego labela. Nikt nie wybiera odbiorcy i
  kwoty (robi to hash poprzedniego bloku); emission-event — źródło FNX i
  ewentualne dalsze kamienie = OTWARTE (§12, decyzja właściciela).
- LICZNIK SIECI (D61, warstwa net): „online" = beacony podpisane co 5 min z gossip
  (estymacja lokalna, NIE cenzus — brak centrali); „zarejestrowanych" = usernames.

## 7b. CENA FNX Z ŁAŃCUCHA — krzywa giełdy FNX-COIN (D65, 2026-08-08 — ⚠️ ROBOCZE §12)
- Giełda **FNX-COIN** (`app/fnx_coin.py`) kupuje i sprzedaje FNX z własnego
  magazynu (desk market-maker); KURSU nie ustawia żaden człowiek — liczy go
  deterministycznie każdy węzeł z publicznych faktów łańcucha (int-only,
  replay klonów bit-w-bit potwierdzone selftestem):
  - `kapitał[¢] = FLOOR_CAP(100) + 100·|usernames| + 500·|attesterzy PoU| + 1·|głosy D60| + 1·wysokość`
  - `podaż = Σ balances` (iskry; ground truth — fee-burn D15 nigdy nie był
    zaksięgowany, więc spalone FNX po prostu nie istnieją w tej sumie)
  - `cena[¢/FNX] = max(1¢, kapitał·ISKRA // max(podaż, ISKRA))`
  - spread 20 000 ppm (2%) każdą stronę: `ask > cena ≥ bid ≥ 1¢`.
- Kierunki uczciwie: podaż w mianowniku (więcej wykopanego przy tej samej
  aktywności = rozcieńczenie ↓), aktywność i praca w liczniku (↑). Handel
  z desk NIE porusza krzywej (transfer ≠ emisja; saldo desku ≠ fakt chain).
- Stałe §12 to wartości STARTOWE — zmiana = głosowanie VOTE_EVT (D60), nie
  podpis jednej osoby (D30 therapostat ceny zdjęty, ślad w audycie mocy D64).
- Desk NIGDY nie emituje FNX: pusty magazyn = odmowa; kurs sprzedaży z chwili
  zaksięgowania; rail fiat/krypto = świat zewnętrzny (P7 — operator + rejestr).
- **WIDOK CENY (D67):** op IPC `price` = pokój cenowy read-only w GUI (źródło
  liczenia nazwane; handel poza kodem = P7; kontrola power_audit zakazuje opków buy/sell).

## 8. RANGI (D16 — wartości nienaruszalne)
ghost 0 • Donor 0.000001 • VIP 0.000002 • VIP+ 0.000003 • SVIP 0.00001 •
ELITE 0.0001 • SELITE 0.01 • FENIX 100.1 (wszystko FNX; upgrade = dopłata różnicy).
- RANK_UP wpisany na-chain po 6 potwierdzeniach; benefity wg tabeli w TODO/regulaminie.
- **WAŻNOŚĆ (D51, decyzja właściciela 2026-08-06):** ranga kupna wygasa po **30 dniach**
  (`until = timestamp bloku zakupu + 30·86400`; konsensus liczy z timestampów bloków,
  nie z zegarów). RENEW = pełna cena tej samej rangi, +30 dni, stos max 60 dni, bez
  resetu 6 confs. Wygasła → ghost; re-buy za pełną cenę; downgrade po wygaśnięciu legalny.
  Dotyczy rang kupnych (donor…elite); selite/fenix systemowe przyznaje właściciel poza TX.
- Podział wpłaty za rangę: PROPOZYCJA 50% burn / 50% skarbiec — **do decyzji ownera** (§12).
- RANGA NIGDY nie daje: głosu, danych innych, kanału do AI, unbana, władzy nad protokołem.

## 8a. DONATE (D50 — dobrowolne datki do skarbca ownera)
- TX_DONATE (0x14): sender płaci `amount` (≥1 iskry, **kwota zawsze wybór użytkownika**),
  recipient MUSI być aktualnym skarbcem — inny adres = to TX_TRANSFER, nie TX_DONATE.
- CAŁY amount + część ownerska fee idzie skarbcowi (kopacz z donate nie zarabia).
- Payload opcjonalny: `{"v":1,"note":≤140 zn.}` — **JAWNY na zawsze** (ostrzeżenie w GUI).
- `ledger.donations {wallet: suma}` liczy się z replay/adopt bit-w-bit → odznaki DONOR (§8b).

## 8b. ODZNAKI PROFILU (D52 — badges)
- Przydział wg katalogu `chain/badges.py` (BADGE_CATALOG): Właściciel Legitymacji
  (aktywna ranga ≠ ghost; gaśnie z rangą D51), Dobroczyńca I/II/III (datki ≥1/≥100/≥1000 FNX),
  Górnik (≥100 coinbase), Czuwający (≥1 kropka k-z-n z BAN_EVT), Ptak Wczesny
  (pierwszy tx ≤ bloku 1000), oraz z licznika lokalnego D54: Strażnik Czasu I/II/III
  (100/1000/10000 h noda), Architekt (1 strona), Założyciel (pierwszy nod).
- Klasy prawdy: `chain` = każdy nod liczy identycznie; `local` = licznik własnego noda
  (oznaczany gwiazdką). Odznaki się LICZY (`evaluate_badges`), nie wkleja.

## 9. BANY, TOMBSTONE I UNBAN (D18)
- **WIDOK BANU (D66, 2026-08-08):** status banu jest PUBLICZNIE czytelny —
  `ban_view` pokazuje: aktywny/czysty/historia, kod + powód PL/EN (z kodeksu),
  wysokość plomby, furtka wykupu (D30; po zużyciu: „na zawsze"). IPC `ban_status`
  (read-only), GUI pokazuje baner przy rejestracji username i lookupu.
  Lusterko: nic nie egzekwuje z siebie — egzekwuje konsensus (§tombstone);
- BAN_EVT zasiada poprzez konsensus sentinel k-z-n, zawiera: wallet, kod (8 kodów regulaminu),
  reason_hash (PL/EN), hash dowodów, verdict_sig. Nieodwracalny. Publiczny.
- UNBAN: jedyna droga = **1 000 000 USD w FNX (jednorazowo — aktualizacja D30, było XMR)**
  do escrow multisig 2-z-3 + timelock; admin ma 30 dni: akcept → środki na skarbiec +
  wpis UNBAN_ACK; odmowa/timeout → zwrot 99%. (MVP D47: kwota ROBOCZA UNBAN_FEE_ISKRY
  wprost do skarbca; escrow+oracle kursu = backlog.)
- Unban NIE przywraca: PoU, streaka, reputacji, rangi (wszystko od zera); 1 wykup/wallet/historia.
- Re-ban po wykupie = permanentny (bez możliwości kolejnego wykupu).

## 10. IDENTITY BOND (moderowana broń, wdrożenie po M5)
- Role podwyższonego zaufania (seed-host, attestor k-z-n) mogą wymagać BOND_LOCK (parametr w M4).
- BOND_SLASH: potwierdzony nadużyciem → depozyt na skarbiec (+prop. 25% burn).
- Cel: "zaboli finansowo" bez dotykania sprzętu użytkownika (D21 — egzekucja sprzętowa odrzucona).

## 11. DRABINA KAR (fairness layer — patrz regulamin)
🟨 yellow (throttle, limit, obserwacja 7 dni, auto-reset) • 🟧 orange (read-only, hosting pauza,
grupy pauza, mnożnik kopania −50%, 14 dni) • 🟥 red (BAN_EVT; tylko konsensus k-z-n).
Yellow/orange bez interwencji człowieka; czerwony zawsze z uzasadnieniem PL/EN publicznie.

## 12. PARAMETRY OTWARTE (do decyzji właściciela — przed kodem M4)
1. BASE reward + krzywa emisji (limity jak 21M BTC czy stały strumień? halvingi?)
2. Podział wpłat za rangi (propozycja 50/50 burn/skarbiec)
3. Wartości progowe: slot BOND_LOCK, wielkości stropów nowych walleti (B4)
4. Ostateczna funkcja PoW (Argon2-lite vs RandomX-port) po benchmarkach
5. Prog k attestorów checkpointa na starcie (propozycja 3-z-5)

## 13. NIECECHY (zapisywalne nagłówkiem, żeby nie wracały za rok)
- FNX nie daje nikomu głosu zakupionego ani uprawnień administracyjnych.
- Node nie może "wykopać" reputacji szybciej niż zegar PoU — czas nie podlega magii.
- Konsensus nigdy nie czyta treści użytkownika; werdykty operują na wzorcach i hashach.
- Każda zmiana ekonomii = nowa wersja specu + 14-dniowe uprzedzenie (governance, §11 ToS).
