# 🔥 FenixOS — RAPORT DZIAŁANIA (nie projekcja: przejazd na żywych procesach)

> **Data:** 2026-08-09 · **Kod:** commit `d0ee540` (D68/D69) · **Audyt przy tym stanie:**
> **48/48 testów · 32/32 kontroli** (`tools/full_audit.py`, rc=0, ~3 min)
> **Dowód główny:** `tools/real_e2e.py` — **REAL-E2E: PASS ✅, 22 fakty, ~5 s**
>
> To jest raport „samego działania" na życzenie właściciela: **żadnych „powinno
> zadziałać"** — tylko to, co PRAWDZIWE procesy demona FenixNode zrobiły na
> prawdziwych gniazdach TCP/IPC, z liczbami i hashami, które każdy może powtórzyć
> (§„Jak odtworzyć"). PDF FenixRap tej rundy NIE robimy (decyzja właściciela).

---

## 1. Co zostało uruchomione (dosłownie)

Trzy niezależne demony `net.fenix_node` jako **osobne procesy** (osobne katalogi
danych, prawdziwe gniazda TCP i gniazda IPC unix), połączone łańcuchem seeds
A ← B ← C, plus czwarty proces (sam harness) gadający z nimi przez IPC:

```
A (45101…46101)  ←seed--  B (46102)  ←seed--  C (46103)
poster zadań              pracownik siatki     pracownik siatki
                          --ai-grid            --ai-grid
```

Ustawienia testowe (jawnie DEV): `--zbits 2` (trudność deweloperska), `--no-cover`,
`--sentinel off`, `--no-mine` (kopanie tylko w kontrolowanych burstach).
Wszystko inne = pełny produkcyjny kod: handshake AEAD, gossip, konsensus PoW,
ledger, mempool, ekonomia fee, usługi IPC, zapis łańcucha na dysk.

## 2. Fakty z przejazdu (verbatim z logu, run finałowy)

| # | FAKT z żywych procesów |
|---|---|
| 1 | P2P mesh żyje: peers A=1 B=2 C=1 (seeds→handshake AEAD→połączone) |
| 2 | rachunek D15/D50 dla donate 1 FNX: burn=1000 owner=55000 → skarbiec MUSI urosnąć o 100055000 iskier (liczymy do iskry) |
| 3 | A kopał w pojedynkę: h=0→4 (burst dev zbits=2, błyskawica — pauza) |
| 4 | po sync: A/B/C na h=4, wspólny tip `695817cd40c5cf3a…` (bloki A zaadoptowane przez B i C — księga leci przez mesh) |
| 5 | C kopał w pojedynkę: h 4→11 → po sync A/B/C znów ZBITOWO zgodne (h=11, tip `8476c150bd28…`) — łańcuch budują różne nody: decentralizacja |
| 6 | pokój cenowy na A: cena $0.0200 ask $0.0300 bid $0.0100 (podaż 55.00 FNX — krzywa z faktów łańcucha D65) |
| 7 | DONATE z C: txid `b15e62aba9ce…` kwota 1.0 FNX (saldo C przed: 35.0000 FNX z nagród kopania) |
| 8 | tx C dotarła gosipem C→B→A: wisi w mempoolu A (czeka na blok) |
| 9 | po bloku A (h=21) i sync: skarbiec na B **+100055000 iskier DOKŁADNIE** jak D15/D50; saldo C **−100056000 iskier** (kwota+fee) — ekonomia zgodna do iskry na 3 nodach |
| 10 | AI-GRID: zadanie `f730b6f3cc23…` ogłoszone z A (chain_hash 30000 iters, bounty 0.50 FNX, kworum 2; seed=tip `de3934932b39…`) |
| 11 | AI-GRID: 2 wyników od różnych walletów → kworum 2 → FINALNY recompute → settle paid=2 (nagrody TX_TRANSFER w mempoolu A) |
| 12 | settle.truth z demona == **niezależny recompute harnessu**; zwycięzcy = dokładnie wallets B i C (kernel deterministyczny, podpisy kopert zweryfikowane) |
| 13 | po bloku A (h=26) i sync: **B +50000000 iskier i C +50000000 iskier ZA WYKONANIE zadania** — siatka AI na mocy użytkowników działa end-to-end (D69) |
| 14 | census A: online≈3 znane=3 zarejestrowani=0 (ESTYMACJA gossip — D61 głośno) |
| 15 | census C: online≈3 znane=3 (drugi punkt obserwacji — różnice są uczciwą granicą, nie bugiem) |
| 16 | ban_status na A: własny wallet czysty; wallet C found=True banned=False (D66 lusterko konsensusu na żywym IPC) |
| 17 | pokój cenowy zgodny A==B ($0.0100) — krzywa liczy się ze wspólnego łańcucha, każdy węzeł pokazuje to samo |
| 18 | toggle ducha na C: ON→OFF przez IPC; stan z demona zgodny (D63 przelata) |
| 19 | A zatrzymane SIGINT-em (czyste zejście) przy h=26 |
| 20 | restart A z tego samego data-dir: h=26→26 — **łańcuch na DYSKU, nie w RAM** |
| 21 | A2 WRÓCIŁ do sieci (peers=2) i po sync znów jeden tip `3da8a9058bbd…` na h=26 — demon odzyskuje pełnię po ubiciu |
| 22 | logi demonów czyste: **ZERO Traceback** po całym scenariuszu |

## 3. Co to znaczy po polsku (odpowiedź na zamówienie, punkt po punkcie)

- **„Własna sieć P2P z szyfrowaniem + klucze + dodatkowe szyfrowanie"** — fakty 1, 8:
  demony łączą się handshake'iem AEAD (X25519+sesja, `net/frame.py` — 6 kroków
  selftestu PASS: replay-okno, glina-frame, chunking), a koperta zadania/wyniku i
  donate leci DODATKOWO podpisana Ed25519 (sig_pub+x_pub wewnątrz; wallet wyliczany,
  nie deklarowany). To szyfrowanie na dwóch piętrach: kanał AEAD + koperta sig.
- **„Decentralizowana AI zasilana mocą użytkowników"** — fakty 10–13: ZADANIE
  poszło z A przez mesh, DWA inne procesy policzyły je WŁASNYM CPU (wątek
  `--ai-grid`), wyniki podpisane wróciły, kworum 2 rozstrzygnęło, zamawiający
  zrobił finalny recompute i WYPŁACIŁ 0.5 FNX każdemu — salda zmieniły się
  dokładnie o bounty, na łańcuchu, na wszystkich nodach. To jest rura „oddaję
  moc — dostaję FNX". Kernel v0 = chain_hash (bieg próbny maszyny); wtyczka
  KERNELS czeka na cięższe zadania (batch-verify CLSAG pierwszy w kolejce).
- **„Wallet crypto FNX"** — fakty 7–9, 13: salda z nagród PoW (35 FNX u C),
  wydawanie przez tx podpisane w demonie, rozliczenie **co do iskry** (1 iskra
  = 10⁻⁸ FNX) na 3 niezależnych księgach po sync. Spalona część fee (1000 iskier)
  nikomu nie przyszła — deflacja by design (D15).
- **„Giełda FNX"** — fakty 6, 17: pokój cenowy FNX-COIN liczy cenę/ask/bid
  WYŁĄCZNIE z łańcucha (podaż 55 FNX ⇒ $0.0200; po wykopaniu kolejnych nagród
  podaż rośnie ⇒ $0.0100 — przeżywa rozcieńczenie, jak w modelu D65). Każdy
  węzeł pokazuje TO SAMO, bo liczy ze wspólnych faktów. Uczciwie: to szyba
  wystawowa (D67); sama kasa (kup/sprzedaj z railami) = P7 na właścicielu.
- **„Anonimizacja jednostki"** — fakt 18 + stan repo: duch D63 (brak reklamy
  własnego adresu, brak beacona) z JAWNYM nietwierdzeniem „=tor" (routing/timing
  zostaje — tak stoi w `--help`); warstwa priv łańcucha: stealth/CLSAG/ukryte
  kwoty (`chain/stealth.py`, `chain/clsag.py`, `chain/tx_hidden.py` — wszystkie
  PASS w audycie) = nasz „silent address": jednorazowe adresy odbiorcze z
  podwójnego klucza, bez linkowania płatności do walleta.
- **„Reszta z todo":** census (fakty 14–15), ban_status (16), ghost (18),
  restart/rejoin (19–21) — wszystkie odhaczone w TODO.md; E2 (challenge PoU),
  E3/E4/E5 (głosowania/grupy/multi-device) = kolejne etapy w plan_do_konca.md.

## 4. Kanapki złapane przy tej robocie (fixlog, z wagami — szczerze)

| Waga | Co złapał test | Fix |
|---|---|---|
| **WYSOKI** (harness, ale uczy o produkcie) | CLI demona domyślnie KOPJE od bootu (`mine=True`). Trzy nody dev na zbits=2 ≈ 400 bloków/s każdy → wieczny storm forków, „zbieg konsensusu" nigdy nie dochodził (RUN 1–3, w tym h=3996 rozjazd). | `--no-mine` na wszystkich + kopanie staggered (jeden naraz) + pigułka `sync` (op IPC) w pętli zbiegu. Od teraz brawa należą do konsensusu, nie do przypadku. |
| **WYSOKI** (mój nowy kod) | SentinelError: kind „grid" niezarejestrowany → `_sense` świadomie re-raisuje („nasz bug w karmieniu ma wywrzeć") → wątek peera B/C umarł na pierwszym T_JOB; zadanie wisiało bez wyników 180 s. | „grid" dopisany do KINDS_DATA w radarze (licznik meta, BEZ dziedziczenia progów msg — własne progi siatki = tuning P). Rerun: pełna zieleń. |
| ŚREDNI (narzędziowy) | `pkill -f net.fenix_node` matchował własną linię poleceń bash → zabijał shell zanim test wystartował. | Wzorzec z klasą znaków (`fenix_nod[e]`) — klasyka, odnotowane. |
| NISKI (przepis) | Stary szkic real_e2e miał `NameError` ({H}) i tolerancję zbiegu ±2 przy ruchomym celu. | Przepisany całkowicie na wariant staggered (zbieg do ZAMROŻONEGO tip-hash, nie „±2"). |

Żadna kanapka nie dotknęła krypto-konsensusu: ledger odrzucał błędy poprawnie
i każdorazowo było jasno CO jest artefaktem (saldo/hash/licznik), a co domysłem.

## 5. Granice — głośno (żeby nikt nie kupił więcej, niż jest)

1. **To dev-PoW (zbits=2) i loopback 127.0.0.1.** Nie jest to QA obciążeniowe (E7)
   ani multi-host przez internet (P2 = VPS-y właściciela). Retarget trudności z
   specu będzie pilnował tempa na produkcji.
2. **AI-GRID v0 = kernel chain_hash.** Siatka zadań/płatności działa; „AI" w
   sensie modeli = dopiero gdy kernel będzie sensowny i deterministyczny
   (batch-verify podpisów CLSAG już teraz jest realnie użyteczny przy syncu).
   Nagrody = tx zamawiającego po recompute (escrow covenant = roadmap); ms jest
   self-reported (etykieta, nie premia); zero zmian emisji w ledgerze.
3. **Giełda = krzywa + szyba.** Handel żywym rail-em = P7 (umowy operatora).
4. **Duch ≠ tor.** Anonimizacja warstwy net jak w D63 + granice w help.
5. **Census = estymacja lokalna** (brak centrali ⇒ brak WIELKIEJ PRAWDY o liczbie
   użytkowników; każdy węzeł mówi, co widzi).
6. **Radar siatki:** kanał „grid" zarejestrowany i liczony; dedykowane progi
   detektorów dla T_JOB/T_JOB_RES = praca P (nie przenosimy progów msg).

## 6. Jak odtworzyć (2 komendy)

```bash
cd FenixOS
python3 tools/real_e2e.py      # ~5 s, kończy się: REAL-E2E: PASS ✅ 22 fakty
python3 tools/full_audit.py    # ~3 min: 48/48 testów · 32/32 kontroli
```

Logi demonów przejazdu: `/tmp/fenix-real-e2e/{A,B,C}.log` (katalog tymczasowy).
JSON podsumowania przejazdu: końcówka stdout `real_e2e.py`; JSON audytu:
`/tmp/fenix_audit.json`.

## 7. Co dalej (propozycje wg plan_do_konca.md)

1. **E2** — `net/pou_challenge.py`: świadek PoU musi REALNIE odpowiedzieć (echo).
2. **AI-GRID krok 2** — kernel batch-verify CLSAG (realny zastep: przyspiesza sync)
   + op read-only podglądu siatki w GUI.
3. **E3** — `chain/proposal_evt.py`: tematy głosowań + quorum k-z-m (rura D60 gotowa).
4. FenixRap-v018 PDF — TYLKO na życzenie (ta runda świadomie bez PDF).

---
*Raport wygenerowany z FAKTÓW z żywych procesów; żadna linia nie jest obietnicą.*

---

## ⚠️ ERRATA (2026-08-09, przy D70/D71): fakt 20 był opisany NIEPRAWIDŁOWO

Przy rozbudowie orkiestry o kamerę drutową i drugi restart wyszło na jaw, że
**fakt 20 („łańcuch na DYSKU, nie w RAM") opisał zły mechanizm**: demon wtedy
w ogóle NIE zapisywał `chain.dat` (katalog data-dir miał tylko peers/stats) —
wysokość po restarcie wracała **od peerów przez sync**, nie z dysku. Dowód „od
sieci" byłby i tak dobry (decentralizacja!), ale opis kłamał — a my raportujemy
mechanizmy, nie narracje.

**Naprawa (D71):** demon teraz zapisuje łańcuch (stop + co 60 s) i czyta go przy
starcie replayem zerozufaniowym; real_e2e rozbija dowód na DWA restarty:
A2 **bez seeds** (h wyłącznie z pliku — 5 426 B, równość dokładna) i A3 z seeds
(rejoin+sync). Oba fakty przechodzą; szczegóły i nowy fixlog:
`docs/raport_sieci_fnx64_2026-08-09.md`.
