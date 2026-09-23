# 🛡️ FenixOS — RAPORT DZIAŁANIA SIECI P2P na własnym szyfrowaniu FNX64 „x tetracja do 10"

> **Data:** 2026-08-09 · **Kod:** commit `43361f3` (D70/D71) · **Audyt przy tym stanie:**
> **49/49 testów · 33/33 kontroli** (`tools/full_audit.py`, rc=0).
> **Dowód główny:** `tools/real_e2e.py` — **REAL-E2E: PASS ✅, 24 fakty, ~13 s**,
> stabilność **6/6 przejazdów**; kamera TCP na kanale C↔B (TcpSniffer).
>
> Zamówienie właściciela: „raport samego działania sieci p2p na własnym szyfrowaniu
> FNX64 x tetracja do 10". Bez PDF-a, bez printów-dekoracji — są bajty z drutu,
> liczby z demonów i kanapki, które po drodze złapaliśmy sami na sobie.

---

## 1. Jak sieć jest teraz zaszyfrowana (3 warstwy, po polsku)

```
TREŚĆ (tx/blok/zadanie siatki)
  └─ warstwa 0: koperta PODPISU Ed25519 (zawartość podpisana kluczami nadawcy;
     np. T_JOB/T_JOB_RES/tx — odbiorca sam wylicza wallet z kluczy w środku)
     └─ warstwa 1: AEAD ChaCha20-Poly1305 na sesji X25519-efemerycznej
        (klucz z DH jednorazowego + HKDF; nonce z blake2s(klucz‖SEQ))
        └─ warstwa 2: PELERYNA FNX64 — XOR strumieniem tetracyjnym
           (blake2s(k‖seq‖i)|1) ↑↑ 10 mod 2^64  ← „tetracja do 10"
           klucz peleryny = sess_key ⊕ DH ze STATYCZNYCH kluczy tożsamości
           (negocjowana polem „fx" w podpisanym HELLO_FIN — D70)
```

Dlaczego warstwa 2 coś wnosi (i czego nie wnosi — uczciwie):
- **Wnosi:** obserwator, który złamałby SAMĄ efemeryczną sesję AEAD (np. przez
  błąd implementacji DH), nadal widzi czarny ekran — peleryna potrzebuje
  DŁUGOTERMINOWYCH kluczy uczestników. To realny przyrost kosztu ataku
  pasywnego + utrudniony fingerprinting ruchu (znana struktura CT znika).
- **Nie wnosi:** odporności na przejęcie kluczy statycznych (wtedy padają obie
  warstwy naraz) i NIE zastępuje ChaCha20-Poly1305 — fundament zostaje
  standardowy i audytowany, FNX64 NIGDY nie leci solo na krytycznej treści.
- **Słowo-klucz:** tetracja mod 2^64 to konstrukcja właścicielska, nie
  prymityw certyfikowany światowo. Mierzymy dyfuzję (≈50% bitów różnicy
  między seq, 256/256 unikalnych bajtów) — to OBSERWACJA, nie dowód
  bezpieczeństwa. Granica zapisana też w module i w docs/decyzje D70.

## 2. Co widzi podsłuch na kablu (kamera TCP — dosłowne bajty)

`TcpSniffer` = głucha rura TCP wpięta między C a B (C łączy się przez proxy,
rura przepisuje bajty 1:1 i składa je do pliku; zero kluczy, kompetencje = ISP).

**Wynik z przejazdu (run stabilny):**
- przechwycone: **528 384 B** ruchu (handshake-efermeryki, bloki, tx donate,
  zadanie siatki, wyniki, sync-e, beacony)
- znaczniki treści: `ZERO` wystąpień — szukano literalnie: label zadania
  (`real-e2e-grid-batch`), nota donate (`real-e2e D68`), prefix walleta
  (`FNX1` — występuje w blokach i tx!), `"amount"`, `fenix-ai-grid`,
  `chain_hash`, `winner`
- entropia-w-malarzu: **256/256** unikalnych bajtów w strumieniu
- jawnie widoczne: **177 nagłówków** `FN\x02…` — TAK MA BYĆ: magic/typ/seq/len
  to meta protokołu (protocol_spec jawny), treść zawsze pod kluczem
- artefakt (pierwsze 48 B po pierwszym rekordzie, hex):
  `464e02300000000000000000010000000d17325390a9a31afb5643c0f8248192b800cd244abd573b30a6ccb3f7794f50`
  (`464e02 30` = „FN"+VER, typ T_SYNC_REQ — nagłówek; reszta to CT⊕peleryna)
- plik strumienia: `/tmp/fenix-real-e2e/wire_c_b.bin` (artefakt z przejazdu)

## 3. Całość gra razem (24 fakty z ostatniego przejazdu)

| # | FAKT z żywych procesów (FX na wszystkich linkach) |
|---|---|
| 1 | P2P mesh żyje: peers A=1 B=2 C=1 (seeds→handshake AEAD+peleryna→połączone) |
| 2 | rachunek D15/D50 dla donate 1 FNX: burn=1000 owner=55000 → skarbiec MUSI urosnąć o 100055000 iskier |
| 3 | A kopał w pojedynkę: h=0→3 (burst dev zbits=2) |
| 4 | po sync: A/B/C na h=3, wspólny tip `f515e5ff081e…` (bloki A zaadoptowane przez B i C) |
| 5 | C kopał w pojedynkę: h 3→5 → po sync znów ZBITOWO zgodne (tip `e8d96da48258…`) — bloki z DWÓCH nodów |
| 6 | pokój cenowy na A: $0.0400 ask $0.0500 bid $0.0300 (podaż 25.00 FNX — krzywa D65 z łańcucha) |
| 7 | DONATE z C: txid `6bcf056463a8…` 1.0 FNX (saldo C: 10 FNX z nagród PoW) |
| 8 | tx C gosipem C→B→A: wisi w mempoolu A |
| 9 | po bloku A (h=7) i sync: skarbiec na B **+100055000 iskier DOKŁADNIE**; saldo C **−100056000** — do iskry na 3 nodach |
| 10 | AI-GRID: zadanie `7f2b3ed6e723…` z A (chain_hash 30000 it, bounty 0.5 FNX, kworum 2; seed=tip `14d668ba4360…`) |
| 11 | AI-GRID: 2 wyniki → kworum → FINALNY recompute → settle paid=2 |
| 12 | settle.truth demona == niezależny recompute harnessu; zwycięzcy = dokładnie wallets B i C |
| 13 | po bloku A (h=8): **B +50000000 iskier, C +50000000 iskier ZA POLICZENIE** (D69 end-to-end) |
| 14-15 | census A: online≈2 znane=2; census C: online≈1 znane=1 (estymacje z różnych punktów — D61 granica) |
| 16 | ban_status na A: własny czysty; wallet C found=True banned=False (D66) |
| 17 | cena A==B ($0.0200 po rozcieńczeniu podaży) — krzywa ze wspólnych faktów |
| 18 | duch na C: ON→OFF przez IPC (D63) |
| 19 | A zatrzymane SIGINT-em przy h=8 |
| 20 | restart **bez seeds**: h=8 WYŁĄCZNIE z chain.dat (**5 426 B**, replay zerozufaniowy) — D71: naprawdę dysk |
| 21 | A3 rejoin: peers=1, po sync jeden tip `3844672876f0…` na h=8 |
| 22 | DRUT-PROOF: 528 384 B przez kamerę; ZERO wycieków markerów; 256/256 bajtów; 177 nagłówków (meta jawne — specem tak) |
| 23 | DRUT-HEX artefakt: `464e02300000000000000000010000000d17325390a9a31afb5643c0f8248192b800cd244abd573b30a6ccb3f7794f50` |
| 24 | ZERO Traceback w logach wszystkich demonów |

## 4. Kanapki tej rundy (fixlog — nasze własne, łapane testem)

| Waga | Co złapał test | Fix / status |
|---|---|---|
| **WYSOKI** | Demon w ogóle **nie zapisywał chain.dat** — „restart z dysku" w dawnym raporcie był tak naprawdę synciem od peerów. Brawo kamerze scenariusza, wstyd pisarzowi faktu. | D71: load przy starcie (replay zerozufaniowy) + flush stop/co-60-s; real_e2e dwa restarty (A2 bez seeds = tylko dysk; A3 = rejoin). **Errata dopisana do raportu z rana.** |
| ŚREDNI | `net/frame.py` uruchamiany jako skrypt padał na `ModuleNotFoundError: core` (import FNX64 na szczycie przed własnym selftestem). | Repo-guard `if __package__ in (None,"")` na górze modułu. |
| ŚREDNI (OTWARTY, P-OPEN) | **Flake 1/8 (fx2):** raz — wyniki siatki nie dotarły do postera w 180 s (topologia: discovery dolutowało bezpośredni kanał B↔C obok proxy). Potem **6/6 PASS**. Brak reprodukcji = jeszcze nie bug-fix. | Wpis do PROBLEMS_OPEN (TODO.md): jeśli wróci — re-broadcast zadania z anti-echo po treści + diagnostyka queue/results w statusie. Brama monitorowana przy każdym audycie. |
| NISKI | `pkill -f net.fenix_node` matchowało własną powłokę (zabójstwo shella). | Wzorzec z klasą znaków `[e]` — odnotowane na przyszłość. |
| NISKI | `cmd | tail; echo rc=$?` zwracało rc tail-a, nie pythona (fałszywe „rc=0" przy martwym teście). | Log do pliku + jawne `rc` — od teraz zasada w narzędziach. |

## 5. Granice (głośno — żeby nikt nie kupił więcej, niż jest)

1. **Dev-PoW (zbits=2) i loopback.** To brama poprawności, nie QA obciążeniowe
   (E7) ani multi-host (P2 — VPS-y właściciela).
2. **FNX64 to warstwa dodatkowa.** Bezpieczeństwo bazowe = ChaCha20-Poly1305 +
   X25519 + Ed25519; FNX64 = peleryna właścicielska, nie audytowany prymityw.
   Szybkość czystego Pythona ~0,08 MiB/s/wątek — mesh znosi (przejazd 13 s);
   przy wielkim syncu port do C, algorytm bez zmian (roadmap).
3. **Nagłówki FN są jawne** (magic/typ/seq/len) — to specem ustalone meta;
   rozmiary treści maskują kubełki 1024/4096 i losowy padding.
4. **chain.dat: okno straty ≤60 s** przy twardej śmierci zasilania (flush co
   minutę); zapis przyrostowy/kompaktacja przy wielkich łańcuchach = roadmap.
5. **AI-GRID v0:** kernel chain_hash (bieg próbny); ms self-reported; nagrody
   = tx postera po recompute (escrow = roadmap); kanał „grid" w radarze liczony
   — własne progi detektorów = tuning P.
6. **Duch ≠ tor**, census ≠ cenzus, giełda = krzywa+szyba (kasа = P7).
7. **Flake siatki (fx2)** — otwarty, patrz fixlog wyżej.

## 6. Jak odtworzyć

```bash
cd FenixOS
python3 tools/real_e2e.py        # ~13 s: 24 fakty + kamera drutowa, kończy się PASS
python3 core/crypto/fnx64.py     # selftest warstwy: wektory tetracji, dyfuzja, tempo
python3 net/frame.py             # selftest ramki: handshake, AEAD, replay, FNX64 7-8
python3 tools/full_audit.py      # ~4 min: 49/49 testów · 33/33 kontroli
```

Artefakty przejazdu: `/tmp/fenix-real-e2e/` — `A/B/C.log`, `wire_c_b.bin`
(surowy strumień podsłuchu, można grepować na własne markery — zero znalezisk).

---
*Raport = fakty z procesów i bajty z drutu. Tam gdzie coś jest obietnicą albo
granica — stoi to napisane wprost, najpóźniej w §5.*
