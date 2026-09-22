# Fenix / AnonNet — PLAN MVP: jak skleić system od A do Z
Data: 2026-07-19 | Zasada: najpierw CHODZĄCY SZKIELET, potem mięśnie.

## 0. Filozofia
Nie budujemy warstw 0→9 po kolei do perfekcji — nikt tak nie buduje systemów.
Budujemy CIENKĄ PRZEJŚCIOWKĘ przez wszystkie warstwy (szkielet), która już działa,
a potem ją pogrubiamy. Każdy kamień milowy = coś, co DA SIĘ URUCHOMIĆ i pokazać.

## 1. Mapa kleju (kto z kim rozmawia)
```
 ┌─────────────────────────────────────────────┐
 │  GUI / Dashboard        (oczy)        Faza 8 │
 ├─────────────────────────────────────────────┤
 │  Komunikator E2E + grupy + rangi      Faza 7 │
 ├─────────────────────────────────────────────┤
 │  AI-Sentry (sentinel.observe(event))  Faza 6 │
 ├─────────────────────────────────────────────┤
 │  Blockchain FNX + storage (ledger)    Faza 5 │
 ├─────────────────────────────────────────────┤
 │  Protokół P2P + routing onion/mix     Faza 4 │  node.send(wallet, bytes)
 ├─────────────────────────────────────────────┤
 │  Crypto core: Identity, E2E, Shamir   Faza 1 │  ✅ MAMY (fenix_crypto.py)
 ├─────────────────────────────────────────────┤
 │  Spoofing layer (kamuflaż)            Faza 2 │
 ├─────────────────────────────────────────────┤
 │  Fenix OS ISO (ciało)                 Faza 3 │  boot.asm ✅ / remaster
 └─────────────────────────────────────────────┘
```
KLEJ = kontrakty: każda warstwa wystawia 2–3 funkcje i NIC więcej nie wie o sąsiadach.
Dzięki temu testujesz każdą z osobna i wymieniasz bez rozbijania reszty.

## 2. Kamienie milowe (kolejność budowy!)

### M1 — "Pierwsze słowo" ✅ crypto gotowe → TERAZ: `net/fenix_node.py`
- 2 node'y na jednym komputerze (lub 2 laptopy w LAN): TCP, handshake,
  wymiana kluczy publicznych (Identity z fenix_crypto.py), wysłanie
  zaszyfrowanej wiadomości A→B i odczyt.
- SUKCES = widzisz na drugim terminalu odszyfrowany tekst i wallet nadawcy.

### M2 — "Przekaźniki" → `net/fenix_relay.py`
- 3. node jako relay: A→R→B (+ podstawa onion: warstwowe szyfrowanie hop-by-hop).
- Stub spoofingu (funkcja camouflage() najpierw tylko loguje co by zrobiła).
- SUKCES = B dostaje wiadomość, nie znając adresu A.

### M3 — "Komunikator" → `app/messenger.py` (CLI)
- Profile (Wallet+Username+UID+Ranga), kontakty, grupy, magazyn offline (later).
- SUKCES = rozmowa 1:1 i grupowa między 3 node'ami.

### M4 — "Rejestr" → `chain/fnx_chain.py` (mini-blockchain ~150 linii)
- Blok = {prev_hash, tx[], PoW}; górnictwo CPU demo; gossip bloków po P2P.
- Tożsamości + werdykty AI na blockchainie (te same bloby co fenix_crypto!).
- SUKCES = 2 node'y kopią i domykają się na identycznym łańcuchu.

### M5 — "Odporność" → `ai/ai_sentinel.py`
- Twarde reguły + statystyka + kapsuły sesyjne (D5), eksport kart zdarzeń.
- SUKCES = symulowany flood na node A → werdykt konsensusu + ban.

### M6 — "Okna" → GUI (CustomTkinter) + dashboard
### M7 — "Ciało" → Fenix OS ISO: remaster live-build (autostart Fenixa, spoof, amnezja,
  self-destruct). boot.asm zostaje jako demo edukacyjne.
### M8+ — dystrybucja: seed nodes, podpisane ISO, strona/web builder.

## 3. Ścieżka nauki (równolegle, 30 min dziennie)
1. Python: funkcje, klasy, wyjątki, pliki, moduły (potrzebne do M1–M3).
2. `socket` + `threading` — w praktyce, na naszych plikach (M1–M2).
3. `git init` od DZIŚ: commit po każdym działającym pliku (ratuje projekt przed Tobą 😉).
4. C/ASM — później, jako hobby (kernel od zera to najtrudniejszy element listy).

## 4. Uczciwe szacunki
- M1: 1–2 wieczory testów. M2–M3: kilka tygodni. M4–M5: 1–2 miesiące.
- Całość z GUI i ISO: realnie 6–12 miesięcy spokojnej pracy — i to jest OK.
- Zasada: jeden plik = jeden działający krok. Nigdy nie piszemy 3 plików "na zapas".

## 5. Co mamy już (2026-07-19)
- core/crypto/fenix_crypto.py  ✅ testy przechodzą (E2E + skarbiec progowy)
- core/crypto/fenix_cipher_demo.py ✅ lawina ~31/64
- core/crypto/fenix_wrap.py ✅ FNX-WRAP v1 (D2) — lawina ~63/128
- core/identity.py ✅ tożsamość (Wallet+Username+UID+Ranga) + anty-MITM profili
- boot/boot.asm ✅ kompiluje się do 512 B
- docs/decyzje_architektury.md ✅
