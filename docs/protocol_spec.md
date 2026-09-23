# FENIX PROTOCOL — Specyfikacja v0.1 (2026-07-19)
> Święta księga własnego protokołu (D13). Implementacja MUSI zgadzać się z tym plikiem.
> Zmiana specu = wersjonowany commit + nagłówek CHANGELOG na końcu.

## 1. ZASADY PROJEKTOWE (nie do negocjacji)
- **Zasada 0:** protokół nie przenosi metadanych użytkownika. Żadnych IP, MAC, fingerprintów,
  wersji klienta, locale, rozdzielczości. Frame zna tylko byty protokołu.
- **Zasada 1 (Kerckhoffs):** format jest jawny; bezpieczeństwo trzymają klucze i koszt ataku.
- **Zasada 2 (defensywny parser):** każde wejście jest śmieciem, dopóki nie zostanie udowodnione,
  że jest ramką. Brak deserializacji obiektów — tylko jawne pola binarne o stałych pozycjach.
- **Zasada 3 (jedna powierzchnia):** wszystko wychodzi warstwą camo (D10/D13). Żaden
  "szybki tryb debug/prosty socket" nie może opuścić laboratorium.

## 2. RAMKA (binarna, kolejność pól ZAWSZE stała; wielobajty = big-endian)
```
 offset  pole        rozmiar  opis
 0       MAGIC       2        0x464E ("FN") — szybka higiena, NIE uwierzytelnienie
 2       VER         1        wersja protokołu (0x01)
 3       TYPE        1        typ wiadomości (tabela §3)
 4       FLAGS       1        bitflagi: 0x01=RELAY, 0x02=ONION, 0x04=PADDED, 0x08=URGENT(control)
 5       SEQ         8        licznik sekwencyjny sesji (anti-replay, od 0, monotoniczny)
 13      LEN         4        długość payloadu bez paddingu (0..PAYLOAD_MAX)
 17      PAYLOAD     LEN      zaszyfrowana ładowność (sesyjny AEAD, §5)
 17+LEN  PAD         zmienna  dopełnienie losowym szumem do STAŁEGO rozmiaru ramki (§4)
 n-16    TAG         16       AEAD tag (XChaCha20-Poly1305) nad całością od MAGIC
```
- RAMKA_WIRE (po camo) ma ZAWSZE długość **1024 B** (segmant podstawowy) lub 4096 B (bulk).
  Mniejsze treści paduje się szumem; większe dzieli na segmenty ze wspólnym SEQ-group id w payload.
- Żadnych stringów w ramce. Żadnych nazw pól. JSON występuje TYLKO wewnątrz zaszyfrowanego payloadu.

## 3. TYPY WIADOMOŚCI (TYPE)
| kod | nazwa | kierunek | przeznaczenie |
|-----|-------|----------|----------------|
| 0x01 | HELLO | c→s | wywołanie handshake (§4) |
| 0x02 | HELLO_ACK | s→c | odpowiedź handshake + challenge |
| 0x03 | HELLO_FIN | obie | zakończenie handshake (MAC wiązania) |
| 0x10 | MSG | obie | wiadomość warstwy aplikacji (E2E payload) |
| 0x11 | RELAY_OPEN | c→r | otwarcie przekazu (warstwa cebuli) |
| 0x12 | RELAY_FWD | r→r | dalsza przekładnia cebuli |
| 0x13 | RELAY_CLOSE | obie | zamknięcie obwodu |
| 0x20 | PEERS_REQ | obie | prośba o próbkę peerów |
| 0x21 | PEERS_ADV | obie | ogłoszenie peerów (podpisane, ≤ 32 wpisy) |
| 0x30 | BLOCK_NEW | obie | nowy blok FNX (gossip) |
| 0x31 | BLOCK_REQ | obie | dociągnięcie zakresu łańcucha |
| 0x40 | TX | obie | transakcja FNX (gossip mempool) |
| 0x50 | VOTE_EVT | obie | zdarzenie konsensusu (werdykt, attestation) |
| 0x51 | BAN_EVT | obie | wpływający werdykt ban + uzasadnienie (D18) |
| 0x60 | PING / 0x61 PONG | obie | utrzymanie + pomiar (co losowe 20–40 s; NIGDY metryki w payload) |
| 0x7F | ERR | obie | błąd ogólny: 1 bajt kodu (§8) |

## 4. HANDSHAKE v1 (3 przebiegi, obustronne uwierzytelnienie Walletów)
```
c -> s: HELLO  { ver, x25519_pub_c, nonce_c (16B), podpis Ed25519_c (nad powyższym) }
s -> c: HELLO_ACK { x25519_pub_s, nonce_s, challenge = H(nonce_c|nonce_s|xpub_c|xpub_s),
                    podpis Ed25519_s (nad challenge) }
obie strony: key_enc = HKDF( X25519(x_priv, y_pub) | challenge , info="fenix/sess/01" )
c -> s: HELLO_FIN { AEAD(key_tmp)[ wallet_c, timestamp±30s, podpis_c(challenge|wallet_c) ] }
s -> c: HELLO_FIN { AEAD(key_tmp)[ wallet_s, akceptacja/odmowa ] }
sesja := AEAD(key_enc); SEQ=0
```
- WALLET jako AAD całej sesji: nie da się podmienić tożsamości w locie.
- Klucze jednorazowe per połączenie (forward secrecy, D1). Re-key co 2^20 ramek albo 1 h.
- Brak TLS, brak znanych nagłówków (D13). Camo opakowuje całość PO złożeniu ramek.

## 5. KRYPTO GRAFICZNIE
- Transport wewnętrzny: AEAD XChaCha20-Poly1305, klucz 256-bit; nonce = 12B pochodnej:
  nonce = H( key_enc, SEQ ) (SEQ NIGDY nie retransmitted / nie resetowany przed re-key)
- Warstwa E2E (użytkownik↔użytkownik) pozostaje w `core/crypto` (X25519+Ed25519 blob z fenix_crypto.py) —
  protokół przenosi te bloby TRANCZYWO (nie rozumie ich, nie otwiera).
- Onion (RELAY_*): każdy hop ściąga jedną warstwę AEAD (klucze per-hop z handshake per-hop);
  ładunek docelowy widoczny dopiero na ostatnim hopie.

## 6. PEER DISCOVERY & GOSSIP
- Bootstrap: podpisana lista seedów + fingerprint (ISO, M9). Potem gossip: PEERS_REQ/ADV.
- Próbka peerów: losowe ≤ 32, z podpisem ogłaszającego + podpisami PoU (reputacja).
- Limity: max 8 wychodzących, 32 przychodzące; max 2 peerów z jednego /16 (anti-eclipse).
- PING/PONG losowe okno 20–40 s (lista NIGDY: przedziały stałe).

## 7. ANTI-ABUSE NA WARSTWIE PROTOKOŁU
- Hashcash-ticket w HELLO (docelowy workfactor wg sentinel; normalnie ~2^18 prób/lokal)
- Token bucket na wiadomości (domyślnie 32 msg/s/peer; przekroczenie = ERR 0x03 i throttle)
- Rozmiar TIMEOUT handshake: 10 s; nieukończony handshake liczy się do limitu (max 3, potem backoff ×2 — D3)
- Każda ramka spoza okna SEQ (replay window 4096) = drop bez odpowiedzi

## 8. KODY ERR (celowo OSZCZĘDNE — błędy gadają atakującemu)
0x01 unauthorized • 0x02 bad_frame • 0x03 rate_limited • 0x04 banned
0x05 version_unsupported (razem z negocjacją min_ver) • 0x0F go_away
Żadnych stacków, wyjątków, nazw funkcji, linii kodu w ERR.

## 9. KONTRAKT DLA IMPLEMENTACJI
- Parser w trybie "strict bounds-check" na każdym polu; payload max 960 B/ramka 1024 B.
- Fuzz-wejścia 1 MB śmieci: parser NIE może się zawiesić, panikować ani ujawnić ścieżek.
- Test gold: wektory referencyjne z `tests/vectors/` (do M2: 3 ramki każdeo typu + 1 zła każdego pola).
- Wersja: VER różny od min_ver → ERR 0x05 i rozlaczenie. NIGDY negocjacja "jako tako".

## 10. CHANGELOG
- v0.1 (2026-07-19): wydanie pierwsze (ramka, typy, handshake, peer/gossip, ERR). Stan: DRAFT do M2.
- v0.2 (2026-08-03): implementacja MVP w `net/frame.py` (VER=2). Doprecyzowania vs v0.1:
  - AEAD = ChaCha20-Poly1305 (12B nonce, brak XChaCha w bibliotece runtime); CT=AEAD(PAYLOAD+PAD, AAD=nagłówek)
    — PRAWDZIWE szyfrowanie payloadu (odchyłka naprawiona: pierwsza iteracja liczyła AEAD „na pusto" = sam MAC i payload leciał jawnie; selftest mesh złapał b\"amount\" na drucie);
  - handshake zgodny z §4 w wariancie „HELLO = same efemeryki": c→s HELLO{eph_pub 32B}, s→c HELLO_ACK{eph_pub 32B}
    (na drucie czysty szum — zero portfeli/podpisów/JSON w plaintext), profile sygnowane lecą w HELLO_FIN pod kluczem,
    podpis nad {profil, eph_c, eph_s} (wiązanie kanału = odpowiednik challenge z §4), check_profile anty-MITM;
  - nonce = blake2s(klucz_sesji||SEQ)[:12]; replay okno 4096 (bitmapa) — jak §5;
  - segmenty >4063B: T_SYNC_PART(0x32) zamiast SEQ-group (MVP; SEQ-group z §3 wróci przy MSG w M4);
  - typy użyte w MVP: 0x01/0x02/0x03, 0x10/0x11 PING/PONG, 0x20 TX_SUBMIT, 0x21 BLOCK_NEW, 0x30/0x31/0x32 SYNC_*, 0x7F ERR.
