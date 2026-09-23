# 🔥 FENIX / AnonNet — MASTER TODO (kompletna mapa projektu)
> Aktualizacja: 2026-09-22 | **D72: port FNX64 do C 1:1** (`core/crypto/fnx64_accel.c`).
> Wieże idą hurtowo; C włącza się dopiero po złotym porównaniu z `tower_mod`.
> 64 KiB strumienia 0,51 s → 0,022 s (~23×). Brak gcc = ten sam strumień w Pythonie.
> Bity +x skryptów ISO przywrócone (zip bez unix-mode zostawiał `fenix-gui` jako 0644).
> Paczka: `pyproject.toml` + `python3 tools/pack_dropin.py` (patrz `JAK_DODAC.md`).
> Aktualizacja: 2026-08-09 (2) | **E-SEC ✅: D70/D71 — peleryna FNX64 „x tetracja
> do 10" na CT każdej ramki (negocjacja `fx` w podpisanym HELLO_FIN; klucz
> sess⊕static-DH — obserwator po złamaniu samej efemeryki ma czarny ekran) +
> kamera drut-proof (TcpSniffer: 561 152 B, ZERO wycieków markerów treści,
> 256/256 unik. bajtów) + D71: demon zapisuje/czyta chain.dat (replay
> zerozufaniowy; errata do raportu 08-09: „restart z dysku" był synciem!).
> Stabilność bramy: 6/6 przejazdów real_e2e (24 fakty, ~13 s).**
> Aktualizacja: 2026-08-09 | **E-AI ✅: D68/D69 — siatka AI-GRID v0 NA DRUCIE
> (T_JOB 0x42/T_JOB_RES 0x43, kworum k-zbieżnych + FINALNY recompute przed pay,
> opt-in `--ai-grid`; płatności TX_TRANSFER iskra-co-iskrę) + brama REAL-E2E:
> 3 ŻYWE demony, cały scenariusz (mesh→kopanie staggered→donate do iskry→
> AI-GRID z nagrodami→census/ban/price/ghost→restart z dysku→rejoin) = PASS
> 22 fakty/5 s. Raport bez PDF: docs/raport_dzialania_2026-08-09.md.**
> Aktualizacja: 2026-08-08 | Stan: M0–M5c gotowe; M5d (badges+donate+rangi-30d+admin)
> + auto-discovery P2P (D50–D54) 2026-08-06; M6 start (radar+tombstone) 2026-08-06;
> łatanie dziur D55 (ONB admina + attest + P0 seeds-file) 2026-08-06;
> D56–D57 (P20 zdjęte + ratchet cross-first) 2026-08-07; **D58: PoU on-chain
> (TX_POU_ATTEST 0x04 + status VOTER) 2026-08-07; D59+D60: ring świadków z łańcucha
> (sybil-hack zamknięty) + VOTE_EVT 0x07 urna dla VOTERa 2026-08-07*; D61–D64:
> licznik sieci (presence D61), airdrop 1M (0x15, D62), tryb ducha (D63), audyt mocy
> (D64) 2026-08-07 — zamówienie właściciela wg raportu z erratą**.
> **D67 (2026-08-08): POKÓJ CENOWY + karty Sieci w GUI — op price (read-only),
> toggle ducha, census w oknie, kartka banu; IPC nie handluje (twarda kontrola; plan etapów:
> docs/plan_do_konca.md).**
> **D66 (2026-08-08): STATUS BANU WIDOCZNY — ban_view/baner PL/EN
> (kod+powód+blok+furtką), IPC ban_status (read-only), GUI: baner przy rejestracji
> username i lookupu; power_audit 19/19 z ludzkim okiem nad opcją read-only.**
> **D65 (2026-08-08): GIEŁDA FNX-COIN (`app/fnx_coin.py`) — kupno+sprzedaż
> z desk-magazynu; cena ZMIENNA z faktów łańcucha (kapitał z users/attesterów/
> głosów/wysokości ÷ podaż Σsald): rozcieńczenie ↓ aktywność ↑, int-only, klon
> bit-w-bit; przycisk kursu ownera (D30) ZDJĘTY — stałe głosowalne VOTE_EVT.**
> **REMANENT 2026-08-07 (przy v012): odhaczone PoU on-chain, P18/P20/P21,
> fenix_crypto, eksport Shamira, zero-treści-w-logach; doprecyzowane gossip
> (peer-listy ✅), okno czatu (brakuje tylko grup), M6 głos VOTER (fundament ✅).
> Zostaje: P25-resztka (challenge-protokół/VOTE_EVT/zimna kropka), grupy M4c,
> link urządzeń, eksplorator banów, snowflake.
> (Szczegóły: PROBLEMS_OPEN w FenixRapv012.pdf.)**
> Zasada: jeden checkbox = jeden działający krok. Priorytet = pierwszy pusty od góry.
> Decyzje D1–D67: patrz `docs/decyzje_architektury.md` — TODO ich NIE przegłosowuje.

---

## 🧭 M0 — FUNDAMENT DOKUMENTACYJNY (zanim kolejna linia kodu)
- [x] `git init` + commit fundamentu (potem commit po KAŻDYm pliku)
- [x] Struktura: `core/ net/ transport/ app/ chain/ ai/ gui/ os/ docs/ tools/`
- [x] `requirements.txt`, `.gitignore` (klucze, seed, *.iso, *.img, __pycache__)
- [x] `README.md` (czym jest Fenix, jak testować, ostrzeżenie prawne/etyczne)
- [x] **`docs/threat_model.md`** — dziura #1: 3 scenariusze wroga
      (ISP/lokalny → państwowy → globalna analiza ruchu): co widzi / czego NIGDY
- [~] `docs/decyzje_architektury.md` — pilnować aktualności przy każdej zmianie
      (aktualne D1–D58; checkbox wiecznie [~] — praca ciągła, nie „raz i już")
- [x] **`docs/protocol_spec.md`** — święta księga własnego protokołu (D13):
      format ramki, versionowanie od dnia 0, handshake, rozmiary pakietów
- [x] **`docs/fnx_spec.md`** — święta księga blockchainu FNX (blok, trudność, opłaty,
      iskry, PoU na łańcuchu, skarbiec ownera)
- [x] Otwarte kwestie (odpisać w specach): emisja/limit FNX? halvingi? kiedy multisig skarbca?

## 🔐 M1 — CORE & CRYPTO (serce)
- [x] `core/crypto/fenix_crypto.py` — E2E (X25519+HKDF+AES-256-GCM+Ed25519) + Shamir k-z-n
      (selftest PASS ✅: E2E AEAD, wallet_addr FNX1, Shamir 3z5, panic-shred — stalej w full_audit)
- [x] `core/crypto/fenix_wrap.py` — **FNX-WRAP v1**: własna warstwa DODATKOWA (D2):
      Feistel 24 rund/128 b + własny S-box (perm. z SHA-512) + tryb CTR + HMAC-EtM;
      klucze z HKDF z osobnymi labelami; testy OK (lawina ~63/128, manipulacja odrzucana)
- [x] `core/identity.py` — Wallet + Username + UID + Ranga (start: "ghost");
      profil publiczny podpisany, anty-podmianka kluczy (check_profile), testy OK (8/8)
- [x] `core/keystore.py` — **kontener KS1 (D3/D9/D24)**: Argon2id→KEK owija losowy MEK→AEAD nad profilem
      (username+kontakty+klucze); **3×❌ = opóźnienie ×2** (2,4,8…300 s; destrukcji brak);
      **hasło paniki = cichy crypto-shred** (plik 2× nadpisany+skasowany, MEK wyzerowany w RAM);
      zapis atomowy chmod 0600; zmiana hasła = przewinięcie 32B wrapu (payload nietknięty);
      recovery = opcjonalne udziały Shamira MEK user-side (off, D9); testy OK (9/9, incl. E2E przez „restart")
- [ ] Rotacja kluczy (co N dni / na żądanie) + lista rewokacji (skompromitowany = martwy)
- [~] Brak recovery w protokole (D9) ✅ zachowane + OPCJONALNY export udziałów Shamira
      user-side ✅ (keystore selftest 9: 2 udziały otwierają, 1 = matematycznie nic);
      brakuje: osobne ostrzeżenie w UI przy eksporcie
- [ ] `core/config.py` — ustawienia, backup zaszyfrowany, wykrywanie OS/VM/GPU/uprawnień
- [x] Testy: Eve nie czyta / manipulacja odrzucona / skarbiec próg działa / panic = martwe
      (selftesty każdego pliku + bateria atakowa `tools/self_attack.py`)
- [x] **Self-attack (czerwony zespół)**: `tools/self_attack.py` — 32 scenariusze ataku
      (tamper/MITM/replay/downgrade/brute-force/shred/S-box) → raport `docs/crypto_attack_report.md`;
      wynik v1.0: 27 odparzone, 5 notatek projektowych, 0 przełamań; odpalać po każdej zmianie krypto

## 🌐 M2 — WŁASNA SIEĆ P2P (suwerenna, D13; bez znanych protokołów)
- [x] `net/frame.py` — ramka wg protocol_spec v0.2 (VER=2, AEAD **szyfruje** payload+pad; padding losowy; kubełki 1024/4096; replay okno 4096)
- [x] `net/fenix_node.py` — node: nasłuch + wybieranie połączeń, handshake efemeryczny + Identity (profile pod kluczem, anty-MITM)
- [x] **Auto-discovery (D54, decyzja właściciela 2026-08-06):** node SAM znajduje dostępne
      nody — adresownia = seeds ∪ cache `peers.json` (atomowa, 0600) ∪ gossip T_ADDR (0x40);
      pętla dobija do target_peers=4 z backoffem per-adres; **brak dostępnych nodów → po grace
      45 s uczciwie zostaje PIERWSZYM NODEM** (i seedem dla innych; tytuł oddaje gdy sieć
      się pojawi); bibliotecznie OFF, w demonie ON; test 8/9/10 ✅ (martwe seeds→pierwszy,
      sam cache→łączy, T_ADDR rozlewa adresy)
- [x] Katalog peerów: cache `peers.json` ✅ (D54; podpisany+na-chain = docelowo w M5) — MVP: seeds.list + mesh z selftestu
- [ ] Relay A→R→B: B nie zna A (pierwszy krok onion)
- [ ] **Cebula pełna:** warstwowe szyfrowanie hop-by-hop, każdy hop zdejmuje 1 warstwę
- [x] Ruch-drobiazgi: stały rozmiar pakietów (padding losowy do kubełków) — jitter-droga: do relay/onion
- [~] Gossip: wiadomości zarządcze (peer listy, werdykty, bloki) z podpisami — MVP: gossip
      tx/bloków z anti-echo ✅ + peer-listy T_ADDR ✅ (D54; wzajemny spis znanych adresów);
      werdykty k-z-n gossipem = później
- [ ] QoS w relayach: kolejki wagowe wg tieru rangi (wagi startowe — sekcja RANGI)
- [x] Test: mesh 3 node'y w jednym procesie ✅ (`python3 -m net.fenix_node`, 3×PASS) → [~] 2 maszyny w LAN: do potwierdzenia na żywym sprzęcie

## 🥷 M3 — KAMUFLAŻ (transport/camo — warunek startu sieci! D10+D13)
- [x] `transport/camo.py` — interfejs profili: send(pkt)->wygląda-jak-X
- [x] **Profil A (szum):** rekordy 4096B nieodróżnialne od losowych bajtów (cover po handshake; selftest chi²)
- [ ] **Profil B (mimikra):** wygląda jak normalne HTTPS/WebRTC (artykuły/streaming) — STUB (szczery NotImplementedError; fałszywa mimikra gorsza niż szum)
- [ ] Odporności profili na: fingerprint JA3/JA4, rozmiary, timing, active probing
- [x] `core/spoof.py` → zrealizowane jako `os/spoof.sh` (D6): MAC lokalny/unicast, hostname+machine-id losowe przy starcie
- [x] Szum sieciowy (cover traffic) — rekordy junk co 0.3–0.8 s w bezczynności, rytm nie zero-jedynkowy
- [ ] Testy przecieków Wiresharkiem: DNS, WebRTC, IPv6, timing ✅ — [~] wymaga VM/realnego ISO (M8); asserty drutu w selftest mesh zrobione
- [ ] (Research, później) Profil C: decoy routing przez prawdziwe strony
- [~] **MULLVAD WIREGUARD + ISO (D29 profil B):** `transport/mullvad.py` — własny keypair (X25519),
      rejestracja w API Mullvada (POST /wg/, token tylko w nagłówku, konto = 16 cyfr nie email),
      **kill switch nftables stawiany PRZED tunelem** (policy drop; tylko endpoint UDP + fnxwg0
      → padnie VPN, NIC nie wycieknie), config w RAM (/run/fenix) + shred, token zeroizowany;
      selftest offline 10/10 ✅; CLI `python3 -m transport.mullvad up|down|status` + ISO:
      `fenix-vpn.service` (opt-in przez /run/fenix/vpn.env RAM), wrapper /usr/local/bin/fenix-vpn,
      fwmark 51820 w bazowym nftables (WG outer); build_iso 49/49 ✅;
      prawdziwe up() = QA z kontem Mullvad na maszynie właściciela
- [~] **DNS-CAMO Profil D (D33):** `transport/dnscamo.py` — koder/bridge DNS (base32 qname ↔
      TXT), Mullvad jako czysty pierwszy hop; bootstrap/seeds-only (KB/s); selftest loopback ✅;
      [ ] do produkcji: domena-most + serwer autorytatywny + DoT/DoH 853/443
- [ ] **SNOWFLAKE_FNX (D29):** własny transport wolontariackich proxy po WebRTC (DTLS-SRTP),
      brokery sygnalizacyjne on-chain + AMP-cache; lepszy od Snowflake (bez warstwy Tora) — etapy M6

## 💬 M4 — KOMUNIKATOR (CLI → potem GUI w M7)
- [x] `app/messenger.py` — rdzeń M4/M4b: send/poll; kontakt = **FNXS1** (D35: fp jest tożsamością,
      username tylko etykietą); E2E **FNX-R1 ratchet (D43): PFS po kickach, nadawca ukryty
      w v2**; legacy v1 (eph-DH) czytane; dedup anty-replay na łańcuchu ratchetu;
      **TofuStore 0600+atom+shred (D9) + walizka TF1 (D40)**; selftest 15/15 ✅
      (impersonacja, flip bitu, replay, skip-okno, PFS-złodziej, TF1-roundtrip,
      concurrent-init D57, sesja nietykalna pod znany fp, utrata ramki z kickiem);
      **transport mesh T_MSG WDROŻONY (D37)** ✅ — relay w `net/fenix_node.py` (gossip
      bez mempoola/łańcucha, ttl=5, dedup, skrzynka RAM per fp, plasterki T_SYNC_PART),
      most `gui/backend_ipc.MsgIpcTransport` (opy msg_sub/msg_send/msg_poll — test 11)
      + wybór transportu w GUI (test 17: ON-LINE=mesh / OFF-LINE=lokalny);
      adresowanie po USERNAME→FNXS1 przez rejestr on-chain ✅ (P21/D45: TX_CONTACT_REF
      + resolver w GUI); **D57 ✅: concurrent-init (cross-first) = kanon mniejszego
      x_pub + kanały cand ≤4 FIFO — zbieżność w 1 RTT, deadlock zdjęty**
- [x] Rejestr username on-chain: `chain/usernames.py` + TX_ID_DECLARE 0x03 w ledgerze —
      claim (1 FNX anty-squatting) / rename (0.1 FNX, stara nazwa wolna natychmiast);
      first-come-first-served; regex ≡ core.identity (fuzz 300 nazw, zero rozjazdu);
      mempool też rezerwuje; replay/adopt odtwarza rejestr bit-w-bit; selftest E2E 10/10 ✅
- [~] Kontakty: TofuStore w app/messenger.py (pin fp→addr, 0600, shred; anty-impersonacja;
      **walizka TF1 = szyfr hasłem ✅ (D40 — KS1-wrap na kontaktach, test 6b+19)**;
      [ ] auto-eksport do kontenera D24)
- [ ] Grupy: klucz grupy rotowany przy zmianie składu; admin grupy ≠ admin sieci
- [x] Offline-buffer (D44): spool RAM+TTL 1h na relayu T_MSG (≤256 fp × ≤16 kopert,
      purge TTL; powrót odbiorcy = msg_sub przenosi do skrzynki; relay nadal widzi sam
      szum+fp; test 6b na 3 node'ach ✅)
- [x] Zero treści w jakichkolwiek logach — asercja w testach ✅
      (backend_ipc test 11/12: kill-słowa priv/secret/seed/text w logach demona i IPC = abort;
      sentinel: odmowa zapisu payloadu — test 7 ai_sentinel)
- [~] Test: 1:1 na 3 node'ach ✅ (T_MSG 6/6b: dostawa + offline-buffer); [ ] grupa

## ⛓️ M5 — BLOCKCHAIN FNX (łańcuch z node'ów; kopie=hostujesz; D15)
- [x] `chain/block.py` — blok {prev_hash, txs (coinbase/transfer podpisane), tx_root, timestamp, nonce}; PoU-zaświadczenia: osobny typ tx później
- [x] PoW CPU-friendly (argon2-lite 1MiB/t1/p1 + fallback sha256d; ~403× wolniejszy niż sha256d) + retarget co 144 bloki (clamp ±2, T=60s) — **robocze: §12 fnx_spec do domknięcia**
- [x] Jednostki: 1 FNX = 10^8 **iskier**; opłata: **0.001% burn + 0.055% skarbiec ownera** (selftest: dokładnie 1000/55000 iskier z 1 FNX)
- [x] **PoU on-chain (D12 → D58+D59, 2026-08-07):** `chain/pou.py` + `ledger.pou` — TX_POU_ATTEST
      0x04: wallet + okno-slot 30 min + ≥3 RÓŻNI świadkowie (podpis pod (wallet,window),
      świadek≠wallet, ≤8/payload, dedup chain+mempool, retencja 40d z timestampów bloków);
      **30 dni streaka (przerwy nigdy >72 h) z pokryciem ≥80% dni + żywa obecność ≤72 h
      = status VOTER** (deterministycznie, replay bit-w-bit); mnożniki §7 jako liczba
      (0.5/1.0/1.25); fee jak usługa rejestru (ppm→skarbiec, kopacz nic); tombstone też
      tu działa. **D59: RING ŚWIADKÓW LOSOWANY Z ŁAŃCUCHA** (seed blake2s(prev‖okno),
      kandydaci = attesterzy ≤4 dni z rejestru, bez sendera; spoza ringu = odmowa;
      bootstrap <3 jawny; szablon bloku filtruje stary ring) — sybil NIE wybiera
      sobie świadków. Uczciwie NIE tu: challenge-reachability („świadek REALNIE
      odpowiedział") = warstwa sieci M6c (P25)
- [x] **AIRDROP kamienia milowego 1M (D62):** `chain/airdrop.py` — TX_AIRDROP 0x15
      zdarzenie SYSTEMOWE: próg licznika usernames (roboczy §12), odbiorca = hash
      prev % sorted(names) z pominięciem zbanowanych, kwota 1–10 FNX deterministycznie;
      dokładnie 1/kamień; szablon wychwytuje sam; replay bit-w-bit; emisja ⚠️ §12
- [x] Gossip bloków (flood z anti-echo) + najdłuższy poprawny łańcuch z remisem na mniejszy hash (zbieżność) — checkpoint anti-51%: backlog
- [ ] Rozproszone hostowanie danych: fragmenty szyfrowane + mapa na-chain (proof-of-storage)
- [x] Skarbiec ownera: adres w genesis (DEV placeholder w chain/block.py; transparentny; multisig/threshold — backlog)
- [ ] Skarbiec progów Shamira dla danych sieci (z M1)
- [x] Registry rang on-chain (D46): chain/ranks.py + TX_RANK_UP — BUYABLE z ROBOCZYMI cenami
      (decyzja §12/P5), upgrade = dopłata różnicy, aktywacja po 6 confs, selite/fenix
      systemowe (TX odrzuca); GUI profil pokazuje onchain_rank+pending; selftest 5/5 + 20b ✅
- [x] Registry USERNAME on-chain (D28) ✅ + **TX_CONTACT_REF (P21→D45) ✅**: nick→wallet→FNXS1
      (tabliczka sig, op set/del; czat pisze po NICKU — GUI auto-rozpoznanie); selftesty 7/7 + 20a ✅
- [x] **Registry BANÓW on-chain (D47, TX_BAN_EVT 0x06) ✅**: `chain/ban_evt.py` — tombstone
      k-z-n (kropka ≥3/5 Ed25519, wpis niesie pub‖x→wallet bind; kod z ban_codes.txt +
      powód PL/EN ≤280 + hash dowodów, NIGDY treści); zbanowany: zero tx (poza wykupem),
      zero coinbase, mempool czyszczony; **wykup = 1/historia → skarbiec (D30; kwota
      ⚠️ ROBOCZA §12/P5, escrow+oracle = backlog), re-ban = na zawsze (D18)**;
      replay/adopt bit-w-bit; attestorzy = dev-hook (P25: zimna kropka zaszuta wydaniem);
      selftest 8/8 ✅; złapane: duplikat≠3-różni (błąd w teście), roster __main__≠pakiet
- [x] **TX_DONATE 0x14 (D50, decyzja właściciela 2026-08-06) ✅**: datek do skarbca ownera,
      KWOTA WYBORU UŻYTKOWNIKA (≥1 iskry); recipient MUSI być skarbcem (inny = TX_TRANSFER);
      100% kwoty + fee ownerskie → skarbiec; rejestr `ledger.donations` (kumulacja, replay
      bit-w-bit) napędza odznaki DONOR I/II/III; IPC `donate` (podpis w demonie) + kontroler
      GUI `donate_tx` + przycisk w Portfelu; selftest 5/5 + IPC 12 + GUI 21 ✅
- [x] **ODZNAKI profilu + grafiki (D52) ✅**: `chain/badges.py` — katalog 12 odznak
      (Właściciel Legitymacji, Strażnik Czasu I/II/III 100/1000h/10000h, Architekt 1×,
      Dobroczyńca I/II/III, Założyciel, Górnik ≥100 bloków, Czuwający ≥1 kropka k-z-n,
      Ptak Wczesny ≤blok 1000); verify=chain (bit-w-bit z konsensusu) vs verify=local
      (licznik własnego noda, gwiazdka w GUI); grafiki heksagonalne `gui/assets/badges/*.png`
      (8×128 px); panel IPC `profile` + pasek na Dashboardzie; selftest 8/8 ✅
- [x] **Rangi wygasają 30 dni (D51, decyzja właściciela) ✅**: `until = timestamp bloku +30d`;
      RENEW żywej rangi = pełna cena (+30d, stos ≤60d, bez resetu 6 confs); wygasła → ghost
      (konsensus z timestampów BLOKÓW, replay bit-w-bit); GUI pokazuje „wygasa za N dni";
      odznaka rangi gaśnie razem z rangą; selftest ranks 6/6 + badges 5 + GUI 21 ✅
- [x] **Konto admina Deimos (D53) ✅**: `core/admin.py` — username on-chain `deimos`
      (display „Deimos"), `<data_dir>/admin.ks` (KS1), hasło startowe Anon123! ⚠️ jawnie
      DEV-DEFAULT z czerwonym meldunkiem do zmiany (`change_admin_password`); prawa białą
      listą: attest_ban_dev (DEV-attestor k-z-n D47)/node_diagnostics/peers_view; ZERO
      przycisku ban i ZERO dostępu do treści; selftest 5/5 ✅
- [x] **ONB admin na ISO (D55, runda łatania dziur) ✅**: `gui/settings_admin.py` — wymuszona
      zmiana hasła Deimosa: walidacja (min. 10 zn., ≠fabryczne, ≠oczywiste, panika≠hasło),
      dowód aktualnego hasła (**uczciwy**: lock+re-unlock — create zostawia keystore
      otwarty, złapane selftestem), WERYFIKACJA z dysku (fabryczne martwe/wallet ten sam);
      GUI: czerwony meldunek na Dashboardzie + karta w Ustawieniach + **modal bez „pomiń"**
      przy pierwszym starcie okna; **attest wpięty w start demona**:
      `register_admin_attestor_boot` czyta publiczną wizytówkę `admin_attestor.json`
      (wallet, 0600; pisana przy create/login/zmianie) i wpisuje do rosteru k-z-n
      (`ban_evt.register_dev_attestor_wallet`) — fail-open (attest nigdy nie zabija noda);
      selftest settings_admin 6/6 + admin 6/6 + GUI 22 + E2E demon z argv ✅
- [x] **P0 seeds-file (D55) ✅**: fenix-node.service podaje `--seeds /etc/fenix/seeds.list`
      (ŚCIEŻKA), a parser robił `int('')` → demon na ISO by NIGDY nie wstał (2. dziura klasy
      „dispatch demona"); `_parse_seeds`: plik LUB `ip:port,ip:port`, `#` także inline,
      zły wpis = głośny SystemExit; strażnicy: build_iso §7a + full_audit 2×add;
      test mesh 11 + smoke demona z argv ✅
- [x] Test: 3 node'y kopią → identyczny łańcuch (zbieżność po pauzie); opłaty liczą się dokładnie ✅ (selftest fenix_node 3×PASS; [~] 2 maszyny: do potwierdzenia w LAN)

### 💱 M-EX — WŁASNA GIEŁDA FNX + monetyzacja (D32)
- [~] `app/exchange.py` — desk wymiany: kurs z owner-oracle (D30), wpłata PSC → kredyt on-chain
      (realna TRANSFER z portfela giełdy, podpis kluczem giełdy), limity dzienne per wallet,
      higiena PIN (tylko sha256 proof-of-redemption); selftest ✅ (gateway PSC: stub testowy,
      prawdziwy Paysafe API = po kontrakcie merchantskim; wypłaty fiat: NIE przez PSC — cash-in only)
- [ ] Paysafe merchant onboarding (poza kodem: MID, KYC operatora, limity PSC) → `PaysafeGateway`
- [~] **SWAP XMR → świeży FNX (D34):** `app/xmr_swap.py` — wash-desk: subadresy XMR, delay 30–120 min,
      rejestr RAM-only + TTL-shred 24h, fee 3%, kredyt on-chain; selftest ✅; [ ] monero-wallet-rpc
      (produkcja), stealth output ← M5b, multi-desk
- [ ] orderbook na promarket-węzłach + notowania on-chain (rynek zamiast oracla)
- [x] **GIEŁDA FNX-COIN (D65):** `app/fnx_coin.py` — kupno + sprzedaż z desk-magazynu;
      **cena ZMIENNA liczona z łańcucha** (krzywa v1: kapitał z users/attesterów/głosów/
      wysokości ÷ podaż Σsald — więcej wykopanego = rozcieńczenie ↓, aktywność = ↑;
      int-only, klon-replay bit-w-bit), spread 2%, podłoga 1¢, zero owner-oracle
      (przycisk kursu D30 ZDJĘTY — stałe głosowalne D60); desk NIE drukuje FNX
      (pusty magazyn=odmowa; inwariant no-mint z księgowaniem podaży w teście);
      sprzedaż: transfer na-chain → settle po bloku (kurs z księgowania), replay-
      strażnik txid; limity dzienne per kierunek; rail=świat zewnętrzny (P7);
      selftest ✅ 9 kroków (krzywa/determinizm/E2E kupno+sprzedaż/fail-path/limity)
- [~] ranga MARKET_MAKER: bond + wymóg płynności (koty obustronne); gui: zakładka „Giełda”
      — **E1/D67 (2026-08-08): pokój cenowy w GUI ZROBIONY (karta kursu na Dashboardzie,
      op IPC price read-only, źródło liczenia nazwane; SZYBA nie kasa)**; toggle ducha
      + licznik census na stronie Sieć ✅; czerwona kartka banu D66 na dashboardzie ✅
      [ ] kupno/sprzedaż z GUI: desk w demonie + rail (P7 — czeka na właściciela)
- [ ] ToS giełdy (fee wymiany 1% skarbiec operatora + PSC 5% kosztów; zadania prawne właściciela)

### 🔐 M5b — CHAIN PRIVACY na zasadach Monero (D31; własna, szyfrowana, prywatna FNX)
- [x] **Stealth addresses** — `chain/stealth.py`: odbiorca niewidoczny na-chain
      (jednorazowy punkt P=HsG+S na ed25519, DH przez X25519; własna arytmetyka punktów
      RFC 8032 — biblioteka nie wystawia add/mul); scan wykrywa „moje", świat widzi losowe
      (P,R); priv_ot·G == stealth_pub (wydobywalność gotowa pod ring); selftest 6/6 ✅
- [x] **Ring signatures** — `chain/ring_sig.py`: nadawca w pierścieniu wabików (LSAG-style
      na ed25519): podpis = „jeden z N", nie da się wskazać którego; KEY IMAGE
      (I = x·Hp[P_pi]) wykrywa double-spend bez ujawniania nadawcy; verify = jazda po
      kółku; wymaga GOŁEGO skalara (konsumuje priv_ot ze stealth.scan_stealth — interop
      przetestowany: jednorazowa moneta realnie podpisana ringiem); selftest 8/8 ✅
- [x] **Confidential amounts** — `chain/amount_hide.py`: Pedersen commitments
      (C = a·H + r·G; H z hasha + cofactor-clear → dlog nieznany nikomu); bilans tx
      weryfikowalny BEZ kwot (Σin − Σout − fee·H == 0); Borromean rangeproof per-bit
      (kwota ∈ [0, 2^64), inflacja zablokowana); pełny 64-bit proof = 6308B (bulletproofs
      backlog D31); szybki silnik punktów w stealth.py (~33×, równoważność testowana);
      selftest 7/7 ✅ (ring_sig przeszedł na FAST: 64 s → 1.7 s)
- [x] **Integracja z blockchainem (etap 3a):** `chain/tx_ring.py` + patch `chain/ledger.py`/`block.py`
      — **TX_SHIELD 0x11** (konto→pool, debet jak transfer + fee D15, wyjście stealth) i
      **TX_RING 0x10** (pool→pool: ring 5..11 memberów tego samego nominału, key-image
      anti-double-spend, Σin=Σout+fee, fee D15 → kopacz bloku (D39); bez konta/nonce = sender anonimowy);
      pool + key_images w stanie ledgera, replay/adopt_chain odtwarza bit-w-bit; selftest E2E 7/7 ✅
      (prawdziwy PoW+ledger; fałszerstwa/druk/double-spend odrzucane). **Kwoty etap 3a JAWNE**
- [x] **Etap 3b: CLSAG + KONSENSUS v2** — rdzeń `chain/clsag.py` ✅ (D36) + wpięcie do
      ledgera: `chain/tx_hidden.py` ✅ (D38) — SHIELD v2 (bramka: amt+r_pub publiczne,
      C==commit wiązanie, suma==spalenie; pool trzyma C+blob, **brak amt**), RING v2
      (pełna mgła: MLSAG+RP+KI w `_validate_economics` i `add_tx`), migracja 3a działa
      (v1-spend OK; ring v2 odrzuca członka v1 i odwrotnie), dedup ki WSPÓLNY v1+v2,
      lookup v2 mempool-aware (v≡1 szkoła); decoys bez nominalizacji (kwoty ukryte →
      wabiki dowolnych kwot); selftesty: clsag 7/7 ✅ + **tx_hidden 9/9 ✅ E2E**
      (mint/wejście/mgła/double-spend/drukarnia/migracja/mempool-lookup).
      **Fix loop:** c0=c[idx] (powinno c[0]) + kanon msg ≠ kanon weryfikatora (clsag)
      + **P0 inflacja 3a: SHIELD v1 z N wyjść kredytował N× tx.amount** → v1=DOKŁADNIE
      1 wyjście (hardening mempool+blok, test 9/9) — wszystkie złapane testem.
      Następnie: UNSHIELD v2 (wyjście z mgły), GUI pool v2 (M7d), bulletproofs (krótsze proofy)
- [x] **UNSHIELD v2 (0x12) + fee do kopacza (D39)** — wyjście z mgły na konto z jawną kwotą Y
      (public `Y·H`, jak z→t w Zcash): `ΣpseudoOut == ΣC_out + (Y+fee)·H`, ki zamykane, reszta
      wraca do mgły; **fee 0.055% → kopacz bloku w coinbase** (skarbiec tylko z ID_DECLARE);
      tx_hidden 11/11 ✅. **Fix loop:** pseudoOut per wejście (D41) — MLSAG wielo-wejścia
      (złapane testem M7d 3-wejścia; stara konstrukcja = tylko 1 wejście); bilans jawnie
      liczbami w build (fail-fast); fallout D39: tx_ring/usernames salda o zwrot fee kopaczowi ✅
- [x] **GUI pool v2 (M7d)** — Pool pokazuje monety w mgle (scan C/blob, ki-filtr, licznik v2),
      wysyła ringiem v2 (wielo-wejście, decoys dowolnych kwot), wtapia (SHIELD v2) i wypłaca
      (UNSHIELD); cienki tłum mgły odrzucany po polsku; pool_panel 9/9 ✅, fenix_gui test 18 ✅
- [x] **Walizka TF1 na kontaktach (D40)** — TofuStore szyfrowany hasłem właściciela
      (b"TF1"+Argon2id+ChaCha20-Poly1305, AAD=b"TF1/tofu"; jak KS1 na keystore); brak/złe
      hasło → odmowa; unlock trzyma szyfr przy save; legacy plaintext czytany; GUI
      `msg_tofu_protect/unlock/status`; messenger 9/9 ✅ (test 6b), fenix_gui test 19 ✅
      Następnie po v2: bulletproofs (krótsze proofy niż Borromean 6308B), emisja §12
- [x] **chain.dat — persystencja łańcucha (D42, P6 zdjęte)** — `Ledger.save_chain/load_chain`:
      b"FCD1"+blake2s+kanon JSON; zapis atomowy 0600; wczytanie = REPLAY pełnym
      konsensusem od genesis (PoW/linki/ekonomia/ki/rp — plik = obcy łańcuch jak z sieci,
      podmiana salda odpada na walidacji, test 7-8) ✅
- [x] **FNX-R1 ratchet PFS (D43, M4b/P22 zdjęte)** — mini double-ratchet (Signal-szkoła):
      mk=HMAC(ck) 1× + ck tylko naprzód; kick X25519 przy zmianie kierunku; koperta v2
      UKRYWA nadawcę (brak from/eph na jawie); dedup na łańcuchu (skip ≤32 + prev 1) —
      zamieszanie mesh legalne; PFS UDOWODNIONY testem: złodziej z długim kluczem + pełnym
      drutem czyta co najwyżej do 1. kicka; stan: RAM albo pod TF1, nigdy jawny tofu;
      v1 legacy czytane; selftesty 9a-9d ✅
- [x] **P24: concurrent-init ratchetu (D57, runda łatania 2026-08-06) ✅** — cross-first
      (obie strony piszą pierwsze „na krzyż"): kanon = root0 strony o MNIEJSZYM x_pub
      (obie liczą z adresów FNXS1), skrzyżowany łańcuch = kanał-czytanka `cand` (≤4,
      FIFO, sam odczyt); zbieżność w 1 RTT, rooty identyczne; grająca sesja NIETYKALNA
      dla „nowego nadawcy" pod znany fp (multi-device bez linku = drop; link = M4c);
      testy 13/14/15 ✅ (dawniej: case3 nadpisywał stan → deadlock rozmowy)
- [ ] Transparentny tryb = tylko dev/test; produkcja prywatna domyślnie
- [x] Test: łańcuch nie ujawnia nadawcy/odbiorcy/**kwoty**; węzły walidują mimo ukrycia ✅
      — nadawca ✅ (ring), odbiorca ✅ (stealth), kwota ✅ konsensus v2 (tx_hidden 9/9:
      payload i pool = zero liczb dla RING v2; węzły walidują MLSAG+RP mimo mgły)

## 🛡️ M6 — AI-SENTRY (radar, nie grabarz; D4/D5)
- [x] `ai/ai_sentinel.py` (D48) — `observe(event) -> werdykt`; warstwa 1 reguły (progi
      wersjonowane z ban_codes §4) + warstwa 2 statystyka (okna 1-s, godziny-persist)
      w jednym pliku; detektory MVP: 0x11 flood / 0x12 bad-TAG / 0x15 replay / 0x16 hello-farm
- [x] **Kapsuły sesyjne:** RAM ring-buffer kart (deque; telemetry=off → karta nie wpada),
      zero dysku, `purge()` = SPAL klucz sesji (test 10); cichy+czysty peer znika z RAM po dobie
- [~] Karty zdarzeń <100 B ✅ (krotka meta; treść/payload/text = SentinelError — zero-treści
      jako FUNKCJA, test 7); [ ] losowe okno 20–40 min + transport kart przez cebulę (jak relay)
- [x] Werdykt k-z-n → ban-lista na-chain ✅ (TX_BAN_EVT 0x06, D47 — kropka≥3/5 podpisów
      Ed25519 na core; [ ] threshold-sign 1-kluczowy zamiast listy = backlog kryptograficzny)
- [x] **Prawo głosu w werdyktach: tylko VOTER (PoU ≥30 dni)** ✅ (D60, 2026-08-07:
      `chain/vote_evt.py` — TX_VOTE_EVT 0x07, brama = pou_status z b.timestamp,
      1 głos/temat/wallet, replay-strażnik; Sybil out kosztem: ring świadków
      wybiera łańcuch — D59). Brakuje (P10): rejestracja tematów + zamykanie
      głosowań/quorum — multi-sentinel ma już rurę
- [x] **Licznik sieci (D61, M6d):** `net/presence.py` + T_PRES 0x41 — beacony
      podpisane co 5 min (dedup anty-echo, kubło częścią podpisu), online = sygnały
      z 10 min (cisza = spadasz sam); op census (IPC): online≈ ESTYMACJA z etykietą
      metody + registered (usernames on-chain) + attestujący PoU + kamień airdropu;
      duch się nie liczy (D63). Uczciwie: estymacja lokalna, NIE cenzus (brak centrali)
- [x] **Tryb ducha (D63):** `--ghost` + IPC ghost + set_ghost w locie — nod NIE
      reklamuje własnego adresu (T_ADDR bez self) i NIE rozsyła beacona; gossip/
      AEAD/kopanie jak zawsze; granice jawnie (routing/timing zostaje — ≠tor).
      [ ] przycisk ducha w panelu Sieć GUI (kontroler/IPC już gotowe)
- [x] Reakcje schodkowe ✅: none → pamietaj → throttle-7d+komunikat → wniosek-do-kropki-k-z-n
      (**AI NIGDY nie banuje, nie dotyka danych, nie self-destruct** — test 10);
      [ ] rotacja trasy/lockdown = po onion-relay (M2 backlog)
- [x] Suwak telemetrii ✅: off / minimal / full (domyślnie: minimal; off = radar zasłonięty)
- [ ] (Skala 10k+) Warstwa 3 ML lokalna + Warstwa 4 federated (wagi, nie dane)
- [x] **AI-GRID v0 (D69, 2026-08-09):** `ai/fnx_ai.py` + drut T_JOB 0x42 / T_JOB_RES 0x43
      w nodzie — zadania deterministyczne (kernel chain_hash), koperty sig-wire (wzór D61),
      kworum k-zbieżnych + FINALNY recompute PRZED płatnością, rate-limit 8/min/wallet,
      opt-in `--ai-grid` (relay zadań = zawsze; liczenie = nigdy po cichu, sufit 250k it),
      nagrody TX_TRANSFER podpisywane w demonie; kanał „grid" w radarze (KINDS_DATA);
      [ ] kernele cięższe (batch-verify CLSAG; embeddingi gdy będzie deterministyczny
      silnik), [ ] escrow covenant, [ ] własne progi siatki w radarze (dziś: tylko licznik)
- [x] **Brama REAL-E2E (D68, 2026-08-09):** `tools/real_e2e.py` — 3 ŻYWE demony (osobne
      procesy/katalogi/gniazda): mesh AEAD, kopanie staggered DWÓCH nodów, zbieg do
      tego samego tip-hash, DONATE iskra-co-iskrę przez gossip, AI-GRID z nagrodami
      on-chain, census/ban_status/price/ghost przez IPC, SIGINT-restart z dysku +
      rejoin, zero Traceback; test E2E wpięty w `tools/full_audit.py`. Rozbudowa
      E-SEC: kamera TcpSniffer (drut-proof na bajtach) + dwa restarty (dysk vs rejoin)
- [x] **FNX64 „x tetracja do 10" (D70, 2026-08-09):** `core/crypto/fnx64.py` + wpinka
      w `net/frame.py` — peleryna XOR ze strumienia tetracyjnego (↑↑10 mod 2^64) na
      CT każdej ramki PO AEAD; negocjacja `fx` w podpisanym HELLO_FIN; klucz
      sess⊕static-DH (niezależny koszt obserwatora); kompat: peer bez flagi = czysty
      AEAD; [x] port do C 1:1 (D72, 2026-09-22: `fnx64_accel.c`, batch uint64,
      złote wektory zanim C wejdzie na drut; ~23× na 64 KiB; fallback Python),
      [ ] niezależny przegląd konstrukcji (na razie: statystyka dyfuzji = OBSERWACJA, nie dowód)
- [x] **Trwałość chain.dat u demona (D71, 2026-08-09):** load przy starcie (replay
      zerozufaniowy — plik to NIE zaufany dysk) + flush stop/co-60-s (okno ≤60 s
      JAWNIE); kanarek tej roboty: demon wcześniej NIE zapisywał łańcucha wcale
      (erratowane w raporcie 08-09); [ ] zapis przyrostowy + kompaktacja przy dużych
      łańcuchach (roadmap)
- [x] **Flake siatki (fx2, 2026-09-22):** przyczyna nie była „dedup-stój", tylko
      pętla seedów — `_handle_conn` wraca od razu, więc co ~1 s zrywała ŻYWE
      gniazdo i gubiła T_JOB_RES w locie, a martwy peer zostawał w książce.
      Teraz sesja żyje aż padnie (krótka = backoff, nie młotek), reader zdejmuje
      peer-a, nowy kanał dostaje dosyłkę znanych zadań+wyników (cap 16/32),
      wynik przed zadaniem czeka w buforze i wchodzi do kolektora po rejestracji.
      Kokpit: `early` + `res_cached`. Test mesh 1b+13 ✅. Escrow i cięższe
      kernele = nadal roadmap D69, nie ten fix
- [x] AI-Sentry = WYŁĄCZNIE owner/admin (D17) ✅: żadnego kanału do użytkownika; werdykt
      = kod powodu + dlaczego PL/EN (z REASONS_RED/ban_codes); status() = same liczby
- [x] Test: symulowany flood → detekcja → werdykt → ban ✅ (testy 4-5 + złączone koło E2E
      test 9: wniosek → kropka 3/5 → TX_BAN_EVT → tombstone; selftest 10/10 ✅)
- [x] **P26 (D49): fenix_node karmi Sentinel żywym ruchem + enforce ✅** — msg per źródłowy
      peer (T_MSG), AEAD→bad_tag / okno SEQ→replay (szew FrameError), hello_fail per addr:IP,
      sync = Safe Harbor osobno; YELLOW → kubełek 8 fps/16 burst PO AEAD (nadmiar cicho ginie,
      TTL sam gaśnie), RED → rozłączenie lokalne (obrona własna; BAN = tylko kropka D47)
      + AUTO-szkic make_proposal (mapowanie fp→wallet rozwiązane: handshake daje prawdziwy
      wallet — podpisy HELLO); widok operatora przez IPC sentinel/sentinel_peer/
      sentinel_proposals (0660); CLI --sentinel; test 7a-c na ŻYWYM mesh 3-node ✅
      (złapane: proposals bez auto-odpalenia, nawak ewaluacji 1/s wymaga rozwleczenia testu)

## 🖥️ M7 — GUI & UX
- [~] `gui/fenix_gui.py` (Tkinter/ttk clam, ciemny motyw Feniksa, PRZEJRZYSTY i ŁADNY):
      **kontroler oddzielony od widoku** (logika headless-testowalna, 12/12 ✅); panele
      Dashboard/Portfel/Kontakty/Sieć/Ustawienia; dashboard: saldo/wysokość/pool/peerzy;
      panic-bar D27 + konto Mullvad w Ustawieniach; CLI dev-demo (`--demo --no-window`);
      pełny widok = QA pod X11/openbox (ISO)
- [x] **Profil edytowalny (D28):** username (zajętość z rejestru on-chain — walidacja
      claim/rename + fee z chain/usernames), avatar (ref-hex), badge rangi KOLOROWA
      (WYŚWIETLANA, nie edytowalna — set_rank zawsze odmawia, test); display_name = username BEZ UID (test!)
- [~] Okno chatu (1:1/grupy) z adresowaniem po USERNAME (D28), kontakty, ranga + historia reputacji —
      resolver w GUI ✅ (Kontakty, TOFU-sloty); **okno czatu E2E po FNXS1 w zakładce Kontakty ✅**
      (test 16: drut bez plaintextu, TOFU pin, replay drop, podszywka = OSOBNY kontakt);
      mesh T_MSG ✅ (P18/D37) + adresowanie po username on-chain ✅ (P21/D45);
      brakuje: okno GRUP (M4c)
- [~] PANIC BUTTON: `gui/panic_button.py` — wielki czerwony **hold-2 s** (próg jak D27);
      sekwencja = TEN SAM kod co os/fenix_panicd.py (loader po ścieżce, bo os/ nie-pakiet — test!);
      idempotentna + ubeczka FENIX_PANIC_DRY=1 (test); logika 8/8 ✅, widok = QA pod X11
- [~] „Czysty ekran" — Shift+Esc + przycisk pod panic-bar: hooki czyszczące + strażnik
      martwych widgetów (wpisy znikają z RAM widgetów); logika ✅, widok = QA pod X11
- [x] **Suwak paranoii (D29):** A szum → B DNS-camo → C + Mullvad WG z kill switchem;
      **C NIE WEJDŹE bez aktywnego fenix-vpn (test)**; uczciwe opisy granic każdego poziomu;
      snowflake_fnx = roadmap D29 (po mimikrze)
- [~] **VPN w GUI:** status/up/down z wątku roboczego (nie zamraża UI) ✅ + **vpn.env writer M7b ✅**
      (gui/panic_button.py: konto 16 cyfr, 0600, atomowy rename, „Zapomnij konto" = shred 2× nadpis);
      ISO: `tmpfiles.d/fenix.conf` stawia /run/fenix 0770 root:fenix (build 53/53); live-QA = P15
- [ ] Ustawienie paranoid: „aktualizacje tylko ręcznie po kliku" (D14)
- [ ] Wykresy: ruch, uptime, zdrowie sieci
- [~] **Zakładka Pool (M7c):** `gui/pool_panel.py` — moje coiny (scan stealth + filtr key-images:
      wydane zostają w poolu jako wabiki, Monero-style), adres prywatny **FNXS1** (sig‖x pub
      + checksum blake2s — anty-literówka), plan wysyłki (coiny+fee z fee_split, reszta do siebie,
      błędy po polsku), TX_RING z ringów ≥5 wabików; IPC ops pool/pool_decoys/pool_mine
      (**spend_hint NIGDY nie leci drutem — GUI liczy priv_ot lokalnie, test!**);
      selftest 8/8 ✅ E2E (bob dostaje anonimowo, double-spend odrzucony 2×); widok = QA pod X11
- [~] **IPC do demona fenix-node** (`gui/backend_ipc.py` M7b): gniazdo unix /run/fenix/node.ipc
      (0660, tmpfiles.d), NDJSON, biała lista opów (status/peers/mining/submit/balance/nonce/sync),
      anty-DoS 64 KiB+timeouty, klient z backoffem 3 s; node: `--ipc/--no-ipc` + **mining_on()**;
      kontroler: dashboard/saldo/nonce/submit przez most, fallback dev gdy demon martwy (test!);
      panel Sieć: mining start/stop+sync; selftest 9/9 ✅ (E2E z prawdziwym Node);
      **ZLAPANY BUG:** `python3 -m net.fenix_node` bez dispatchu ZAWSZE odpalał selftest —
      fenix-node.service nigdy nie wystartowałby demona na ISO → fix (__main__: flagi=demon),
      strażnik w build_iso; **P20 zdjęte (D56): żywy test 2 procesów (spawn demona z argv +
      klient GUI pełna runda opów + SIGINT czysty; backend_ipc selftest 13) ✅**;
      widok pod X11/openbox dalej = P17 (ISO)
- [~] Odznaka rangi w profilu ✅ (D52: badgy chain+local + panel + 8×png ikon) +
      zakup/upgrade rangi ✅ (D46/D51: TX_RANK_UP w GUI profilu, wygasanie 30d/renew) —
      brakuje: publiczny eksplorator banów (kod powodu + wyjaśnienie z ban_codes.txt)

## 💿 M8 — FENIX OS ISO (remaster, D8)
- [x] **`docs/iso_plan.md`** v0.1 — BoM projektu, strategia live-build, zapieczętowany boot, hardening, QA
- [x] **`docs/boot_security.md`** v0.1 — matryca 6 ataków „przejęcia kodu", pipeline zapieczętowanego payloadu (Shamir 3-z-5 seedów), boot flow, QA
- [~] `os/live-build/` — Debian live-build, profil FENIX
      (auto/config + package-list + hooki 0100/0200 gotowe; selftest ✅; `lb build` ← na Twoim Debianie)
- [x] **Zapieczętowany ładunek kodu (boot_security §3)**: `os/fenix_payload.py` — kod na ISO
      jako payload.enc (chunked AEAD + manifest podpisany + klucz do Shamira 3-z-5 na seedy;
      klucz NIGDY na ISO); SEALED build: kod NIE leży jawnie; boot agent wypakowuje do
      /run/fenix-payload (tmpfs) i robi self-check hashy. Selftest 7/7 ✅; udziały od seedów ← M5
- [ ] Boot: **UEFI + Legacy** (test obu w VM)
- [~] Autostart Fenixa; amnezja: tmpfs, **swap OFF**, hibernacja OFF
      (hook 0100: maski/journald-volatile/fstab-tmpfs ✅; QA w VM ←)
- [~] `os/spoof.sh` — MAC/hostname/machine-id losowe przy KAŻDYm boot
      (generatory + walidatory + dry-run: SELFTEST PASS ✅; ścieżka `--apply` ← test w VM przy budowie ISO)
- [~] Firewall startowy: fail-closed (cały ruch tylko przez FNX-camo albo DROP) zanim wstanie GUI
      (`includes.chroot/etc/nftables.conf`: DROP all poza DHCP i uid 1088=fenix, DNS/NTP poza camo = DROP;
       spójność uid pilnuje `build_iso.sh --selftest` ✅; zachowanie potwierdzi QA w VM)
- [x] **Okablowanie sieci ISO**: `fenix-spoof.service` (Before=network-pre) → nftables →
      `fenix-netup` (self-check fail-closed + reach seedów) → `fenix-node.service` (User=fenix,
      `--profile A --seeds`, na kod M2/M3); `seeds.list` DEV-placeholder + `os/verify_iso.sh` (D14);
      **SELFTEST paczki: 35/35 PASS ✅**
- [ ] Anti-forensic: **wyzwalacz paniki = Del+PageUp 2 s (D27)** → `os/fenix_panicd.py` wykonuje
      crypto-shred kontenera D24 + wipe poświadczeń RAM + drop_caches + poweroff [~] (selftest ✅, QA w VM ←);
      USB kill switch zostaje jako OPCJA dodatkowa (druga ścieżka tego samego kodu)
- [x] Self-destruct: JEDNA ścieżka paniki dla klawiatury/GUI/USB (D27) → shred kluczy + wipe + poweroff (D3)
- [x] **Kontener przetrwania (D24)**: username + klucze w zaszyfrowanym pliku (keystore D3 ✅);
      reszta = amnezja jak Tails; panic = shred kontenera razem ze wszystkim (kontakty: M4)
- [x] **BARIERA BOOT (D24+D3)**: `os/fenix_boot.py` — kreator 1. bootu / unlock-agent
      (systemd-ask-password, backoff ×2 z kontenera) / hasło paniki → sekwencja D27;
      przekaz identity.json na tmpfs /run/fenix (0440 root:fenix, jednorazowy) → node
      `--identity-file` (wczytuje i kasuje). Selftesty obu PASS; [~] przepływ na TTY do QA w VM
- [ ] Secure Boot: instrukcja „wyłącz Secure Boot" ze zrzutami UEFI (D23; MOK/shim = backlog M9)
- [ ] Hidden volume / plausible deniability (opcjonalnie, domyślnie OFF)
- [ ] Build **reprodukowalny** (ten sam config = ten sam SHA256)
- [ ] Podpis ISO kluczem ownera (D14) + publikacja sum SHA256
- [ ] Test: VM → pendrive → **prawdziwy sprzęt** (Wi-Fi!)
- [ ] (hobby) `boot/boot.asm` + `kernel.c` — własny kernel edukacyjny

## 🚀 M9 — DYSTRYBUCJA & OPERACJE
- [ ] **Fenix App portable** (PyInstaller .exe/.AppImage) — oficjalny kanał wdrożenia OBOK ISO (D25);
      GUI pokazuje poziom ochrony: apka / VM / Live-ISO + uczciwe ostrzeżenie opSec
- [ ] Klucze ownera: **master offline, Shamir 2-z-3 na 3 zimnych nośnikach**; hot-podklucz do podpisu buildów; protokół rewokacji podklucza (D14)
- [ ] Seed nodes 3–5 (różne jurysdykcje), lista podpisana w ISO + fingerprint
- [ ] Kanał aktualizacji: tylko podpis ownera; klient weryfikuje przed instalacją
- [ ] Strona projektu: statyczna, zero trackerów, serwowana z sieci FNX
- [ ] Dokumentacja użytkownika PL/EN + „Jak się nie zdeanonimizować"
- [ ] Stanowisko Chat Control: brak centralnego serwera / audytowalność (spójne z threat model)

---

## 🏅 RANGI — cenik & uprawnienia (decyzja właściciela, wpisano 2026-07-19)
> ZASADA NADRZĘDNA: ranga = PERK sieciowy (prędkość, komfort, AI). Ranga NIGDY nie daje:
> prawa głosu (to zawsze PoU ≥30 dni, D12), dostępu do cudzych danych, władzy nad siecią,
> ani odkupienia bana od konsensusu AI. Płacisz za szybszy pociąg, nie za lokomotywę. 🔥
> Ranga jest zapisana ON-CHAIN (registry) — klient i relaye weryfikują podpisem, nie podrobisz.

| Ranga | Cena (FNX) | BENEFITY (per ranga — mocne i sprzedażowe) |
|---|---|---|
| **ghost** (startowa, darmowa) | 0 | hosting: 1 strona • generowany avatar (identicon z walleta) • ciemny motyw • 1 grupa (25 osób) • bufor offline 7 dni • pełne PoU/głos po 30 dniach |
| **Donor** | 0.000001 | własny avatar (upload, szyfrowany) • odznaka + nick w kolorze brąz • hosting: 3 strony • rezerwacja username (name protection) • bufor 30 dni • tier 1 |
| **VIP** | 0.000002 | animowany avatar • baner profilu • hosting: 5 stron + motywy premium stron • 2 zmiany username/rok • grupy 3×100 os. • własne motywy GUI • tier 2 + priorytet łączenia z seedami |
| **VIP+** | 0.000003 | ramka avatara z poświatą • odznaka wspierającego • hosting: 10 stron + vanity path `/nick/strona` • dostęp beta • grupy 5×250 • podpisane raporty bezpieczeństwa własnego konta • tier 3 |
| **SVIP** | 0.00001 | hosting: 25 stron + panel hostingowy (agregaty liczbowe, ZERO logów gości) • interaktywna ramka avatara • storage ×2 • grupy 10×500 • feed ogłoszeń na własnych stronach • bufor 180 dni • tier 4 |
| **ELITE** | 0.0001 | hosting: 100 stron + własne szablony Web Buildera (sandbox CSS) • fast-lane E2E gwarantowana • buildy RC • ankiety doradcze (niewiążące) • grupy bez limitu liczby (2k os./grupa) • vanity wallet (mielenie prefiksu) • aura odznaki w GUI • tier 5 |
| **SELITE** | 0.01 | hosting: 500 stron + white-label (bez stopki Fenix) • kanał ogłoszeń sieciowych (moderacja admin) • wpis na stronie (opt-in) • test builds + kanał do dev • vanity premium (dłuższy prefiks) • sub-kanały grupowe, grupy 5k • LIMIT: 10 kont/rok (ekskluzywność) • tier 6 |
| **FENIX** | 100.1 | LIFETIME • hosting bez twardego limitu (fair-use) • dedykowany priorytetowy relay E2E • fotel w radzie doradczej (kwartalnie, BEZ władzy nad protokołem) • współprojekt 1 funkcji kosmetycznej z adminem • unikalna odznaka shard • Ściana Legend (opt-in) • LIMIT: 21 w całej historii sieci (jak 21M BTC) |

Zasady inżynierskie rang:
- [x] Tx `RANK_UP` na-chain ✅ (D46 wyżej); upgrade = dopłata różnicy ✅
- [x] **WYGASANIE 30 dni (D51, decyzja właściciela 2026-08-06) ✅**: ranga = legitymacja
      miesięczna; renew za życia = pełna cena (+30d, stos ≤60d); wygasła → ghost; dotyczy
      rang kupnych TX (donor…elite); selite/fenix systemowe przyznawane poza TX
- [ ] Wagi tierów = punkt startowy QoS (tuning po testach M2, relay nie może oszukać — audyt konsensusu)
- [ ] Podział wpłaty za rangę: PROPOZYCJA 50% burn / 50% skarbiec ownera → OSTATECZNA DECYZJA OWNERA (spójnie z D15)
- [ ] Prywatność: do czasu stealth addresses kupno rangi jest PUBLICZNE na-chain → tip: kupuj ze świeżego walletu
- [ ] AI bezpieczeństwa = WYŁĄCZNIE owner/admin (D17) — żadna ranga NIE daje kanału do AI

## ⚖️ POLITYKA BANÓW (D18)
- [ ] Auto-ban: konsensus AI (narzędzie admina, D17) → wpis on-chain: **kod powodu + wyjaśnienie PL/EN + hash dowodów** (z kapsuł sesyjnych, bez treści!)
- [x] Kody banów v1.0: **30 kodów w 7 kategoriach (A–G)** → `docs/ban_codes.txt` (oceniają wzorce, NIE treści; stare kody zmapowane)
- [x] **Tryb FAIL-OPEN anty-false-positive (D22)** → `docs/ban_policy.md` v1.0: Safe Harbor, progi „sustained", decay flag, red tylko konsensusem k-z-n, symetria bondów, okres nowicjusza 7 dni, auto-kalibracja FPR
- [ ] **UNBAN: jedyna droga = 1 000 000 USD w XMR, jednorazowo** — escrow multisig 2-z-3 + timelock
- [ ] Admin ma **30 dni** na decyzję: akcept → środki do skarbca + unban on-chain; odmowa/brak decyzji w 30 dni → **zwrot 99%** (1% = opłata anti-spam)
- [ ] Unban = tożsamość czysta technicznie, ALE: PoU/reputacja/licznik VOTER od ZERA, ranga nie wraca
- [ ] **Jeden wykup na wallet w historii sieci**; ponowny ban = permanentny, bez wyjątków
- [ ] Publiczny rejestr banów z wyjaśnieniami (GUI + eksplorator), zero danych wrażliwych

## 📚 NAUKA RÓWNOLEGŁA (30 min/dzień, nie więcej)
- [ ] Python: funkcje/klasy/wyjątki/moduły (M1–M4)
- [ ] socket + threading (M2 w praktyce)
- [ ] git od dziś: init/add/commit/log
- [ ] Sieci: handshake, NAT, DPI basics (M2–M3)
- [ ] Krypto użytkowa: nonce, forward secrecy (M4–M5)

## 🔒 CHECKLISTA KAŻDEGO PLIKU
- [ ] Uruchomiony + test przeszedł (fizycznie, nie w głowie)
- [ ] Zero sekretów w kodzie
- [ ] Surowe dane nie wychodzą poza RAM bez decyzji (D-rejestr)
- [ ] Komentarze „dlaczego"
- [ ] `git commit`

## 🚫 NIGDY (D-rejestr, nie do negocjacji)
- NIGDY treści wiadomości w logach/kapsułach (nawet zaszyfrowanych)
- NIGDY klucza na sztywno w kodzie/binarce/ISO
- NIGDY recovery w protokole (D9) — jedyne tylne drzwi = SKAZA
- NIGDY self-destruct z decyzji samego AI
- NIGDY własny szyfr jako jedyna warstwa (D2)
- NIGDY sztywne okna czasowe (telemetria/heartbeat) — losowe jittery
- NIGDY pakiet Fenixa bez warstwy camo poza laboratorium (D13)
- NIGDY aktualizacja bez podpisu ownera (D14)

## ⏳ BACKLOG (wizja docelowa — wraca, gdy MVP żyje)
Ranga VIP/Elita szczegóły • stealth addresses + ukrywanie kwot • Web Builder + FNX Browser •
rozproszone zadania AI (1% CPU) • decoy routing (Camo C) • własny kernel •
roczne głosowania • multisig skarbca • emisja/halvingi FNX
