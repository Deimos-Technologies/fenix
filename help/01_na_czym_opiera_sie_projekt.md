# 🧠 01 — Na czym opiera się projekt FenixOS / AnonNet (brief dla AI)

> **Data:** 2026-08-08 · **Stan:** HEAD `1a893e3`, audyt **46/46 testów · 29/29 kontroli**,
> najnowszy raport **FenixRapv015.pdf** · **Po co ten plik:** AI czytający to ma wejść
> w projekt bez odczytu 65 decyzji i 15 raportów — i nie złamać niczego, co tu święte.
>
> **EN TL;DR:** FenixOS/AnonNet is a privacy-first decentralized P2P network with its own
> Monero-style blockchain (FNX), a live amnesic OS ISO, a Tkinter GUI, an E2E messenger
> with PFS, an AI defense sentinel, and a supply-driven exchange desk (FNX-COIN). Python 3.13
> + `cryptography` + bash + live-build. Everything is self-tested, decisions D1–D65 are the
> constitution, honesty about limits beats marketing. Work rules: selftest first (catch the
> bug, show it, fix it, re-run), full audit after changes, docs updated in the same commit.

---

## 1. Jedno zdanie: co budujemy

**Zdecentralizowana, ekstremalnie anonimowa sieć P2P** z własnym blockchainem **FNX**
(monero-style: stealth + ring + ukryte kwoty), komunikatorem E2E z PFS, systemem
operacyjnym **Fenix OS Live ISO** (amnezja — nic nie zostaje na dysku), własnym GUI,
radar-em obronnym AI i giełdą FNX-COIN, której kurs liczy się sam z faktów łańcucha.

Właściciel: osoba początkująca — **piszemy prosto, jak dla 16-latka**, z analogiami
(sejf, walizka z dwoma kluczami, listonosz, dziennik obecności w fabryce…).

## 2. Filary — wartości, których NIE wolno naruszyć

1. **Anonimowość > wygoda.** Jeśli feature kosztuje prywatność — odpada albo dostaje
   jawne ostrzeżenie (jak donate-karteczka JAWNA na zawsze).
2. **Konsensus = determinizm bit-w-bit.** Każdy węzeł z replay liczy IDENTYCZNIE
   (salda, rangi, rejestry, PoU, głosy, airdrop, a od D65 także cenę). Czas na łańcuchu
   = timestampy bloków, nigdy zegary lokalne.
3. **Żaden człowiek nie ma przycisku władzy.** Nie ma przycisku ban (ban = konsensus
   kropki k-z-n, D18/D47). Nie ma przycisku kursu (D65: jednoosobowy owner-oracle D30
   ZDJĘTY; cena z krzywej łańcucha, stałe głosowalne VOTE_EVT D60). Audyt mocy:
   `tools/power_audit.py` pilnuje tego statycznie (18/18).
4. **Fail-open tam, gdzie cenzura; fail-closed tam, gdzie wyciek.** Radar ataków
   przy niepewności NIE banuje (Safe Harbor); firewall ISO przy błędzie ODCINA sieć.
5. **Szczerość granic głośno.** Nigdy „brak 0day". Zamiast tego: testowane mechanizmy
   + jawna lista PROBLEMS_OPEN w raportach. Tryb ducha (D63) ≠ tor — piszemy to wszędzie.
   Licznik online (D61) = ESTYMACJA, nie cenzus. Desk giełdy NIE drukuje FNX.
6. **Ban Policy v1.0 jest WIĄZĄCA** (`docs/ban_policy.md`): wzorce-nie-zdarzenia,
   decay, Safe Harbor, zero kar zbiorowych, red tylko konsensusem k-z-n.
7. **Higiena treści:** logi bez payloadu, PIN-y tylko jako hash proof, klucze w RAM,
   shred 2× nadpis, zero sekretów w repo i w IPC.

## 3. Stos techniczny

- **Python 3.13** (całość logiki), biblioteka `cryptography` (X25519, HKDF,
  ChaCha20-Poly1305, Ed25519, Argon2id); zero zewnętrznych serwerów.
- **Własna warstwa dodatkowa FNX-WRAP v1** (D2): Feistel 24 rundy/128 b + własny S-box
  (permutacja z SHA-512) + CTR + HMAC-EtM — własność DOKŁADNA, nigdy zamiast standardów.
- **Chain (Monero-style):** stealth adresy (własna arytmetyka punktów RFC 8032),
  ring-LSAG 5–11, key-images, Pedersen+Borromean, CLSAG wielo-wejścia (pseudoOut D41),
  konsensus ukrytych kwot v2 (tx_hidden D38).
- **Sieć:** AEAD frame v2, nonce per SEQ, replay-okno, padding+cover (camo profil A),
  drut bez markerów jawnych (test obowiązkowy na każdej nowej warstwie), gossip mesh
  z anti-echo, auto-discovery (seeds + peers.json + T_ADDR/T_PRES).
- **OS:** bash + live-build (Debian 13), tmpfs, spoof MAC/hostname PRZED siecią,
  nftables FAIL-CLOSED, panicd (Del+PageUp 2 s), Mullvad WG z kill switchem.
- **GUI:** Tkinter (logika testowana headless 22/22), most IPC NDJSON z demonem.
- **Raporty:** fpdf2; weryfikacja PDF pypdf tokenami.

## 4. Mapa repo (warstwy 0–9)

```
core/      tożsamość (Ed25519+X25519, adres FNXS1), keystore KS1, konto admina Deimos
core/crypto/ fenix_crypto (E2E+Shamir), fenix_wrap (własna warstwa D2)
net/       frame (AEAD v2), fenix_node (demon: mesh, mining, discovery, census, ghost),
           presence (beacony licznika D61)
transport/ camo (padding/cover), dnscamo (DNS bridge), mullvad (kill switch)
chain/     block (typed tx), ledger (konsensus: konta+nonce, fee D15, retarget),
           stealth/ring_sig/clsag/amount_hide/tx_hidden/tx_ring (prywatność),
           usernames (D28), contact_ref (D45), ranks (D46/51), ban_evt (D47/18),
           donate (D50), pou (D58+dziennik obecności, D59 ring świadków z chain),
           vote_evt (D60 urna VOTER), airdrop (D62 kamień 1M), badges (D52),
           miner/pow (PoW argon-lite dev)
ai/        ai_sentinel (radar fail-open, wniosek→kropka k-z-n; AI NIGDY nie banuje sam)
app/       messenger (E2E+PFS ratchet FNX-R1, TOFU=D43/D57), exchange (PSC desk D32),
           xmr_swap (wash-desk D34), fnx_coin (GIEŁDA FNX-COIN D65)
gui/       fenix_gui (dashboard/portfel/pool/kontakty/czat), backend_ipc, pool_panel,
           panic_button, settings_admin (ONB Deimosa D55), assets/badges
os/        build_iso (57/57), spoof (200/200 MAC), verify_iso, includes.chroot
           (nftables, systemd units, fenix-vpn/netup)
docs/      decyzje_architektury.md (D1–D65 = KONSTYTUCJA), fnx_spec.md (spec FNX,
           §12 = parametry robocze), ban_policy.md (WIĄZĄCA), threat_model, ToS, legal/
tools/     full_audit (orkiestra 46 testów + 29 kontroli), self_attack (red team),
           power_audit (kto ma moc D64), make_rap001 (generator FenixRap-vXXX)
help/      TEN FOLDER — briefy pisane dla AI
TODO.md    master mapa (checkbox = URUCHOMIONY+PRZETESTOWANY krok; [~] = częściowo)
FenixRapv001–v015.pdf  raporty wersjonowane (NIE nadpisujemy; nowsza wersja = nowy plik)
```

## 5. Blockchain FNX — cheat-sheet

- Adres walleta: `FNX1` + base32(blake2s(sig_pub‖x_pub)) (36 znaków). Kontakt: FNXS1.
- Jednostka: **ISKRA = 10^8**; `BLOCK_REWARD = 5 FNX` (⚠️ROBOCZE §12 — emisja OTWARTA).
- Fee: `fee_split(amount)` = burn 10 ppm (0.001%, znika) + owner 550 ppm (→skarbiec) +
  reszta → kopacz w coinbase (D39). Skarbiec z usług rejestru (ID_DECLARE).
- Typed tx (bajt): TRANSFER, RING(3a), SHIELD/UNSHIELD(v1/v2 mgła), ID_DECLARE,
  USERNAME(claim/rename, 1 username/wallet — D28), CONTACT_REF 0x45(D45), RANK_UP(D46),
  **BAN_EVT 0x06** (tombstone k-z-n; zbanowany: zero tx/coinbase), **DONATE 0x14**,
  **POU_ATTEST 0x04** (D58), **VOTE_EVT 0x07** (D60, brama=VOTER), **AIRDROP 0x15**
  (D62: 1 strzał przy 1M users, odbiorca i kwota 1–10 FNX z blake2s(prev‖milestone)).
- Ledger: `balances/nonces/mempool/seen_tx/pool/key_images/usernames/contact_refs/
  ranks/bans/donations/pou/votes/airdrop_fired/airdrops`; `height(), tip(), balance_of(),
  nonce_of(), add_tx, block_template, apply_block, adopt_chain` (replay bit-w-bit),
  `snapshot(), save_chain/load_chain` (chain.dat D42).
- PoU (dziennik obecności): okno 30 min, ≥3 świadków Z RINGU losowanego z łańcucha
  (D59 — zamknięty sybil-hack), VOTER po 30 dniach + 80% pokrycia (mnożniki 0.5/1.0/1.25).
- PoW: argon-lite/sha256d; dev `--zbits 2` = natychmiastowe kopanie w testach.
- **Cena FNX (D65):** `app/fnx_coin.curve_price_cents(supply_stats(ledger))`, int-only:
  kapitał[¢] = 100 + 100·users + 500·attesterzy + 1·głosy + 1·wysokość;
  cena = max(1¢, kapitał·ISKRA // max(Σsald, ISKRA)); spread 2%; ask>cena≥bid≥1¢.
  Stałe ROBOCZE §12, zmiana TYLKO przez VOTE_EVT. Desk nigdy nie drukuje FNX.

## 6. Proces pracy — rytuały OBOWIĄZKOWE (w tej kolejności)

1. **Start każdej sesji:**
   `cd /home/user/FenixOS && pip install -q -r requirements.txt && pip install -q pypdf`
   (piaskownica gubi pakiety co restart — `cryptography` ZAWSZE sprawdzić),
   `git config user.name "Fenix Dev"` + `git config user.email "dev@fenix.local"`
   (resetuje się co sesję), `chmod +x os/*.sh os/includes.chroot/usr/local/bin/* tools/*.py`
   (snapshot gubi exec-bity; NIE dodawać execu plikom, które go w repo nie mają).
2. **Zasada debugowania „kanapka":** test najpierw ŁAPIE buga → pokazujemy szczerze
   (z wagą P0-KRYTYCZNY/WYSOKI/ŚREDNI/NISKI) → fix → rerun. Każde znalezisko trafia
   do FIXLOG raportu. Wyjątki w wątkach giną cicho — debugować tracebackiem.
3. **Po każdej zmianie krypto/net/konsensus:** rerun `python3 tools/self_attack.py`,
   potem pełny `python3 tools/full_audit.py` (~3 min; wynik: `46/46 · 29/29`).
   Kontrola „drzewo czyste" wymaga commitów przed raportem (wyjątek: regenerowany
   `docs/crypto_attack_report.md`).
4. **Nowa funkcja krypto/net/konsensus = decyzja D##** (dopisek w
   `docs/decyzje_architektury.md`) + wpis w TODO.md + etykieta w full_audit.py +
   (jeśli ekonomia) § w `docs/fnx_spec.md`.
5. **Checkbox w TODO.md odhaczamy TYLKO po URUCHOMIENIU+TEŚCIE.** `[~]` = częściowo.
6. **Selftest = kontrakt stdout:** kroki `[OK] N.` i finał ze słowem `PASS`
   (full_audit matchuje marker; rc=0 bez PASS = FAIL — lekcja z power_audit).
7. **Raporty:** edytujemy `tools/make_rap001.py` SKRYPTEM (/tmp, z asercjami count==1
   na każdej kotwicy, strażnikiem parzystości cudzysłowów, ast.parse przed zapisem —
   atomowo: crash przed zapisu = pół-edycji), po generacji WERYFIKUJEMY PDF tokenami
   pypdf (`re.sub(r"\s+"," ", ...)` — pypdf rozciąga spacje) + print generatora.
8. **Commity ×2:** najpierw kod (z testami+docsami), potem raport PDF osobno.
9. **Nazw plików nie zmieniamy.** Nowe pliki = nowe funkcje, nie zamienniki.

## 7. System obrony jakości (co już istnieje i działa)

- `tools/full_audit.py` — 46 selftestów (osobne procesy) + 29 kontroli statycznych
  (zero PEM w repo, .gitignore, exec-bity, docs istnieją, integracje D55–D65,
  drzewo git czyste). Wynik → `/tmp/fenix_audit.json` (nie przetrwa restartu — regen).
- `tools/self_attack.py` — red team: 27 ataków odparzonych, 5 notatek, 0 problemów
  (brute/flip/spray keystore, drut, replay, impersonacja, druk FNX, fee-kłamstwo…).
- `tools/power_audit.py` — „kto ma moc": 18/18 (kropka attestorów tylko dev+core,
  moduły pou/vote/airdrop bez dostępu do skarbca, tx systemowe bez podpisów,
  IPC whitelist snapshot przez AST, zero sekretów w IPC, ghost czysty z krypto).
- Test drutu: setki rekordów 4096 B po ramkach — ZERO jawnych markerów (obowiązkowy
  dla każdej nowej warstwy sieciowej).
- Live-qa już zrobione: 2 procesy demona (P20/D56, runda IPC E2E), 2 procesy P2P
  z seeds (2026-08-08: peers=1, T_ADDR rozlewa; P29 INFO: peers=2 przy 1 łączniku
  = inbound+outbound liczone 2× — dedup w planie M3).

## 8. Remanenty (co OTWARTE — patrz PROBLEMS_OPEN w najnowszym raporcie)

- **Czeka na właściciela (poza kodem):** P2 seeds na VPS-ach, P3 boot ISO w qemu,
  P5 decyzje §12 (emisja, skarbiec-cold, źródło airdropu, STEAŁE krzywej D65),
  P7 kontrakty raili (Paysafe/monero-rpc/ProductionRail — uczciwie odmawiają),
  P8 domena dnscamo, P15 Mullvad z kontem, P17 GUI pod X11.
- **W backlogu kodu:** P10 multi-sentinel (rejestr tematów + quorum przez VOTE_EVT),
  P11 bulletproofs, P24 link urządzeń + grupy M4c, P25 challenge-reachability +
  zimne klucze attestorów + rotacja kropki, P29 dedup peerów po handshake,
  GUI: zakładka Giełda FNX-COIN + toggle ducha + karta census.

## 9. Czerwone linie — czego AI w tym projekcie NIGDY nie robi

- Nie dodaje uprzywilejowanych ścieżek (backdoor, „admin command", cenny kurs
  ręczny, wyjątek konsensusu „tylko dla nas"). Audyt mocy to złapie — i słusznie.
- Nie loguje payloadu/treści; nie zapisuje kluczy prywatnych/seedów/PIN-ów nigdzie
  trwale; nie wysyła sekretów przez IPC.
- Nie obiecuje anonimowości ponad udowodnione (duch ≠ tor; DNS-camo ≠ VPN;
  licznik ≠ cenzus; krzywa ceny ≠ gwarancja wartości).
- Nie usuwa / nie osłabia testów-strażników; nie „naprawia" testu pod kod
  (chyba że test kłamie — wtedy pokazujemy DOWÓD kłamstwa w fixlogu).
- Nie zmienia ban_policy: AI-Sentry może co najwyżej ZŁOŻYĆ WNIOSEK do kropki.
- Nie łamie determinizmu: żadnego wall-clock w walidacji (poza ±4 h timestampu
  bloku i dotarciem MEMPLOOLU — to jawne wyjątki sieciowe, nie konsensus).

## 10. Szybki start dla AI (komendy, które zawsze działają)

```bash
cd /home/user/FenixOS
pip install -q -r requirements.txt && pip install -q pypdf
git config user.name "Fenix Dev" && git config user.email "dev@fenix.local"
chmod +x os/*.sh os/includes.chroot/usr/local/bin/* tools/*.py
python3 tools/full_audit.py        # 46/46 · 29/29 → /tmp/fenix_audit.json
python3 tools/self_attack.py       # red team
python3 tools/power_audit.py       # kto ma moc (18/18)
python3 app/fnx_coin.py            # demo giełdy FNX-COIN (krzywa + E2E)
python3 -m net.fenix_node --port 45511 --zbits 2 --no-cover --sentinel off
```

---

*Wątpliwość strategiczna? Pytaj właściciela, zanim zaczniesz kodzić — decyzje
D1–D65 pokazują styl: zawsze decyzja głośno, z powodem, z granicami, z datą.*
