# 🎯 FENIX — THREAT MODEL v1.0 (2026-07-19)
> Dokument żywy: aktualizowany przy każdej nowej funkcji i co przeglądzie fazy.
> Status: draft projektowy. Nie porada bezpieczeństwa prawna.

## 1. CO CHRONIMY (aktywa, w kolejnosci waznosci)
1. **Tresc komunikacji uzytkownikow** (wiadomosci, pliki, strony)
2. **Metadane powiazan** (kto z kim, kiedy, jak czesto)
3. **Klucze prywatne / tozsamosc** (Wallet, klucze sesyjne, klucz zbiorczy)
4. **Srodki FNX i skarbiec**
5. **Dostepnosc i integralnosc sieci** (konsensus, blockchain, deliverability)
6. **Operatorow i administracje** (przed przymusem — D9 daje im "nie mam czego dac")

## 2. CZEGO NIE OBIECUJEMY (uczciwie, zebysmy nie klamali)
- Ochrony przed **fizyczna przemoca / torturami** (kluczowa granica kazdego systemu)
- Ochrony przed **rootkitem na juz skompromitowanym urzadzeniu** (keylogger nagrywa zanim zaszyfrujemy)
- Pelnej **anonimowosci statystycznej przy malej sieci** (< ~1000 aktywnych nodow globalna analiza ruchu T3 ma przewage — mowimy to otwarcie w UI)
- Ochrony przed **pomylka uzytkownika** (OpSec to polowa bezpieczenstwa; edukacja to nasz obowiazek)
- Sprzezonym z tym trzema powyzszym: NIE piszemy "nie do zlamania". Piszemy "koszt ataku > zysk z ataku".

## 3. SCENARIUSZ T1 — Przeciwnik lokalny / ISP (pasywny lub slabo aktywny)
**Profil:** dostawca internetu, korpo-firewall, administrator LAN, sluzba z pozwoleniem na podsłuch ruchu ISP.
**Widzi:** ze urzadzenie generuje ruch; rozmiary i timing I/O; cel = nasz relay/seed (pre-camo).
**Nasza obrona:**
- E2E zawsze (D1) — tresc nieczitelna juz na tej warstwie
- Camo profil A (szum) / B (mimikra HTTPS-WebRTC) (D10) — cel i wzorzec zatkane
- Spoof lokalny MAC/hostname na starcie ISO (D6) — warstwa LAN/kamer
- Padding do stalych rozmiarow + jitter (spec protokolu) — rozmiary przestaja gadac
**NIGDY nie zdobedzie:** tresci, metadanych kontaktow, kluczy.
**Ryzyko resztkowe (akceptujemy):** wniosek "ten klient PRAWDOPODOBNIE uzywa Fenix" — minimalizowany Camo B.
**Test brzegowy:** Wireshark probka 24h — wyglada jak losowy szum albo zwykle HTTPS; zero identyfikowalnych sygnatur.

## 4. SCENARIUSZ T2 — Aktor panstwowy (zasoby srednie, moze aktywnie dzialac)
**Profil:** nakaz dla "administracji", podszywanie pod seed node, przejecie pojedynczego VPS, geoblokada wyjscia.
**Nasza obrona:**
- brak centralnego serwera = **brak adresata nakazu** (dobry wizerunek Chat-Control stance)
- progi k-z-n (D1, D9, D15): wydanie wymaga konsensusu niezaleznych podmiotow; **nie ma czego wymusic**
- aktualizacje podpisane kluczem OFFLINE (D14) + rewokowalny hot-podklucz — przejecie laptopa deva != zatrucie sieci
- bootstrap podpisany + fingerprint w ISO (M9) — podszyty seed upada na weryfikacji (reputacja + ostrzezenie SCAM_ALERT)
- jawne werdykty i rejestry (D18): nielegalne "ciche" operacje admina nie przejda niezauwazone
**NIGDY nie zdobedzie:** kluczy uzytkownika, recovery (nie istnieje), master-key (zimny, offline 2-z-3).
**Ryzyko resztkowe:** przejecie wiekszosci seedow = degradacja bootstrap na pierwszym wejsciu (mit: wielu seed-jurysdykcji + rotacja).
**Test brzegowy:** symulowana kapitulacja administracji pod nakazem = oficjalnie zero materialu do wydania (listujemy co bysmy "mogli" dac: nic poza dawnymi sumami SHA256 ISO).

## 5. SCENARIUSZ T3 — Globalny / aktywny atak na sama siec
**Profil:** analiza ruchu calego internetu, armie Sybili, eclipse-attack, flood, zatrucie AI/danych, ban-evasion.
**Nasza obrona (kosztowanie ataku zamiast walki szyframi):**
- **PoU 30d (D12)** + hashcash na handshake + stropy nowych walleti (B4) — kazda nowa tozsamosc = czas+prad+kapital
- **mnoznik kopania od reputacji (A1)** + streaki lojalnosciowe (A3) — ban odcina strumien dochodu, nie tylko konto
- **identity bond + slash (A2)** dla rol zaufanych — finansowy bol reinkarnacji
- konsensus werdyktow k-z-n + agregacja odporna na bizantyjczykow (mediana wartosci, nie srednia)
- AI-Sentry zamkniety dla uzytkownikow (D17) — nie da sie nim "pogawedzic" ani sterowac
- eclipse def.: bootstrap podpisany + rotacja peerow + limity z jednego /16
- ban-evasion: tombstone na-chain (nieusuwalne), reset PoU, (backlog: ZK non-membership)
**Uczciwe limity:** mala siec = slaba mieszanka statystyczna; roadmap: opoznienia mixnet + cover traffic staly (M3).
**Test brzegowy:** chaos-weekend — symulowany Sybil+flood+zatrucie w labie; sentinel ma dac werdykty, siec zyje.

## 6. SCENARIUSZE UZYTKOWNIKA (OpSec — polowa threat modelu)
| Zdarzenie | Odpowiedz systemu | Co robimy my / co musi user |
|---|---|---|
| Utrata hasla | D9: bez recovery; MEK martwy | edukacja: offline backup, menedzer hasel |
| Wymuszenie hasla | haslo paniki D3 -> cichy crypto-shred | user moze (i powinien) cwiczyc w labie |
| Zabranie sprzetu w czasie sesji | LUKS + tmpfs + wipe RAM przy shutdown (M8); USB kill | user: zablokowac ekran/wylaczyc |
| Keylogger/RAT na hoscie | poza zasiegiem protokolu | edukacja: Fenix OS live, higiena |
| Phishing "admin prosi o klucz" | admin NIGDY nie prosi (ToS §5.3), SCAM_ALERT | user: weryfikacja fingerprintow |

## 7. ATAKI NA EKONOMIE FNX
- **51% przy malej sieci:** checkpointy co N blokow podpisane progiem (k-z-n), trudnosc adaptacyjna (fnx_spec)
- **wash-trading rang:** rangi przywiazane do walletow + opaty idace w burn/skarbiec, brak rynku pierwotnego NFT-likwidow
- **spam przeciw skarbcowi:** oplaty tx (0.001% burn + 0.055% owner) = kazdy atak-finans dopelnia FNX

## 8. MACIERZ POKRYCIA (decyzje -> zagrozenia)
D1(E2E/Shamir): T1,T2,T3 | D3(panic): T1 user | D5/D9(kapsuly, brak recovery): T1,T2,admin | D10/D13(camo+suwerennosc): T1,T3 | D12(PoU): T3 Sybil | D14(update owner): T2 | D15(fee/burn): T3-econ | D17(AI admin-only): T3 steering | D18(bany): T3 recydywa | D19-D21(sprzet odrzucony): oszczedza prywatnosc wszystkich.

## 9. RYTM PRACY Z TYMI ZAGRZOZENIAMI
- kazdy nowy plik funkcyjny => update sekcji odpowiedniej
- co kamien milowy => "try to break it" weekend przed odhaczeniem
- dokument zaklada, ze przeciwnik zna caly kod (Kerckhoffs) — sekret to klucz i koszt, nie algorytm.
