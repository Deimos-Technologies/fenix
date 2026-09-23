# FENIX / AnonNet — Dokument Sieci
**Dzialanie sieci | Regulamin | Kompetencje Administracji | Ryzyka prawne | Ochrona Uzytkownika | ToS**
*Wersja 1.0 — 2026-07-19 (draft; nie stanowi porady prawnej)*

## 1. Wprowadzenie i status dokumentu
Niniejszy dokument opisuje sposob dzialania Sieci Fenix, obowiazujacy w niej Regulamin, katalog kompetencji Administracji, scenariusze ryzyk prawnych oraz mechanizmy ochrony Uzytkownika. Stanowi integralne uzupelnienie Warunkow Korzystania (ToS) v1.0.
Dokument ma charakter informacyjny i roboczy. Nie stanowi porady prawnej dla zadnej ze stron. Przed publikacja i wdrozeniem zalecana jest konsultacja z prawnikiem znajacym jurysdykcje docelowe Sieci.
W przypadku rozbieznosci rozstrzygajaca jest wersja polskojezyczna; wersje angielska i rosyjska pelnia funkcje informacyjna.

> **PO LUDZKU: **To mapa calej sieci zapisana dwoma glosami: prawniczym i ludzkim. Warto przeczytac oba.

## 2. Jak dziala Siec Fenix
- Siec peer-to-peer bez centralnego serwera: tresci i konta istnieja wylacznie na urzadzeniach Uzytkownikow. Nie ma infrastruktury Administracji przechowujacej dane uzytkownikow — nie ma czego przejac ani wydac.
- Tozsamosc = Wallet Address + Username + UID + Ranga; rejestr publiczny na blockchainie FNX, bez danych osobowych.
- Komunikacja szyfrowana end-to-end; klucze prywatne nigdy nie opuszczaja urzadzenia; kazda wiadomosc uzywa klucza jednorazowego (forward secrecy).
- Transport: wlasny protokol z warstwa kamuflazu (camo) utrudniajaca identyfikacje ruchu (DPI); routing cebulowy hop-by-hop — zaden relay nie zna rownoczesnie nadawcy, odbiorcy i tresci.
- Gospodarka FNX: oplata 0.001% burn + 0.055% skarbiec ownera; kopanie PoW (CPU) sprzezone z hostowaniem fragmentow danych (proof-of-storage).
- Obrona: system AI-Sentry wylacznie w gestii Administracji (D17); werdykty jawne z uzasadnieniem; reputacja Proof-of-Uptime (30 dni = status VOTER i prawo glosu).
- Rangi: dobrowolne wplaty FNX za benefity (hosting, QoS, kosmetyka) — NIGDY w zamian za wladze, glos lub dane innych.

> **PO LUDZKU: **Firmowego serwera nie ma — nie ma czego przejac. Listy czyta tylko nadawca i adresat. Ranga kupuje wygode, nie wladze.

## 3. Regulamin Sieci
3.1 Dozwolone: komunikacja prywatna i grupowa; hostowanie legalnych tresci; kopanie FNX; udzial w glosowaniach (VOTER); zakup rang i benefitow; samodzielne ustawianie suwaka telemetrii.
3.2 Zabronione (podstawa automatycznego bana):
- ROUTE_LEAKAGE — kierowanie ruchu Fenix przez niezabezpieczone proxy / wyciaganie danych poza Siec;
- PROTO_FLOOD — wolumetryczne zalewanie protokolu; INVALIDTAG_STORM — masowe falszowane pakiety;
- SYBIL_RING — pierscienie falszywych tozsamosci; STORAGE_FRAUD — oszustwa proof-of-storage;
- MSG_SPAM — masowa wysylka (analiza wzorca meta, NIGDY tresci); CAMO_VIOLATION — ruch bez warstwy kamuflazu;
- DOXXING — publikowanie danych osobowych osob trzecich; oraz wszelkie tresci i dzialania nielegalne (pkt 5).
3.3 Egzekwowanie: automatyczne, z uzasadnieniem. Tresci nie sa skanowane (przy E2E jest to technicznie niemozliwe); egzekwowane sa wzorce bezpieczenstwa oraz rejestr ostrzezonych hashy — konsensus wstrzymuje dystrybucje oznaczonego fragmentu bez odczytu jego tresci.

> **PO LUDZKU: **Prywatnosc — zawsze. Ale atak na siec, oszustwo protokolu i nielegalna handlarka koncza sie banem — z nazwy i z powodu, publicznie.

## 4. Co moze Administracja (katalog zamkniety)
4.1 Administracja MOZE wylacznie:
- podpisywac i publikowac aktualizacje Oprogramowania (klucz ownera, D14);
- operowac systemem ochrony AI-Sentry (D17) i wydawac werdykty banow z uzasadnieniem (D18);
- przyjmowac albo odrzucac wykupienia banow — decyzja ostateczna;
- pobierac oplate protokolu 0.055% do skarbca ownera (D15) i zarzadzac skarbcem;
- utrzymywac seed nodes, bootstrap i oficjalny kanal ogloszen;
- zmieniac Warunki z co najmniej 14-dniowym uprzedzeniem;
- wstrzymywac dystrybucje fragmentow oznaczonych hashem, wylacznie droga konsensusu.
4.2 Administracja wyraznie NIE MOZE (zobowiazania projektu):
- odczytywac tresci wiadomosci ani logow aktywnosci (nie istnieja);
- odzyskac utraconego klucza ani hasla Uzytkownika (D9);
- deanonimizowac Uzytkownikow srodkami systemowymi;
- cofac transakcji on-chain ani zmieniac sald poza zasadami konsensusu;
- wydac dane, ktorych nie posiada — jakimkolwiek podmiotom (par.4 ToS).

> **PO LUDZKU: **Wladza admina konczy sie na serwisie silnika. Nie widzi listow, nie zna hasel, nie ma kluczy — wiec nie ma czego wydac.

## 5. Scenariusze ryzyk prawnych i stanowisko Administracji
Siec Fenix NIE jest tworzona ani utrzymywana w celu ulatwiania dzialan bezprawnych. Dla kazdego scenariusza obowiazuje: (a) zakaz, (b) wylaczna odpowiedzialnosc sprawcy, (c) wylaczenie odpowiedzialnosci Administracji w maksymalnym zakresie dozwolonym prawem, (d) mechanizmy ograniczajace zjawisko.
### 5.1 Tresci nielegalne, w tym materialy wykorzystujace dzieci (CSAM)
Tolerancja zero; kategoryczny zakaz; odpowiedzialnosc wylacznie sprawcy. Administracja nie skanuje tresci (E2E), lecz utrzymuje rejestr ostrzezonych hashy i wstrzymuje dystrybucje oznaczonych fragmentow (konsensus). Wspoldzialanie z organami ogranicza sie do danych z natury publicznych on-chain.
### 5.2 Kradziez tozsamosci i podszywanie sie
Zakaz. Mechanizmy ochronne: tozsamosc kryptograficzna z podpisami, name protection (benefit rang), jawne odciski walletow do weryfikacji poza pasmem. Administracja nie odpowiada za szkody powstale wskutek braku weryfikacji odciskow przez Uzytkownika.
### 5.3 Oszustwa kryptowalutowe („scamy”)
Zakaz. Administracja nie posredniczy w wymianach P2P, nie gwarantuje kontrahentow ani nie depozytuje srodkow uzytkownikow. Zasada bezwzgledna: Administracja NIGDY nie zwraca sie o klucz, seed, zaliczke ani „wplate weryfikacyjna”. Potwierdzone konsensusem adresy scamow trafiaja do rejestru SCAM_ALERT. Umowy i ich skutki obciazaja wylacznie strony.
### 5.4 Handel nielegalnymi towarami i uslugami (narkotyki, bron, kradzione dane itp.)
Zakaz; odpowiedzialnosc wylacznie stron; Administracja nie odpowiada za oferty, umowy ani ich skutki.
### 5.5 Zlosliwe oprogramowanie, ransomware, phishing
Zakaz; wzorce egzekwowane kodami banow; SCAM_ALERT dla potwierdzonych kampanii; Administracja nie odpowiada za szkody.
### 5.6 Pranie pieniedzy i obchodzenie sankcji
Zakaz; Uzytkownik odpowiada za zgodnosc ze swoja jurysdykcja (w tym AML i podatkowa). Administracja nie swiadczy uslug finansowych, nie prowadzi KYC (decyzja projektowa), nie gwarantuje plynnosci ani wartosci FNX.
### 5.7 Terroryzm, przemoc, nawolywanie do przemocy
Kategoryczny zakaz; wylaczenie odpowiedzialnosci Administracji; wskazac mozna wylacznie dane z natury publiczne on-chain.
### 5.8 Dane osobowe osob trzecich, doxxing, naruszenia wlasnosci intelektualnej
Zakaz; odpowiedzialnosc publikujacego; Administracja nie odpowiada.
### 5.9 Ataki na sama Siec (w tym na warstwe camo i konsensus)
Obslugiwane automatycznie kodami banow; Administracja nie odpowiada za szkody powstale wskutek atakow osob trzecich.
### 5.10 Granica klauzul
Zadne postanowienie nie wylacza odpowiedzialnosci, ktorej bezwzglednie obowiazujace prawo nie pozwala wylaczyc. Dokument sporzadzono w dobrej wierze, w celu minimalizacji szkod dla wszystkich uczestnikow.

> **PO LUDZKU: **Prywatna nie znaczy bezprawna. Kto tu handluje kradzionym, scamuje albo sie podszywa — odpowiada sam. Siec nie moze go „podejrzec”, bo z tych samych powodow nie moze podejrzec ciebie. To cena i dar prywatnosci.

## 6. Mechanizmy ochrony Uzytkownika
- Szyfrowanie E2E z kluczami jednorazowymi (forward secrecy) — nawet przejecie klucza stalego nie otwiera historii.
- Brak logow i tresci po stronie sieci: kapsuly sesyjne w RAM, spalenie klucza sesji przy wylogowaniu (crypto-shred).
- Kamuflaz transportowy (camo) + routing cebulowy — przeciw DPI, profilowaniu i analizie ruchu.
- Jawne werdykty bezpieczenstwa: kazdy ban z kodem i wyjasnieniem PL/EN oraz hashem dowodow; rejestr publiczny.
- Suwak telemetrii off/minimal/full (domyslnie minimal) — Uzytkownik decyduje.
- Proof-of-Uptime zamiast danych osobowych — reputacja bez deanonimizacji.
- Procedura unban: 30 dni na decyzje Administracji, zwrot 99% przy odmowie lub braku decyzji.
- Ostrzezenia anty-scam (SCAM_ALERT), weryfikacja odciskow walletow, rejestr falszywych tozsamosci „Administracji”.
- Haslo paniki (cichy crypto-shred), „czysty ekran”, self-destruct po hasle duress (D3).
- Zasady higieny publikowane Uzytkownikom: weryfikuj sumy SHA256 ISO; Administracja nigdy nie pisze pierwsza w sprawach srodkow; nigdy nie prosi o klucz, seed ani haslo.

> **PO LUDZKU: **Siec broni cie matematyka, nie obietnicami. Przed scamem broni jedna zelazna zasada: nikt z obslugi nigdy nie poprosi o twoj klucz. Nigdy.

## 7. Warunki Korzystania — kluczowe postanowienia (skrot)
- Swiadczenie „jak jest”, bez gwarancji; pelna wersja: docs/ToS.md.
- Tresci i odpowiedzialnosc za nie: wylacznie Uzytkownicy.
- Brak danych = brak mozliwosci ich wydania; brak recovery (D9).
- Rangi: platnosci finalne; benefity ewoluuja tylko w granicach protokolu.
- Bany automatyczne z uzasadnieniem; unban 1 000 000 USD XMR, 30 dni, zwrot 99%; jeden wykup na wallet; ponowny ban permanentny.
- System ochrony (AI) w wylacznej gestii Administracji; uzytkownicy nie komunikuja sie z nim.
- Odpowiedzialnosc Administracji ograniczona do USD 0 w maksymalnym dozwolonym zakresie.
- Zmiany Warunkow: publikacja co najmniej 14 dni wczesniej; dalsze korzystanie = akceptacja.

> **PO LUDZKU: **To samo co wyzej — w punktach na lodowke.

## 8. Odpowiedzialnosc i wiek Uzytkownika
Usluga przeznaczona dla osob pelnoletnich (18+). Uzytkownik odpowiada za: zgodnosc z prawem wlasnej jurysdykcji, bezpieczenstwo kluczy i hasel, tresci ktore tworzy i hostuje, oraz skutki transakcji zawartych z innymi uzytkownikami. Nieznajomosc prawa nie zwalnia z odpowiedzialnosci — jak wszedzie.

## 9. Postanowienia koncowe
Separowalnosc postanowien; zmiany z 14-dniowym wyprzedzeniem; wersja polska rozstrzygajaca; kontakt wylacznie przez oficjalne kanaly ogloszeniowe w Sieci; data dokumentu: 2026-07-19.

## Aneks A — Rangi i Benefity (cenik)
### ghost — startowa (0 FNX)
- hosting: 1 strona (Web Builder)
- generowany avatar (identicon z walleta)
- ciemny motyw, 1 grupa (25 osob)
- bufor offline 7 dni, tier 0
- pelne PoU/glos po 30 dniach uptime

### Donor — 0.000001 FNX
- wlasny avatar (upload, szyfrowany)
- odznaka Donor + brazowy nick
- hosting: 3 strony
- rezerwacja username (name protection)
- bufor 30 dni, tier 1

### VIP — 0.000002 FNX
- animowany avatar + baner profilu
- hosting: 5 stron + motywy premium stron
- 2 zmiany username/rok
- grupy 3x100, wlasne motywy GUI
- tier 2 + priorytet laczenia z seedami

### VIP+ — 0.000003 FNX
- ramka avatara z poswiata + odznaka
- hosting: 10 stron + vanity path /nick/strona
- dostep do funkcji beta
- grupy 5x250
- podpisane raporty bezpieczenstwa konta, tier 3

### SVIP — 0.00001 FNX
- hosting: 25 stron + panel (agregaty, ZERO logow gosci)
- interaktywna ramka avatara
- storage x2, grupy 10x500
- feed ogloszen na wlasnych stronach
- bufor 180 dni, tier 4

### ELITE — 0.0001 FNX
- hosting: 100 stron + wlasne szablony Web Buildera (CSS sandbox)
- fast-lane E2E gwarantowana
- buildy RC + ankiety doradcze (niewiazace)
- grupy bez limitu liczby (2k os./grupa)
- vanity wallet (prefiks), aura odznaki, tier 5

### SELITE — 0.01 FNX
- hosting: 500 stron + white-label
- kanal ogloszen sieciowych (moderacja admina)
- wpis na stronie (opt-in), test builds + kanal do dev
- vanity premium, sub-kanaly, grupy 5k
- LIMIT: 10 kont/rok, tier 6

### FENIX — 100.1 FNX
- LIFETIME; hosting bez twardego limitu (fair-use)
- dedykowany priorytetowy relay E2E
- fotel w radzie doradczej (kwartalnie, BEZ wladzy nad protokolem)
- wspolprojekt 1 funkcji kosmetycznej; odznaka shard
- Sciana Legend (opt-in); LIMIT: 21 w historii sieci

### Zasady nadrzedne rang
- Ranga = perk sieciowy. NIGDY nie daje: glosu (tylko PoU >=30 dni), dostepu do AI bezpieczenstwa (wylacznie owner/admin), danych innych, unbana, wladzy nad protokolem.
- Ranga zapisana ON-CHAIN (tx RANK_UP, 6 potwierdzen); upgrade = doplata roznicy.
- Do czasu stealth addresses kupno rangi jest publiczne — zalecany swiezy wallet.

## Aneks B — Polityka banow i wykupu (UNBAN)
- Auto-ban = konsensus AI (narzedzie admina) -> wpis ON-CHAIN: kod powodu + wyjasnienie PL/EN + hash dowodow (bez tresci!).
- Kody: ROUTE_LEAKAGE (routing przez niezabezpieczone proxy — wyciaganie danych poza Fenix!), PROTO_FLOOD, INVALIDTAG_STORM, SYBIL_RING, STORAGE_FRAUD, MSG_SPAM (meta, nie tresc), CAMO_VIOLATION, DOXXING.
- UNBAN: jedyna droga = 1 000 000 USD w XMR, JEDNORAZOWO (escrow multisig 2-z-3 + timelock).
- Admin ma 30 dni: akceptacja -> skarbiec + unban on-chain; odmowa/timeout -> zwrot 99% (1% anti-spam). Decyzja admina ostateczna.
- Unban: PoU/reputacja/VOTER od zera; ranga nie wraca.
- Jeden wykup na wallet w calej historii; ponowny ban = PERMANENTNY.
- Publiczny rejestr banow z wyjasnieniami (GUI + eksplorator).

*— Koniec wersji polskiej —*