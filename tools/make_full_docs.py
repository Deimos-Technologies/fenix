# tools/make_full_docs.py
# ============================================================
#  Generator dokumentow Sieci Fenix: PL / EN / RU
#  Produkuje: docs/legal/FENIX_Dokument_{PL,EN,RU}.md
#         oraz docs/FENIX_Dokument_Sieci_PL_EN_RU.pdf
#  Uruchom: python3 tools/make_full_docs.py  (z katalogu FenixOS)
# ============================================================
import os
from fpdf import FPDF
try:
    from fpdf.enums import X as NX, Y as NY
except Exception:
    class NX: LMARGIN = "LMARGIN"; RIGHT = "RIGHT"
    class NY: NEXT = "NEXT"; TOP = "TOP"
_MXY = dict(new_x=NX.LMARGIN, new_y=NY.NEXT)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PDF = os.path.join(ROOT, "docs", "FENIX_Dokument_Sieci_PL_EN_RU.pdf")
LEGAL_DIR = os.path.join(ROOT, "docs", "legal")

def font(cands):
    for p in cands:
        if os.path.exists(p):
            return p
    return None

F_REG  = font(["/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"])
F_BOLD = font(["/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"])
FP = "DV" if F_REG else "helvetica"

# ============================================================
#  TRESC DOKUMENTOW — 3 JEZYKI
#  Typy: ("p", tekst) akapit | ("b", tekst) punktor | ("h3", tekst) pod-naglowek
# ============================================================
DOCS = {

"PL": {
 "part": "CZESC 1 z 3 — WERSJA POLSKA (rozstrzygajaca)",
 "title": "FENIX / AnonNet — Dokument Sieci",
 "sub": "Dzialanie sieci | Regulamin | Kompetencje Administracji | Ryzyka prawne | Ochrona Uzytkownika | ToS",
 "date": "Wersja 1.0 — 2026-07-19 (draft; nie stanowi porady prawnej)",
 "plain_label": "PO LUDZKU: ",
 "sections": [
  ("1. Wprowadzenie i status dokumentu", [
    ("p","Niniejszy dokument opisuje sposob dzialania Sieci Fenix, obowiazujacy w niej Regulamin, katalog kompetencji Administracji, scenariusze ryzyk prawnych oraz mechanizmy ochrony Uzytkownika. Stanowi integralne uzupelnienie Warunkow Korzystania (ToS) v1.0."),
    ("p","Dokument ma charakter informacyjny i roboczy. Nie stanowi porady prawnej dla zadnej ze stron. Przed publikacja i wdrozeniem zalecana jest konsultacja z prawnikiem znajacym jurysdykcje docelowe Sieci."),
    ("p","W przypadku rozbieznosci rozstrzygajaca jest wersja polskojezyczna; wersje angielska i rosyjska pelnia funkcje informacyjna."),
  ], ["To mapa calej sieci zapisana dwoma glosami: prawniczym i ludzkim. Warto przeczytac oba."]),
  ("2. Jak dziala Siec Fenix", [
    ("b","Siec peer-to-peer bez centralnego serwera: tresci i konta istnieja wylacznie na urzadzeniach Uzytkownikow. Nie ma infrastruktury Administracji przechowujacej dane uzytkownikow — nie ma czego przejac ani wydac."),
    ("b","Tozsamosc = Wallet Address + Username + UID + Ranga; rejestr publiczny na blockchainie FNX, bez danych osobowych."),
    ("b","Komunikacja szyfrowana end-to-end; klucze prywatne nigdy nie opuszczaja urzadzenia; kazda wiadomosc uzywa klucza jednorazowego (forward secrecy)."),
    ("b","Transport: wlasny protokol z warstwa kamuflazu (camo) utrudniajaca identyfikacje ruchu (DPI); routing cebulowy hop-by-hop — zaden relay nie zna rownoczesnie nadawcy, odbiorcy i tresci."),
    ("b","Gospodarka FNX: oplata 0.001% burn + 0.055% skarbiec ownera; kopanie PoW (CPU) sprzezone z hostowaniem fragmentow danych (proof-of-storage)."),
    ("b","Obrona: system AI-Sentry wylacznie w gestii Administracji (D17); werdykty jawne z uzasadnieniem; reputacja Proof-of-Uptime (30 dni = status VOTER i prawo glosu)."),
    ("b","Rangi: dobrowolne wplaty FNX za benefity (hosting, QoS, kosmetyka) — NIGDY w zamian za wladze, glos lub dane innych."),
  ], ["Firmowego serwera nie ma — nie ma czego przejac. Listy czyta tylko nadawca i adresat. Ranga kupuje wygode, nie wladze."]),
  ("3. Regulamin Sieci", [
    ("p","3.1 Dozwolone: komunikacja prywatna i grupowa; hostowanie legalnych tresci; kopanie FNX; udzial w glosowaniach (VOTER); zakup rang i benefitow; samodzielne ustawianie suwaka telemetrii."),
    ("p","3.2 Zabronione (podstawa automatycznego bana):"),
    ("b","ROUTE_LEAKAGE — kierowanie ruchu Fenix przez niezabezpieczone proxy / wyciaganie danych poza Siec;"),
    ("b","PROTO_FLOOD — wolumetryczne zalewanie protokolu; INVALIDTAG_STORM — masowe falszowane pakiety;"),
    ("b","SYBIL_RING — pierscienie falszywych tozsamosci; STORAGE_FRAUD — oszustwa proof-of-storage;"),
    ("b","MSG_SPAM — masowa wysylka (analiza wzorca meta, NIGDY tresci); CAMO_VIOLATION — ruch bez warstwy kamuflazu;"),
    ("b","DOXXING — publikowanie danych osobowych osob trzecich; oraz wszelkie tresci i dzialania nielegalne (pkt 5)."),
    ("p","3.3 Egzekwowanie: automatyczne, z uzasadnieniem. Tresci nie sa skanowane (przy E2E jest to technicznie niemozliwe); egzekwowane sa wzorce bezpieczenstwa oraz rejestr ostrzezonych hashy — konsensus wstrzymuje dystrybucje oznaczonego fragmentu bez odczytu jego tresci."),
  ], ["Prywatnosc — zawsze. Ale atak na siec, oszustwo protokolu i nielegalna handlarka koncza sie banem — z nazwy i z powodu, publicznie."]),
  ("4. Co moze Administracja (katalog zamkniety)", [
    ("p","4.1 Administracja MOZE wylacznie:"),
    ("b","podpisywac i publikowac aktualizacje Oprogramowania (klucz ownera, D14);"),
    ("b","operowac systemem ochrony AI-Sentry (D17) i wydawac werdykty banow z uzasadnieniem (D18);"),
    ("b","przyjmowac albo odrzucac wykupienia banow — decyzja ostateczna;"),
    ("b","pobierac oplate protokolu 0.055% do skarbca ownera (D15) i zarzadzac skarbcem;"),
    ("b","utrzymywac seed nodes, bootstrap i oficjalny kanal ogloszen;"),
    ("b","zmieniac Warunki z co najmniej 14-dniowym uprzedzeniem;"),
    ("b","wstrzymywac dystrybucje fragmentow oznaczonych hashem, wylacznie droga konsensusu."),
    ("p","4.2 Administracja wyraznie NIE MOZE (zobowiazania projektu):"),
    ("b","odczytywac tresci wiadomosci ani logow aktywnosci (nie istnieja);"),
    ("b","odzyskac utraconego klucza ani hasla Uzytkownika (D9);"),
    ("b","deanonimizowac Uzytkownikow srodkami systemowymi;"),
    ("b","cofac transakcji on-chain ani zmieniac sald poza zasadami konsensusu;"),
    ("b","wydac dane, ktorych nie posiada — jakimkolwiek podmiotom (par.4 ToS)."),
  ], ["Wladza admina konczy sie na serwisie silnika. Nie widzi listow, nie zna hasel, nie ma kluczy — wiec nie ma czego wydac."]),
  ("5. Scenariusze ryzyk prawnych i stanowisko Administracji", [
    ("p","Siec Fenix NIE jest tworzona ani utrzymywana w celu ulatwiania dzialan bezprawnych. Dla kazdego scenariusza obowiazuje: (a) zakaz, (b) wylaczna odpowiedzialnosc sprawcy, (c) wylaczenie odpowiedzialnosci Administracji w maksymalnym zakresie dozwolonym prawem, (d) mechanizmy ograniczajace zjawisko."),
    ("h3","5.1 Tresci nielegalne, w tym materialy wykorzystujace dzieci (CSAM)"),
    ("p","Tolerancja zero; kategoryczny zakaz; odpowiedzialnosc wylacznie sprawcy. Administracja nie skanuje tresci (E2E), lecz utrzymuje rejestr ostrzezonych hashy i wstrzymuje dystrybucje oznaczonych fragmentow (konsensus). Wspoldzialanie z organami ogranicza sie do danych z natury publicznych on-chain."),
    ("h3","5.2 Kradziez tozsamosci i podszywanie sie"),
    ("p","Zakaz. Mechanizmy ochronne: tozsamosc kryptograficzna z podpisami, name protection (benefit rang), jawne odciski walletow do weryfikacji poza pasmem. Administracja nie odpowiada za szkody powstale wskutek braku weryfikacji odciskow przez Uzytkownika."),
    ("h3","5.3 Oszustwa kryptowalutowe („scamy”)"),
    ("p","Zakaz. Administracja nie posredniczy w wymianach P2P, nie gwarantuje kontrahentow ani nie depozytuje srodkow uzytkownikow. Zasada bezwzgledna: Administracja NIGDY nie zwraca sie o klucz, seed, zaliczke ani „wplate weryfikacyjna”. Potwierdzone konsensusem adresy scamow trafiaja do rejestru SCAM_ALERT. Umowy i ich skutki obciazaja wylacznie strony."),
    ("h3","5.4 Handel nielegalnymi towarami i uslugami (narkotyki, bron, kradzione dane itp.)"),
    ("p","Zakaz; odpowiedzialnosc wylacznie stron; Administracja nie odpowiada za oferty, umowy ani ich skutki."),
    ("h3","5.5 Zlosliwe oprogramowanie, ransomware, phishing"),
    ("p","Zakaz; wzorce egzekwowane kodami banow; SCAM_ALERT dla potwierdzonych kampanii; Administracja nie odpowiada za szkody."),
    ("h3","5.6 Pranie pieniedzy i obchodzenie sankcji"),
    ("p","Zakaz; Uzytkownik odpowiada za zgodnosc ze swoja jurysdykcja (w tym AML i podatkowa). Administracja nie swiadczy uslug finansowych, nie prowadzi KYC (decyzja projektowa), nie gwarantuje plynnosci ani wartosci FNX."),
    ("h3","5.7 Terroryzm, przemoc, nawolywanie do przemocy"),
    ("p","Kategoryczny zakaz; wylaczenie odpowiedzialnosci Administracji; wskazac mozna wylacznie dane z natury publiczne on-chain."),
    ("h3","5.8 Dane osobowe osob trzecich, doxxing, naruszenia wlasnosci intelektualnej"),
    ("p","Zakaz; odpowiedzialnosc publikujacego; Administracja nie odpowiada."),
    ("h3","5.9 Ataki na sama Siec (w tym na warstwe camo i konsensus)"),
    ("p","Obslugiwane automatycznie kodami banow; Administracja nie odpowiada za szkody powstale wskutek atakow osob trzecich."),
    ("h3","5.10 Granica klauzul"),
    ("p","Zadne postanowienie nie wylacza odpowiedzialnosci, ktorej bezwzglednie obowiazujace prawo nie pozwala wylaczyc. Dokument sporzadzono w dobrej wierze, w celu minimalizacji szkod dla wszystkich uczestnikow."),
  ], ["Prywatna nie znaczy bezprawna. Kto tu handluje kradzionym, scamuje albo sie podszywa — odpowiada sam. Siec nie moze go „podejrzec”, bo z tych samych powodow nie moze podejrzec ciebie. To cena i dar prywatnosci."]),
  ("6. Mechanizmy ochrony Uzytkownika", [
    ("b","Szyfrowanie E2E z kluczami jednorazowymi (forward secrecy) — nawet przejecie klucza stalego nie otwiera historii."),
    ("b","Brak logow i tresci po stronie sieci: kapsuly sesyjne w RAM, spalenie klucza sesji przy wylogowaniu (crypto-shred)."),
    ("b","Kamuflaz transportowy (camo) + routing cebulowy — przeciw DPI, profilowaniu i analizie ruchu."),
    ("b","Jawne werdykty bezpieczenstwa: kazdy ban z kodem i wyjasnieniem PL/EN oraz hashem dowodow; rejestr publiczny."),
    ("b","Suwak telemetrii off/minimal/full (domyslnie minimal) — Uzytkownik decyduje."),
    ("b","Proof-of-Uptime zamiast danych osobowych — reputacja bez deanonimizacji."),
    ("b","Procedura unban: 30 dni na decyzje Administracji, zwrot 99% przy odmowie lub braku decyzji."),
    ("b","Ostrzezenia anty-scam (SCAM_ALERT), weryfikacja odciskow walletow, rejestr falszywych tozsamosci „Administracji”."),
    ("b","Haslo paniki (cichy crypto-shred), „czysty ekran”, self-destruct po hasle duress (D3)."),
    ("b","Zasady higieny publikowane Uzytkownikom: weryfikuj sumy SHA256 ISO; Administracja nigdy nie pisze pierwsza w sprawach srodkow; nigdy nie prosi o klucz, seed ani haslo."),
  ], ["Siec broni cie matematyka, nie obietnicami. Przed scamem broni jedna zelazna zasada: nikt z obslugi nigdy nie poprosi o twoj klucz. Nigdy."]),
  ("7. Warunki Korzystania — kluczowe postanowienia (skrot)", [
    ("b","Swiadczenie „jak jest”, bez gwarancji; pelna wersja: docs/ToS.md."),
    ("b","Tresci i odpowiedzialnosc za nie: wylacznie Uzytkownicy."),
    ("b","Brak danych = brak mozliwosci ich wydania; brak recovery (D9)."),
    ("b","Rangi: platnosci finalne; benefity ewoluuja tylko w granicach protokolu."),
    ("b","Bany automatyczne z uzasadnieniem; unban 1 000 000 USD XMR, 30 dni, zwrot 99%; jeden wykup na wallet; ponowny ban permanentny."),
    ("b","System ochrony (AI) w wylacznej gestii Administracji; uzytkownicy nie komunikuja sie z nim."),
    ("b","Odpowiedzialnosc Administracji ograniczona do USD 0 w maksymalnym dozwolonym zakresie."),
    ("b","Zmiany Warunkow: publikacja co najmniej 14 dni wczesniej; dalsze korzystanie = akceptacja."),
  ], ["To samo co wyzej — w punktach na lodowke."]),
  ("8. Odpowiedzialnosc i wiek Uzytkownika", [
    ("p","Usluga przeznaczona dla osob pelnoletnich (18+). Uzytkownik odpowiada za: zgodnosc z prawem wlasnej jurysdykcji, bezpieczenstwo kluczy i hasel, tresci ktore tworzy i hostuje, oraz skutki transakcji zawartych z innymi uzytkownikami. Nieznajomosc prawa nie zwalnia z odpowiedzialnosci — jak wszedzie."),
  ], []),
  ("9. Postanowienia koncowe", [
    ("p","Separowalnosc postanowien; zmiany z 14-dniowym wyprzedzeniem; wersja polska rozstrzygajaca; kontakt wylacznie przez oficjalne kanaly ogloszeniowe w Sieci; data dokumentu: 2026-07-19."),
  ], []),
 ],
 "rangi_h": "Aneks A — Rangi i Benefity (cenik)",
 "rangi": [
  ("ghost — startowa (0 FNX)", ["hosting: 1 strona (Web Builder)","generowany avatar (identicon z walleta)","ciemny motyw, 1 grupa (25 osob)","bufor offline 7 dni, tier 0","pelne PoU/glos po 30 dniach uptime"]),
  ("Donor — 0.000001 FNX", ["wlasny avatar (upload, szyfrowany)","odznaka Donor + brazowy nick","hosting: 3 strony","rezerwacja username (name protection)","bufor 30 dni, tier 1"]),
  ("VIP — 0.000002 FNX", ["animowany avatar + baner profilu","hosting: 5 stron + motywy premium stron","2 zmiany username/rok","grupy 3x100, wlasne motywy GUI","tier 2 + priorytet laczenia z seedami"]),
  ("VIP+ — 0.000003 FNX", ["ramka avatara z poswiata + odznaka","hosting: 10 stron + vanity path /nick/strona","dostep do funkcji beta","grupy 5x250","podpisane raporty bezpieczenstwa konta, tier 3"]),
  ("SVIP — 0.00001 FNX", ["hosting: 25 stron + panel (agregaty, ZERO logow gosci)","interaktywna ramka avatara","storage x2, grupy 10x500","feed ogloszen na wlasnych stronach","bufor 180 dni, tier 4"]),
  ("ELITE — 0.0001 FNX", ["hosting: 100 stron + wlasne szablony Web Buildera (CSS sandbox)","fast-lane E2E gwarantowana","buildy RC + ankiety doradcze (niewiazace)","grupy bez limitu liczby (2k os./grupa)","vanity wallet (prefiks), aura odznaki, tier 5"]),
  ("SELITE — 0.01 FNX", ["hosting: 500 stron + white-label","kanal ogloszen sieciowych (moderacja admina)","wpis na stronie (opt-in), test builds + kanal do dev","vanity premium, sub-kanaly, grupy 5k","LIMIT: 10 kont/rok, tier 6"]),
  ("FENIX — 100.1 FNX", ["LIFETIME; hosting bez twardego limitu (fair-use)","dedykowany priorytetowy relay E2E","fotel w radzie doradczej (kwartalnie, BEZ wladzy nad protokolem)","wspolprojekt 1 funkcji kosmetycznej; odznaka shard","Sciana Legend (opt-in); LIMIT: 21 w historii sieci"]),
 ],
 "rangi_rules_h": "Zasady nadrzedne rang",
 "rangi_rules": [
  "Ranga = perk sieciowy. NIGDY nie daje: glosu (tylko PoU >=30 dni), dostepu do AI bezpieczenstwa (wylacznie owner/admin), danych innych, unbana, wladzy nad protokolem.",
  "Ranga zapisana ON-CHAIN (tx RANK_UP, 6 potwierdzen); upgrade = doplata roznicy.",
  "Do czasu stealth addresses kupno rangi jest publiczne — zalecany swiezy wallet.",
 ],
 "bany_h": "Aneks B — Polityka banow i wykupu (UNBAN)",
 "bany": [
  "Auto-ban = konsensus AI (narzedzie admina) -> wpis ON-CHAIN: kod powodu + wyjasnienie PL/EN + hash dowodow (bez tresci!).",
  "Kody: ROUTE_LEAKAGE (routing przez niezabezpieczone proxy — wyciaganie danych poza Fenix!), PROTO_FLOOD, INVALIDTAG_STORM, SYBIL_RING, STORAGE_FRAUD, MSG_SPAM (meta, nie tresc), CAMO_VIOLATION, DOXXING.",
  "UNBAN: jedyna droga = 1 000 000 USD w XMR, JEDNORAZOWO (escrow multisig 2-z-3 + timelock).",
  "Admin ma 30 dni: akceptacja -> skarbiec + unban on-chain; odmowa/timeout -> zwrot 99% (1% anti-spam). Decyzja admina ostateczna.",
  "Unban: PoU/reputacja/VOTER od zera; ranga nie wraca.",
  "Jeden wykup na wallet w calej historii; ponowny ban = PERMANENTNY.",
  "Publiczny rejestr banow z wyjasnieniami (GUI + eksplorator).",
 ],
 "end": "— Koniec wersji polskiej —",
},

"EN": {
 "part": "PART 2 of 3 — ENGLISH VERSION (informational)",
 "title": "FENIX / AnonNet — Network Document",
 "sub": "How the network works | Rules | Administration powers | Legal-risk scenarios | User protection | ToS",
 "date": "v1.0 — 2026-07-19 (draft; not legal advice)",
 "plain_label": "IN PLAIN TERMS: ",
 "sections": [
  ("1. Introduction and document status", [
    ("p","This document describes how the Fenix Network operates, its Rules, the closed catalogue of Administration powers, legal-risk scenarios and the mechanisms protecting Users. It forms an integral supplement to the Terms of Service (ToS) v1.0."),
    ("p","This is an informational working draft. It is not legal advice for any party. Publication and rollout should be preceded by review with counsel familiar with the Network's target jurisdictions."),
    ("p","In case of divergence, the Polish version prevails; the English and Russian versions are informational."),
  ], ["This is the map of the whole network written in two voices: legal and human. Read both."]),
  ("2. How the Fenix Network works", [
    ("b","Peer-to-peer network with no central server: content and accounts exist solely on Users' devices. No Administration infrastructure stores user data — there is nothing to seize or hand over."),
    ("b","Identity = Wallet Address + Username + UID + Rank; public registry on the FNX blockchain, without personal data."),
    ("b","End-to-end encrypted messaging; private keys never leave the device; per-message one-time keys (forward secrecy)."),
    ("b","Transport: proprietary protocol with a camouflage layer (camo) hindering traffic identification (DPI); onion routing hop-by-hop — no relay knows sender, recipient and content at once."),
    ("b","FNX economy: 0.001% burn fee + 0.055% owner treasury; CPU proof-of-work mining coupled with hosting of data fragments (proof-of-storage)."),
    ("b","Defense: AI-Sentry operated exclusively by the Administration (D17); verdicts public with reasoning; Proof-of-Uptime reputation (30 days = VOTER status and vote)."),
    ("b","Ranks: voluntary FNX payments for perks (hosting, QoS, cosmetics) — NEVER in exchange for power, votes or others' data."),
  ], ["No company server — nothing to seize. Only sender and recipient can read a letter. A rank buys comfort, not power."]),
  ("3. Network Rules", [
    ("p","3.1 Permitted: private and group communication; hosting lawful content; FNX mining; voting (VOTER); purchasing ranks and perks; setting one's own telemetry slider."),
    ("p","3.2 Prohibited (grounds for automatic ban):"),
    ("b","ROUTE_LEAKAGE — routing Fenix traffic through unsecured proxies / extracting data out of the Network;"),
    ("b","PROTO_FLOOD — volumetric floods of the protocol; INVALIDTAG_STORM — mass forged packets;"),
    ("b","SYBIL_RING — rings of fake identities; STORAGE_FRAUD — proof-of-storage fraud;"),
    ("b","MSG_SPAM — bulk sending (metadata-pattern analysis, NEVER content); CAMO_VIOLATION — traffic without the camouflage layer;"),
    ("b","DOXXING — publishing third parties' personal data; plus all unlawful content and conduct (sec. 5)."),
    ("p","3.3 Enforcement: automatic, with reasoning. Content is not scanned (technically impossible under E2E); security patterns and a warned-hash registry are enforced — consensus suspends distribution of a flagged fragment without reading its content."),
  ], ["Privacy — always. But attacking the network, defrauding the protocol and unlawful dealing end in a ban — with its name and reason, publicly."]),
  ("4. What the Administration may do (closed catalogue)", [
    ("p","4.1 The Administration MAY only:"),
    ("b","sign and publish Software updates (owner key, D14);"),
    ("b","operate the AI-Sentry defense system (D17) and issue ban verdicts with reasoning (D18);"),
    ("b","accept or reject ban buyouts — decision final;"),
    ("b","collect the 0.055% protocol fee to the owner treasury (D15) and manage the treasury;"),
    ("b","maintain seed nodes, bootstrap and the official announcement channel;"),
    ("b","amend the Terms with at least 14 days' notice;"),
    ("b","suspend distribution of hash-flagged fragments, solely via consensus."),
    ("p","4.2 The Administration expressly CANNOT (design undertakings):"),
    ("b","read message content or activity logs (they do not exist);"),
    ("b","recover a User's lost key or password (D9);"),
    ("b","deanonymize Users by systemic means;"),
    ("b","reverse on-chain transactions or alter balances outside consensus rules;"),
    ("b","disclose data it does not possess — to any parties (ToS sec. 4)."),
  ], ["Admin power ends at engine maintenance. It cannot read mail, does not know passwords, holds no keys — so there is nothing to hand over."]),
  ("5. Legal-risk scenarios and the Administration's position", [
    ("p","The Fenix Network is NOT created or maintained to facilitate unlawful activity. Each scenario below carries: (a) a prohibition, (b) the perpetrator's sole liability, (c) exclusion of the Administration's liability to the maximum extent permitted by law, (d) mitigating mechanisms."),
    ("h3","5.1 Unlawful content, including child-abuse material (CSAM)"),
    ("p","Zero tolerance; categorical prohibition; sole liability of the perpetrator. The Administration does not scan content (E2E) but maintains a warned-hash registry and suspends distribution of flagged fragments (consensus). Cooperation with authorities is limited to data that is public on-chain by nature."),
    ("h3","5.2 Identity theft and impersonation"),
    ("p","Prohibited. Protective mechanisms: signature-based identity, name protection (rank perk), public wallet fingerprints for out-of-band verification. The Administration is not liable for harm caused by a User's failure to verify fingerprints."),
    ("h3","5.3 Cryptocurrency fraud ('scams')"),
    ("p","Prohibited. The Administration does not broker P2P exchanges, does not vouch for counterparties and does not custody user funds. Iron rule: the Administration NEVER requests a key, seed, advance payment or 'verification deposit'. Consensus-confirmed scam addresses enter the SCAM_ALERT registry. Contracts and their consequences burden the parties alone."),
    ("h3","5.4 Trade in unlawful goods and services (drugs, weapons, stolen data, etc.)"),
    ("p","Prohibited; sole liability of the parties; the Administration is not responsible for offers, contracts or their outcomes."),
    ("h3","5.5 Malicious software, ransomware, phishing"),
    ("p","Prohibited; patterns enforced via ban codes; SCAM_ALERT for confirmed campaigns; Administration not liable for resulting damage."),
    ("h3","5.6 Money laundering and sanctions evasion"),
    ("p","Prohibited; the User is responsible for compliance with their own jurisdiction (incl. AML and tax). The Administration provides no financial services, performs no KYC (design decision) and guarantees neither liquidity nor any value of FNX."),
    ("h3","5.7 Terrorism, violence, incitement"),
    ("p","Categorically prohibited; Administration liability excluded; only naturally public on-chain data can be indicated."),
    ("h3","5.8 Third parties' personal data, doxxing, intellectual-property infringement"),
    ("p","Prohibited; liability of the publisher; the Administration is not responsible."),
    ("h3","5.9 Attacks on the Network itself (incl. the camo layer and consensus)"),
    ("p","Handled automatically via ban codes; the Administration is not liable for damage caused by third-party attacks."),
    ("h3","5.10 Limitation of clauses"),
    ("p","No provision excludes liability that mandatory law does not allow to be excluded. This document is drafted in good faith to minimize harm for all participants."),
  ], ["Private does not mean lawless. Whoever sells stolen goods here, scams or impersonates — answers alone. The network cannot 'peek' at them for the same reasons it cannot peek at you. That is the price and the gift of privacy."]),
  ("6. User-protection mechanisms", [
    ("b","E2E encryption with one-time keys (forward secrecy) — even a compromised long-term key does not open history."),
    ("b","No logs or content network-side: RAM session capsules, session-key burning on logout (crypto-shred)."),
    ("b","Transport camouflage (camo) + onion routing — against DPI, profiling and traffic analysis."),
    ("b","Public security verdicts: every ban with a code and PL/EN explanation plus evidence hash; public register."),
    ("b","Telemetry slider off/minimal/full (default minimal) — the User decides."),
    ("b","Proof-of-Uptime instead of personal data — reputation without deanonymization."),
    ("b","Unban procedure: 30 days for the Administration's decision, 99% refund on rejection or timeout."),
    ("b","Anti-scam alerts (SCAM_ALERT), wallet-fingerprint verification, registry of fake 'Administration' identities."),
    ("b","Panic password (silent crypto-shred), 'clean screen', duress-password self-destruct (D3)."),
    ("b","Hygiene rules published to Users: verify ISO SHA256 sums; the Administration never initiates contact about funds; never asks for key, seed or password."),
  ], ["The network defends you with mathematics, not promises. Against scams there is one iron rule: support will never ask for your key. Ever."]),
  ("7. Terms of Service — key provisions (summary)", [
    ("b","Provided 'as is', without warranties; full text: docs/ToS.md."),
    ("b","Content and liability for it: Users alone."),
    ("b","No data = no possibility of disclosing it; no account recovery (D9)."),
    ("b","Ranks: payments final; perks evolve only within protocol bounds."),
    ("b","Automatic bans with reasoning; unban 1,000,000 USD XMR, 30 days, 99% refund; one buyout per wallet; re-ban permanent."),
    ("b","The protection system (AI) is in the Administration's exclusive control; users cannot communicate with it."),
    ("b","Administration liability limited to USD 0 to the maximum extent permitted."),
    ("b","Amendments: published at least 14 days ahead; continued use = acceptance."),
  ], ["Same as above — fridge-door bullet points."]),
  ("8. User responsibility and age", [
    ("p","Service intended for adults (18+). The User is responsible for: compliance with the law of their own jurisdiction, security of keys and passwords, the content they create and host, and the consequences of transactions concluded with other users. Ignorance of the law is no excuse — as everywhere."),
  ], []),
  ("9. Final provisions", [
    ("p","Severability of provisions; amendments with 14 days' notice; the Polish version prevails; contact exclusively via official announcement channels inside the Network; document date: 2026-07-19."),
  ], []),
 ],
 "rangi_h": "Annex A — Ranks and Perks (price list)",
 "rangi": [
  ("ghost — starter (0 FNX)", ["hosting: 1 site (Web Builder)","generated avatar (wallet identicon)","dark theme, 1 group (25 people)","offline buffer 7 days, tier 0","full PoU/vote after 30 days uptime"]),
  ("Donor — 0.000001 FNX", ["custom avatar (encrypted upload)","Donor badge + brown nickname","hosting: 3 sites","username reservation (name protection)","buffer 30 days, tier 1"]),
  ("VIP — 0.000002 FNX", ["animated avatar + profile banner","hosting: 5 sites + premium site themes","2 username changes/year","groups 3x100, custom GUI themes","tier 2 + priority seed connections"]),
  ("VIP+ — 0.000003 FNX", ["glowing avatar frame + supporter badge","hosting: 10 sites + vanity path /nick/site","beta features access","groups 5x250","signed account security reports, tier 3"]),
  ("SVIP — 0.00001 FNX", ["hosting: 25 sites + panel (aggregates, ZERO visitor logs)","interactive avatar frame","storage x2, groups 10x500","announcement feed on own sites","buffer 180 days, tier 4"]),
  ("ELITE — 0.0001 FNX", ["hosting: 100 sites + custom Web Builder templates (CSS sandbox)","guaranteed E2E fast-lane","RC builds + advisory polls (non-binding)","unlimited group count (2k each)","vanity wallet (prefix grind), aura badge, tier 5"]),
  ("SELITE — 0.01 FNX", ["hosting: 500 sites + white-label","network announcement channel (admin moderated)","supporters page listing (opt-in), test builds + dev channel","premium vanity, sub-channels, groups 5k","LIMIT: 10 accounts/year, tier 6"]),
  ("FENIX — 100.1 FNX", ["LIFETIME; hosting without hard limit (fair-use)","dedicated priority relay E2E","advisory council seat (quarterly, NO protocol power)","co-design of 1 cosmetic feature; unique shard badge","Wall of Legends (opt-in); LIMIT: 21 in network history"]),
 ],
 "rangi_rules_h": "Overriding rank rules",
 "rangi_rules": [
  "A rank = a network perk. It NEVER grants: a vote (PoU >=30 days only), access to the security AI (owner/admin only), others' data, an unban, or power over the protocol.",
  "Rank recorded ON-CHAIN (RANK_UP tx, 6 confirmations); upgrade = pay the difference.",
  "Until stealth addresses ship, rank purchase is public — a fresh wallet is advised.",
 ],
 "bany_h": "Annex B — Ban & buyout policy (UNBAN)",
 "bany": [
  "Auto-ban = AI consensus (admin tool) -> ON-CHAIN record: reason code + PL/EN explanation + evidence hash (no content!).",
  "Codes: ROUTE_LEAKAGE (routing via unsecured proxy — extracting data out of Fenix!), PROTO_FLOOD, INVALIDTAG_STORM, SYBIL_RING, STORAGE_FRAUD, MSG_SPAM (metadata, not content), CAMO_VIOLATION, DOXXING.",
  "UNBAN: only path = 1,000,000 USD in XMR, ONE-TIME (multisig escrow 2-of-3 + timelock).",
  "Admin has 30 days: accept -> treasury + unban on-chain; reject/timeout -> 99% refund (1% anti-spam). Admin decision final.",
  "Unban resets PoU/reputation/VOTER to zero; rank does not return.",
  "One buyout per wallet in network history; re-ban = PERMANENT.",
  "Public ban register with explanations (GUI + explorer).",
 ],
 "end": "— End of English version —",
},

"RU": {
 "part": "ЧАСТЬ 3 из 3 — РУССКАЯ ВЕРСИЯ (информационная)",
 "title": "FENIX / AnonNet — Документ Сети",
 "sub": "Устройство сети | Правила | Полномочия Администрации | Правовые риски | Защита пользователя | ToS",
 "date": "v1.0 — 2026-07-19 (черновик; не является юридической консультацией)",
 "plain_label": "ПРОСТЫМИ СЛОВАМИ: ",
 "sections": [
  ("1. Введение и статус документа", [
    ("p","Настоящий документ описывает устройство Сети Fenix, действующие в ней Правила, закрытый перечень полномочий Администрации, сценарии правовых рисков и механизмы защиты Пользователя. Он является неотъемлемым дополнением к Условиям использования (ToS) v1.0."),
    ("p","Документ носит информационный и рабочий характер и не является юридической консультацией ни для одной из сторон. Перед публикацией и запуском рекомендуется консультация юриста, знакомого с целевыми юрисдикциями Сети."),
    ("p","При расхождениях приоритет имеет польская версия; английская и русская версии носят информационный характер."),
  ], ["Это карта всей сети, написанная двумя голосами: юридическим и человеческим. Прочитайте оба."]),
  ("2. Как устроена Сеть Fenix", [
    ("b","Одноранговая сеть (P2P) без центрального сервера: контент и учётные записи существуют исключительно на устройствах Пользователей. Инфраструктуры Администрации, хранящей данные пользователей, нет — нечего изъять и нечего передать."),
    ("b","Идентичность = Wallet Address + Username + UID + Rank; публичный реестр на блокчейне FNX, без персональных данных."),
    ("b","Сквозное шифрование (E2E); приватные ключи никогда не покидают устройство; для каждого сообщения — одноразовый ключ (forward secrecy)."),
    ("b","Транспорт: собственный протокол со слоем камуфляжа (camo), затрудняющим опознавание трафика (DPI); луковая маршрутизация hop-by-hop — ни один relay не знает отправителя, получателя и содержимое одновременно."),
    ("b","Экономика FNX: комиссия 0.001% burn + 0.055% в казну владельца; майнинг PoW (CPU) совмещён с хостингом фрагментов данных (proof-of-storage)."),
    ("b","Защита: система AI-Sentry исключительно в ведении Администрации (D17); вердикты публичны, с обоснованием; репутация Proof-of-Uptime (30 дней = статус VOTER и право голоса)."),
    ("b","Ранги: добровольные платежи FNX за преимущества (хостинг, QoS, косметика) — НИКОГДА в обмен на власть, голос или чужие данные."),
  ], ["Фирменного сервера нет — нечего захватить. Письмо читают только отправитель и адресат. Ранг покупает удобство, а не власть."]),
  ("3. Правила Сети", [
    ("p","3.1 Разрешено: частное и групповое общение; хостинг законного контента; майнинг FNX; участие в голосованиях (VOTER); покупка рангов и преимуществ; самостоятельная настройка ползунка телеметрии."),
    ("p","3.2 Запрещено (основание автоматического бана):"),
    ("b","ROUTE_LEAKAGE — маршрутизация трафика Fenix через незащищённые прокси / вывод данных за пределы Сети;"),
    ("b","PROTO_FLOOD — объёмное наводнение протокола; INVALIDTAG_STORM — массовые поддельные пакеты;"),
    ("b","SYBIL_RING — кольца поддельных личностей; STORAGE_FRAUD — мошенничество с proof-of-storage;"),
    ("b","MSG_SPAM — массовая рассылка (анализ мета-паттернов, НИКОГДА содержимого); CAMO_VIOLATION — трафик без слоя камуфляжа;"),
    ("b","DOXXING — публикация персональных данных третьих лиц; а также любой незаконный контент и действия (п. 5)."),
    ("p","3.3 Правоприменение: автоматическое, с обоснованием. Контент не сканируется (при E2E это технически невозможно); обеспечивается соблюдение шаблонов безопасности и реестра предупреждённых хэшей — консенсус приостанавливает распространение помеченного фрагмента, не читая его содержимое."),
  ], ["Приватность — всегда. Но атака на сеть, обман протокола и незаконная торговля заканчиваются баном — по имени и по причине, публично."]),
  ("4. Что может Администрация (закрытый перечень)", [
    ("p","4.1 Администрация МОЖЕТ только:"),
    ("b","подписывать и публиковать обновления Программного обеспечения (ключ владельца, D14);"),
    ("b","управлять системой защиты AI-Sentry (D17) и выносить вердикты банов с обоснованием (D18);"),
    ("b","принимать либо отклонять выкупы банов — решение окончательное;"),
    ("b","взимать протокольную комиссию 0.055% в казну владельца (D15) и управлять казной;"),
    ("b","поддерживать seed-узлы, bootstrap и официальный канал объявлений;"),
    ("b","изменять Условия с уведомлением не менее чем за 14 дней;"),
    ("b","приостанавливать распространение фрагментов, помеченных хэшем, только путём консенсуса."),
    ("p","4.2 Администрация прямо НЕ МОЖЕТ (проектные обязательства):"),
    ("b","читать содержимое сообщений или журналы активности (их не существует);"),
    ("b","восстановить утерянный ключ или пароль Пользователя (D9);"),
    ("b","деанонимизировать Пользователей системными средствами;"),
    ("b","отменять транзакции on-chain или изменять балансы вне правил консенсуса;"),
    ("b","передать данные, которыми не располагает, — никаким сторонам (§4 ToS)."),
  ], ["Власть админа заканчивается на обслуживании двигателя. Он не видит писем, не знает паролей, не имеет ключей — поэтому ему нечего выдать."]),
  ("5. Сценарии правовых рисков и позиция Администрации", [
    ("p","Сеть Fenix НЕ создаётся и не поддерживается для содействия незаконной деятельности. Для каждого сценария действует: (а) запрет, (b) исключительная ответственность нарушителя, (c) исключение ответственности Администрации в максимальном разрешённом законом объёме, (d) механизмы минимизации явления."),
    ("h3","5.1 Незаконный контент, включая материалы с эксплуатацией детей (CSAM)"),
    ("p","Нулевая терпимость; категорический запрет; исключительная ответственность нарушителя. Администрация не сканирует контент (E2E), но ведёт реестр предупреждённых хэшей и приостанавливает распространение помеченных фрагментов (консенсус). Взаимодействие с органами ограничено данными, публичными по своей природе on-chain."),
    ("h3","5.2 Кража личности и выдача себя за другого"),
    ("p","Запрет. Защитные механизмы: криптографическая идентичность с подписями, name protection (преимущество рангов), публичные отпечатки кошельков для проверки вне канала. Администрация не отвечает за ущерб, возникший из-за того, что Пользователь не проверил отпечатки."),
    ("h3","5.3 Криптовалютные мошенничества («скамы»)"),
    ("p","Запрет. Администрация не посредничает в P2P-обменах, не поручается за контрагентов и не хранит средства пользователей. Железное правило: Администрация НИКОГДА не запрашивает ключ, seed, предоплату или «верификационный платёж». Подтверждённые консенсусом скам-адреса попадают в реестр SCAM_ALERT. Договоры и их последствия лежат исключительно на сторонах."),
    ("h3","5.4 Торговля незаконными товарами и услугами (наркотики, оружие, краденые данные и т.п.)"),
    ("p","Запрет; исключительная ответственность сторон; Администрация не отвечает за предложения, сделки и их последствия."),
    ("h3","5.5 Вредоносное ПО, ransomware, фишинг"),
    ("p","Запрет; паттерны пресекаются кодами банов; SCAM_ALERT для подтверждённых кампаний; Администрация не несёт ответственности за ущерб."),
    ("h3","5.6 Отмывание денег и обход санкций"),
    ("p","Запрет; Пользователь отвечает за соответствие своей юрисдикции (включая AML и налоги). Администрация не оказывает финансовых услуг, не проводит KYC (проектное решение), не гарантирует ни ликвидность, ни стоимость FNX."),
    ("h3","5.7 Терроризм, насилие, подстрекательство"),
    ("p","Категорический запрет; ответственность Администрации исключена; указать возможно лишь данные, публичные по природе on-chain."),
    ("h3","5.8 Персональные данные третьих лиц, доксинг, нарушение интеллектуальной собственности"),
    ("p","Запрет; ответственность публикующего; Администрация не отвечает."),
    ("h3","5.9 Атаки на саму Сеть (включая слой camo и консенсус)"),
    ("p","Обрабатываются автоматически кодами банов; Администрация не отвечает за ущерб, причинённый атаками третьих лиц."),
    ("h3","5.10 Предел оговорок"),
    ("p","Никакое положение не исключает ответственности, которую императивно действующий закон не позволяет исключить. Документ подготовлен добросовестно, с целью минимизации вреда для всех участников."),
  ], ["Приватная — не значит беззаконная. Кто торгует здесь краденым, скамит или выдаёт себя за другого — отвечает сам. Сеть не может за ним «подсмотреть» по тем же причинам, по которым не может подсмотреть за тобой. Это цена и дар приватности."]),
  ("6. Механизмы защиты Пользователя", [
    ("b","E2E-шифрование с одноразовыми ключами (forward secrecy) — даже захват долгосрочного ключа не открывает историю."),
    ("b","Никаких журналов и контента на стороне сети: сессионные капсулы в ОЗУ, сжигание сессионного ключа при выходе (crypto-shred)."),
    ("b","Транспортный камуфляж (camo) + луковая маршрутизация — против DPI, профилирования и анализа трафика."),
    ("b","Публичные вердикты безопасности: каждый бан с кодом и объяснением PL/EN и хэшем доказательств; публичный реестр."),
    ("b","Ползунок телеметрии off/minimal/full (по умолчанию minimal) — решает Пользователь."),
    ("b","Proof-of-Uptime вместо персональных данных — репутация без деанонимизации."),
    ("b","Процедура unban: 30 дней на решение Администрации, возврат 99% при отказе или тайм-ауте."),
    ("b","Антискам-оповещения (SCAM_ALERT), проверка отпечатков кошельков, реестр поддельных личностей «Администрации»."),
    ("b","Пароль паники (тихий crypto-shred), «чистый экран», self-destruct по паролю duress (D3)."),
    ("b","Публикуемые правила гигиены: проверяйте SHA256-суммы ISO; Администрация никогда не пишет первой по вопросам средств; никогда не просит ключ, seed или пароль."),
  ], ["Сеть защищает тебя математикой, а не обещаниями. От скама защищает одно железное правило: никто из поддержки никогда не попросит твой ключ. Никогда."]),
  ("7. Условия использования — ключевые положения (кратко)", [
    ("b","Предоставляется «как есть», без гарантий; полный текст: docs/ToS.md."),
    ("b","Контент и ответственность за него: исключительно Пользователи."),
    ("b","Нет данных = невозможность их передачи; нет восстановления аккаунта (D9)."),
    ("b","Ранги: платежи окончательны; преимущества развиваются только в рамках протокола."),
    ("b","Баны автоматические, с обоснованием; unban 1 000 000 USD XMR, 30 дней, возврат 99%; один выкуп на кошелёк; повторный бан — навсегда."),
    ("b","Система защиты (AI) — исключительно в ведении Администрации; пользователи с ней не общаются."),
    ("b","Ответственность Администрации ограничена USD 0 в максимально допустимом объёме."),
    ("b","Изменения Условий: публикация не менее чем за 14 дней; дальнейшее использование = согласие."),
  ], ["То же самое — пунктами на дверцу холодильника."]),
  ("8. Ответственность и возраст Пользователя", [
    ("p","Услуга предназначена для совершеннолетних (18+). Пользователь отвечает за: соответствие законам своей юрисдикции, безопасность ключей и паролей, создаваемый и размещаемый контент, а также последствия сделок с другими пользователями. Незнание закона не освобождает от ответственности — как и везде."),
  ], []),
  ("9. Заключительные положения", [
    ("p","Делимость положений; изменения с уведомлением за 14 дней; приоритет польской версии; контакт исключительно через официальные каналы объявлений в Сети; дата документа: 2026-07-19."),
  ], []),
 ],
 "rangi_h": "Приложение А — Ранги и преимущества (прайс)",
 "rangi": [
  ("ghost — стартовый (0 FNX)", ["хостинг: 1 сайт (Web Builder)","аватар-идентикон (из кошелька)","тёмная тема, 1 группа (25 чел.)","офлайн-буфер 7 дней, tier 0","полный PoU/голос через 30 дней аптайма"]),
  ("Donor — 0.000001 FNX", ["свой аватар (зашифрованная загрузка)","значок Donor + коричневый ник","хостинг: 3 сайта","резерв ника (name protection)","буфер 30 дней, tier 1"]),
  ("VIP — 0.000002 FNX", ["анимированный аватар + баннер профиля","хостинг: 5 сайтов + премиум-темы сайтов","2 смены ника в год","группы 3x100, свои темы GUI","tier 2 + приоритет соединения с seed"]),
  ("VIP+ — 0.000003 FNX", ["светящаяся рамка аватара + значок сторонника","хостинг: 10 сайтов + vanity-путь /ник/сайт","доступ к бета-функциям","группы 5x250","подписанные отчёты безопасности аккаунта, tier 3"]),
  ("SVIP — 0.00001 FNX", ["хостинг: 25 сайтов + панель (агрегаты, НОЛЬ логов гостей)","интерактивная рамка аватара","storage x2, группы 10x500","лента объявлений на своих сайтах","буфер 180 дней, tier 4"]),
  ("ELITE — 0.0001 FNX", ["хостинг: 100 сайтов + свои шаблоны Web Builder (CSS sandbox)","гарантированная fast-lane E2E","RC-сборки + совещательные опросы (необязывающие)","группы без лимита (2к чел./группа)","vanity-адрес (префикс), aura-значок, tier 5"]),
  ("SELITE — 0.01 FNX", ["хостинг: 500 сайтов + white-label","канал сетевых объявлений (модерация админа)","страница сторонников (opt-in), тест-сборки + канал с dev","премиум-ванити, под-каналы, группы 5к","ЛИМИТ: 10 аккаунтов/год, tier 6"]),
  ("FENIX — 100.1 FNX", ["НАВСЕГДА; хостинг без жёсткого лимита (fair-use)","выделенный приоритетный relay E2E","место в совещательном совете (ежеквартально, БЕЗ власти над протоколом)","совместный дизайн 1 косметической функции; уникальный shard-значок","Стена Легенд (opt-in); ЛИМИТ: 21 за всю историю сети"]),
 ],
 "rangi_rules_h": "Верховные правила рангов",
 "rangi_rules": [
  "Ранг = преимущество сети. Он НИКОГДА не даёт: голос (только PoU >=30 дней), доступ к AI безопасности (только owner/admin), чужие данные, unban, власть над протоколом.",
  "Ранг записан ON-CHAIN (tx RANK_UP, 6 подтверждений); апгрейд = доплата разницы.",
  "До внедрения stealth-адресов покупка ранга публична — рекомендуется свежий кошелёк.",
 ],
 "bany_h": "Приложение Б — Политика банов и выкупа (UNBAN)",
 "bany": [
  "Авто-бан = консенсус AI (инструмент админа) -> запись ON-CHAIN: код причины + объяснение PL/EN + хэш доказательств (без содержимого!).",
  "Коды: ROUTE_LEAKAGE (маршрутизация через незащищённый прокси — вывод данных из Fenix!), PROTO_FLOOD, INVALIDTAG_STORM, SYBIL_RING, STORAGE_FRAUD, MSG_SPAM (мета, не содержимое), CAMO_VIOLATION, DOXXING.",
  "UNBAN: единственный путь = 1 000 000 USD в XMR, ОДНОКРАТНО (эскроу multisig 2-из-3 + timelock).",
  "У админа 30 дней: принятие -> казна + unban on-chain; отказ/тайм-аут -> возврат 99% (1% anti-spam). Решение админа окончательное.",
  "Unban: PoU/репутация/VOTER с нуля; ранг не возвращается.",
  "Один выкуп на кошелёк за всю историю; повторный бан = НАВСЕГДА.",
  "Публичный реестр банов с объяснениями (GUI + обозреватель).",
 ],
 "end": "— Конец русской версии —",
},
}

# ============================================================
#  1) ZAPISZ MD DLA KAZDEGO JEZYKA
# ============================================================
def build_md(lang, D):
    L = []
    L.append(f"# {D['title']}")
    L.append(f"**{D['sub']}**")
    L.append(f"*{D['date']}*")
    L.append("")
    for h, body, plain in D["sections"]:
        L.append(f"## {h}")
        for kind, txt in body:
            if kind == "h3":
                L.append(f"### {txt}")
            elif kind == "b":
                L.append(f"- {txt}")
            else:
                L.append(txt)
        if plain:
            L.append("")
            L.append(f"> **{D['plain_label']}**{plain[0]}")
        L.append("")
    L.append(f"## {D['rangi_h']}")
    for name, perks in D["rangi"]:
        L.append(f"### {name}")
        for p in perks:
            L.append(f"- {p}")
        L.append("")
    L.append(f"### {D['rangi_rules_h']}")
    for z in D["rangi_rules"]:
        L.append(f"- {z}")
    L.append("")
    L.append(f"## {D['bany_h']}")
    for b in D["bany"]:
        L.append(f"- {b}")
    L.append("")
    L.append(f"*{D['end']}*")
    return "\n".join(L)

os.makedirs(LEGAL_DIR, exist_ok=True)
for lang in ("PL", "EN", "RU"):
    path = os.path.join(LEGAL_DIR, f"FENIX_Dokument_{lang}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_md(lang, DOCS[lang]))
    print(f"[OK] MD: {path}")

# ============================================================
#  2) PDF — trzy komplety jezykowe w jednym pliku
# ============================================================
class Doc(FPDF):
    def header(self):
        self.set_font(FP, "B", 8)
        self.set_text_color(180, 60, 40)
        self.cell(0, 5, "FENIX / AnonNet — Network Document v1.0 (2026-07-19) — DRAFT", align="R",
                  **_MXY)
        self.ln(2)
    def footer(self):
        self.set_y(-12)
        self.set_font(FP, "", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 6, f"{self.page_no()}", align="C", **_MXY)

    def h_part(self, t):
        self.set_fill_color(25, 25, 35)
        self.set_text_color(255, 180, 60)
        self.set_font(FP, "B", 18)
        self.multi_cell(0, 10, t, fill=True, **_MXY)
        self.ln(4)
    def h1(self, t):
        self.set_font(FP, "B", 15); self.set_text_color(25, 25, 25)
        self.multi_cell(0, 8, t, **_MXY); self.ln(1)
    def h2(self, t):
        self.set_font(FP, "B", 12); self.set_text_color(180, 60, 40)
        self.multi_cell(0, 6.5, t, **_MXY); self.ln(1)
    def h3(self, t):
        self.set_font(FP, "B", 10.5); self.set_text_color(20, 20, 60)
        self.multi_cell(0, 5.5, t, **_MXY)
    def p(self, t, size=9.5):
        self.set_font(FP, "", size); self.set_text_color(45, 45, 45)
        self.set_x(self.l_margin)
        self.multi_cell(0, 4.8, t, **_MXY); self.ln(0.5)
    def b(self, t, indent=5):
        self.set_font(FP, "", 9.5); self.set_text_color(45, 45, 45)
        self.set_x(self.l_margin + indent)
        cw = self.w - self.l_margin - self.r_margin - indent
        self.multi_cell(cw, 4.8, chr(8226) + "  " + t, **_MXY); self.ln(0.5)
    def plain(self, label, t):
        self.set_font(FP, "", 9); self.set_text_color(90, 60, 0)
        self.set_fill_color(255, 245, 220)
        self.set_x(self.l_margin)
        self.multi_cell(0, 5, label + " " + t, fill=True, **_MXY); self.ln(3)

pdf = Doc("P", "mm", "A4")
pdf.set_auto_page_break(True, 18)
if F_REG:  pdf.add_font("DV", "", F_REG)
if F_BOLD: pdf.add_font("DV", "B", F_BOLD)

for lang in ("PL", "EN", "RU"):
    D = DOCS[lang]
    pdf.add_page()
    pdf.h_part(D["part"]); 
    pdf.h1(D["title"])
    pdf.p(D["sub"], 10)
    pdf.p(D["date"], 8.5); pdf.ln(3)
    for h, body, plain in D["sections"]:
        pdf.h2(h)
        for kind, txt in body:
            if kind == "h3": pdf.h3(txt)
            elif kind == "b": pdf.b(txt)
            else: pdf.p(txt)
        for pt in plain:
            pdf.plain(D["plain_label"], pt)
        pdf.ln(1)
    # Aneks rangi
    pdf.h2(D["rangi_h"])
    for name, perks in D["rangi"]:
        pdf.h3(name)
        for perk in perks:
            pdf.b(perk)
        pdf.ln(0.7)
    pdf.h3(D["rangi_rules_h"])
    for z in D["rangi_rules"]:
        pdf.b(z)
    pdf.ln(2)
    pdf.h2(D["bany_h"])
    for b in D["bany"]:
        pdf.b(b)
    pdf.ln(2)
    pdf.set_font(FP, "", 9); pdf.set_text_color(120, 120, 120)
    pdf.multi_cell(0, 5, D["end"], **_MXY)

pdf.output(OUT_PDF)
print(f"[OK] PDF: {OUT_PDF} ({os.path.getsize(OUT_PDF)//1024} KB)")
