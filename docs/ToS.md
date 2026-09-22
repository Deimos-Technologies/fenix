# FENIX / AnonNet — Warunki Korzystania (Terms of Service)
**Wersja 1.0 | 2026-07-19 | Dokument roboczy projektu**
> Nota: niniejszy dokument nie stanowi porady prawnej. Przed publikacją zaleca się
> konsultację z prawnikiem znającym jurysdykcje docelowe.

## 1. Definicje
- **Administracja** — Owner/Operatorzy projektu Fenix / AnonNet.
- **Użytkownik** — każdy podmiot uruchamiający node lub korzystający z Oprogramowania.
- **Sieć Fenix** — zdecentralizowana sieć P2P użytkowników; nie jest własnością jednego podmiotu.
- **Oprogramowanie** — klient Fenix, skrypty, Fenix OS ISO i powiązane narzędzia.

## 2. Świadczenie „JAK JEST" (AS IS)
Oprogramowanie i Sieć udostępniane są „jak jest", bez jakichkolwiek gwarancji —
w tym gwarancji ciągłości działania, kompatybilności, bezpieczeństwa absolutnego
czy anonimowości absolutnej. Korzystanie odbywa się na wyłączne ryzyko Użytkownika.

## 3. Treści Użytkowników — zrzeczenie odpowiedzialności
1. Sieć działa autonomicznie, w modelu peer-to-peer: treści są tworzone, przechowywane
   i przesyłane WYŁĄCZNIE przez Użytkowników, na ich urządzeniach.
2. Administracja nie tworzy, nie inicjuje, nie wybiera, nie moderuje, nie nadzoruje
   i nie kontroluje treści umieszczanych w Sieci przez Użytkowników.
3. W maksymalnym zakresie dozwolonym przez prawo Administracja **nie ponosi
   jakiejkolwiek odpowiedzialności** za treści użytkowników, ich legalność,
   skutki ich publikacji ani działania podjęte wobec nich przez podmioty trzecie.
4. Administracja nie jest dostawcą treści, hostingodawcą ani pośrednikiem
   w rozumieniu regulacji o usługach cyfrowych; dostarcza wyłącznie oprogramowanie.

## 4. Brak danych = brak możliwości ich podania
1. Z założenia architektonicznego (decyzje D5, D9) Administracja **nie gromadzi**:
   treści wiadomości, logów aktywności, adresów IP, powiązań między użytkownikami,
   historii połączeń, ani metadanych pozwalających na identyfikację.
2. Administracja **nie posiada kluczy** użytkowników ani materiału umożliwiającego
   odszyfrowanie ich danych.
3. W konsekwencji Administracja **nie jest w stanie** — technicznie i matematycznie —
   podać jakichkolwiek powyższych danych jakimkolwiek podmiotom, w tym organom
   jakiejkolwiek jurysdykcji. Nie ma obowiązku podawania danych, które nie istnieją.
4. Informacje publiczne na blockchainie (transakcje rang, rejestry banów) są jawne
   z natury protokołu i nie zawierają treści wiadomości ani danych osobowych.

## 5. Brak mechanizmu odzyskiwania konta (D9)
1. Utracone hasło bądź klucz oznacza **nieodwracalną utratę** tożsamości, rany,
   środków FNX i danych powiązanych z kontem.
2. Administracja nie dysponuje żadnym mechanizmem odzyskiwania — również na prośbę,
   nakaz lub pod przymusem. Nie ma konta pomocy technicznej dla kluczy.
3. Użytkownik jest wyłącznie odpowiedzialny za bezpieczeństwo swoich kluczy i haseł.

## 6. Obowiązki Użytkownika
1. Użytkownik zobowiązuje się korzystać z Sieci zgodnie z prawem swojej jurysdykcji
   i ponosi wyłączną odpowiedzialność za własne działania i treści.
2. Zabronione są działania wymienione jako kody banów (§8), w szczególności próby
   wyciągania danych poza Sieć przez niezabezpieczone proxy, ataki wolumetryczne,
   podszywanie się pod inne tożsamości oraz ingerencja w warstwę kamuflażu.
3. Usługa przeznaczona dla osób pełnoletnich (18+).

## 7. Rangi, płatności, FNX
1. Rangi są cyfrowymi wpisami do rejestru blockchain; płatności są **ostateczne
   i niepodlegają zwrotowi**, z wyjątkiem procedury unban (§8).
2. FNX jest tokenem użytkowym Sieci; **nie stanowi instrumentu finansowego,
   udziału, ani obietnicy zysku**. Wartość FNX może wynosić zero.
3. Benefity rang mogą ewoluować wyłącznie w granicach protokołu; zakup rangi nie
   daje prawa głosu (wyłącznie Proof-of-Uptime ≥30 dni), dostępu do danych innych
   użytkowników, dostępu do systemu ochrony sieci (AI) ani władzy nad protokołem.

## 8. Bany i wykupienie (unban)
1. Werdykty banów wydaje automatyczny system ochrony Sieci (konsensus) —
   każdy ban posiada **kod powodu i czytelne wyjaśnienie** (PL/EN) oraz hash dowodów.
2. Kody banów: `ROUTE_LEAKAGE`, `PROTO_FLOOD`, `INVALIDTAG_STORM`, `SYBIL_RING`,
   `STORAGE_FRAUD`, `MSG_SPAM`, `CAMO_VIOLATION` (definicje w dokumentacji).
3. Jedyna droga unbana: **jednorazowa opłata 1 000 000 USD liczona w FNX**
   (kurs: owner-oracle, podpisany dokument kursowy z timelockiem — D30)
   do depozytu escrow (multisig 2-z-3 z timelockiem).
4. Administracja ma **30 dni** na decyzję o przyjęciu wykupienia:
   - akceptacja → środki wpływają do skarbca, ban zdejmowany wpisem on-chain;
   - odmowa lub brak decyzji po 30 dniach → **zwrot 99%** wpłaty (1% opłaty anti-spam).
5. Decyzja Administracji o przyjęciu lub odmowie jest ostateczna.
6. Unban nie przywraca reputacji: licznik Proof-of-Uptime i status VOTER zaczynają
   się od zera; utracona ranga nie wraca.
7. Na jeden wallet przysługuje **jeden** wykup w historii Sieci; ponowny ban jest permanentny.

## 9. System ochrony Sieci (AI) — wyłączność Administracji
System ochrony (AI-Sentry) jest narzędziem wyłącznie w gestii Administracji.
Użytkownicy nie mogą się z nim komunikować, sterować nim, ani żądać jego działań.
Jawne są wyłącznie werdykty i ich wyjaśnienia (§8).

## 10. Wyłączenie i ograniczenie odpowiedzialności
W maksymalnym zakresie dozwolonym przez prawo Administracja nie odpowiada za:
szkody pośrednie i następcze, utratę danych, kluczy, środków, reputacji, zysków;
działania i zaniechania innych Użytkowników lub podmiotów trzecich; skutki
jurysdykcyjne korzystania z Sieci. Łączna odpowiedzialność Administracji,
o ile w ogóle powstanie, ograniczona jest do USD 0.

## 11. Zmiany Warunków
Administracja może zmieniać Warunki z publikacją w Sieci co najmniej 14 dni przed
wejściem w życie. Dalsze korzystanie po tej dacie oznacza akceptację zmian.

## 12. Postanowienia końcowe
1. Nieważność jednego postanowienia nie narusza pozostałych (separowalność).
2. Rozstrzygająca jest wersja polskojęzyczna.
3. Spory — w miarę możliwości polubownie; Użytkownik akceptuje brak możliwości
   identyfikacji drugiej strony jako cechę systemu, nie wadę.
