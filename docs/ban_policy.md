# Fenix — Polityka egzekwowania zasad i ochrona zwykłych użytkowników (ban_policy.md)

wersja 1.0 · 2026-07-25 · status: **WIĄZĄCE dla całej implementacji od M1 wzwyż**
powiązane: `ban_codes.txt` mówi **CO** jest zabronione · ten plik mówi **JAK DELIKATNIE** to egzekwujemy · decyzja D22

---

## 0. Zasada nadrzędna: fail-open w stronę użytkownika

> **Lepiej przepuścić 10 atakujących, niż skrzywdzić 1 niewinnego.**

Dlaczego tak, a nie odwrotnie? Bo w Fenix błąd w stronę użytkownika jest **nieodwracalny**:

- D9 mówi: zero recovery, zero tylnych drzwi → błędny ban = tożsamość umarła na zawsze.
- Atakujący, którego nie złapiemy dziś, złapiemy jutro — **wzorzec zawsze się powtórzy**.
- Niewinny zbanowany dziś nie wróci nigdy.

Wniosek inżynierski: system **minimalizuje false positives, nawet kosztem false negatives**.
Wskaźnik zdrowia sieci: cel **FPR (odsetek błędnych werdyktów) < 0,1% rocznie**.

## 1. Trzy filary bezpieczeństwa niewinnych

1. **Wzorce, nie zdarzenia.** Żaden kod karny nie odpala się od pojedynczego zdarzenia
   (wyjątek: krótka lista ZERO-TOLERANCE w §6 — ale i tam wymagany konsensus k-z-n).
2. **Automatyczne przebaczanie (decay).** Wszystkie flagi gasną same z upływem czasu.
   Nikt nigdy nie musi się tłumaczyć ani „składać odwołania" za drobiazg.
3. **Dowody albo nic.** Nie istnieje wina „na przeczucie AI". Każdy werdykt wyższy niż
   yellow wymaga kryptograficznie zweryfikowalnego materiału (hash dowodów, D18).

## 2. Safe Harbor — co NIGDY nie jest karalne

Poniższe sytuacje to normalne życie sieci. System MUSI traktować je jak szum tła:

| sytuacja | dlaczego to norma |
|---|---|
| wolny / przerywany internet, duże pingi | łącza bywają złe; VPN/mostki dodają opóźnienia |
| restart ISO, utrata zasilania, zniknięcie node'a | Fenix OS to Live OS — restarty to codzienność |
| rozjazd zegara do ±5 min | NTP przez mixnet bywa kapryśny |
| stary klient (do 1 wersji wstecz) | grace period 14 dni po każdym update protokołu (D13) |
| pierwsza synchronizacja blockchainu | sync ma własny, legalny kanał ruchu — liczony osobno |
| wiele walletów z jednego domu / łącza | tożsamość = wallet, nie IP. Rodzina ≠ Sybil |
| 3× błędne hasło | lokalne opóźnienie ×2 (D3). NIGDY nie leci do sieci jako sygnał |
| pojedynczy zły TAG (bitflip w RAM) | promieniowanie kosmiczne i błędy RAM się zdarzają — drop i zapomnij |

**Okres nowicjusza (7 dni od ID_DECLARE):** wszystkie wykrycia techniczne z kategorii A
(protokół) kończą się komunikatem edukacyjnym w GUI („Twój klient robi X — naprawiliśmy
throttlem; jeśli to bug, zaktualizuj"), z **zerowym wpisem** do reputacji. Nauka nie może kosztować.

## 3. Lejek: jak rzadko cokolwiek się dzieje

```
anomalia  (dzieje się u WSZYSTKICH, codziennie; licznik lokalny w RAM, nikt jej nie widzi)
   ↓ bardzo rzadko
🟨 yellow  (throttle 7 dni, auto-reset, wpis gaśnie po 30 dniach)
   ↓ ekstremalnie rzadko
🟧 orange  (read-only 14 dni + kopanie −50%, wpis gaśnie po 90 dniach)
   ↓ prawie nigdy
🟥 red     (ban on-chain — WYŁĄCZNIE konsensus k-z-n + hash dowodów + wyjaśnienie PL/EN)
```

Cel projektowy: w zdrowej sieci **< 0,01% użytkowników kiedykolwiek zobaczy yellow**.
Jeśli realne liczby są wyższe — system jest za czuły i sam się luzuje (§7).

Twarde reguły lejka:

- **3 żółte w 30 dni = 1 orange. KONIEC drabiny.** Z samych drobiazgów NIE DA SIĘ
  dojść do red — do czerwieni prowadzi wyłącznie kategoria red z twardymi dowodami.
- Jeden peer może zgłosić ten sam node **maks. 1 raz na dobę** (anti-griefing).
- Wniosek o red wymaga **mikro-bonda** od wnioskodawcy; konsensus uzna wniosek za
  bezpodstawny → bond obcinany. Oskarżanie nie jest darmowe (symetria kosztów).

## 4. Progi startowe — „sustained", nie „przekroczone raz"

Kategorie A i E są najbardziej wrażliwe na false positives, więc dostają twarde liczby.
„PATRZĘ" = podniesiony licznik lokalny; „FLAGA" = pierwsze yellow. Niżej niż „PATRZĘ"
system zdarzenia wręcz nie rejestruje.

| kod | zaczynam PATRZEĆ gdy | yellow dopiero gdy | dlaczego niewinny nie wpadnie |
|---|---|---|---|
| 0x11 PROTO_FLOOD | >32 msg/s przez 60 s | >5 min ciągle + ignoruje backoff | sync bloków i PING/PONG liczone osobnym licznikiem; burst przy wysyłce mieści się w limicie |
| 0x12 INVALIDTAG_STORM | >5 złych TAG/dobę | >100/h przez 3 h | pojedyncze bitflipy są dropowane bez echa |
| 0x14 FRAME_FUZZ | losowe mutacje w ≥3 różnych polach | wzorzec >30 min | bug klienta = jedno pole, stała postać → kanał CLIENT_BUG (§5) |
| 0x15 REPLAY_ATTACK | ta sama ramka >3× po ACK | >50 duplikatów/h | NAT/TCP retry daje ≤2 kopie |
| 0x16 HANDSHAKE_FARM | >32 nieudane HELLO/h | >200/h | spec pozwala max 8 połączeń wychodzących — legitny klient fizycznie nie dobije |
| 0x23 TIMING_PROBE | korelacja statystyczna przez >72 h | wzorzec z wielu dni | normalny PING/PONG ma losowe okna 20–40 s (protocol_spec) |
| 0x51 MSG_SPAM | >120 msg/min przez 10 min | + odrzuca auto-throttle | człowiek pisząc „jak szalony" robi ~30/min; najpierw throttle, dopiero potem flaga |
| 0x52 DM_BOMBARDING | ≥5 niezależnych odbiorców, 0 odpowiedzi | wzorzec z wielu dni | rozmowa 1:1 (nawet natrętna) NIGDY nie spełnia progu bez zgłoszeń ofiar |
| 0x53 GROUP_STORM | >20 join/leave/min | wielokrotnie + wiele grup | zwykły użytkownik siada i siedzi |

Progi są wersjonowane razem z `ban_codes.txt` — zmiana = publikacja 14 dni wcześniej (ToS §11).

## 5. BUG czy ATAK? — test sygnatury celowości

Zanim jakikolwiek kod kategorii A/B odpali flagę, system ocenia CHARAKTER wzorca:

| cecha | bug klienta | atak |
|---|---|---|
| miejsce błędu | zawsze to samo pole / znana sekwencja | losowe mutacje po wielu polach |
| wersja klienta | koreluje z konkretnym buildem | mieszana / celowo nielegalna |
| reakcja na backoff | klient się podporządkowuje | „dobija" dokładnie do limitu |
| czas trwania | znika po restarcie / update | utrzymuje się godzinami i dniami |

Wzorzec pasuje do znanego buga → kanał **CLIENT_BUG**: wymuszony update + zgłoszenie
do ownera buildów, **żadnej kary**. Karanie użytkownika za cudzy bug byłoby absurdem.

## 6. ZERO-TOLERANCE — jedyna lista z możliwym natychmiastowym red

Krótka, świadomie:

- `0x42 DOUBLE_SPEND` — dowód = dwa podpisy tego samego wejścia; matematycznie niepodważalny
- `0x45 CHECKPOINT_FORGE` — fałszywy podpis checkpointa = dowód kryptograficzny
- `0x55 CSAM_ALERT` — wyłącznie dopasowanie z jawnego rejestru hashy (system NIE widzi treści)
- `0x21 ROUTE_LEAKAGE` — ale dopiero po **k ≥ 3 niezależnych potwierdzeniach** z różnych regionów sieci

Nawet tu: zanim red trafi on-chain, wymagany jest **konsensus k-z-n (k ≥ 3 attestorów)**
+ hash dowodów + wyjaśnienie PL/EN (D18). Fałszywe zgłoszenie z tej listy kosztuje
zgłaszającego cały bond — symetria pełna.

## 7. Decay — pamięć systemu jest krótka

| flaga | efekt | wpis żyje | potem |
|---|---|---|---|
| anomalia | brak | 0–24 h, tylko RAM node'a | kasowana; NIGDY nie opuszcza node'a (zgodnie z D5) |
| 🟨 yellow | throttle 7 dni | 30 dni | gaśnie automatycznie, ślad znika |
| 🟧 orange | read-only 14 dni, kopanie −50% | 90 dni | gaśnie automatycznie |
| 🟥 red | ban on-chain | na zawsze | jedyna trwała — dlatego tylko z dowodami i konsensusem |

Błędnie uszkodzony streak PoU / reputacja / ranga → przywracane wprost w kodzie
(system „przeprasza" poprawką stanu on-chain, nie listem).

## 8. System sam się kalibruje (pętla FPR)

- Sentinel raportuje co miesiąc **same liczby** (karty zdarzeń wg D5 — bez treści):
  ile flag, ile werdyktów, ile unieważnień.
- FPR powyżej celu → progi kategorii A i E **automatycznie luzują się o jeden poziom**,
  aż wróci do normy. System domyślnie zawodzi OTWARTY w stronę użytkownika (fail-open).
- Każda zmiana progów = wersja + data + 14 dni publikacji (ToS §11). Zero cichych zmian.

## 9. Czego ta polityka NIE wprowadza

- **Nie ma statusu „podejrzany".** Albo próg przekroczony (i wszystko jawne dla właściciela
  konta), albo dla systemu nie istniejesz. Brak list obserwowanych.
- **AI nie czyta treści** (D5/D17) — oceniane są wyłącznie metadane i wzorce ruchu.
- **Żaden człowiek nie ma przycisku „ban".** Admin ma wyłącznie „wniosek do konsensusu" z bondem.
- **Brak kar zbiorowych** — odpowiada konto, nie rodzina, nie podsieć, nie „znajomi".

## 10. Jak to zobaczy użytkownik (GUI)

- Stan konta zawsze widoczny obok paska VOTER: `czysty / 🟨 do dnia X / 🟧 do dnia Y`.
- Każda flaga ma ekran „co się stało i jak to naprawić" (PL/EN/RU).
- Żaden komunikat nie zawiera danych innych użytkowników.

---
*ban_policy.md v1.0 — dokument wiążący. Zmiany: wersjonowane + 14 dni publikacji. Spory rozstrzyga zasada §0.*
