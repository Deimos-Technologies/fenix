# Fenix — Plan ISO systemu (Fenix OS) + Bill of Materials projektu

wersja 0.1 · 2026-07-25 · status: PLAN (kamień M8, ale fundamenty robimy wcześniej)
powiązane: D6 (spoof), D8 (strategia ISO), D11 (zastrzeżenie obfuskacja), D14 (podpis), D3/D9 (klucze/panika)

---

## CZĘŚĆ A — Co jest potrzebne, żeby PROJEKT działał (BoM)

### A1. Deweloperka (to masz już dziś — wystarczy do M1–M4)
| rzecz | minimum | po co |
|---|---|---|
| PC z Linuksem/Windows+WSL | 8 GB RAM, 20 GB dysku | repo + testy |
| Python | ≥ 3.10 | cały kod |
| pip pakiety | `requirements.txt` (cryptography, fpdf2) | krypto + PDF-y |
| git | dowolny | historia, NIGDY sekretów w commitach |

### A2. Testy sieciowe (M2–M3 — protokół i camo)
| rzecz | minimum | po co |
|---|---|---|
| WirtualBox/QEMU | 2 VM po 2 GB RAM | node A ↔ node B na jednym PC |
| Wireshark | host lub VM | dowód: na wiresie same 1024/4096 B + szum |
| Drugi fizyczny komp (opcj.) | stary laptop | test przez prawdziwy router/NAT |

### A3. Testnet FNX (M5 — blockchain)
| rzecz | minimum | po co |
|---|---|---|
| 3 maszyny/VM (seed nodes) | 2 vCPU, 4 GB RAM, 40 GB każda | genesis, checkpointy k-z-n, udziały Shamira |
| publiczne VPS-y (potem) | 3 × najtańsze VPS | seed-y muszą być osiągalne 24/7 |

### A4. Budowa ISO (M8 — ta część dokumentu)
| rzecz | minimum | po co |
|---|---|---|
| Host build = Debian 12 (czysty) | 8 GB RAM, 40 GB wolnego | live-build jest wybredny — budujemy na Debianie pod Debiana |
| pakiety | `live-build xorriso squashfs-tools debootstrap` | składanie obrazu |
| klucz ownera OFFLINE | 3 zimne nośniki (Shamir 2-z-3, D14) | podpis ISO; nigdy na hoście build |
| czas | ~30–60 min / build | iteracje najlepiej nocą |

### A5. Docelowy użytkownik Fenixa (nasza grupa docelowa — optymalizujemy pod nią)
| rzecz | minimum | rekomendacja |
|---|---|---|
| PC x86_64 | 4 GB RAM, UEFI | 8 GB RAM |
| pendrive USB | 8 GB (Live) | 16 GB USB 3.x (szybszy boot, miejsce na opcjonalny wolumen) |
| network | Wi-Fi/Ethernet obsługiwane przez kernel | karta z dobrym sterownikiem Linux (test na liście QA) |
| Secure Boot | **decyzja OTWARTA — §C1** | — |

### A6. Ważna prawda o kolejności
> ISO jest OPAKOWANIEM. Najpierw musi istnieć co pakować: node (M2–M3),
> komunikator (M4), keystore (M1). Dlatego do końca M3 budujemy w VM deweloperskiej,
> a prace ISO zaczynamy równolegle od SKRYPTÓW (os/spoof.sh, hooks), które testujemy
> w tej samej VM. Pierwszy pełny build ISO = tuż po M3 (MVP sieci na żywo z pendrive'a).

### A7. Live ISO NIE jest wymagany — 3 poziomy wdrożenia (D25)
Fenix to aplikacja Python — działa jako zwykły program (portable) na Windows/Linux/macOS.
ISO to opcjonalna zbroja, nie warunek wejścia. Ten sam kontener D24 służy apce i ISO.

| poziom | instalacja | co chroni | czego NIE chroni |
|---|---|---|---|
| 1. Fenix App | portable, każdy OS | E2E, treści, tożsamość, blockchain, camo ↔ ISP | ślady w OS (swap/logi), wrogły OS, brak amnezji |
| 2. App w VM | Qubes/Whonix-style | + separacja od hosta | root hosta/hiperwizora; sygnał VM (D20 = soft) |
| 3. Fenix OS Live | pendrive (M8) | wszystko wyżej + amnezja + fail-closed + anti-forensic + sprzętowy panic | fizyczny dostęp do sprzętu podczas sesji |

GUI zawsze pokazuje, na którym poziomie użytkownik jedzie (uczciwe ostrzeżenie, D25).

---

## CZĘŚĆ B — Strategia ISO (D8)

**Odrzucamy:** własny OS od zera (boot.asm = artefakt edukacyjny, zostaje w repo jako hobby).
**Wybieramy:** remaster **Debian 12 live-build** — 90% wartości za 5% pracy:
stabilny kernel, sterowniki, UEFI+Legacy, narzędzia live-build, ogromna baza pakietów.

Filozofia obrazu (3 zasady, nie do ruszenia):
1. **Amnezja domyślnie** — system żyje w RAM; reboot = czysta karta. Ślady piszemy tylko
   tam, gdzie użytkownik ŚWIADOMIE wskaże (opcjonalny zaszyfrowany wolumen — §C2).
2. **Fail-closed** — zanim Fenix nie wstanie, firewall DROP-puje WSZYSTKO poza camo.
   DNS poza tunelem = DROP. IPv6 = OFF (policy) albo tunelowany — nigdy “mniejsze zło”.
3. **Zero sekretów w ISO** — obraz jest publiczny, z podpisem (D14). Sekrety rodzą się
   dopiero na maszynie użytkownika (kreator) i umierają z wyłączeniem.

Warstwy obrazu (od spodu):
```
Debian live (bazowy)
  └─ hardening OS (AppArmor, lockdown, sysctl anti-leak, journald volatile, swap OFF)
       └─ os/spoof.sh (MAC/hostname/machine-id losowe PRZED podniesieniem interfejsu, D6)
            └─ firewall fail-closed (nftables: tylko camo DNS/porty)
                 └─ Fenix (node + keystore + komunikator) [później: zaszyfrowany ładunek §B3]
                      └─ GUI (Tkinter dark, M7)
```

### B1. Kreator pierwszego bootu (zatwierdzona koncepcja — do specyfikacji w docs/boot_security.md)
1. pierwszy start → kreator: **Username + hasło + OSOBNE hasło paniki**
2. Argon2id(hasło) → KEK → owija losowy **MEK** → (opcjonalnie) LUKS szyfruje wolumen danych;
   hasło NIGDY nie szyfruje ISO — zmiana hasła = przewinięcie 32 B, nie terabajta danych
3. po poprawnym loginie: **challenge-response do seed nodes** → udziały Shamira (k-z-n)
   → klucz zbiorczy składa się LOKALNIE w RAM (hasło NIGDY nie leci siecią)
4. klucz zbiorczy odszyfrowuje **ładunek** (protokół/camo/aplikacja) do tmpfs
5. zbanowany wallet → seed-y NIE wydają udziałów → ładunek martwy (egzekucja D18/D21 bez HWID!)
6. skradzione ISO + hasło, ale bez sieci konsensusu = cegła
7. logout / wyłączenie / wyrwanie USB = klucze znikają z RAM
8. tryb offline (brak seedów) = **tryb szkieletowy**: terminal, edytor, narzędzia offline, zero sieci Fenixa

### B2. Dlaczego ładunek jest szyfrowany (i zastrzeżenie D11)
Szyfrowany ładunek NIE jest “ukrywaniem kodu” (kod źródłowy Fenixa i tak jawny w repo
dla audytu — Kerckhoffs, Filar 3). To **mechanizm egzekwowania**: nie da się uruchomić
pełnego stosu bez ważnego, niezbanowanego walleta i konsensusu seedów. Zastrzeżenie
inżynierskie z D11 (koszt CPU UX, flagowanie AV, utrudniony debug) nadal obowiązuje —
dlatego ładunek = option ON od wersji publicznej, wyłączany flagą builda dla deweloperki.

### B3. Hardening obrazu (checklista wykonawcza)
- kernel: `lockdown=integrity`, `apparmor=1 security=apparmor`, ASLR domyślne, kexec off
- sysctl: `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`, `fs.suid_dumpable=0`,
  `net.ipv4.ip_forward=0`, IPv6 `disable_ipv6=1` (policy), rp_filter
- pamięć: klucze Fenixa w mlock; `prctl(PR_SET_DUMPABLE,0)` na procesie Fenixa (zero core dumpów)
- dysk: brak persistence domyślnie; tmpfs na /tmp /var/tmp; journald Storage=volatile; swap OFF
- autostart: Fenix jako user `fenix` (nie root); sudo wyłączone w live; AppArmor profil
  `fenix` = tylko swoje pliki + wyjście camo
- czas: NTP TYLKO przez camo/mixnet (zegar ±5 min tolerowany przez protokół — ban_policy §2)
- aktualizacje: wyłączone w live; nowa wersja = nowy podpisany ISO (D14)

### B4. Anti-forensic / panika (rozwiniecie pozycji TODO M8)
- **panic password**: wpisane zamiast hasła → cichy shred kluczy (RAM + ew. wolumen),
  wipe tmpfs, natychmiastowy poweroff (D3). Brak komunikatów, brak logów — cisza.
- **USB kill switch**: wyrwanie nośnika = udev wyłapuje → sync-freeze → poweroff w <2 s
- **wipe RAM przy shutdown**: skrypt w ramdysk final (sdmem-style overwrite + cold boot
  jest mało realny na DDR4/DDR5, ale minimum robimy)
- **auto-lock**: bezczynność N min (domyślnie 10) → lock = kapsuła sesji spalona,
  powrót wymaga hasła (D5: klucze sesji nie żyją dłużej niż sesja)
- **ekran logowania bez informacji**: zero wersji, zero „niepoprawne hasło” vs
  „użytkownik nie istnieje” — jeden neutralny komunikat

---

## CZĘŚĆ C — Decyzje OTWARTE (do zamknięcia przed pierwszym buildem)

### C1. Secure Boot — DECYZJA (D23, 2026-07-25, właściciel)
**Wybrano (a): instrukcja „wyłącz Secure Boot" (MVP).** Zero kosztów i formalności,
standard wśród live-OS-y prywatności. Instrukcja instalacji dostanie krok BIOS
ze zrzutami dla popularnych płyt głównych/UEFI. Ścieżki awaryjne w backlogu M9:
(b) własny klucz MOK enrollowany przy 1. boot, (c) shim z podpisem Microsoft.

### C2. Persistence — DECYZJA (D24, 2026-07-25, właściciel)
**Amnezja jak Tails dla WSZYSTKIEGO — poza jednym małym kontenerem zaszyfrowanym.**
W kontenerze (pojedynczy plik na nośniku): **username + kontakty + owinięte klucze tożsamości**.
- kontener = keystore wg D3: Argon2id(passkey) → KEK → losowy MEK → AEAD nad plikiem
- każdy boot: kreator prosi o passkey; 3× ❌ = opóźnienie ×2 (D3)
- **PANIC BUTTON = crypto-shred kontenera** (nadpisanie + skasowanie pliku)
  + wipe RAM + poweroff → wraz z kontenerem ginie WSZYSTKO, co przetrwa reboot
- jeden kod obsługuje aplikację i ISO: `core/keystore.py` (M1)

### C3. Profile obrazu (decyzja techniczna, rekomendacja: oba)
- **fenix-min** (~700 MB): terminal + node + keystore — dla słabych maszyn i trybu szkieletowego
- **fenix-full** (~1.5 GB): GUI, komunikator, Web Builder (M7), narzędzia QA
- oba z jednego configu live-build (jedna prawda), podpisywane osobno (D14)

---

## CZĘŚĆ D — Co trafia do repo (struktura `os/` — pliki do napisania)

```
os/
├── build_iso.sh            # wrapper: live-build → ISO → SHA256 → (podpis offline ownerem)
├── verify_iso.sh           # dla użytkownika: sprawdź SHA256 + podpis (instrukcja)
├── live-build/
│   ├── auto/config         # Debian 12 amd64, UEFI+Legacy, bez recommends zbędnych
│   ├── config/package-lists/fenix.list.chroot   # python3, tk, nftables, wireguard-tools(?) nie — nasz protokół
│   ├── config/hooks/live/0100-fenix-hardening.hook.chroot  # sysctl, apparmor, journald volatile, swap off
│   ├── config/hooks/live/0200-fenix-install.hook.chroot    # kopia repo → /opt/fenix-core/ (dev) albo payload.enc
│   └── config/includes.chroot/
│       ├── etc/nftables.conf            # FAIL-CLOSED: drop all; allow tylko camo
│       ├── usr/local/bin/fenix-boot     # kreator pierwszego bootu (§B1)
│       ├── usr/local/bin/fenix-panicd   # daemon paniki / kill switch
│       └── etc/systemd/system/fenix*.service
├── spoof.sh                # D6: MAC/hostname/machine-id losowe PRZED if-up (testowalne w VM już teraz!)
└── README.md               # jak zbudować, jak przetestować, zastrzeżenia prawne/UX
```

Zasada: **każdy z tych plików testujemy w VM od razu po napisaniu** (checkbox = dopiero
po uruchomieniu), tak jak dotychczas. Nie czekamy z ISO do M8 — ISO = składnia tego,
co po drodze powstanie.

---

## CZĘŚĆ E — QA ISO (checklist przed publikacją każdego obrazu)

1. boot: UEFI + Legacy w QEMU; boot na fizycznym pendrive (2 różne PC, w tym Wi-Fi)
2. **leak test**: host + Wireshark: 60 min działania → zero pakietów poza camo,
   zero DNS poza, zero IPv6; test rozgłoszeń mDNS/LLMNR = OFF
3. **amnezja**: reboot po sesji z danymi → brak śladów w systemie (porównanie obrazów RAM/fs)
4. **panika**: hasło paniki → klucze nie do odzyskania (nawet z obrazem RAM zrobionym po)
5. **fail-closed**: zabity proces Fenixa = sieć martwa (nie “przełącza się na normalny net”)
6. **podpis**: verify_iso.sh na czystej maszynie weryfikuje SHA256 + podpis (D14)
7. **reprodukowalność**: dwa buildy z tego samego commita = ten sam SHA256 (cel; pierwsze
   wydania mogą odstępować — dokumentujemy różnice)
8. **timing/perf**: boot do gotowości ≤ 90 s na USB 3.0; kreator ≤ 2 min dla nowicjusza

---

## CZĘŚĆ F — Szacunki i ryzyka (uczciwie)

- budowa ISO: 1–2 tygodnie pracy rozłożonej (po M3), iteracje nocą
- utrzymanie: rebase na point-release Debiana co ~2–3 miesiące (~pół dnia pracy)
- ryzyka: sterowniki Wi-Fi na dziwnych laptopach (lista kompatybilności + fallback Ethernet);
  antywirusy flagujące ISO z “podpisem prywatności” (D11 — komunikat w README, nie problem techniczny);
  rosnący rozmiar obrazu z GUI (pilnujemy profil min)

---
*iso_plan.md v0.1 — zmiany wersjonowane; §C zamyka właściciel i wpisujemy do rejestru D.*
