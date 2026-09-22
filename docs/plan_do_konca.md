# 🗺️ FenixOS / AnonNet — plan DO KOŃCA (mapa etapów)

> **Data:** 2026-08-08 · **Stan wejścia:** HEAD `741a721` (v016), audyt 46/46 · 30/30,
> warstwy 0–9 działają, giełda FNX-COIN (D65), licznik (D61), duch (D63),
> widok banu (D66). **Zasada:** etapy wykonujemy po kolei; każdy = decyzja D## +
> test-strażnik + wpis TODO + raport PDF v###. Czego kod nie zrobi (decyzje
> właściciela) — checklista na dole, jawnie nazwana.

## Etapy kodu (po kolei, zamykamy PROBLEMS_OPEN)

| # | Nazwa | Plik(i) | Co zamykamy |
|---|---|---|---|
| **E1** ✅ | D67 pokój cenowy + karty Sieci w GUI | `net/fenix_node.py`, `gui/backend_ipc.py`, `gui/fenix_gui.py`, `tools/*` | cena D65 w oknie; licznik D61; toggle ducha D63; kartka banu D66 na dashboardzie |
| **E-AI** ✅ | D68/D69: AI-GRID v0 + brama real-e2e (2026-08-09) | `ai/fnx_ai.py`, `net/fenix_node.py`, `net/frame.py`, `gui/backend_ipc.py`, `tools/real_e2e.py` | siatka obliczeniowa na drucie (T_JOB 0x42/T_JOB_RES 0x43), kworum+recompute, płatności iskra-dokładne; DOWÓD: 3 żywe demony, cały scenariusz w 5 s |
| **E-SEC** ✅ | D70/D71: peleryna FNX64 + trwałość chain.dat (2026-08-09) | `core/crypto/fnx64.py`, `core/identity.py`, `net/frame.py`, `net/fenix_node.py`, `tools/real_e2e.py` | własna warstwa „x tetracja do 10" na CT każdej ramki (negocjacja w HELLO_FIN; klucz sess⊕static-DH); kamera drut-proof: 561 KB, ZERO wycieków markerów; demon zapisuje/czyta chain.dat (replay zerozufaniowy) — errata do raportu 08-09 |
| **E2** | challenge-reachability świadków PoU | `net/pou_challenge.py` | P25 część sieciowa: świadek musi REALNIE odpowiedzieć (echo usługi), zanim podpisze |
| **E3** | tematy głosowań + quorum k-z-m | `chain/proposal_evt.py` | P10: rejestracja tematów, multi-sentinel głosuje zbiorczo przez VOTE_EVT (D60 rura gotowa) |
| **E4** | czat grupowy M4c | `app/groups.py` | P24 część: grupy z rotowanym kluczem grupy (bez pomieszania z ratchetem 1:1) |
| **E5** | link urządzeń (multi-device) | `app/messenger.py` + GUI | P24 druga część: to samo konto na 2 urządzeniach zamiast uczciwego drop |
| **E6** | dedup peerów (P29) + zimna kropka + rotacja | `net/fenix_node.py`, `core/admin.py` | P29: jeden kanał per wallet (M3); P25: attestorzy offline + rotacja kropki |
| **E7** | bulletproofs + finalny QA | `chain/bulletproof.py` + M9 | P11: lżejsze rangeproofy; QA obciążeniowe; raport release-candidate |

## Czeka na WŁAŚCICIELA (kodu nie wystarczy — checklista jawna)

- **P2** ≥3 VPS jako seed-nody → podmiana `/etc/fenix/seeds.list`
- **P3** boot ISO w qemu/kvm na własnej maszynie (smoke QA)
- **P5** decyzje §12: emisja/halving, zimny multisig skarbca (D14), źródło airdropu (D62),
  stałe krzywej ceny (D65 — domyślne już działają)
- **P7** kontrakty raili płatności: Paysafe MID (D32), monero-wallet-rpc (D34),
  operator FNX-COIN (D65 — wtedy kupno/sprzedaż z GUI zostaje wpięte;
  dziś szyba jest read-only UMYŚLNIE)
- **P8** domena dla DNS-camo (D33)
- **P15** Mullvad z prawdziwym kontem (live-QA)
- **P17** GUI pod X11/openbox na ISO (logika 24/24 headless już zielona)

## Zasady etapów (niezmienne jak poprzednio)

1. selftest łapie → kanapka (pokazujemy szczerze) → fix → rerun; fixlog do raportu z wagą.
2. nowa funkcja krypto/net/konsensus = **decyzja D##** + § w spec (jeśli ekonomia) +
   testy + kontrola w `tools/full_audit.py`.
3. raport **FenixRapv017…** osobno po każdym etapie; commity ×2 (kod → raport).
   **2026-08-09 (właściciel):** etap E-AI dokumentuje **raport DZIAŁANIA**
   (`docs/raport_dzialania_*.md` — same fakty z żywych procesów), bez PDF.
4. `power_audit` po każdym nowym op-cie IPC / przełączniku (ludzkie oko + twarde kontrole read-only).
