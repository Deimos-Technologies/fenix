# FenixOS — STRUKTURA PROJEKTU (mapa do VS Code)

wersja 1.0 · 2026-08-04 · status: mapa zgodna z commit `40679f8`
spis: gdzie jest coin FNX · gdzie szyfrujemy transakcje · co składa się na bootowalne ISO

Legenda statusów:
- ✅ gotowe i PRZETESTOWANE (selftest PASS)
- 🟡 gotowe strukturalnie, czeka na QA w VM/realnym środowisku
- ⬜ planowane (pliku jeszcze nie ma — jest w TODO.md)
- 🔒 plik z sekretami NIGDY nie wchodzi do repo (jest w .gitignore)

---

## 0. Drzewo projektu (pogląd całości)

```
FenixOS/
├── README.md / TODO.md / requirements.txt
├── FenixOS.code-workspace          ← OTWÓRZ TO w VS Code (File → Open Workspace)
├── core/          TOŻSAMOŚĆ + SEJF (krypto fundament)
├── core/crypto/   prymitywy kryptograficzne + FNX-WRAP
├── net/           WŁASNA SIEĆ P2P (ramka szyfrowana, node)
├── transport/     KAMUFLAŻ ruchu (ISP widzi tylko szum)
├── chain/         💰 COIN FNX (blockchain, kopanie, opłaty)
├── app/           ⬜ komunikator (M4)
├── gui/           ⬜ GUI (M7)
├── ai/            ⬜ AI-sentry dla administracji (M6)
├── boot/          edukacyjny bootloader ASM (nie w ISO)
├── os/            💿 BOOTOWALNE ISO (Debian live-build)
├── tools/         narzędzia (self-attack, generatory PDF)
└── docs/          specy + decyzje + ToS
```

---

## 1. 💰 COIN FNX — gdzie siedzi nazwa, jednostki, ekonomia

| plik | co robi | status |
|---|---|---|
| `chain/block.py` | **nazwa coina i jednostki**: 1 FNX = 10^8 **iskier**; typy tx (COINBASE/TRANSFER); TREASURY wallet DEV; podpisy tx; fee split **0.001% burn + 0.055% skarbiec** (D15) | ✅ |
| `chain/ledger.py` | księga: salda, nonce (anti-replay), mempool, retarget trudności co 144 bloki, fork-choice (najdłuższy; remis → mniejszy hash) | ✅ |
| `chain/pow.py` | PoW CPU-friendly: argon2-lite (1024 KiB / t1 / p1) + fallback sha256d | ✅ |
| `chain/miner.py` | pętla kopania (stop-event, max_tries) | ✅ |
| `core/identity.py` | **wallet FNX1…** = blake2s(klucze)→base32; klucze X25519+Ed25519; username | ✅ |
| `docs/fnx_spec.md` | pełny spec coina (emisja, halving — §12 do domknięcia) | 🟡 |
| `core/keystore.py` | SEJF na klucze coina (Kontener D24: Argon2id→KEK→MEK→AEAD) | ✅ |

**Do znalezienia w 30 sekund w VS Code:** szukaj `ISKRA`, `TREASURY_WALLET_DEV`, `FEE_BURN_PPM`, `BLOCK_REWARD`.

---

## 2. 🔒 SZYFROWANIE TRANSAKCJI — co jest, czego brakuje

### 2.1 Już jest (warstwa transportowa — transakcja NIEWIDOCZNA dla ISP)

| plik | co robi | status |
|---|---|---|
| `net/frame.py` | **ramka VER=2: AEAD szyfruje payload+pad** (ChaCha20-Poly1305, nonce per SEQ, replay okno 4096); handshake = same efemeryki 32B | ✅ |
| `transport/camo.py` | Profil A: rekordy 4096B czystego szumu; cover traffic 0.3–0.8 s | ✅ |
| `net/fenix_node.py` | gossip tx/bloków po szyfrowanym kanale; drut = zero markerów (selftest #5) | ✅ |
| `core/crypto/fenix_wrap.py` | FNX-WRAP: własna DODATKOWA warstwa (Feistel 24r + HMAC) — opcjonalna (D2) | ✅ |
| `core/crypto/fenix_crypto.py` | E2E X25519+HKDF+AES-256-GCM+Ed25519; Shamir 3-z-5 | ✅ |

Efekt: podsłuch na kablu widzi wyłącznie losowe bajty — nie widzi, że to transakcja, kto, komu, ile.

### 2.2 Czego brakuje (prywatność NA-CHAIN — plan M5b, Monero-style)

Dziś ledger jest transparentny (jak Bitcoin). Plan D31 — pliki do napisania:

| planowany plik | co zrobi | priorytet |
|---|---|---|
| `chain/stealth.py` | **stealth addresses**: odbiorca niewidoczny na-chain (jednorazowy klucz DH) | 1 |
| `chain/ring_sig.py` | **ring signatures**: nadawca w pierścieniu wabików (CLSAG-style) | 2 |
| `chain/amount_hide.py` | **confidential amounts**: Pedersen commitments + prosty rangeproof | 3 |
| `chain/ledger_priv.py` | walidacja prywatnych tx (suma zobowiązań = 0, ring podpis ważny) | 4 |

Transparentny tryb zostaje jako dev/test; produkcja = prywatna domyślnie.

---

## 3. 💿 BOOTOWALNE ISO — kompletny zestaw os/

### 3.1 Build (na Twoim Debianie)

| plik | rola | status |
|---|---|---|
| `os/build_iso.sh` | orkiestrator: selftest (45/45 ✅) → staging → `lb build` → `dist/*.iso` + sha256 | 🟡 (lb na Twoim Debianie) |
| `os/live-build/auto/config` | Debian bookworm amd64, iso-hybrid (UEFI+Legacy), syslinux+grub-efi | 🟡 |
| `os/live-build/config/package-lists/fenix.list.chroot` | pakiety ISO | 🟡 |
| `os/live-build/config/hooks/live/0100-*.hook.chroot` | hardening: user fenix(1088), purge sudo, journald volatile, maski bt/avahi, enable usług Fenixa | 🟡 |
| `os/live-build/config/hooks/live/0200-*.hook.chroot` | instalacja stosu: venv + launcher `fenix-node` + bity x | 🟡 |

### 3.2 Bezpieczeństwo bootu (bariera)

| plik | rola | status |
|---|---|---|
| `os/fenix_boot.py` | **BARIERA**: kreator 1. bootu / unlock hasłem / hasło paniki | ✅ (selftest 6/6) |
| `os/fenix_payload.py` | **KOD ISO ZASZYFROWANY**: payload.enc, klucz tylko Shamir z seedów | ✅ (selftest 7/7) |
| `os/fenix_panicd.py` | **PANIKA**: Del+PageUp 2 s → shred + wipe + poweroff | ✅ (selftest 5/5) |
| `os/spoof.sh` | losowy MAC/hostname/machine-id przy każdym boot | ✅ |

### 3.3 Usługi systemd (kolejność = opancerzenie)

```
fenix-spoof.service  →  nftables(fail-closed)  →  fenix-boot.service  →  fenix-netup  →  fenix-node.service
 (losowa tożsamość     (mur: tylko FNX-camo      (BARIERA: hasło →       (self-check     (node FNX z identity
  sprzętowa)            albo DROP)                identity.json z tmpfs)   fail-closed)     z bariery, /run)
fenix-panicd.service — równolegle, czuwa nad Del+PageUp
```

| plik usługi | status |
|---|---|
| `os/includes.chroot/etc/systemd/system/fenix-spoof.service` | 🟡 |
| `os/includes.chroot/etc/systemd/system/fenix-boot.service` | 🟡 |
| `os/includes.chroot/etc/systemd/system/fenix-node.service` | 🟡 |
| `os/includes.chroot/etc/systemd/system/fenix-panicd.service` | 🟡 |

### 3.4 Sieć startowa i weryfikacja

| plik | rola | status |
|---|---|---|
| `os/includes.chroot/etc/nftables.conf` | fail-closed: input/forward/output DROP; uid 1088 może tylko Fenix | 🟡 |
| `os/includes.chroot/usr/local/bin/fenix-netup` | bootstrap: default route + self-check DROP + reach seedów | 🟡 |
| `os/includes.chroot/etc/fenix/seeds.list` | seedy DEV (RFC5737) — do podmiany na prawdziwe | 🟡 |
| `os/verify_iso.sh` | weryfikacja ISO podpisem ownera (D14) przed nagraniem | 🟡 |

**Żeby ISO się bootowało (minimalny warunek):** `live-build/auto/config` (iso-hybrid) + hook 0100/0200 + includes.chroot + `lb build` na Debianie. Reszta (bariera/panika/ładunek) to warstwy ochrony.

---

## 4. Jak tego użyć w VS Code

1. Otwórz `FenixOS.code-workspace` (File → Open Workspace from File…) — masz wszystkie główne
   katalogi jako foldery, ustawiony Python, wykluczenia `__pycache__`.
2. Polecane rozszerzenia (workspace zaproponuje): Python, Pylance, Even Better TOML, Shell-Format.
3. Uruchamianie selftestów w terminalu VS Code (Terminal → New Terminal):
   - `python3 -m net.fenix_node`      — mesh 3 node'y ✅
   - `python3 os/fenix_panicd.py`     — panika (dry) ✅
   - `python3 os/fenix_boot.py`       — bariera ✅
   - `python3 os/fenix_payload.py`    — ładunek ✅
   - `bash os/build_iso.sh --selftest` — paczka ISO (45/45) ✅
   - `python3 tools/self_attack.py`   — 32 scenariusze ataku na ECDH (27 odparzone, 5 notatek)

---

## 5. Konwencje — żeby VS Code i my się nie pogubili

- **Jeden plik = jedna odpowiedzialność.** Każdy plik ma selftest na dole (`if __name__ == "__main__":`).
- **Importy:** pliki w `./os/` mają shim `sys.path.insert(0, parents[1])` po `from __future__`, żeby działać standalone.
- **Katalog `os/` NIE jest pakietem Python** (kolizja ze stdlib) — importy z niego po ŚCIEŻCE pliku (importlib), nigdy `from os.x import y`.
- **Zmiana kodu = zielone testy + zapis decyzji w `docs/decyzje_architektury.md` + odhaczenie TODO.md.**
- **Nazwy plików są stałe** — nie zmieniamy ich między sesjami (Twoja zasada).

---

*STRUKTURA_PROJEKTU.md v1.0 — aktualizowana przy każdym kamieniu milowym (M0→M9).*
