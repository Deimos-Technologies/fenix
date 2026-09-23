# os/ — Fenix OS: budowa ISO i okablowanie sieci zbiorczej

Ten katalog = maszyna produkująca Fenix OS (remaster Debiana, D8) oraz okablowanie,
dzięki któremu **każde ISO po starcie staje się węzłem jednej sieci FNX**.

## Co tu jest
| plik | rola |
|---|---|
| `build_iso.sh` | główna budowa + `--selftest` (walidacja paczki bez roota) |
| `verify_iso.sh` | użytkownik: weryfikacja SHA256 + podpisu ownera (D14) |
| `spoof.sh` | losowa tożsamość sprzętowa MAC/hostname/machine-id (D6) |
| `live-build/` | konfiguracja Debiana live-build (bookworm, UEFI+Legacy, lockdown, IPv6 OFF) |
| `live-build/config/hooks/live/0100-…-hardening` | amnezja, maski usług, sysctl, user `fenix` (uid **1088**) |
| `live-build/config/hooks/live/0200-…-install` | stos Fenixa (`/opt/fenix` + venv) + launcher |
| `includes.chroot/etc/nftables.conf` | **firewall FAIL-CLOSED**: net tylko usera `fenix`, DNS/NTP poza camo = DROP |
| `includes.chroot/etc/fenix/seeds.list` | seed nodes (PLACEHOLDERY DEV — prawdziwe w M9) |
| `includes.chroot/etc/systemd/system/fenix-*.service` | kolejność bootu sieci |
| `includes.chroot/usr/local/bin/fenix-netup` | bootstrap: self-check fail-closed + reach seedów |

## Jak każde ISO tworzy zbiorczą sieć (flow bootu, M2/M3-ready)

```
1. fenix-spoof.service   Before=network-pre.target  → losowy MAC/host/machine-id PRZED siecią (D6)
2. nftables.service      /etc/nftables.conf          → DROP wszystko poza DHCP i uid 1088
3. fenix-netup           ExecStartPre noda           → sprawdza: trasa ✓ fail-closed ✓ seedy ✓
4. fenix-node.service    User=fenix, Restart=on-failure
                         → /usr/local/bin/fenix-node --profile A --seeds …
                         → M2: handshake wg protocol_spec, gossip, relay A→R→B
                         → M3: transport camo (profil A szum / B mimikra, D10)
```

Efekt: dwa pendrive'y z Fenix OS na dwóch końcach miasta = dwa node'y tej samej sieci.
Seed-y są tylko bramą startową; peer listy rozchodzą się gossip'em (katalog podpisany,
docelowo on-chain — TODO M2/M5).

## Budowa (na Twoim Debianie, nigdy nie „w chmurze")

```bash
sudo apt install live-build xorriso squashfs-tools debootstrap rsync
./os/build_iso.sh --selftest      # walidacja paczki (bez roota, ~2 s)
sudo ./os/build_iso.sh            # ~30–60 min → dist/fenix-os-*.iso + .sha256
```

## Podpis i weryfikacja (D14)

```bash
# na ZIMNEJ maszynie z kluczem ownera (master offline, Shamir 2-z-3):
gpg --detach-sign --armor dist/fenix-os-*.iso     # → .asc
# użytkownik przed nagraniem:
./os/verify_iso.sh dist/fenix-os-*.iso
```

## Co jeszcze NIE działa (uczciwie)

- `net/fenix_node.py` — przyjdzie w M2 (launcher już czeka; zamiast fail-open: brak sieci)
- `transport/camo.py` — M3; bez niego node się nie łączy (by design, D13)
- `vm test`, `dm-verity` — kolejne pliki os/
- ✅ `panicd` = `os/fenix_panicd.py` (Del+PageUp 2 s; D27) + `fenix_boot.py` (bariera unlock/kreator/panika; D24)

## Zasady nienaruszalne (TODO/NIGDY)

- żadnych kluczy prywatnych w `os/` (nie przejdzie selftestu)
- seeds.list = tylko publiczne odciski
- Secure Boot: instrukcja „wyłącz" (D23); podpis ISO zawsze offline (D14)
- build reprodukowalny = cel (ten sam commit → ten sam SHA256; na start raportujemy różnice)
