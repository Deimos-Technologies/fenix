# FENIX / AnonNet 🔥

Zdecentralizowana, anonimowa siec P2P z wlasnym blockchainem FNX, systemem
Fenix OS (Live ISO) i kryptografia progowym. Identyfikacja wylacznie przez
Wallet Address + Username + UID + Ranga — zero IP, MAC i fingerprintow
w logice sieci.

> Status: **wczesny rozwoj** (patrz TODO.md — kamienie milowe M0→M9).
> Dokument roboczy projektu; nie stanowi porady prawnej.

## Struktura

```
core/      — rdzen: krypto, identity, keystore, config
net/       — wlasny protokol P2P (ramki, node, relay, cebula)
transport/ — warstwa kamuflazu camo (profile A/B)
app/       — komunikator (CLI -> GUI)
chain/     — blockchain FNX (PoW, PoU, op┼éaty, rangi)
ai/        — AI-Sentry (narzedzie wylacznie administracji)
gui/       — dashboard + komunikator graficzny
os/        — Fenix OS ISO (live-build, spoof, amnezja)
tools/     — generatory dokumentow (PDF PL/EN/RU)
docs/      — TODO, decyzje D1-D21, plan, threat model, specy, legal
```

## Jak dodac

Szczegoly: `JAK_DODAC.md`.

```bash
pip install -e .                          # pakiety Pythona (ai/app/chain/core/gui/net/transport)
python3 tools/pack_dropin.py              # dist/FenixOS-do-dodania.zip z bitami +x
bash tools/ensure_exec_bits.sh            # po unzipie, ktory zgubil tryb unixa
```

`os/` nie jest pakietem — zostaje katalogiem skryptow ISO. Zip bez unix-mode
zostawia `fenix-gui` jako 0644 i `build_iso.sh --selftest` wtedy pada.

## Szybki start (testy krypto)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python core/crypto/fenix_crypto.py        # test: E2E + skarbiec progowy
python core/crypto/fenix_wrap.py          # test: FNX-WRAP v1 (własna warstwa DODATKOWA, D2)
python core/crypto/fnx64.py               # test: tetracja do 10; C jesli jest gcc
python core/crypto/fenix_cipher_demo.py   # test: wlasny Feistel + lawina
python -m core.identity                   # test: tożsamość Wallet+Username+UID+Ranga
python tools/make_full_docs.py       # regeneruj dokumenty PDF
bash os/build_iso.sh --selftest           # paczka ISO bez budowania obrazu
```

## Dokumenty kluczowe

- `TODO.md` — master plan od A do Z (pierwszy pusty checkbox = zadanie na dziś)
- `docs/decyzje_architektury.md` — rejestr decyzji D1–D21 (nie do przeglosowania TODO)
- `docs/plan_mvp.md` — filozofia „chodzacego szkieletu"
- `docs/ToS.md` + `docs/FENIX_Dokument_Sieci_PL_EN_RU.pdf` — warunki/regulamin/rangi/bany

## Zasady zelazne (lista NIGDY)

Zadna tresc wiadomosci w logach. Zaden klucz na sztywno. Zero recovery
w protokole. Wlasny szyfr nigdy solo. Pakiet bez camo nie wylatuje.
Pelna lista: `TODO.md`, sekcja NIGDY.
