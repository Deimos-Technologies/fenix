# Jak dodać FenixOS

Dwa sposoby. Oba zostawiają skrypty ISO wykonywalne — zip z Windows tego nie robi
i `bash os/build_iso.sh --selftest` pada na `fenix-gui` (plik jest, ale bez `+x`).

## 1. Drop-in (całe drzewo, do istniejącego katalogu)

Z tego repozytorium:

```bash
python3 tools/pack_dropin.py
# → dist/FenixOS-do-dodania.zip
```

U odbiorcy (Linux/macOS):

```bash
unzip FenixOS-do-dodania.zip -d fenix
cd fenix
bash tools/ensure_exec_bits.sh          # gdyby unzip i tak ściął tryb
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python3 core/crypto/fnx64.py            # selftest; przy gcc wstaje akcelerator C
bash os/build_iso.sh --selftest         # woła `python3` z PATH — po activate, nie goły systemowy
```

Paczka ustawia `create_system=Unix` i `0755` na launcherach, hakach live-build
oraz `os/*.sh`. `os/` nie jest pakietem Pythona — zostaje katalogiem skryptów.

## 2. Pakiet Pythona (sam kod, bez ISO)

```bash
pip install -e .
# albo: pip install .
```

Wchodzą pakiety `ai app chain core gui net transport` plus `fnx64_accel.c`
(kompiluje się przy pierwszym imporcie `core.crypto.fnx64`, wynik 1:1 z
`tower_mod`; brak kompilatora = ten sam strumień w czystym Pythonie) i
ikony odznak. `os/`, `docs/`, `tools/` dokładaj drop-inem z punktu 1 —
nie należą do koła pip.

Zależności: Python ≥ 3.10, `cryptography` ≥ 44, `fpdf2` (tylko generatory PDF).
