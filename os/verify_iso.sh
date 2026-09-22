#!/bin/bash
# os/verify_iso.sh — weryfikacja pobranego ISO przed nagraniem (D14)
#
# UZYCIE:
#   ./verify_iso.sh dist/fenix-os-YYYYMMDD-abcd123-full.iso
# Oczekuje obok: <iso>.sha256 oraz <iso>.asc (podpis detaszowany ownera)
# Klucz publiczny ownera: ownersc/pobierz ze strony projektu jako fenix-owner-release.asc
set -euo pipefail

iso="${1:?uzycie: verify_iso.sh PLIK.iso}"
[[ -f "$iso" ]] || { echo "brak pliku: $iso" >&2; exit 2; }

say(){ printf '[verify_iso] %s\n' "$*"; }
ok=1

# --- 1) hash SHA256 ---------------------------------------------------------
if [[ -f "$iso.sha256" ]]; then
  (cd "$(dirname "$iso")" && sha256sum -c "$(basename "$iso").sha256") && \
    say "✅ SHA256 zgodny" || { say "❌ SHA256 NIEZGODNY — plik uszkodzony/podmieniony"; ok=0; }
else
  say "⚠️  brak $iso.sha256 — nie mam z czym porownac (pobierz oba pliki)"
  ok=0
fi

# --- 2) podpis ownera (opcjonalny, ale wymagany dla wydan publicznych) -----
if [[ -f "$iso.asc" && -f fenix-owner-release.asc ]]; then
  if gpg --import fenix-owner-release.asc 2>/dev/null && gpg --verify "$iso.asc" "$iso" 2>/dev/null; then
    say "✅ podpis ownera POPRAWNY"
  else
    say "❌ podpis ownera NIEPOPRAWNY — NIE UZYWAJ tego obrazu"
    ok=0
  fi
else
  say "ℹ️  brak .asc albo klucza publicznego — pomijam podpis (tryb deweloperski)"
fi

echo
if (( ok == 1 )); then
  say "WERDYKT: ISO jest zgodne z wydaniem — mozesz nagrywac na pendrive"
else
  say "WERDYKT: NIE nagrywaj tego obrazu"
  exit 1
fi
