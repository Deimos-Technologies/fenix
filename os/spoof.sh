#!/bin/bash
# os/spoof.sh — losowa tożsamość sprzętowa przy KAŻDYM budowie ISO i KAŻDYM bootcie (D6)
#
# Co robi:
#   1. MAC interfejsu  → losowy, lokalnie administrowany, unicast (02:xx:xx:xx:xx:xx)
#   2. hostname        → fenix-<8 hex>  (NIGDY nazwa z poprzedniego bootu)
#   3. machine-id      → 32 hex losowe (systemd/dbus NIE zdradza stałego ID maszyny)
#
# Czego NIE robi (uczciwie, D6): to warstwa LOKALNA — chroni przed LAN/trackerami
# w kawiarni/hotelu i przed korelacją "ta sama maszyna, wczoraj i dziś". Przed ISP
# chroni camo/mixnet (M3), nie MAC. Spoof musi odpalić się PRZED podniesieniem
# interfejsu — stąd na ISO startuje jako usługa systemd: Before=network-pre.target.
#
# Tryby:
#   --dry-run    wypisz plan, NIC nie zmieniaj (domyślny w sandboxie/testach)
#   --apply      wykonaj (WYMAGA roota); używane TYLKO na Fenix OS podczas bootu
#   --print      wypisz same wartości (MAC/HOSTNAME/MACHINE_ID) — do skryptów
#   --selftest   test generatorów (200 próbek): unikalność + format + flagi
#
# Autor: projekt Fenix. Zero zależności poza bash + coreutils + iproute2 (przy --apply).

set -euo pipefail

# ---------------------------------------------------------------- generatory
# Byte 0 = 0x02: bit "locally administered" SET, bit "multicast" CLEAR.
# To legalny, poprawny losowy MAC (tak robią też routery przy klonowaniu).
gen_mac() {
  local b
  b=$(od -An -N5 -tx1 /dev/urandom | tr -d ' \n')
  printf '02:%s:%s:%s:%s:%s\n' \
    "${b:0:2}" "${b:2:2}" "${b:4:2}" "${b:6:2}" "${b:8:2}"
}

gen_hostname() {
  printf 'fenix-%s\n' "$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
}

gen_machine_id() {
  od -An -N16 -tx1 /dev/urandom | tr -d ' \n'
  printf '\n'
}

# ---------------------------------------------------------------- walidatory (używa ich i selftest, i --apply)
valid_mac() { # format + flagi: lokalny (bit1) i unicast (bit0)
  local m="$1"
  [[ "$m" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || return 1
  local first=$((16#${m:0:2}))
  (( first & 2 )) && (( ! (first & 1) ))
}
valid_hostname() { [[ "$1" =~ ^fenix-[0-9a-f]{8}$ ]]; }
valid_machine_id() { [[ "$1" =~ ^[0-9a-f]{32}$ ]]; }

# ---------------------------------------------------------------- pomocnicze
log() { printf '[fenix-spoof] %s\n' "$*" >&2; }

detect_iface() { # pierwszy interfejs nie-lo z operstate (ethernet/wifi), lub $1
  local want="${1:-}"
  if [[ -n "$want" ]]; then printf '%s\n' "$want"; return 0; fi
  local d name
  for d in /sys/class/net/*; do
    name="${d##*/}"
    [[ "$name" == "lo" ]] && continue
    [[ -e "$d/address" ]] || continue
    printf '%s\n' "$name"
    return 0
  done
  return 1
}

# ---------------------------------------------------------------- aplikowanie (root, tylko Fenix OS)
apply_spoof() {
  local iface_opt="${1:-}"
  (( EUID == 0 )) || { log "BLAD: --apply wymaga roota (Fenix OS boot)"; exit 3; }

  local iface mac host mid
  iface=$(detect_iface "$iface_opt") || { log "BLAD: brak interfejsu do spoof"; exit 4; }
  mac=$(gen_mac); host=$(gen_hostname); mid=$(gen_machine_id)

  valid_mac "$mac" && valid_hostname "$host" && valid_machine_id "$mid" \
    || { log "BLAD: generator dal niepoprawna wartosc — przerywam bez zmian"; exit 5; }

  # MAC: interfejs MUSI byc down; po zmianie wstaje z nowa tozsamoscia
  log "iface=$iface MAC→$mac"
  ip link set dev "$iface" down
  ip link set dev "$iface" address "$mac"
  ip link set dev "$iface" up

  # hostname (hostnamectl gdy jest; inaczej plik + hostname -F)
  log "hostname→$host"
  if command -v hostnamectl >/dev/null 2>&1; then
    hostnamectl set-hostname "$host"
  else
    printf '%s\n' "$host" > /etc/hostname
    hostname -F /etc/hostname
  fi
  # /etc/hosts: aktualizuj linie 127.0.1.1 (jak nie ma — dodaj)
  if grep -q '^127\.0\.1\.1' /etc/hosts 2>/dev/null; then
    sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t$host/" /etc/hosts
  else
    printf '127.0.1.1\t%s\n' "$host" >> /etc/hosts
  fi

  # machine-id (singleton identyfikatora maszyny — dzis losowy)
  log "machine-id→$mid"
  printf '%s\n' "$mid" > /etc/machine-id
  if [[ -e /var/lib/dbus/machine-id && ! -L /var/lib/dbus/machine-id ]]; then
    printf '%s\n' "$mid" > /var/lib/dbus/machine-id
  fi

  # DHCP nie wysyla naszego hostname (jesli dhclient obecny)
  if [[ -f /etc/dhcp/dhclient.conf ]] && ! grep -q 'fenix-no-hostname' /etc/dhcp/dhclient.conf; then
    printf '# fenix-no-hostname\nsend host-name = "";\n' >> /etc/dhcp/dhclient.conf
  fi
  log "OK: tozsamosc sprzetowa wylosowana"
}

# ---------------------------------------------------------------- tryby
dry_run() {
  local iface mac host mid
  iface=$(detect_iface "${1:-}" 2>/dev/null || printf '(brak-wykrytego)')
  mac=$(gen_mac); host=$(gen_hostname); mid=$(gen_machine_id)
  cat <<EOF
[DRY-RUN] nic nie zmieniam. Plan:
  interfejs: $iface
  MAC:       $mac  (lokalny/unicast: $(valid_mac "$mac" && echo OK || echo ZLY))
  hostname:  $host
  machine-id: $mid
EOF
}

print_values() {
  printf 'MAC=%s\nHOSTNAME=%s\nMACHINE_ID=%s\n' \
    "$(gen_mac)" "$(gen_hostname)" "$(gen_machine_id)"
}

selftest() {
  local fails=0 i m h ids uniq
  echo "os/spoof.sh --selftest"

  # 200 MAC: format, flagi, unikalnosc
  declare -A seen=()
  for i in $(seq 1 200); do
    m=$(gen_mac)
    valid_mac "$m" || { echo "  [FAIL] zly MAC: $m"; fails=$((fails+1)); }
    seen[$m]=1
  done
  uniq=${#seen[@]}
  (( uniq == 200 )) || { echo "  [FAIL] MAC unikalnosc $uniq/200"; fails=$((fails+1)); }
  echo "  [OK] MAC: 200/200 poprawne (lokalny, unicast), unikalne $uniq/200"

  # 200 hostname: format + unikalnosc
  unset seen; declare -A seen=()
  for i in $(seq 1 200); do
    h=$(gen_hostname)
    valid_hostname "$h" || { echo "  [FAIL] zly hostname: $h"; fails=$((fails+1)); }
    seen[$h]=1
  done
  uniq=${#seen[@]}
  (( uniq == 200 )) || { echo "  [FAIL] hostname unikalnosc $uniq/200"; fails=$((fails+1)); }
  echo "  [OK] hostname: 200/200 poprawne, unikalne $uniq/200"

  # 50 machine-id: format + unikalnosc
  unset seen; declare -A seen=()
  for i in $(seq 1 50); do
    ids=$(gen_machine_id)
    valid_machine_id "$ids" || { echo "  [FAIL] zly machine-id"; fails=$((fails+1)); }
    seen[$ids]=1
  done
  uniq=${#seen[@]}
  (( uniq == 50 )) || { echo "  [FAIL] machine-id unikalnosc $uniq/50"; fails=$((fails+1)); }
  echo "  [OK] machine-id: 50/50 poprawne (32 hex), unikalne $uniq/50"

  # walidator łapie śmieci (nie przepusci multicast/globalnych)
  ! valid_mac "01:00:5e:00:00:01" && ! valid_mac "48:5f:99:00:11:22" \
    || { echo "  [FAIL] walidator MAC przepuszcza nielegalne"; fails=$((fails+1)); }
  echo "  [OK] walidator: odrzuca multicast (01:00:5e) i globalne (48:5f)"

  # dry-run bez roota niczego nie rusza i konczy 0
  dry_run >/dev/null || { echo "  [FAIL] dry-run"; fails=$((fails+1)); }
  echo "  [OK] dry-run: dziala bez roota, zero zmian"

  # shellcheck (informacyjnie)
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -S warning "$0" >/dev/null && echo "  [OK] shellcheck: czysto (warning+)" \
      || echo "  [INFO] shellcheck: sa uwagi (nie blokujace)"
  fi

  if (( fails == 0 )); then echo "SELFTEST: PASS ✅"; exit 0
  else echo "SELFTEST: FAIL ❌ ($fails)"; exit 1; fi
}

usage() {
  sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

case "${1:---dry-run}" in
  --dry-run) dry_run "${2:-}" ;;
  --apply) apply_spoof "${2:-}" ;;
  --print) print_values ;;
  --selftest) selftest ;;
  -h|--help) usage ;;
  *) usage ;;
esac
