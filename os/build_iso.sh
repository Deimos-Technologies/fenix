#!/bin/bash
# os/build_iso.sh — budowa Fenix OS .iso (Debian live-build; D8, D14, D23, D24)
#
# UZYCIE (na Twoim Debianie — build NIGDY nie w cudzym srodowisku, D14):
#   sudo apt install live-build xorriso squashfs-tools debootstrap
#   sudo ./os/build_iso.sh [--profile full|min]
# artefakt: dist/fenix-os-<data>-<commit>-<profil>.iso + .sha256
#
# PODPIS (D14): master NIGDY na maszynie build. Hash zdejmujesz na zimny system:
#   gpg --homedir /zimny/keyring --detach-sign --armor dist/fenix-os-*.iso  → .asc
#   (uzytkownik weryfikuje: os/verify_iso.sh)
#
# ./os/build_iso.sh --selftest — walidacja calej paczki os/ BEZ budowania (bez roota),
#   uruchamiaj przed kazdym buildem i po kazdej zmianie w os/.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="full"
DO_SELFTEST=0

while (( $# )); do
  case "$1" in
    --profile) PROFILE="${2:?--profile full|min}"; shift 2;;
    --selftest) DO_SELFTEST=1; shift;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "nieznana opcja: $1" >&2; exit 2;;
  esac
done
[[ "$PROFILE" =~ ^(full|min)$ ]] || { echo "profil: full albo min" >&2; exit 2; }

say(){ printf '[build_iso] %s\n' "$*"; }
fail(){ printf '[build_iso] BLAD: %s\n' "$*" >&2; exit 1; }

# =====================================================================
# --selftest: co sprawdzamy bez budowania (sandbox-safe)
# =====================================================================
selftest() {
  local n=0 bad=0 t
  ok(){ n=$((n+1)); say "  [OK] $1"; }
  no(){ n=$((n+1)); bad=$((bad+1)); say "  [FAIL] $1"; }

  say "SELFTEST paczki os/ (bez budowania ISO)"

  # 1) wszystkie pliki paczki istnieja
  local files=(
    os/build_iso.sh os/verify_iso.sh os/spoof.sh os/README.md
    os/fenix_panicd.py os/fenix_boot.py os/fenix_payload.py
    os/live-build/auto/config
    os/live-build/config/package-lists/fenix.list.chroot
    os/live-build/config/hooks/live/0100-fenix-hardening.hook.chroot
    os/live-build/config/hooks/live/0200-fenix-install.hook.chroot
    os/includes.chroot/etc/nftables.conf
    os/includes.chroot/etc/fenix/seeds.list
    os/includes.chroot/etc/systemd/system/fenix-spoof.service
    os/includes.chroot/etc/systemd/system/fenix-node.service
    os/includes.chroot/etc/systemd/system/fenix-panicd.service
    os/includes.chroot/etc/systemd/system/fenix-boot.service
    os/includes.chroot/etc/tmpfiles.d/fenix.conf
    os/includes.chroot/usr/local/bin/fenix-netup
  )
  for f in "${files[@]}"; do
    if [[ -f "$REPO_ROOT/$f" ]]; then ok "plik: $f"; else no "BRAK pliku: $f"; fi
  done

  # 2) skladnia bash wszystkich skryptow
  while IFS= read -r f; do
    if bash -n "$f" 2>/dev/null; then ok "skladnia: ${f#$REPO_ROOT/}"; else no "SKLADNIA: ${f#$REPO_ROOT/}"; fi
  done < <(find "$REPO_ROOT/os" -type f \( -name '*.sh' -o -name '*.hook.chroot' \
            -o -name config -o -name fenix-netup \) ! -path '*/includes.chroot/etc/*')

  # 3) selftest generatorow spoofa (powtorka z rozrywki — zawsze zielona)
  if bash "$REPO_ROOT/os/spoof.sh" --selftest >/dev/null 2>&1; then
    ok "spoof.sh --selftest: PASS"
  else
    no "spoof.sh --selftest: FAIL"
  fi

  # 4) SPIJNOSC uid: hook==1088 i niezerowe skuid w nftables MUSZA byc takie same
  local uid_hook uid_nft
  uid_hook=$(grep -oE 'useradd -u [0-9]+' \
    "$REPO_ROOT/os/live-build/config/hooks/live/0100-fenix-hardening.hook.chroot" \
    | grep -oE '[0-9]+' | head -1)
  uid_nft=$(grep -oE 'meta skuid [0-9]+' "$REPO_ROOT/os/includes.chroot/etc/nftables.conf" \
    | grep -oE '[0-9]+' | grep -vx '0' | sort -u)
  if [[ "$uid_hook" == "$uid_nft" && -n "$uid_hook" ]]; then
    ok "spojnosc uid fenix: hook=$uid_hook, nft=$uid_nft"
  else
    no "ROZJAZD uid fenix: hook='$uid_hook' nft='$uid_nft'"
  fi

  # 5) fail-closed w nftables: 3 lancuchy policy drop + zakazy DNS/NTP
  local nft="$REPO_ROOT/os/includes.chroot/etc/nftables.conf"
  t=$(grep -c 'policy drop' "$nft")
  (( t >= 3 )) && ok "nft: $t lancuchy policy drop" || no "nft: za malo policy drop ($t)"
  grep -q 'dport {53, 123}' "$nft" && ok "nft: DNS/NTP udp zakazane (fenix uid)" \
    || no "nft: brak zakazu DNS/NTP udp"
  grep -q 'dport {53, 853}' "$nft" && ok "nft: DNS tcp/DoT zakazane" \
    || no "nft: brak zakazu DNS tcp/DoT"

  # 6) kolejnosc boot: spoof PRZED siecia, node PO firewallu
  grep -q 'Before=network-pre.target' \
    "$REPO_ROOT/os/includes.chroot/etc/systemd/system/fenix-spoof.service" \
    && ok "fenix-spoof: Before=network-pre.target" || no "fenix-spoof: zla kolejnosc"
  grep -q 'Requires=nftables.service' \
    "$REPO_ROOT/os/includes.chroot/etc/systemd/system/fenix-node.service" \
    && ok "fenix-node: Requires=nftables (fail-closed pierwszy)" \
    || no "fenix-node: brak zaleznosci od firewalla"
  grep -q 'User=fenix' \
    "$REPO_ROOT/os/includes.chroot/etc/systemd/system/fenix-node.service" \
    && ok "fenix-node: nie root, tylko fenix" || no "fenix-node: nie user fenix"
  grep -q 'Before=fenix-node.service' \
    "$REPO_ROOT/os/includes.chroot/etc/systemd/system/fenix-boot.service" \
    && ok "fenix-boot: bariera PRZED node (D24)" || no "fenix-boot: zla kolejnosc"
  grep -q 'identity-file /run/fenix/identity.json' \
    "$REPO_ROOT/os/includes.chroot/etc/systemd/system/fenix-node.service" \
    && ok "fenix-node: identity z tmpfs bariery" || no "fenix-node: brak identity-file"
  # FENIX_PYTHON: selftest woła interpreter z PATH. Goły systemowy python3
  # bez `cryptography` pada tu tak samo jak zepsuty skrypt — ostatnia linia
  # błędu zostaje w komunikacie, żeby nie zgadywać.
  local py="${FENIX_PYTHON:-python3}"
  _py_selftest() {
    local label="$1" script="$2" oknote="${3:-PASS}" out rc=0 tail
    out=$("$py" "$script" 2>&1) && rc=0 || rc=$?
    if (( rc == 0 )); then
      ok "$label: $oknote"
    else
      tail=$(printf '%s\n' "$out" | tail -n 1)
      no "$label: FAIL — ${tail:-rc $rc} (interpreter: $py)"
    fi
  }
  _py_selftest "fenix_panicd selftest" "$REPO_ROOT/os/fenix_panicd.py"
  _py_selftest "fenix_boot selftest" "$REPO_ROOT/os/fenix_boot.py"
  _py_selftest "fenix_payload selftest" "$REPO_ROOT/os/fenix_payload.py" "PASS (szczelny ładunek)"

  # 7) seeds.list: format linii + przynajmniej 1 wpis DEV
  local good=0
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    head1=$(awk '{print $1}' <<<"$line")
    [[ "$head1" =~ ^[0-9a-fA-F:.]+:[0-9]{2,5}$ ]] || no "seeds.list zla linia: $line"
    good=$((good+1))
  done < "$REPO_ROOT/os/includes.chroot/etc/fenix/seeds.list"
  (( good >= 1 )) && ok "seeds.list: $good wpisow (DEV-placeholdery — M9 podmieni)" \
    || no "seeds.list: zero poprawnych wpisow"

  # 7a) KONTRAKT seeds (P0 zlapanie 2026-08-06, latanie dziur): fenix-node.service podaje
  #     w --seeds ŚCIEŻKĘ PLIKU — demon MUSI umieć plik (net/fenix_node._parse_seeds),
  #     inaczej int('') i usługa nigdy nie wstaje. Strażnik paruje oba końce kontraktu.
  grep -q -- '--seeds /etc/fenix/seeds.list' \
    "$REPO_ROOT/os/includes.chroot/etc/systemd/system/fenix-node.service" \
    && ok "fenix-node.service: --seeds wskazuje PLIK (kontrakt ISO)" \
    || no "fenix-node.service: --seeds NIE wskazuje /etc/fenix/seeds.list"
  grep -q 'def _parse_seeds' "$REPO_ROOT/net/fenix_node.py" \
    && grep -q 'os.path.isfile' "$REPO_ROOT/net/fenix_node.py" \
    && ok "net/fenix_node: _parse_seeds akceptuje plik (druga strona kontraktu)" \
    || no "net/fenix_node: BRAK _parse_seeds z obsluga pliku — service_umrze_na_starcie"

  # 8) hardening: resolv.conf->/dev/null, journald volatile, maski, lockdown, ipv6 off
  local h="$REPO_ROOT/os/live-build/config/hooks/live/0100-fenix-hardening.hook.chroot"
  grep -q 'ln -s /dev/null /etc/resolv.conf' "$h" && ok "hardening: DNS otwarty tekstem OFF" \
    || no "hardening: brak resolv.conf->/dev/null"
  grep -q 'Storage=volatile' "$h" && ok "hardening: journald tylko RAM" \
    || no "hardening: brak journald volatile"
  grep -q 'disable_ipv6=1' "$h" && ok "hardening: IPv6 OFF (sysctl)" \
    || no "hardening: IPv6 nie wylaczone"
  grep -q 'lockdown=integrity' "$REPO_ROOT/os/live-build/auto/config" \
    && ok "kernel: lockdown=integrity w bootappend" || no "kernel: brak lockdown"

  # 9) zero sekretow w paczce os/ (klucze prywatne NIGDY tu nie trafiaja)
  #    wzorzec zakotwiczony o naglowek PEM (-----BEGIN ... PRIVATE KEY-----),
  #    zeby nie lapac falszywie samej tej reguly/dokumentacji
  if grep -rIlE '^-----BEGIN [A-Z ]*PRIVATE KEY-----' "$REPO_ROOT/os" >/dev/null 2>&1; then
    no "SEKRET w os/! (plik z kluczem prywatnym PEM)"
  else
    ok "zero kluczy prywatnych PEM w os/"
  fi

  # 10) node stub sie zgadza z pornelkami (.py placeholdery M2 nie sa wymagane tu)
  grep -q 'net.fenix_node' \
    "$REPO_ROOT/os/live-build/config/hooks/live/0200-fenix-install.hook.chroot" \
    && ok "launcher: wskazuje net.fenix_node (M2)" || no "launcher: zla sciezka noda"

  # 11) fenix-vpn (D29B): usluga opt-in, wrapper bez tokena w argv, hook enable, fwmark
  local svc="$REPO_ROOT/os/includes.chroot/etc/systemd/system/fenix-vpn.service"
  local wrap="$REPO_ROOT/os/includes.chroot/usr/local/bin/fenix-vpn"
  [[ -f "$svc" ]] && grep -q 'ConditionPathExists=/run/fenix/vpn.env' "$svc" \
    && ok "fenix-vpn.service: opt-in przez /run/fenix/vpn.env (RAM)" \
    || no "fenix-vpn.service: brak uslugi lub warunku opt-in"
  [[ -f "$wrap" ]] && grep -q 'transport.mullvad up' "$wrap" && ! grep -q 'MULLVAD_ACCOUNT=\$' "$wrap" \
    && ok "fenix-vpn wrapper: woła transport.mullvad, token TYLKO z env (nie z argv)"
  grep -q 'systemctl enable fenix-vpn.service' "$h" \
    && ok "hardening hook: fenix-vpn enable'owany" || no "hardening hook: brak enable fenix-vpn"
  grep -q 'meta mark 51820 accept' "$REPO_ROOT/os/includes.chroot/etc/nftables.conf" \
    && ok "nftables: fwmark 51820 (WG outer) puszczony" || no "nftables: brak fwmark 51820"
  local tpd="$REPO_ROOT/os/includes.chroot/etc/tmpfiles.d/fenix.conf"
  [[ -f "$tpd" ]] && grep -qE '^d[[:space:]]+/run/fenix[[:space:]]+0770[[:space:]]+root[[:space:]]+fenix' "$tpd" \
    && ok "/run/fenix: tmpfiles.d pozwala GUI (user fenix) pisac vpn.env (M7b)" \
    || no "/run/fenix: brak tmpfiles.d/fenix.conf — vpn.env z GUI nie zapisze sie"

  # 12) GUI na ISO (M7): launcher + desktop entry + openbox autostart + pakiet python3-tk
  local gl="$REPO_ROOT/os/includes.chroot/usr/local/bin/fenix-gui"
  [[ -f "$gl" && -x "$gl" ]] && grep -q 'gui.fenix_gui' "$gl" \
    && ok "fenix-gui: launcher wskazuje gui.fenix_gui" || no "fenix-gui: brak/zły launcher"
  [[ -f "$REPO_ROOT/os/includes.chroot/usr/share/applications/fenix-gui.desktop" ]] \
    && grep -q 'fenix-gui' "$REPO_ROOT/os/includes.chroot/etc/xdg/openbox/autostart" \
    && grep -q '^python3-tk$' "$REPO_ROOT/os/live-build/config/package-lists/fenix.list.chroot" \
    && ok "GUI: desktop entry + autostart + python3-tk w pakietach" \
    || no "GUI: brak desktop/autostart/python3-tk"

  # 13) IPC GUI<->demon (M7b) + dispatch fix demona (KRYTYCZNE dla ISO boot)
  grep -q 'from gui.backend_ipc import IpcServer' "$REPO_ROOT/net/fenix_node.py" \
    && [[ -f "$REPO_ROOT/gui/backend_ipc.py" ]] \
    && ok "IPC M7b: fenix_node wystawia gui/backend_ipc (/run/fenix/node.ipc)" \
    || no "IPC M7b: brak mostu GUI<->demon"
  grep -q 'if len(sys.argv) > 1:' "$REPO_ROOT/net/fenix_node.py" \
    && ok "fenix_node: dispatch fix — z flagami demon, bez flag selftest (ISO boot!)" \
    || no "fenix_node: ZNOWU bez dispatchu (ISO odpaliloby selftest zamiast demona)"
  grep -q 'import pool_panel' "$REPO_ROOT/gui/fenix_gui.py" \
    && [[ -f "$REPO_ROOT/gui/pool_panel.py" ]] \
    && ok "GUI: zakładka Pool (M7c, TX_RING) dociągnięta" \
    || no "GUI: brak zakładki Pool (M7c)"
  grep -q 'T_MSG' "$REPO_ROOT/net/frame.py" \
    && grep -q '_accept_msg' "$REPO_ROOT/net/fenix_node.py" \
    && grep -q 'MsgIpcTransport' "$REPO_ROOT/gui/backend_ipc.py" \
    && ok "T_MSG M4-mesh: typ ramki + relay w node + transport IPC (czat po sieci)" \
    || no "T_MSG M4-mesh: brak ogniwa (frame/node/ipc) — czat zostałby lokalny"

  say "SELFTEST: $((n-bad))/$n OK"
  if (( bad == 0 )); then say "SELFTEST: PASS ✅"; return 0; else say "SELFTEST: FAIL ❌ ($bad)"; return 1; fi
}

# =====================================================================
# build: wlasciwa budowa (wymaga roota + live-build)
# =====================================================================
build() {
  (( EUID == 0 )) || fail "budowa ISO wymaga roota (sudo ./os/build_iso.sh)"
  local missing=()
  for tool in lb xorriso mksquashfs debootstrap git rsync; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  (( ${#missing[@]} == 0 )) || fail "brak narzedzi: ${missing[*]} → sudo apt install live-build xorriso squashfs-tools debootstrap rsync git"

  selftest   # nigdy bez zielonego selftestu (fail-loud)

  local work="$REPO_ROOT/build/live-build.$$"
  local dist="$REPO_ROOT/dist"
  local commit; commit=$(git -C "$REPO_ROOT" rev-parse --short HEAD)
  say "staging → $work (commit $commit, profil $PROFILE)"
  mkdir -p "$work" "$dist"

  # 1) czysta kopia konfiguracji live-build
  rsync -a "$REPO_ROOT/os/live-build/" "$work/"

  # 2) staging repo Fenixa (to, co hook 0200 skopiuje na obraz)
  #    SEALED (FENIX_PAYLOAD_KEY ustawiony): katalogi kodu NIE wchodzą jawnie —
  #    są wyłącznie w payload.enc; os/ + requirements zostają (to loader/odblokowywacz).
  mkdir -p "$work/config/includes.chroot/opt/fenix-repo-stage"
  local STAGE_DIRS="os requirements.txt README.md TODO.md"
  if [[ -z "${FENIX_PAYLOAD_KEY:-}" ]]; then
    STAGE_DIRS="core net transport chain app gui crypto os requirements.txt README.md TODO.md"
  fi
  git -C "$REPO_ROOT" archive HEAD $STAGE_DIRS 2>/dev/null \
    | tar -x -C "$work/config/includes.chroot/opt/fenix-repo-stage/" \
    || fail "git archive staging (czy katalogi M2+ istnieja? utworz puste: mkdir -p net transport app gui)"

  # 3) nasze includes (nftables, uslugi, seeds, netup)
  rsync -a "$REPO_ROOT/os/includes.chroot/" "$work/config/includes.chroot/"
  chmod +x "$work"/config/hooks/live/*.hook.chroot
  chmod +x "$work"/config/includes.chroot/usr/local/bin/* 2>/dev/null || true

  # 3b) ZAPIECZĘTOWANY ŁADUNEK kodu (boot_security §3): payload.enc + manifest.
  #     Tryby: FENIX_PAYLOAD_KEY=hex64 → produkcyjnie-zaszyfrowany (klucz z ENV,
  #     NIGDY nie na ISO); brak → DEV jawny payload DEV (gated ENV przy boot).
  say "pakowanie ładunku kodu (fenix_payload.py)…"
  if [[ -n "${FENIX_PAYLOAD_KEY:-}" ]]; then
    python3 "$REPO_ROOT/os/fenix_payload.py" build --root "$REPO_ROOT" \
        --out "$work/config/includes.chroot/opt/fenix-payload.enc" \
        --commit "$commit" \
        ${FENIX_BUILD_KEY:+--build-key "$FENIX_BUILD_KEY"} \
      || fail "build ładunku zaszyfrowanego"
    say "ładunek: ZASZYFROWANY — klucz NIE wchodzi na ISO (dzielisz Shamirem miedzy seedy)"
  else
    python3 "$REPO_ROOT/os/fenix_payload.py" build-dev --root "$REPO_ROOT" \
        --out "$work/config/includes.chroot/opt/fenix-payload.dev" \
        --commit "$commit" || fail "build ładunku DEV"
    say "ładunek: DEV (jawny, gated ENV przy boot — GUI pokaze 'DEV BUILD')"
  fi

  # 4) budowa
  say "lb build (~30–60 min, idz sie przejsc)"
  pushd "$work" >/dev/null
  FENIX_PROFILE="$PROFILE" lb config
  lb build
  popd >/dev/null

  # 5) artefakt + hash
  local date; date=$(date +%Y%m%d)
  local iso="fenix-os-$date-$commit-$PROFILE.iso"
  mv "$work/live-image-amd64.hybrid.iso" "$dist/$iso" 2>/dev/null \
    || mv "$work/binary/live-image-amd64.hybrid.iso" "$dist/$iso"
  (cd "$dist" && sha256sum "$iso" > "$iso.sha256")
  say "ARTEFAKT: dist/$iso"
  say "SHA256:   dist/$iso.sha256 → $(cut -d' ' -f1 "$dist/$iso.sha256")"

  cat <<EOF

[build_iso] CONSTRUKTOR SKONCZONY. Teraz kolejnosc D14/QA:
 1. QA w VM: boot UEFI + Legacy, leak test Wireshark, amnezja, panika (iso_plan §E)
 2. PODPIS OFFLINE: zabierz dist/$iso na zimna maszyne z kluczem ownera:
      gpg --detach-sign --armor dist/$iso   → dist/$iso.asc
 3. Weryfikujesz jak uzytkownik: ./os/verify_iso.sh dist/$iso
 4. Publikujesz: .iso + .sha256 + .asc (M9, strona z sieci FNX)
EOF
}

if (( DO_SELFTEST )); then selftest; else build; fi
