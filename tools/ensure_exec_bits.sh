#!/bin/bash
# tools/ensure_exec_bits.sh — przywraca +x skryptom, które zip bez unix-mode gubi.
# Zip z Windows/MS-DOS zapisuje tryb 0; unzip zostawia 0644 i build_iso --selftest
# pada na fenix-gui (-x). Wołaj po rozpakowaniu, zanim odpalisz selftest ISO.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
chmod 755 \
  "$ROOT/os/spoof.sh" \
  "$ROOT/os/build_iso.sh" \
  "$ROOT/os/verify_iso.sh" \
  "$ROOT/os/live-build/auto/config" \
  "$ROOT/os/live-build/config/hooks/live/0100-fenix-hardening.hook.chroot" \
  "$ROOT/os/live-build/config/hooks/live/0200-fenix-install.hook.chroot" \
  "$ROOT/os/includes.chroot/usr/local/bin/fenix-gui" \
  "$ROOT/os/includes.chroot/usr/local/bin/fenix-netup" \
  "$ROOT/os/includes.chroot/usr/local/bin/fenix-vpn" \
  "$ROOT/tools/ensure_exec_bits.sh" \
  "$ROOT/tools/pack_dropin.py"
echo "ensure_exec_bits: +x na skryptach os/ i tools/ (launcher GUI włącznie)"
