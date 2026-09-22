#!/usr/bin/env python3
# tools/pack_dropin.py — paczka „do dodania": całe drzewo, z bitami +x.
"""Buduje dist/FenixOS-do-dodania.zip.

Zip z Windows gubi tryb unixa (external_attr = 0) i po unzip skrypty ISO są
0644 — `build_iso.sh --selftest` pada na fenix-gui. Ten skrypt zapisuje
create_system=Unix i tryb w górnych 16 bitach, a skryptom z listy wymusza
0755 nawet gdy drzewo robocze je zgubiło.

Nie pakuje: .git, __pycache__, *.pyc, *.so (akcelerator buduje się przy
imporcie), dist/, egg-info, wirtualnych środowisk.
"""
from __future__ import annotations

import os
import stat
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "dist" / "FenixOS-do-dodania.zip"

# Ścieżki względem korzenia, które MUSZĄ być wykonywalne w paczce.
EXEC = {
    "os/spoof.sh",
    "os/build_iso.sh",
    "os/verify_iso.sh",
    "os/live-build/auto/config",
    "os/live-build/config/hooks/live/0100-fenix-hardening.hook.chroot",
    "os/live-build/config/hooks/live/0200-fenix-install.hook.chroot",
    "os/includes.chroot/usr/local/bin/fenix-gui",
    "os/includes.chroot/usr/local/bin/fenix-netup",
    "os/includes.chroot/usr/local/bin/fenix-vpn",
    "tools/ensure_exec_bits.sh",
    "tools/pack_dropin.py",
}

SKIP_DIR = {".git", "__pycache__", ".venv", "venv", "dist", "build", ".egg-info"}
SKIP_SUFFIX = {".pyc", ".pyo", ".so"}


def _skip(rel: Path) -> bool:
    if any(p in SKIP_DIR or p.endswith(".egg-info") for p in rel.parts):
        return True
    if rel.suffix in SKIP_SUFFIX:
        return True
    if rel.name.startswith("libfnx64accel"):
        return True
    return False


def _mode(rel: str, st: os.stat_result) -> int:
    if rel in EXEC or rel.endswith(".sh") or rel.endswith(".hook.chroot"):
        return 0o755
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o111:
        return mode
    return 0o644


def build(dest: Path = OUT) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".zip.tmp")
    n = 0
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIR and not d.endswith(".egg-info")]
            for name in filenames:
                full = Path(dirpath) / name
                rel = full.relative_to(ROOT)
                if _skip(rel):
                    continue
                rel_s = rel.as_posix()
                st = full.stat()
                mode = _mode(rel_s, st)
                info = zipfile.ZipInfo(rel_s)
                info.create_system = 3  # Unix — unzip honoruje external_attr
                info.external_attr = (stat.S_IFREG | mode) << 16
                info.date_time = time_tuple(st.st_mtime)
                info.compress_type = zipfile.ZIP_DEFLATED
                with full.open("rb") as fh:
                    zf.writestr(info, fh.read())
                n += 1
    os.replace(tmp, dest)
    _verify(dest)
    print(f"pack_dropin: {n} plików → {dest} ({dest.stat().st_size} B)")
    return dest


def time_tuple(mtime: float) -> tuple:
    import time
    t = time.localtime(mtime)
    return (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)


def _verify(dest: Path) -> None:
    with zipfile.ZipFile(dest) as zf:
        names = set(zf.namelist())
        missing = [p for p in EXEC if p not in names]
        if missing:
            raise SystemExit(f"paczka bez wymaganych skryptów: {missing}")
        for p in EXEC:
            mode = (zf.getinfo(p).external_attr >> 16) & 0o777
            if mode & 0o111 == 0:
                raise SystemExit(f"{p} w zipie nie jest wykonywalny (mode {mode:o})")
        if zf.getinfo("os/includes.chroot/usr/local/bin/fenix-gui").create_system != 3:
            raise SystemExit("zip nie jest oznaczony jako Unix — bity +x znowu zginą")
    print("pack_dropin: weryfikacja +x OK (fenix-gui i haki live-build)")


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else OUT
    build(out)
