#!/usr/bin/env python3
# os/fenix_panicd.py — demon PANIKI: Del+PageUp ≥2 s ⇒ usuń wszystko (D27)
"""
WYZWALACZ (decyzja właściciela D27): klawisze DEL i PAGEUP trzymane RAZEM
co najmniej 2 sekundy. Działa na bare-metal, laptopie i pod ISO — czyta
bezpośrednio z /dev/input/event* (evdev), więc nie zależy od X11/Waylanda.

SEKWENCJA PANIKI („usuwa wszystko"):
  1. crypto-shred każdego kontenera persistencji D24 (keystore.ks1):
     2× nadpis (losowe + zera) + fsync + usunięcie pliku,
  2. zabicie procesów Fenixa (MAT klucze trzymane w RAM procesu/node),
  3. sync + drop_caches (wymiata resztki z buforów RAM),
  4. natychmiastowy poweroff (sysrq s,u,o;  fallback: poweroff --force).
Live-system i tak żyje w tmpfs — odcięcie prądu zabija RAM fizycznie.

TRYB TESTOWY: --dry wykonuje wszystko PRÓČZ realnego shred/poweroff,
a selftest (ten plik, `python3 os/fenix_panicd.py`) nie wymaga roota
ani /dev/input — strumień zdarzeń jest wstrzykiwany (EventSource).

Uwaga D9: NIEODWRACALNE. Brak kosza, brak backupu, brak „czy na pewno?".
Próg celowości = DWA klawisze jednocześnie przez 2 s — to jak dwa klucze
w sejfie: przypadek nie naciska dwóch naraz i nie trzyma ich 2 sekund.
"""
from __future__ import annotations

import argparse
import glob
import os
import select
import struct
import sys
import time
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

# ------------------------------------------------------------------ stałe
EV_KEY = 0x01
KEY_DELETE = 111
KEY_PAGEUP = 104
HOLD_S = 2.0                    # decyzja D27: dwa klawisze razem ≥ 2 s
PRESS, RELEASE, REPEAT = 1, 0, 2

# linuksowy struct input_event na 64-bit: timeval(16) + type(2) + code(2) + value(4)
_INPUT_EVENT = struct.Struct("llHHi")
assert _INPUT_EVENT.size == 24

PANIC_KEYS = (KEY_DELETE, KEY_PAGEUP)
KEYSTORE_GLOB = "/home/*/.fenix/keystore.ks1"     # kontener D24 (jeden na usera)
NODE_PROCS = ("fenix-node", "fenix_node")          # do pobicia przez kill -TERM
SYSRQ = "/proc/sysrq-trigger"
DROP_CACHES = "/proc/sys/vm/drop_caches"


# ------------------------------------------------------------------ maszyna stanu
class PanicCombo:
    """Czysta maszyna stanu (bez IO — w 100% testowalna).

    Zasada: oba klawisze w dół ⇒ licznik startuje; którykolwiek w górę
    ⇒ reset. Autorepeat (value=2) NIE resetuje ani nie skraca trzymania.
    """

    def __init__(self, keys=PANIC_KEYS, hold_s: float = HOLD_S):
        self.keys = frozenset(keys)
        self.hold_s = hold_s
        self._down: set[int] = set()
        self._since: float | None = None

    def feed(self, ev_type: int, code: int, value: int, now: float) -> bool:
        """Zwraca True w momencie, gdy combo jest trzymane ≥ hold_s (raz!)."""
        if ev_type != EV_KEY or code not in self.keys:
            return False
        if value == PRESS:
            self._down.add(code)
        elif value == RELEASE:
            self._down.discard(code)
            self._since = None            # puszczenie cegokolwiek = reset
            return False
        # REPEAT: klawisz dalej w dole — nic nie zmienia
        return self.check_timeout(now)

    def check_timeout(self, now: float) -> bool:
        """Wywoływane też na timeout read() — nie każda klawiatura autorepeat'uje,
        a panika nie może czekać na kolejny event (np. trzymasz i nic nie wciskasz)."""
        if self._down == self.keys:
            if self._since is None:
                self._since = now
            elif now - self._since >= self.hold_s:
                self._down.clear()        # jednorazowo; potem combo od nowa
                self._since = None
                return True
        return False


# ------------------------------------------------------------------ źródła zdarzeń
class EventSource:
    """Interfejs: read() → (type, code, value) albo None (timeout)."""

    def read(self, timeout: float):
        raise NotImplementedError

    def close(self):
        pass


class EvdevSource(EventSource):
    """Czyta WSZYSTKIE klawiatury z /dev/input (root), reskan co 5 s (hotplug USB)."""

    def __init__(self, pattern: str = "/dev/input/event*"):
        self.pattern = pattern
        self._fds: dict[int, str] = {}
        self._rescan_at = 0.0

    def _rescan(self, now: float):
        if now < self._rescan_at:
            return
        self._rescan_at = now + 5.0
        want = set(glob.glob(self.pattern))
        have = set(self._fds.values())
        for path in want - have:
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
                self._fds[fd] = path
            except OSError:
                pass                        # brak uprawnień/urządzenie znikło
        for fd, path in list(self._fds.items()):
            if path not in want:
                self._close_fd(fd)

    def _close_fd(self, fd: int):
        try:
            os.close(fd)
        except OSError:
            pass
        self._fds.pop(fd, None)

    def read(self, timeout: float):
        self._rescan(time.time())
        if not self._fds:
            time.sleep(timeout)
            return None
        r, _, _ = select.select(list(self._fds), [], [], timeout)
        for fd in r:
            try:
                data = os.read(fd, _INPUT_EVENT.size)
            except OSError:
                data = b""
            if len(data) != _INPUT_EVENT.size:
                self._close_fd(fd)          # urządzenie odpięte / EOF
                continue
            _sec, _usec, typ, code, value = _INPUT_EVENT.unpack(data)
            return (typ, code, value)
        return None

    def close(self):
        for fd in list(self._fds):
            self._close_fd(fd)


class FakeSource(EventSource):
    """Kolejka zdarzeń do selftestu — identyczny interfejs jak evdev."""

    def __init__(self, events=()):
        self.events = list(events)

    def push(self, typ, code, value):
        self.events.append((typ, code, value))

    def read(self, timeout: float):
        if self.events:
            return self.events.pop(0)
        return None


# ------------------------------------------------------------------ sekwencja paniki
def _shred_file(path: str) -> bool:
    """2× nadpis (losowe + zera) + fsync + usunięcie. Ten sam algorytm co
    core/keystore.py::panic — jeden wzorzec shred dla całego projektu."""
    try:
        size = os.path.getsize(path)
        for payload in (os.urandom, lambda n: b"\x00" * n):
            with open(path, "r+b", buffering=0) as f:
                left = size
                while left > 0:
                    chunk = payload(min(left, 1 << 20))
                    f.write(chunk)
                    left -= len(chunk)
                f.flush()
                os.fsync(f.fileno())
        os.remove(path)
        # fsync katalogu, żeby usunięcie też było trwałe
        dfd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        return True
    except OSError:
        return False


def run_panic_sequence(keystore_glob: str = KEYSTORE_GLOB, dry: bool = False,
                       log=print) -> dict:
    """Kroki 1–4. dry=True: raportuje co BY zrobiła (wisienka na GUI-testy)."""
    report = {"shredded": [], "killed": 0, "poweroff": False, "dry": dry}

    # 1) crypto-shred kontenerów D24
    targets = sorted(glob.glob(keystore_glob))
    for path in targets:
        if dry:
            log(f"  [PANIC-dry] shred pominięty: {path}")
            report["shredded"].append(path)
        elif _shred_file(path):
            log(f"  [PANIC] shred OK: {path}")
            report["shredded"].append(path)
        else:
            log(f"  [PANIC] UWAGA: shred NIEUDANY: {path}")

    # 2) stop procesów noda (klucze sesyjne giną z RAM procesu)
    if not dry:
        import subprocess
        for name in NODE_PROCS:
            r = subprocess.run(["pkill", "-TERM", "-f", name],
                               capture_output=True)
            if r.returncode == 0:
                report["killed"] += 1

    # 3) sync + drop_caches (wymiatanie buforów)
    if not dry:
        try:
            os.sync()
            with open(DROP_CACHES, "w") as f:
                f.write("3\n")
        except OSError:
            pass

    # 4) poweroff (sysrq: sync → remount-ro → off; fallback: systemctl)
    if not dry:
        try:
            with open("/proc/sys/kernel/sysrq", "w") as f:
                f.write("1\n")
            for cmd in ("s", "u", "o"):
                with open(SYSRQ, "w") as f:
                    f.write(cmd + "\n")
                time.sleep(0.5)
        except OSError:
            import subprocess
            subprocess.run(["systemctl", "poweroff", "--force", "--force"],
                           capture_output=True)
    report["poweroff"] = not dry
    return report


# ------------------------------------------------------------------ pętla demona
def panicd_loop(source: EventSource, combo: PanicCombo,
                keystore_glob: str = KEYSTORE_GLOB, dry: bool = False,
                log=print, max_panics: int = 1, clock=time.monotonic) -> int:
    """Czyta zdarzenia i przy combo uruchamia sekwencję. Zwraca liczbę panik.
    clock wstrzykiwany dla testów; na timeout też sprawdzamy combo (check_timeout)."""
    panics = 0
    while max_panics <= 0 or panics < max_panics:
        ev = source.read(timeout=0.2)
        fired = (combo.feed(ev[0], ev[1], ev[2], now=clock()) if ev is not None
                 else combo.check_timeout(clock()))
        if fired:
            panics += 1
            log("  [PANIC] Del+PageUp ≥2s — URUCHAMIAM SEKWENCJĘ PANIKI")
            run_panic_sequence(keystore_glob, dry=dry, log=log)
    return panics


# ------------------------------------------------------------------ CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="fenix-panicd",
        description="Demon paniki Fenixa: Del+PageUp 2 s ⇒ usuwa wszystko (D27)")
    ap.add_argument("--pattern", default="/dev/input/event*",
                    help="glob urządzeń evdev")
    ap.add_argument("--hold", type=float, default=HOLD_S,
                    help="sekundy trzymania obu klawiszy (domyślnie 2.0)")
    ap.add_argument("--keystore-glob", default=KEYSTORE_GLOB,
                    help="glob kontenerów D24 do shredu")
    ap.add_argument("--dry", action="store_true",
                    help="pełna logika, zero niszczenia (bezpieczny test na żywym systemie)")
    args = ap.parse_args(argv)

    if os.geteuid() != 0 and not args.dry:
        print("fenix-panicd: wymaga roota (czyta /dev/input). "
              "Do testu bez roota: --dry + selftest modułu.", file=sys.stderr)
        return 2

    combo = PanicCombo(hold_s=args.hold)
    src = EvdevSource(args.pattern)
    print(f"fenix-panicd: czuwam nad {args.pattern} "
          f"(Del+PageUp ≥{args.hold:.1f}s){' — TRYB DRY' if args.dry else ''}")
    try:
        panicd_loop(src, combo, keystore_glob=args.keystore_glob, dry=args.dry,
                    max_panics=0)          # 0 = wiecznie (systemd Restart=always i tak pilnuje)
    except KeyboardInterrupt:
        print("fenix-panicd: stop (Ctrl+C — to NIE jest panika)")
    finally:
        src.close()
    return 0


# ------------------------------------------------------------------ selftest
if __name__ == "__main__":
    print("os/fenix_panicd.py — selftest: combo 2 s, shred, sekwencja (bez /dev/input)\n")

    # 1) combo: oba klawisze ≥2 s → PANIKA
    c = PanicCombo(hold_s=2.0)
    t = 1000.0
    assert not c.feed(EV_KEY, KEY_DELETE, PRESS, now=t)
    assert not c.feed(EV_KEY, KEY_PAGEUP, PRESS, now=t + 0.1)
    assert not c.feed(EV_KEY, KEY_DELETE, REPEAT, now=t + 1.0), "autorepeat nie trigeruje"
    assert not c.feed(EV_KEY, KEY_PAGEUP, REPEAT, now=t + 1.9), "1.8 s od pary — czekaj"
    assert not c.feed(EV_KEY, KEY_DELETE, REPEAT, now=t + 2.05), "1.95 s — wciąż czekaj"
    assert c.feed(EV_KEY, KEY_DELETE, REPEAT, now=t + 2.15), "2.05 s od pary → PANIKA"
    print("  [OK] 1. Del+PageUp trzymane 2.05 s→PANIKA (licznik od 2. klawisza: precyzyjnie)")

    # 2) puszczenie jednego klawisza resetuje licznik
    c2 = PanicCombo(hold_s=2.0)
    assert not c2.feed(EV_KEY, KEY_DELETE, PRESS, now=0.0)
    assert not c2.feed(EV_KEY, KEY_PAGEUP, PRESS, now=0.1)
    assert not c2.feed(EV_KEY, KEY_PAGEUP, RELEASE, now=1.9), "reset na release"
    assert not c2.feed(EV_KEY, KEY_PAGEUP, PRESS, now=1.95)
    assert not c2.feed(EV_KEY, KEY_PAGEUP, REPEAT, now=3.9), "od nowa: dopiero 1.95 s"
    assert c2.feed(EV_KEY, KEY_PAGEUP, REPEAT, now=4.0), "sumaryczne 2.05 s od nowego startu"
    print("  [OK] 2. release resetuje licznik (przypadek ≠ panika)")

    # 3) jeden klawisz sam przez 10 s + inne klawisze → NIC
    c3 = PanicCombo(hold_s=2.0)
    assert not c3.feed(EV_KEY, KEY_DELETE, PRESS, now=0.0)
    for i in range(1, 11):
        assert not c3.feed(EV_KEY, KEY_DELETE, REPEAT, now=float(i))
        assert not c3.feed(EV_KEY, 28, PRESS, now=float(i)), "Enter nie ma znaczenia"
        assert not c3.feed(EV_KEY, 28, RELEASE, now=float(i))
    print("  [OK] 3. sam Del przez 10 s → brak paniki; obce klawisze olewane")

    # 4) end-to-end: FakeSource → pętla → sekwencja w trybie DRY (zero zniszczenia)
    src = FakeSource()
    src.push(EV_KEY, KEY_DELETE, PRESS)
    src.push(EV_KEY, KEY_PAGEUP, PRESS)               # dalej ANI jeden event:
    c4 = PanicCombo(hold_s=0.5)                       # panika na samych timeoutach
    clock = {"now": 1000.0}                           # (klawiatura może nie autorepeat'ować)
    logs: list[str] = []
    n = panicd_loop(src, c4, dry=True, log=logs.append, max_panics=1,
                    clock=lambda: clock.__setitem__("now", clock["now"] + 0.2)
                    or clock["now"])
    assert n == 1, "pętla musi odpracować dokładnie 1 panikę (timeouty!)"
    assert any("PANIC" in l for l in logs)
    print(f"  [OK] 4. FakeSource→pętla→sekwencja(dry): panika na samych timeoutach, "
          f"log: {logs[0][:44]}…")

    # 5) shred NA PRAWDĘ na pliku temp: plik znika, katalog spójny
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="fenix-panic-test-")
    victim = os.path.join(tmpdir, "keystore.ks1")
    secret = os.urandom(4096)
    with open(victim, "wb") as f:
        f.write(secret)
    rep = run_panic_sequence(os.path.join(tmpdir, "*.ks1"), dry=True,
                             log=lambda *_: None)
    assert os.path.exists(victim), "dry NIE wolno niczego ruszać!"
    assert rep["shredded"] == [victim] and rep["dry"] is True
    ok = _shred_file(victim)
    assert ok and not os.path.exists(victim), "shred musi skasować plik"
    os.rmdir(tmpdir)
    print("  [OK] 5. shred: dry nic nie rusza; real shred → plik znika (2×nadpis+fsync+rm)")

    print("\nSELFTEST: PASS ✅  Del+PageUp 2 s = panika; reszta świata = bezpieczna")
