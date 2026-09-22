# gui/panic_button.py — wielki czerwony PANIC (D27) + „czysty ekran” + vpn.env (M7b)
"""
Trzy rzeczy dla GUI, każda z logiką headless-testowalną (jak reszta projektu):

  PanicHold — CZYSTA maszyna stanu „trzymaj przycisk 2 s” (analogia: jak dwa
      klucze w sejfie, ale jednym palcem). Zero Tkintera — goni go selftest.
      Próg 2 s = identyczny jak klawiszowy Del+PageUp (D27): przypadek
      NIE trzyma przycisku 2 sekund.
  PanicController — (1) „czysty ekran”: wywołuje hooki czyszczące widok
      (kurtyna, NIE pożar — sesja żyje, można wrócić klikiem w menu);
      (2) hard-PANIC: uruchamia DOKŁADNIE tę samą sekwencję co os/fenix_panicd
      (shred kontenerów D24 → kill procesów → drop_caches → poweroff).
      os/ NIE jest pakietem Pythona, więc ładujemy fenix_panicd.py po ścieżce
      (importlib) — test to sprawdza. Panika jest IDEMPOTENTNA (drugie
      wywołanie nie powtarza niszczenia) i ma ubeczkę FENIX_PANIC_DRY=1,
      która wymusza tryb dry (raportuje „co BY zrobiła”, zero zniszczenia)
      — dzięki temu NIKT przez pomyłkę nie odpali prawdziwej paniki w testach.
  vpn.env (M7b) — zapis konta Mullvad (16 cyfr) do /run/fenix/vpn.env
      (tmpfs = RAM, nie dysk!), tryb 0600, atomowy rename; + forget = shred
      2× nadpis (ten sam wzorzec co core/keystore.py i os/fenix_panicd.py).
      fenix-vpn.service wystartuje dopiero, gdy ten plik istnieje (opt-in D29).

WIDOK: PanicBar na dole sidebara FenixApp — wielki czerwony przycisk
(press-and-hold 2 s, pasek postępu), pod nim „Wyczyść ekran (Shift+Esc)”.
Tworzyć TYLKO pod DISPLAY (selftest headless omija widok, uczciwy SKIP).
"""
from __future__ import annotations

import importlib.util as _ilu
import os
import sys
import time
import pathlib as _pl
from dataclasses import dataclass, field
from typing import Callable

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

REPO_ROOT = _pl.Path(__file__).resolve().parents[1]
PANICD_PATH = REPO_ROOT / "os" / "fenix_panicd.py"

HOLD_S = 2.0                    # D27: 2 s trzymania — przypadek ≠ panika
VPN_DIR = "/run/fenix"          # tmpfs (RAM!) na ISO; katalog stawia tmpfiles.d
VPN_ENV_NAME = "vpn.env"
ACCOUNT_DIGITS = 16             # konto Mullvad = 16 cyfr (gotówka/XMR, nie email)

# kolory paska paniki — LOKALNA kopia motywu (gui.fenix_gui importuje TEN moduł,
# więc my NIE możemy importować gui.fenix_gui — unikamy cyklu)
C_PANIC = "#c0392b"
C_PANIC_HI = "#e74c3c"
C_BG = "#0e1116"
C_CARD2 = "#1d222b"


class PanicButtonError(Exception):
    """Błędy tego modułu — jeden typ (łapiemy bez zgadywania)."""


# -------------------------------------------------------------------------- hold-to-arm
class PanicHold:
    """Czysta maszyna stanu „hold 2 s”. Interfejs jak PanicCombo z panicd,
    ale dla JEDNEGO przycisku (myśz/touchpad), nie pary klawiszy."""

    def __init__(self, hold_s: float = HOLD_S):
        self.hold_s = hold_s
        self._down = False
        self._since: float | None = None

    def feed_down(self, now: float) -> None:
        """Wciśnięcie. Odbity styk (drugi press bez release) NIE restartuje licznika."""
        if not self._down:
            self._down = True
            self._since = now

    def feed_up(self) -> None:
        """Puszczenie — pełny rozbrojenie."""
        self._down = False
        self._since = None

    def progress(self, now: float) -> float:
        """0.0..1.0 — do paska postępu w widoku."""
        if not self._down or self._since is None:
            return 0.0
        return max(0.0, min(1.0, (now - self._since) / self.hold_s))

    def check(self, now: float) -> bool:
        """True JEDEN raz na przytrzymanie (potem reset: trzeba puścić i wcisnąć znowu)."""
        if self._down and self._since is not None and now - self._since >= self.hold_s:
            self.feed_up()
            return True
        return False


# -------------------------------------------------------------------------- loader panicd
_panicd_cache = None


def _load_panicd():
    """os/fenix_panicd.py po ŚCIEŻCE (os/ to katalog obrazu ISO, nie pakiet Pythona;
    `import os.fenix_panicd` i tak wylądowałby we wbudowanym module `os`!)."""
    global _panicd_cache
    if _panicd_cache is not None:
        return _panicd_cache
    if not PANICD_PATH.exists():
        raise PanicButtonError(f"brak {PANICD_PATH} — sekwencja paniki niedostępna")
    spec = _ilu.spec_from_file_location("fenix_panicd_loaded", PANICD_PATH)
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)          # selftest panicd jest pod __main__ → nie odpala
    _panicd_cache = mod
    return mod


def _env_dry() -> bool:
    return os.environ.get("FENIX_PANIC_DRY", "").lower() in ("1", "true", "yes")


# -------------------------------------------------------------------------- kontroler
@dataclass
class PanicController:
    """clean_hooks: callable() czyszczące widok (GUI podpina _clean_screen).
    sequence_fn: wstrzykiwalna sekwencja paniki (testy); None → prawdziwa z panicd."""
    clean_hooks: list[Callable[[], None]] = field(default_factory=list)
    keystore_glob: str | None = None      # None → domyślny glob D24 z os/fenix_panicd
    sequence_fn: Callable | None = None
    log: Callable[[str], None] = print
    _fired_report: dict | None = field(default=None, init=False, repr=False)

    def clean_screen(self) -> int:
        """„Czysty ekran” — kurtyna, NIE pożar. Zwraca liczbę odpracowanych hooków.
        Padnięty hook NIE zatrzymuje pozostałych (panika nie może wybuchnąć od błędu UI)."""
        done = 0
        for hook in self.clean_hooks:
            try:
                hook()
                done += 1
            except Exception as e:  # noqa: BLE001 — celowo łapiemy wszystko
                self.log(f"  [panic] hook czystego ekranu padł: {e}")
        return done

    def panic(self, dry: bool | None = None) -> dict:
        """PEŁNA PANIKA (D27) — ten sam kod sekwencji co klawiatura Del+PageUp.
        Idempotentna: drugie i kolejne wywołania zwracają raport z _already=True
        i NIE powtarzają niszczenia. FENIX_PANIC_DRY=1 ZAWSZE wygrywa (nawet
        gdy ktoś jawnie prosi o real) — ubeczka na testy/CI."""
        if self._fired_report is not None:
            rep = dict(self._fired_report)
            rep["_already"] = True
            return rep
        if _env_dry():
            dry = True
        elif dry is None:
            dry = False
        if self.sequence_fn is not None:
            report = self.sequence_fn(dry=dry)
        else:
            panicd = _load_panicd()
            kw = {"dry": dry, "log": self.log}
            if self.keystore_glob:
                kw["keystore_glob"] = self.keystore_glob
            report = panicd.run_panic_sequence(**kw)
        self._fired_report = dict(report)
        return report


# -------------------------------------------------------------------------- vpn.env (M7b)
def validate_account(account: str) -> tuple[bool, str]:
    """Konto Mullvad = 16 cyfr (spacje/taby dozwolone dla czytelności)."""
    squeezed = "".join(account.split())
    if not squeezed:
        return False, "pusty numer konta"
    if not squeezed.isdigit():
        return False, "numer konta = same cyfry (spacje dozwolone grupująco)"
    if len(squeezed) != ACCOUNT_DIGITS:
        return False, f"konto Mullvad ma {ACCOUNT_DIGITS} cyfr, a nie {len(squeezed)}"
    return True, squeezed


def write_vpn_env(account: str, dir: str = VPN_DIR, country: str = "pl",
                  hostname: str | None = None) -> str:
    """Zapisuje /run/fenix/vpn.env (0600) ATOMOWO (tmp+rename).
    OSError (brak prawa do /run/fenix) leci do wywołującego — GUI pokaże komunikat."""
    ok, res = validate_account(account)
    if not ok:
        raise PanicButtonError(res)
    d = _pl.Path(dir)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass                          # np. katalog stworzony przez roota (tmpfiles) — OK
    lines = [f"FENIX_MULLVAD_ACCOUNT={res}", f"FENIX_VPN_COUNTRY={country}"]
    if hostname:
        lines.append(f"FENIX_VPN_HOST={hostname}")
    target = d / VPN_ENV_NAME
    tmp = d / (VPN_ENV_NAME + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp), str(target))   # atomowo: nigdy nie ma pół-pliku
    os.chmod(str(target), 0o600)
    return str(target)


def shred_file(path: str) -> bool:
    """2× nadpis (losowe + zera) + fsync + usunięcie — TEN SAM wzorzec co
    core/keystore.py::panic i os/fenix_panicd::_shred_file. Plik 0-bajtowy: samo rm."""
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
        return True
    except OSError:
        return False


def forget_vpn_env(dir: str = VPN_DIR) -> bool:
    """Shred vpn.env. True = zniszczony; False = nie istniał LUB brak uprawnień
    (GUI pokaże wówczas „nic do zapomnienia / brak uprawnień”)."""
    p = _pl.Path(dir) / VPN_ENV_NAME
    if not p.exists():
        return False
    return shred_file(str(p))


# -------------------------------------------------------------------------- WIDOK (leniwy)
class PanicBar:
    """Pasek paniki w sidebarze FenixApp. Tworzyć TYLKO pod DISPLAY.
    Nie importuje fenix_gui — dostaje `app` (duck-typing: app.tk/ttk/sidebar/root/_job)."""

    TICK_MS = 50                        # odświeżanie paska postępu

    def __init__(self, app):
        self.app = app
        tk, ttk = app.tk, app.ttk
        self.hold = PanicHold()
        self._after_id = None
        bar = ttk.Frame(app.sidebar, style="TFrame")
        bar.pack(side="bottom", fill="x", padx=10, pady=(8, 14))
        self.canvas = tk.Canvas(bar, height=6, bg=C_CARD2, highlightthickness=0, bd=0)
        self.canvas.pack(fill="x", pady=(0, 4))
        self.button = tk.Button(
            bar, text="⚠ PANIC — trzymaj 2 s", font=("DejaVu Sans", 11, "bold"),
            bg=C_PANIC, fg="#ffffff", activebackground=C_PANIC_HI,
            activeforeground="#ffffff", relief="flat", bd=0, cursor="hand2",
            padx=6, pady=8)
        self.button.pack(fill="x")
        self.button.bind("<ButtonPress-1>", self._press)
        self.button.bind("<ButtonRelease-1>", self._release)
        ttk.Button(bar, text="Wyczyść ekran (Shift+Esc)",
                   command=app._clean_screen).pack(fill="x", pady=(6, 0))
        ttk.Label(bar, text="PANIC = shred D24 + poweroff (D27).\nCzysty ekran = kurtyna (odwracalna).",
                  style="Muted.TLabel", background=C_BG, justify="left",
                  font=("DejaVu Sans", 8), wraplength=145).pack(fill="x", pady=(6, 0))

    # ---------- hold-to-arm ----------
    def _press(self, _e=None):
        self.hold.feed_down(time.monotonic())
        self._tick()

    def _release(self, _e=None):
        self.hold.feed_up()
        self._paint(0.0)
        if self._after_id is not None:
            self.app.root.after_cancel(self._after_id)
            self._after_id = None

    def _tick(self):
        now = time.monotonic()
        if self.hold.check(now):
            self._fire()
            return
        self._paint(self.hold.progress(now))
        self._after_id = self.app.root.after(self.TICK_MS, self._tick)

    def _paint(self, frac: float):
        w = self.canvas.winfo_width() or 150
        self.canvas.delete("all")
        if frac > 0:
            self.canvas.create_rectangle(0, 0, int(w * frac), 6, fill=C_PANIC_HI, outline="")

    def _fire(self):
        """Zbrojenie zakończone → sekwencja w wątku roboczym (UI nie zamraża)."""
        self._paint(1.0)
        self.button.configure(text="PANIKA W TOKU…", state="disabled")
        self.app._job("panic", self.app._panic_ctl.panic, self.app._panic_done)


def build_panic_bar(app) -> PanicBar:
    """Montowany przez FenixApp._build_shell (tylko pod DISPLAY)."""
    return PanicBar(app)


# -------------------------------------------------------------------------- selftest (headless)
if __name__ == "__main__":
    import os as _os
    import stat as _stat
    import tempfile as _tf

    print("gui/panic_button.py — selftest headless: hold 2 s (D27), czysty ekran,\n"
          "sekwencja panicd po ścieżce, vpn.env 0600+atomowo, shred-forget\n")

    # 1) hold: press → < 2 s NIC; ≥ 2 s OGNIA RAZ; dalsze trzymanie = cisza
    h = PanicHold(hold_s=2.0)
    h.feed_down(now=1000.0)
    assert h.progress(1000.5) == 0.25 and abs(h.progress(1001.0) - 0.5) < 1e-9
    assert not h.check(1001.9), "1.9 s — jeszcze nie"
    assert h.check(1002.05), "2.05 s → PANIKA"
    assert not h.check(1002.5), "jedno przytrzymanie = JEDEN strzał (reset po ogniu)"
    assert h.progress(1003.0) == 0.0
    print("  [OK] 1. hold 2.05 s → OGIEN raz; dalsze trzymanie milczy; pasek postępu 0..1")

    # 2) release resetuje; odbity styk (drugi press bez release) NIE restartuje licznika
    h2 = PanicHold(hold_s=2.0)
    h2.feed_down(now=0.0)
    assert not h2.check(1.9)
    h2.feed_up()
    assert h2.progress(2.5) == 0.0 and not h2.check(5.0), "po puszczeniu: rozbrojony"
    h2.feed_down(now=10.0)
    h2.feed_down(now=11.0)                              # bounce — musi być zignorowany
    assert not h2.check(11.95), "1.95 s od pierwszego press — czekaj"
    assert h2.check(12.05), "licznik leciał od 10.0 (bounce nie restartował)"
    print("  [OK] 2. release rozbraja; odbicie przycisku nie restartuje licznika")

    # 3) czysty ekran: hooki lecą po kolei, padnięty hook nie zatrzymuje reszty
    calls: list[str] = []
    def _boom():
        raise RuntimeError("ui-glitch")
    logs: list[str] = []
    pc = PanicController(clean_hooks=[lambda: calls.append("a"), _boom,
                                      lambda: calls.append("c")], log=logs.append)
    assert pc.clean_screen() == 2 and calls == ["a", "c"] and len(logs) == 1
    print("  [OK] 3. czysty ekran: 2/3 hooków odpracowane, padnięty zalogowany (nie crash)")

    # 4) vpn.env: walidacja + zapis 0600 do tmp + atomowy rename + nadpis starego
    d = _tf.mkdtemp(prefix="fenix-vpnenv-")
    okv, digits = validate_account("1234 5678 9012 3456")
    assert okv and digits == "1234567890123456"
    for bad in ("12345", "12345678901234567", "abcd567890123456", ""):
        okb, why = validate_account(bad)
        assert not okb and why
    p = write_vpn_env("1234 5678 9012 3456", dir=d, country="nl", hostname="nl-ams-wg-001")
    body = open(p).read()
    assert "FENIX_MULLVAD_ACCOUNT=1234567890123456\n" in body
    assert "FENIX_VPN_COUNTRY=nl\n" in body and "FENIX_VPN_HOST=nl-ams-wg-001\n" in body
    assert _stat.S_IMODE(_os.stat(p).st_mode) == 0o600, "vpn.env musi być 0600"
    assert _stat.S_IMODE(_os.stat(d).st_mode) == 0o700, "katalog 0700"
    p2 = write_vpn_env("9999999999999999", dir=d)     # nadpisanie starego konta
    assert p2 == p and "9999999999999999" in open(p).read()
    assert not _os.path.exists(p + ".tmp"), "po rename nie ma pliku .tmp"
    print("  [OK] 4. vpn.env: 16 cyfr (spacje zmywane), 0600+0700, atomowy rename, nadpis OK")

    # 5) forget = shred (2× nadpis + rm); drugi raz → False (nic do zapomnienia)
    assert forget_vpn_env(dir=d) is True
    assert not _os.path.exists(p)
    assert forget_vpn_env(dir=d) is False
    _os.rmdir(d)
    print("  [OK] 5. forget_vpn_env: shred → plik znika; powtórka = False")

    # 6) panicd po ścieżce: os/ NIE jest pakietem, a loader i tak działa (dry!)
    try:
        import os.fenix_panicd  # noqa: F401 — to MUSI się wysypać (os to wbudowany moduł!)
        raise SystemExit("import os.fenix_panicd przeszedł?! sandbox się sypie")
    except (ImportError, ModuleNotFoundError):
        pass
    panicd = _load_panicd()
    assert hasattr(panicd, "run_panic_sequence") and panicd.__name__ == "fenix_panicd_loaded"
    d6 = _tf.mkdtemp(prefix="fenix-panictest-")
    victim = _os.path.join(d6, "keystore.ks1")
    open(victim, "wb").write(_os.urandom(2048))
    pc6 = PanicController(keystore_glob=_os.path.join(d6, "*.ks1"), log=lambda *_: None)
    rep = pc6.panic(dry=True)
    assert rep["dry"] is True and rep["shredded"] == [victim] and rep["poweroff"] is False
    assert _os.path.exists(victim), "dry NIE WOLNO niczego ruszać!"
    print("  [OK] 6. os/ nie-pakiet → loader po ścieżce OK; panic(dry) raportuje bez niszczenia")

    # 7) idempotencja + ubeczka FENIX_PANIC_DRY: dry wymuszone z env (nawet przy dry=False)
    seen: list[bool] = []
    spy = lambda dry: seen.append(dry) or {"shredded": [], "killed": 0, "poweroff": False, "dry": dry}
    pc7 = PanicController(sequence_fn=spy, log=lambda *_: None)
    r1 = pc7.panic(dry=True)
    r2 = pc7.panic(dry=True)
    assert len(seen) == 1 and r2.get("_already") is True, "druga panika = raport-zombie, bez ognia"
    _os.environ["FENIX_PANIC_DRY"] = "1"
    try:
        pc7b = PanicController(sequence_fn=spy, log=lambda *_: None)
        pc7b.panic(dry=False)                            # env MUSI to obniżyć do dry
        assert seen[-1] is True, "FENIX_PANIC_DRY=1 wymusza dry nawet gdy ktoś prosi real"
    finally:
        del _os.environ["FENIX_PANIC_DRY"]
    print("  [OK] 7. panika idempotentna (_already); FENIX_PANIC_DRY=1 = ubeczka na testy")

    # 8) widok: SKIP headless (uczciwie), definicje gotowe do X11
    if _os.environ.get("DISPLAY"):
        print("  [OK] 8. widok: (DISPLAY jest — pasek sprawdzisz z gui/fenix_gui.py)")
    else:
        assert "PanicBar" in globals() and hasattr(PanicBar, "_fire") and hasattr(PanicBar, "_tick")
        print("  [OK] 8. widok: SKIP (headless; PanicBar gotowy do X11/openbox na ISO)")

    print("\nSELFTEST: PASS ✅  gui/panic_button.py — D27 w GUI: hold-2s, czysty ekran,\n"
          "ta sama sekwencja co klawiatura, vpn.env bezpiecznie w RAM")
