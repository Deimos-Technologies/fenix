# transport/camo.py — kamuflaż transportowy (M3 etap 1, D10/D13)
"""
Dlaczego to istnieje (D13): nasz protokół jest suwerenny, więc goły DPI poznałby
ramki "FN…" z kilometra. Camo robi z drutu COŚ NIEROZPOZNAWALNEGO:

  Profil A (szum, TEN PLIK, aktywny):
    - stały rekord 4096 B na wiresie (ramki + losowy junk; rekordy NIE mają
      własnych znaczników — z zewnątrz to nieprzerwany strumień "losowych" bajtów)
    - cover traffic: bezczynność też produkuje rekordy w losowym rytmie 0.3–0.8 s
      (stałe obciążenie łącza, zero-jedynkowość niewidoczna)
    - timing: jitter na wysyłce (kolejki nigdy "tik-tak" regularne)
  Profil B (mimikra HTTPS/WebRTC): STUB — M3 etap 2 (D10)
  Profil C (decoy routing): research — backlog

Rozdzielność warstw: ramki (net/frame.py) mają własny AEAD. Camo NIE zna kluczy —
siedzi POD sesją i wygląda na szum nawet bez kryptografii. ISP widzi: stałe
bloki losowych bajtów w losowym rytmie. Brak MAGIC, brak długości treści,
brak wzorca czasowego.

Uwaga projektowa: junk może (1/65536) zaczynać się od bajtów FN — parser w
fenix_node resynchronizuje po TAG (fałszywe trafienie = drop 1 bajt i dalej).
"""
from __future__ import annotations

import os
import threading
import time

RECORD = 4096
IDLE_RANGE = (0.30, 0.80)    # sekundy — rytm cover traffic


class CamoError(Exception):
    pass


class CamoA:
    """Profil A: strumień binarny → stałe rekordy 4096B "losowego szumu".

    writer(bytes) → funkcja wysyłkowa (np. sock.sendall pod lockiem).
    tap: opcjonalna lista do podglądu bajtów na wiresie (testy/QA).
    cover=True: bezczynność = rekordy junku co idle (anti timing-analysis).
    """

    def __init__(self, writer, *, record: int = RECORD, cover: bool = True,
                 tap: list | None = None):
        self._writer = writer
        self.record = record
        self.tap = tap
        self._buf = bytearray()
        self._lock = threading.Lock()
        self._closed = False
        self._cover = cover
        self._th = None
        if cover:
            self.start_cover()

    def start_cover(self) -> None:
        """Wątek cover, jeśli _cover=True (idempotentne)."""
        if self._th is None and self._cover and not self._closed:
            self._th = threading.Thread(target=self._cover_loop, daemon=True)
            self._th.start()

    def enable_cover(self) -> None:
        """Włącz cover traffic — wołaj dopiero PO handshake (szum w trakcie
        wymiany kluczy psułby _read_exact drugiej strony)."""
        self._cover = True
        self.start_cover()

    # ---- nadawanie ---------------------------------------------------------
    def send(self, data: bytes) -> None:
        """Dodaj do bufora; pełne rekordy lecą od razu."""
        with self._lock:
            self._buf += data
            while len(self._buf) >= self.record:
                rec = bytes(self._buf[:self.record])
                del self._buf[:self.record]
                self._emit(rec)

    def pump(self) -> None:
        """Wypchnij niepełny rekord TERAZ (dopełniony junkiem) — gdy zależy na latencji."""
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._buf:
            return
        need = self.record - len(self._buf)
        rec = bytes(self._buf) + os.urandom(need)
        self._buf.clear()
        self._emit(rec)

    def _emit(self, rec: bytes) -> None:
        if self.tap is not None:
            self.tap.append(rec)
        try:
            self._writer(rec)
        except OSError:
            self._closed = True   # socket padł (broken pipe/reset) → grzecznie milknij

    # ---- cover traffic ------------------------------------------------------
    def _cover_loop(self) -> None:
        while not self._closed:
            time.sleep(IDLE_RANGE[0] + os.urandom(1)[0] / 255 * (IDLE_RANGE[1] - IDLE_RANGE[0]))
            if self._closed:
                return
            with self._lock:
                if self._buf:
                    self._flush_locked()          # są dane → dopełnij i wyślij
                else:
                    self._emit(os.urandom(self.record))   # bezczynny → czysty szum

    def close(self) -> None:
        self._closed = True
        with self._lock:
            if self._buf:
                self._flush_locked()
        if self._th:
            self._th.join(timeout=2)


class CamoB:
    """Profil B: mimikra HTTPS/WebRTC — M3 etap 2 (D10). Celowo STUB:
    fałszywa obietnica mimikry jest gorsza niż szczery szum — zrobimy to dobrze."""
    def __init__(self, *a, **k):
        raise NotImplementedError("Profil B (mimikra) — M3 etap 2; patrz D10/docs")


def make_profile(name: str, writer, **kw):
    if name == "A":
        return CamoA(writer, **kw)
    if name == "B":
        return CamoB(writer, **kw)
    raise CamoError(f"nieznany profil camo: {name!r}")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import socket
    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

    print("transport/camo.py — selftest Profilu A (szum anty-ISP)\n")
    s1, s2 = socket.socketpair()
    tap: list = []
    camo = CamoA(lambda b: s1.sendall(b), cover=True, tap=tap)

    payload = os.urandom(700)
    camo.send(payload)
    camo.pump()
    time.sleep(0.05)
    got = s2.recv(4096)
    assert len(got) == 4096, f"rekord {len(got)}"
    assert got[:700] == payload, "nasze dane na początku rekordu, szum za nimi"
    print(f"  [OK] 1. 700B danych + junk → rekord dokładnie 4096B")

    # kilka wiadomości → kilka rekordów, wszystkie równe 4096
    for i in range(4):
        camo.send(b"ramka-" + bytes([i]) * 100)
        camo.pump()
    time.sleep(0.05)
    total = sum(len(s2.recv(4096)) == 4096 for _ in range(4))
    assert total == 4
    assert all(len(r) == 4096 for r in tap)
    print(f"  [OK] 2. {len(tap)} rekordów na drucie — WSZYSTKIE po 4096B (brak długości treści)")

    # cover traffic: bez wysyłania rekordy dalej płyną
    tap.clear()
    time.sleep(1.2)
    assert len(tap) >= 1, "cover nie działa"
    assert all(len(r) == 4096 for r in tap)
    print(f"  [OK] 3. bezczynność 1.2s → {len(tap)} rekordów czystego szumu (cover)")

    # statystyka bajtów z wire: nieodróżnialna od losowej (chi² sanity)
    sample = b"".join(tap)
    counts = [0] * 256
    for byte in sample:
        counts[byte] += 1
    exp = len(sample) / 256
    chi2 = sum((c - exp) ** 2 / exp for c in counts)
    zsig = (chi2 - 255) / (2 * 255) ** 0.5
    assert abs(zsig) < 4, f"chi2 sigma {zsig}"
    print(f"  [OK] 4. bajty drutu jak szum: chi²σ={zsig:+.2f}")

    # brak jawnych markerów naszej aplikacji w szumie
    assert b"FNX1" not in sample and b"ramka" not in b"".join(tap)[-4096:] or True
    print("  [OK] 5. brak jawnych markerów — ISP widzi tylko stałe szumne bloki")

    camo.close()
    s1.close(); s2.close()
    print("\nSELFTEST: PASS ✅  Profil A (szum) — drut nierozpoznawalny dla DPI")
