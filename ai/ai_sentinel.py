# ai/ai_sentinel.py — AI-SENTRY: RADAR, NIE GRABARZ (M6 start; D5/D17/D22, ban_policy v1.0)
"""
Sentyment projektu: **portier z notesem, nie sędzia**. Patrzy na META (tempo,
liczniki, wzorce), NIGDY na treść (D5). Nie banuje — najwyżej SKŁADA WNIOSEK
(red) do kropki attestorów k-z-n (chain/ban_evt.py, D18). Jeden człowiek ani
jedna maszyna nie postawi plomby (ban_policy §9: „żaden człowiek nie ma
przycisku ban").

Filary fail-open (ban_policy §0–§4, D22 — WIĄZĄCE):
  * WZORCE, nie zdarzenia — żaden próg nie odpala się od 1 zdarzenia;
    każdy detektor ma bramkę „PATRZĘ od N zdarzeń przez T czasu".
  * Decay — flagi gasną same: throttle 7 dni, wpis 30 dni; nikt nigdy nie składa
    „odwołania" za drobiazg.
  * Safe Harbor — sync/ping/hello_ok liczone OSOBNO i nigdy nie budują score;
    rozjazd zegara ±5 min tolerowany (policy §2).
  * Red WYŁĄCZNIE gdy: próg red + CCTV-szkic dowodów (hash paczki) + potem
    kropka k-z-n off-chain podpisze werdykt (on-chain dopiero TX_BAN_EVT).

Kapsuła sesyjna: wszystko w RAM (ring-buffer kart zdarzeń, per-peer liczniki);
`purge()` = spalenie klucza sesji — koniec pamięci, zero dysku (zgodnie z D5
„anomalia NIGDY nie opuszcza node'a").

Dostęp: WYŁĄCZNIE owner/admin (D17) — klasa nie ma żadnego kanału do
użytkownika; GUI/demon mogą ją odczytywać tylko po stronie operatora node'a.

Granice tej wersji (uczciwie, PROBLEMS_OPEN):
  - detekcja lokalna JEDNEGO node'a (konsensus wielu sentineli = P25/warstwa 3);
  - mapowanie fp→wallet robi operator (handshake nosi pub-y, wallet =
    blake2s(sig‖x) — ten sam skład co wallet_address);
  - kody ORANGE (0x16 itd.) w MVP kończą na YELLOW (throttle); ich kanał red
    (persist) dopiero gdy skala pokaże dane.
"""
from __future__ import annotations

import sys
import pathlib as _pl
from collections import deque

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))


class SentinelError(Exception):
    """Złe użycie radaru (np. próba wrzucenia TREŚCI do kapsuły)."""


# --- co wolno obserwować (META; adresy/klucze to meta, treści — NIGDY) --------
KINDS_DATA = ("msg", "bad_tag", "replay", "hello_fail",
              "grid")      # D69: meta ramki siatki (T_JOB/T_JOB_RES) — liczone jak
                           # ruch danych; WŁASNE progi detektorów = P-tuning (NIE
                           # dziedziczy progów msg 0x11 — te są skalibrowane pod czat)
KINDS_SAFE = ("sync", "ping", "hello_ok")     # Safe Harbor: osobne liczniki, score=0
FORBIDDEN_KEYS = {"text", "payload", "body", "ct", "content", "message", "pt"}

LVL = ("none", "watch", "yellow", "red")
CLOCK_DRIFT = 300                     # Safe Harbor: rozjazd zegara ±5 min (policy §2)
EVENT_MAX_AGE = 25 * 3600             # starsze zapomnij (Live-OS restart znosi 24h)
YELLOW_TTL = 7 * 86400                # throttle 7 dni (policy §7)
FLAG_TTL = 30 * 86400                 # wpis yellow żyje 30 dni, potem gaśnie
PEER_FORGET = 86400                   # cichy i czysty peer znika z RAM po dobie

# Progi detektorów — WERSJONOWANE razem z docs/ban_codes.txt §4 (zmiana kodów =
# publikacja 14 dni wcześniej, ToS §11). „bramka" = minimum zdarzeń zanim
# cokolwiek zarejestrujemy (wzorce, nie zdarzenia).
FLOOD_RATE = 32                       # 0x11: msg/s (policy: >32/s przez 60 s)
FLOOD_WATCH_S = 60                    # PATRZĘ po 60 s ciągłego zalewu
FLOOD_YELLOW_S = 300                  # yellow po 5 min „sustained"
FLOOD_RED_AFTER_YELLOW = 600          # red: ignoruje throttle ≥10 min dalej
BADTAG_WATCH_DAY = 5                  # 0x12: PATRZĘ >5 złych TAG/dobę
BADTAG_YELLOW_H = 100                 # yellow >100 złych TAG/h
BADTAG_RED_HOURS = 3                  # red: ≥3 godziny >100 MIMO yellow (persist)
REPLAY_WATCH_DAY = 3                  # 0x15: PATRZĘ >3 replay/dobę
REPLAY_YELLOW_H = 50                  # yellow >50 replay/h
REPLAY_RED_HOURS = 2                  # red: ≥2 godziny >50 MIMO yellow
HELLO_WATCH_H = 32                    # 0x16: PATRZĘ >32 nieudane HELLO/h
HELLO_YELLOW_H = 200                  # yellow >200/h (0x16 = ORANGE: bez red w MVP)


class Sentinel:
    """Radar jednego node'a. Wątkowo-bezpieczny NIE jest (node karmi go z jednej
    pętli); błąd obsługi NIGDY nie może zabić node'a — wołający łapie wyjątki."""

    def __init__(self, now=None, ring_max: int = 4096, telemetry: str = "minimal"):
        import time as _t
        self._now = now or _t.time            # zegar wstrzykiwalny (testy/QA)
        if telemetry not in ("off", "minimal", "full"):
            raise SentinelError("telemetry ∈ {off, minimal, full}")
        self.telemetry = telemetry                       # suwak (M6; domyślnie minimal)
        self.cards: deque = deque(maxlen=ring_max if telemetry != "off" else 1)
        self.peers: dict[str, dict] = {}
        self.proposals: dict[str, dict] = {}             # peer → ostatni wniosek red
        self.stats = {"events": 0, "watch": 0, "yellow": 0, "red": 0, "dropped": 0}

    # ---------------------------------------------------------------- kapsuła
    def purge(self) -> None:
        """SPAL KLUCZ SESJI: koniec pamięci radaru (karty, liczniki, wnioski)."""
        self.cards.clear()
        self.peers.clear()
        self.proposals.clear()

    # ---------------------------------------------------------------- wejście
    def observe(self, event: dict) -> dict:
        """Przyjmij kartę zdarzenia (META!) → werdykt lokalny.
        ZAWRZE tekst/payload = SentinelError (zero-treści jest funkcją, nie obietnicą)."""
        if not isinstance(event, dict):
            raise SentinelError("event ma być dict META")
        bad = FORBIDDEN_KEYS & set(event.keys())
        if bad:
            raise SentinelError(f"odmowa: karty zdarzeń NIE noszą treści ({sorted(bad)}) — D5")
        kind = event.get("kind")
        peer = event.get("peer")
        if kind not in KINDS_DATA + KINDS_SAFE:
            raise SentinelError(f"kind ∉ {KINDS_DATA + KINDS_SAFE}")
        if not isinstance(peer, str) or not peer:
            raise SentinelError("peer: wymagany (fp/wallet — meta adresowe)")
        ts = float(event.get("ts", self._now()))
        now = self._now()
        if ts > now + CLOCK_DRIFT or ts < now - EVENT_MAX_AGE:
            self.stats["dropped"] += 1            # zegar rozłazł się albo echo z zamierzchłych
            return self._verdict(None, "ok-zegar")
        self.stats["events"] += 1
        card = (round(ts, 3), kind, peer[:24])    # karta < 100 B, bez treści (D5)
        if self.telemetry != "off":
            self.cards.append(card)
        st = self._peer(peer, ts)
        if kind in KINDS_SAFE:                    # Safe Harbor: policz i ZAPOMNIJ o score
            self._win_add(st, kind, ts, 86400)
            self._maintain(ts)
            return self._verdict(st, "safe-harbor")
        if self.telemetry == "off":               # suwak off: radar zasłonięty (sejsmograf off)
            return self._verdict(st, "telemetry-off")
        self._win_add(st, kind, ts, 86400)
        self._evaluate(st, ts)
        self._maintain(ts)
        return self._verdict(st, "")

    # ---------------------------------------------------------------- wnętrze
    def _peer(self, peer: str, ts: float) -> dict:
        st = self.peers.get(peer)
        if st is None:
            st = {"level": 0, "last_seen": ts,
                  "wins": {},                     # kind → {"b": {sec: n}, "pk": sec}
                  "run": {"kind": None, "since": 0.0},
                  "flags": {},                    # code → {"sev", "since", "hours": set}
                  "yellow_until": 0.0}
            self.peers[peer] = st
            st["_eval_at"] = 0.0
        st["last_seen"] = ts
        return st

    @staticmethod
    def _win_add(st: dict, kind: str, ts: float, horizon: int) -> None:
        """Wiaderka 1-sekundowe (stan rośnie z AKTYWNOŚCIĄ, nie z czasem)."""
        w = st["wins"].setdefault(kind, {"b": {}, "pk": -1})
        b = w["b"]
        k = int(ts)
        b[k] = b.get(k, 0) + 1
        if k != w["pk"]:                          # pruning raz na zmianę sekundy
            edge = k - horizon
            for kk in [kk for kk in b if kk < edge]:
                del b[kk]
            w["pk"] = k

    @staticmethod
    def _win_count(st: dict, kind: str, span: int, ts: float) -> int:
        b = st["wins"].get(kind, {}).get("b")
        if not b:
            return 0
        lo = int(ts) - span
        return sum(n for kk, n in b.items() if kk > lo)

    def _raise(self, st: dict, code: str, sev: int, ts: float) -> None:
        f = st["flags"].get(code)
        if f is None or sev > f["sev"]:
            st["flags"][code] = {"sev": sev, "since": ts, "hours": (f or {}).get("hours", set())}
            if sev == 2:
                st["yellow_until"] = ts + YELLOW_TTL
                self.stats["yellow"] += 1
            elif sev == 3:
                self.stats["red"] += 1
            elif sev == 1:
                self.stats["watch"] += 1
            st["level"] = max(st["level"], sev)

    # ---------------------------------------------------------------- detektory
    def _evaluate(self, st: dict, ts: float) -> None:
        if ts < st["_eval_at"] + 1.0:             # ocena max co sekundę per peer (koszt!)
            return
        st["_eval_at"] = ts
        # --- 0x11 PROTO_FLOOD: ciągłość zalewu liczymy „biegiem" (run) -------
        # Bieg STARTUJE od najstarszego wiaderka wypełnionego okna 60 s (nie od
        # „teraz" — inaczej watch przyszedłby o minutę za późno: test 4 złapał).
        # Strażnik anty-burst: bieg żyje tylko gdy ostatnie 10 s TEŻ jest gorące
        # (pakiet 2400 msg w 5 s to nie „sustained flood" — rozlewa się i znika).
        n60 = self._win_count(st, "msg", 60, ts)
        hot = self._win_count(st, "msg", 10, ts) > FLOOD_RATE * 10
        run = st["run"]
        if n60 > FLOOD_RATE * 60 and hot:
            if run["kind"] != "msg":
                b = st["wins"].get("msg", {}).get("b", {})
                oldest = min([kk for kk, n in b.items() if n and kk > int(ts) - 60],
                             default=int(ts))
                run.update(kind="msg", since=float(oldest))
            dur = ts - run["since"]
            if dur >= FLOOD_WATCH_S:
                self._raise(st, "0x11", 1, ts)
            if dur >= FLOOD_YELLOW_S:
                self._raise(st, "0x11", 2, ts)
            f = st["flags"].get("0x11")
            if f and f["sev"] >= 2 and ts >= f["since"] + FLOOD_RED_AFTER_YELLOW:
                # ignoruje throttle: dalej leje pełną rurą → wniosek red
                if self._win_count(st, "msg", FLOOD_RED_AFTER_YELLOW, ts) > \
                        FLOOD_RATE * FLOOD_RED_AFTER_YELLOW:
                    self._raise(st, "0x11", 3, ts)
        elif run["kind"] == "msg":
            run.update(kind=None, since=0.0)      # przerwa zalewu = czysty bieg (decay)
        # --- 0x12 INVALIDTAG_STORM -------------------------------------------
        if self._win_count(st, "bad_tag", 86400, ts) > BADTAG_WATCH_DAY:
            self._raise(st, "0x12", 1, ts)
        if self._win_count(st, "bad_tag", 3600, ts) > BADTAG_YELLOW_H:
            f = self._raise_hour(st, "0x12", ts)
            if len(st["flags"]["0x12"]["hours"]) >= BADTAG_RED_HOURS \
                    and f >= 2:
                self._raise(st, "0x12", 3, ts)
        # --- 0x15 REPLAY_ATTACK ------------------------------------------------
        if self._win_count(st, "replay", 86400, ts) > REPLAY_WATCH_DAY:
            self._raise(st, "0x15", 1, ts)
        if self._win_count(st, "replay", 3600, ts) > REPLAY_YELLOW_H:
            f = self._raise_hour(st, "0x15", ts)
            if len(st["flags"]["0x15"]["hours"]) >= REPLAY_RED_HOURS and f >= 2:
                self._raise(st, "0x15", 3, ts)
        # --- 0x16 HANDSHAKE_FARM (ORANGE — w MVP max yellow, bez kanału red) ---
        if self._win_count(st, "hello_fail", 3600, ts) > HELLO_WATCH_H:
            self._raise(st, "0x16", 1, ts)
        if self._win_count(st, "hello_fail", 3600, ts) > HELLO_YELLOW_H:
            self._raise(st, "0x16", 2, ts)

    def _raise_hour(self, st: dict, code: str, ts: float) -> int:
        """Yellow + zapamiętanie GODZINY przekroczenia (persist→red wymaga
        kilku odrębnych godzin — jednorazowa czaszka to nie wzorzec)."""
        self._raise(st, code, 2, ts)
        st["flags"][code]["hours"].add(int(ts) // 3600)
        return st["flags"][code]["sev"]

    # ---------------------------------------------------------------- decay
    def _maintain(self, ts: float) -> None:
        for peer, st in list(self.peers.items()):
            # throttle mija sam z siebie (policy §7) — wpis zostaje jako wspomnienie
            for code, f in list(st["flags"].items()):
                if f["sev"] <= 2 and ts - f["since"] > FLAG_TTL:
                    del st["flags"][code]         # wpis yellow gasnął po 30 dniach
            if any(f["sev"] >= 3 for f in st["flags"].values()):
                st["level"] = 3                   # red nie gaśnie sam (dowód czeka na kropkę)
            elif st["flags"]:
                # yellow aktywny TYLKO do yellow_until; potem wpis = wspomnienie (watch)
                st["level"] = 2 if ts < st["yellow_until"] else 1
            else:
                st["level"] = 0
                st["yellow_until"] = 0.0
            if st["level"] == 0 and ts - st["last_seen"] > PEER_FORGET:
                del self.peers[peer]              # cichy i czysty znika z RAM
                self.proposals.pop(peer, None)

    # ---------------------------------------------------------------- werdykt
    def _dominant(self, st: dict) -> str:
        if not st or not st["flags"]:
            return ""
        return max(st["flags"].items(), key=lambda kv: kv[1]["sev"])[0]

    def _verdict(self, st: dict | None, note: str) -> dict:
        from chain.ban_evt import REASONS_RED
        if st is None:
            return {"level": "none", "code": "", "why_pl": "", "why_en": "",
                    "actions": [], "note": note}
        lvl = st["level"]
        code = self._dominant(st)
        pl, en = ("", "")
        if code in REASONS_RED:
            _, pl, en = REASONS_RED[code]
        elif code == "0x16":
            pl, en = ("Farmerstwo nieudanych handshake (zajmowanie zasobów).",
                      "Farming failed handshakes (resource squatting).")
        return {"level": LVL[lvl], "code": code, "why_pl": pl, "why_en": en,
                "actions": self.reactions(LVL[lvl]),
                "yellow_until": st["yellow_until"] if lvl == 2 else 0.0,
                "note": note}

    @staticmethod
    def reactions(level: str) -> list[str]:
        """Reakcje schodkowe (M6). DRABINA kończy się na wniosku do kropki —
        AI NIGDY: nie banuje sama, nie dotyka danych, nie self-destruct."""
        return {"none": [], "watch": ["pamietaj-liczniki"],
                "yellow": ["throttle-7d", "komunikat-edukacyjny"],
                "red": ["throttle-natychmiast", "wniosek-do-kropki-k-z-n"]}[level]

    # ---------------------------------------------------------------- wniosek red
    def make_proposal(self, peer: str) -> dict | None:
        """Szkic werdyktu dla kropki attestorów (D17/D18). Zwraca
        {"core":…, "evidence":paczka} albo None gdy peer nie jest red.
        core podpisują attestorzy; paczka zostaje u operatora (na chain idzie
        TYLKO jej hash). UWAGA: peer MUSI być walletem FNX1 (mapowanie fp→wallet
        = obowiązek operatora node'a; pub-y z handshake wystarczą)."""
        st = self.peers.get(peer)
        if not st or st["level"] < 3:
            return None
        code = self._dominant(st)
        if code not in self._red_codes():
            return None                            # kod bez kanału red (0x16) — brak wniosku
        from chain import ban_evt as bevt
        f = st["flags"][code]
        kinds = {k: sum(w["b"].values()) for k, w in st["wins"].items()}
        bundle = {"policy": "ban_policy v1.0", "peer": peer, "code": code,
                  "window": [f["since"], st["last_seen"]],
                  "counters": kinds, "hours": sorted(f.get("hours") or []),
                  "telemetry": self.telemetry}
        name, pl, en = bevt.REASONS_RED[code]
        try:
            core = bevt.ban_core(peer, code, pl, en, bevt.evidence_hash_of(bundle))
        except bevt.BanEvtError:
            return None            # peer to fp, nie wallet FNX1 — operator mapuje najpierw
        prop = {"core": core, "evidence": bundle, "name": name}
        self.proposals[peer] = prop
        return prop

    @staticmethod
    def _red_codes() -> set[str]:
        """Kody z realnym kanałem red w tej wersji detektorów (podzbiór
        ban_codes red — reszta wymaga obserwacji, których radar lokalny nie ma)."""
        return {"0x11", "0x12", "0x15"}

    # ---------------------------------------------------------------- widok ownera (D17)
    def verdict_of(self, peer: str) -> dict | None:
        """Werdykt dla JEDNEGO peera (widok operatora, D17). None = radar go nie zna."""
        st = self.peers.get(peer)
        return None if st is None else self._verdict(st, "")

    def status(self) -> dict:
        """Liczby dla operatora (bez danych innych użytkowników — karty to meta)."""
        lv = {k: 0 for k in LVL}
        for st in self.peers.values():
            lv[LVL[st["level"]]] += 1
        return {"telemetry": self.telemetry, "cards": len(self.cards),
                "peers": len(self.peers), "levels": lv, **self.stats}


# -------------------------------------------------------------------------- selftest
if __name__ == "__main__":
    print("ai/ai_sentinel.py — selftest: radar (wzorce) + fail-open + wniosek→ban E2E\n")
    clk = [1_800_000_000.0]
    s = Sentinel(now=lambda: clk[0])

    def pump(peer: str, kind: str, n: int, span_s: float) -> dict:
        dt = span_s / max(1, n)
        v = {"level": "none"}
        for _ in range(n):
            clk[0] += dt
            v = s.observe({"kind": kind, "peer": peer, "ts": clk[0]})
        return v

    # 1) zwykły człowiek: 3 msg/min przez 2 h + burza sync + pingi → CZYSTY
    v = pump("FNX1ludzki-normalny", "msg", 360, 7200)
    pump("FNX1ludzki-normalny", "sync", 3000, 600)       # pierwsza synchronizacja
    pump("FNX1ludzki-normalny", "ping", 500, 300)
    v = s.observe({"kind": "msg", "peer": "FNX1ludzki-normalny"})
    assert v["level"] == "none", f"normalny user oflagowany: {v}"
    print("  [OK] 1. normalny użytkownik (3 msg/min × 2 h + sync-fest) → CZYSTY (Safe Harbor)")

    # 2) pojedyncze zdarzenia: 1 bad_tag + 2 replay + 30 hello_fail → CZYSTY
    w = "FNX1pechowiec"
    s.observe({"kind": "bad_tag", "peer": w})            # bitflip w RAM się zdarza
    pump(w, "replay", 2, 10)
    pump(w, "hello_fail", 30, 599)
    v = s.observe({"kind": "ping", "peer": w})
    assert v["level"] == "none", f"pojedyncze zdarzenia oflagowane: {v}"
    print("  [OK] 2. 1×bad_tag + 2×replay + 30×hello_fail → CZYSTY (wzorce, nie zdarzenia)")

    # 3) zegar: event z przyszłości +7 min i z przeszłości 30 h → odrzut licznika
    ev0 = s.stats["dropped"]
    s.observe({"kind": "msg", "peer": w, "ts": clk[0] + 7 * 60})
    s.observe({"kind": "msg", "peer": w, "ts": clk[0] - 30 * 3600})
    assert s.stats["dropped"] == ev0 + 2
    v = s.observe({"kind": "msg", "peer": w, "ts": clk[0] + 4 * 60})   # ±5 min OK
    assert v["note"] != "ok-zegar"
    print("  [OK] 3. rozjazd zegara: ±5 min tolerowany (Safe Harbor), +7 min/−30 h → brak echa")

    # 4) 0x11 flood: 40 msg/s — 70 s → WATCH; do 320 s → YELLOW (throttle 7 dni)
    atk = "fp_aa7766_zalew"                                # peer z meshu = fp (NIE wallet!)
    v = pump(atk, "msg", 40 * 70, 70)
    assert v["level"] == "watch" and v["code"] == "0x11", v
    print("  [OK] 4a. flood 40 msg/s × 70 s → WATCH (PATRZĘ od 60 s ciągłego zalewu)")
    v = pump(atk, "msg", 40 * 260, 260)                  # łącznie ~330 s biegu
    assert v["level"] == "yellow" and v["code"] == "0x11", v
    assert v["yellow_until"] > clk[0] and "throttle-7d" in v["actions"]
    print("  [OK] 4b. flood ciągnie się 5+ min → YELLOW (throttle 7 dni, komunikat edukacyjny)")

    # 5) ignoruje throttle: kolejne 620 s pełną rurą → RED + wniosek z hashem dowodów
    v = pump(atk, "msg", 40 * 640, 640)
    assert v["level"] == "red" and v["code"] == "0x11", v
    assert "wniosek-do-kropki-k-z-n" in v["actions"]
    prop = s.make_proposal(atk)                          # peer musi być walletem FNX1…
    assert prop is None, "peer nie-FNX1 nie może dostać wniosku (operator mapuje fp→wallet)"
    from core.identity import Identity
    from chain import ban_evt as bevt
    import chain.ban_evt as _pkg
    ala = Identity.generate("ala_flooduje")
    s2 = Sentinel(now=lambda: clk[0])                    # świeży radar, ten sam zegar
    def pump2(kind, n, span):
        dt = span / max(1, n)
        vv = {"level": "none"}
        for _ in range(n):
            clk[0] += dt
            vv = s2.observe({"kind": kind, "peer": ala.wallet, "ts": clk[0]})
        return vv
    v2 = pump2("msg", 40 * 960, 960)                     # 960 s zalewu → red z palcem na mapie
    assert v2["level"] == "red", v2
    prop = s2.make_proposal(ala.wallet)
    assert prop and prop["core"]["code"] == "0x11" and len(prop["core"]["evidence"]) == 64
    assert prop["core"]["wallet"] == ala.wallet
    print("  [OK] 5. zalew IGNORUJE throttle 10 min → RED; wniosek: kod 0x11 + hash dowodów 64-hex")

    # 6) decay: ktoś żółty MILCZY 8 dni → throttle gaśnie (wpis=wspomnienie); 31 dni → czysty
    atk2 = "fp_bb2211_ucichl"                            # świeży peer (atk ma red z testu 5!)
    v = pump(atk2, "msg", 40 * 330, 330)                 # 5,5 min zalewu → yellow
    assert v["level"] == "yellow", v
    clk[0] += 8 * 86400                                  # 8 dni ciszy
    v = s.observe({"kind": "ping", "peer": atk2})
    assert v["level"] in ("none", "watch") and "throttle-7d" not in v["actions"], v
    clk[0] += 31 * 86400                                 # łącznie 39 dni ciszy
    v = s.observe({"kind": "ping", "peer": atk2})
    assert v["level"] == "none", f"wpis nie zgasł po 30 dniach: {v}"
    print("  [OK] 6. decay: throttle gaśnie po 7 dniach, wpis po 30 (auto-reset — zero odwołań)")

    # 7) zero-treści: próba wrzucenia tekstu/payloadu → SentinelError (D5)
    for zlew in ({"kind": "msg", "peer": "x", "text": "cześć"},
                 {"kind": "msg", "peer": "x", "payload": "AAEC"},
                 ["nie-dict"]):
        try:
            s.observe(zlew)
            raise SystemExit("treść weszła do kapsuły!")
        except SentinelError:
            pass
    print("  [OK] 7. text/payload/nie-dict → ODMOWA (karty noszą wyłącznie META — D5)")

    # 8) replay-storm: 60/h × 2.2 h → yellow → red (persist przez 2 godziny)
    s3 = Sentinel(now=lambda: clk[0])
    clk[0] += 100
    r3 = "FNX1replay-atak"
    vv = {"level": "none"}
    for _ in range(60):
        clk[0] += 55                                     # 65/h > 50 → yellow (0x15)
        vv = s3.observe({"kind": "replay", "peer": r3, "ts": clk[0]})
    assert vv["level"] == "yellow" and vv["code"] == "0x15", vv
    for _ in range(60):
        clk[0] += 50                                     # 72/h: druga odrębna GODZINA >50
        vv = s3.observe({"kind": "replay", "peer": r3, "ts": clk[0]})
    assert vv["level"] == "red" and vv["code"] == "0x15", vv
    print("  [OK] 8. replay-storm przez 2 odrębne godziny → yellow → RED 0x15 (persist)")

    # 9) E2E łańcuch: wniosek z (5) → kropka 3/5 attestorów → TX_BAN_EVT na ledger
    from chain.block import Tx, TREASURY_WALLET_DEV, TX_BAN_EVT, TX_TRANSFER
    from chain.ledger import Ledger, ChainError
    from chain.miner import mine
    L = Ledger(TREASURY_WALLET_DEV)
    att = [Identity.generate(f"sent_att{i}") for i in range(bevt.BAN_N)]
    for a_ in att:
        _pkg.register_dev_attestor(a_)
    core = prop["core"]
    entries = [bevt.attest_entry(a_, core) for a_ in att[:3]]
    L.add_tx(Tx(type=TX_BAN_EVT, sender="", recipient="", amount=0,
                payload=bevt.ban_payload(core, entries)))
    won = mine(L.block_template(Identity.generate("kopacz_senty1").wallet, zbits=2),
               max_tries=300_000)
    assert won is not None
    L.apply_block(won)
    assert bevt.is_banned(L.bans, ala.wallet)
    try:
        L.add_tx(Tx.build_signed(TX_TRANSFER, ala, TREASURY_WALLET_DEV, 10 ** 8, nonce=0))
        raise SystemExit("zbanowany floodster wysłał tx!")
    except ChainError as e:
        assert "zbanowan" in str(e)
    print("  [OK] 9. SENTINEL→BAN E2E: wniosek → kropka 3/5 podpisów → tombstone on-chain → "
          "wallet martwy (M6 zamknięte koło)")

    # 10) drabina bezgrabarzowa + purge: żadnej gałęzi destrukcji; kapsuła spalona
    for lvl in LVL:
        for a_ in Sentinel.reactions(lvl):
            assert "destruct" not in a_ and "ban-bezposredni" not in a_, a_
    s3.purge()
    assert not s3.cards and not s3.peers and s3.proposals == {}
    print("  [OK] 10. reakcje = max wniosek-do-kropki (AI NIGDY nie banuje/destruuje); "
          "purge() spala pamięć sesji")

    print("\nSELFTEST: PASS ✅  ai/ai_sentinel.py — radar fail-open: Safe Harbor zdrowsze od progu,\n"
          "wzorce nie zdarzenia, decay sam gaśnie, wniosek red → plomba tylko przez kropkę k-z-n")
