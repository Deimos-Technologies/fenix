# ai/fnx_ai.py — AI-GRID v0 (D69): siatka obliczeniowa Fenixa — moc użytkowników, na drucie
"""
Fenix ma dwie siły robocze: moja maszyna i MASZYNY WSZYSTKICH w sieci. Ten plik
dokręca drugą: jakiekolwiek node może ogłosić ZADANIE obliczeniowe (T_JOB 0x42),
inne nody je liczą swoim CPU i odsyłają wynik (T_JOB_RES 0x43), a kworum zbieżnych
odpowiedzi rozstrzyga, komu należy się mikro-nagroda FNX.

Dlaczego to jest PRAWDZIWE, a nie print:
  * zadanie = deterministyczna funkcja (v0: kernel „chain_hash" — łańcuch sha256 z
    jawnych parametrów): każdy uczciwy węzeł liczy DOKŁADNIE to samo; leniwy próbuje
    zgadywać — wypada z kworum;
  * wyniki podpisane kluczem pracownika (wzór presence D61: sig_pub+x_pub w środku,
    wallet = FNX1 z tych kluczy — samo-weryfikujące się koperty);
  * KWORUM k-zbieżnych identycznych odpowiedzi od ROŻNYCH walletów + JEDEN finalny
    recompute przez zamawiającego przed wypłatą (kworum przyspiesza, recompute
    rozlicza — spisek fałszywych kworumantów nie wyciągnie ani iskry);
  * seed = hash ostatnich bloków (świeżość zadania oknem), deadline = wysokość,
    dedup i rate-limit — to nie chat, to produkcyjna rura z zapasami anty-sybil.

AI w tym gdzie? (uczciwie, D69): v0 dostarcza SIATKĘ ZADAŃ z płatnościami — tę część,
która musi działać bezpiecznie ZANIM wpuścimy ciężkie zadania. Kernel-chain_hash to
bieg próbny maszyny; wtyczka KERNELS jest otwarta na kolejne kindy (batch-verify
podpisów CLSAG = prawdziwa pomoc w syncu; embeddingi/inferencja = dopiero gdy będzie
deterministyczny silnik — obiecuje się siatkę, nie cuda).

Twarde granice v0 (głośno):
  * płatność = intent-list (poster podpisuje nagrody osobnymi tx; escrow covenant =
    roadmap, dziś: recompute PRZED płatnością maksymalnie ogranicza ryzyko zamawiającego);
  * ms (czas liczenia) jest SELF-REPORTED — etykieta, nigdy argument ani premia;
  * jobs nie nagradzane z konsensusu (żadnej zmiany w ledgerze/emisji);
  * treść zadań = jawne parametry publiczne; zadania z tajnym wejściem = później (MPC).

Selftest (bez argumentów): kernel deterministyczny; koperty sig-wire; dedup/replay;
kworum 2z3; fałszywa odpowiedź zguby; finalny recompute przed płatnością; insufficient
funds = uczciwy intent; rate-limit; wire-roundtrip na ramce T_JOB/T_JOB_RES.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

from core.identity import Identity                                    # noqa: E402
from core.crypto.fenix_crypto import wallet_address                   # noqa: E402
from chain.block import canon as bcanon, h32 as bh32, ISKRA           # noqa: E402
from net.frame import T_JOB, T_JOB_RES, TYPES                          # noqa: E402

GRID_MAX_ITERS = 2_000_000          # sufit roboczy jednego zadania (anty-bomba CPU)
GRID_MAX_RESULTS = 64               # koperta wyników per job w kolektorze
GRID_RATE_PER_MIN = 8               # max wyników od 1 walleta/min w kolektorze
GRID_PAY_NOTE = "fnx-ai-grid job"   # nota w intentach płatności (max 140 zn. jak donate)
GRID_FRESH_SEEDS = 6                # okno hashy tip-ów, w którym zadanie jest świeże


class GridError(Exception):
    """Brudna koperta/podpis/zadanie — jeden typ, zero orakli dla złodzieja."""


def _b32_hex(x: bytes) -> str:
    return hashlib.blake2s(x, digest_size=32).hexdigest()


# ---------------------------------------------------------------- kernel v0
def kernel_chain_hash(seed_hex: str, label: str, iters: int) -> str:
    """Deterministyczny łańcuch: head0 = sha256(seed‖label‖iters); head_i = sha256(head_{i-1}).
    Każdy node liczy identycznie; wynik 32B hex. To jest robota udowadnialna KOSZTEM,
    a rozliczana KWOREM + finalnym recompute (patrz nagłówek)."""
    if not (1 <= iters <= GRID_MAX_ITERS):
        raise GridError(f"iters poza sufitem 1..{GRID_MAX_ITERS}")
    cur = hashlib.sha256((seed_hex + "|" + label + "|" + str(iters)).encode()).digest()
    for _ in range(iters - 1):
        cur = hashlib.sha256(cur).digest()
    return cur.hex()


KERNELS = {"chain_hash": kernel_chain_hash}        # wtyczka: kolejne kindy = wpis tu


# ---------------------------------------------------------------- koperta zadania (T_JOB)
def job_core(kind: str, seed_hex: str, label: str, iters: int,
             bounty_iskry: int, quorum_k: int, deadline_h: int,
             poster_sig_pub: bytes, poster_x_pub: bytes) -> dict:
    if kind not in KERNELS:
        raise GridError(f"nieznany kind (registry ma: {sorted(KERNELS)})")
    if not (0 < bounty_iskry) or not (2 <= quorum_k <= 32) or not (0 < deadline_h):
        raise GridError("złe parametry zadania (bounty/quorum/deadline)")
    if quorum_k * bounty_iskry > 1_000_000 * ISKRA:
        raise GridError("zadanie przerasta budżet bezpieczeństwa v0")
    return {"v": 1, "app": "fnx-ai-grid", "kind": kind, "seed": seed_hex,
            "label": label, "iters": iters, "bounty": bounty_iskry,
            "quorum_k": quorum_k, "deadline_h": deadline_h,
            "sig_pub": poster_sig_pub.hex(), "x_pub": poster_x_pub.hex()}


def build_job(identity: Identity, *, kind: str, seed_hex: str, label: str,
              iters: int, bounty_iskry: int, quorum_k: int, deadline_h: int) -> dict:
    core = job_core(kind, seed_hex, label, iters, bounty_iskry, quorum_k, deadline_h,
                    identity.sig_pub_b, identity.x_pub_b)
    jid = _b32_hex(bcanon(core))
    sig = identity.sign(bcanon({**core, "job": jid}))
    return {"core": core, "job": jid, "sig": sig.hex()}


def job_wallet(job: dict) -> str:
    return wallet_address(bytes.fromhex(job["core"]["sig_pub"]),
                          bytes.fromhex(job["core"]["x_pub"]))


def verify_job(job: dict, *, height: int, fresh_seeds: set[str]) -> str:
    """Struktura+świeżość+podpis. Zwraca job_id albo rzuca GridError."""
    try:
        core = job["core"]
        jid = job["job"]
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(core["sig_pub"])) \
            .verify(bytes.fromhex(job["sig"]), bcanon({**core, "job": jid}))
        assert _b32_hex(bcanon(core)) == jid
        assert core["seed"] in fresh_seeds or len(fresh_seeds) == 0
        assert height <= core["deadline_h"]
        job_core(core["kind"], core["seed"], core["label"], core["iters"],
                 core["bounty"], core["quorum_k"], core["deadline_h"],
                 bytes.fromhex(core["sig_pub"]), bytes.fromhex(core["x_pub"]))
    except GridError:
        raise
    except Exception:
        raise GridError("koperta zadania nieważna (podpis/struktura/id)") from None
    return jid


def run_job(job: dict) -> tuple[str, int]:
    """Wykonanie zadania LOKALNIE (CPU pracownika). Zwraca (head_hex, ms self-reported)."""
    core = job["core"]
    fn = KERNELS[core["kind"]]
    t0 = time.monotonic()
    head = fn(core["seed"], core["label"], core["iters"])
    return head, int((time.monotonic() - t0) * 1000)


# ---------------------------------------------------------------- koperta wyniku (T_JOB_RES)
def build_result(identity: Identity, job: dict, head_hex: str, ms: int) -> dict:
    core = {"v": 1, "app": "fnx-ai-grid", "job": job["job"], "head": head_hex,
            "ms": max(0, int(ms)), "sig_pub": identity.sig_pub_b.hex(),
            "x_pub": identity.x_pub_b.hex()}
    sig = identity.sign(bcanon(core))
    return {"core": core, "sig": sig.hex()}


def result_wallet(res: dict) -> str:
    return wallet_address(bytes.fromhex(res["core"]["sig_pub"]),
                          bytes.fromhex(res["core"]["x_pub"]))


def verify_result(res: dict, job: dict) -> None:
    try:
        core = res["core"]
        assert core["job"] == job["job"]
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(core["sig_pub"])) \
            .verify(bytes.fromhex(res["sig"]), bcanon(core))
        int(core["head"], 16) and len(core["head"]) == 64
    except Exception:
        raise GridError("koperta wyniku nieważna (podpis/job/format)") from None


# ---------------------------------------------------------------- kolektor kworum (strona noda/zamawiającego)
class JobCollector:
    """Zbiera T_JOB_RES dla JEDNEGO zadania: dedup per wallet (1 wynik/wallet/job),
    quorum k-zbieżnych odpowiedzi, finalny recompute PRZED płatnością (D69).
    Rate-limit per wallet wobec WIELU zadań żyje piętro wyżej — GridRegistry."""

    def __init__(self, job: dict):
        self.job = verify_job(job, height=0, fresh_seeds=set()) and job
        self.results: dict[str, dict] = {}      # wallet -> res (pierwszy wygrywa)

    def note(self, res: dict, *, now: float | None = None) -> bool:
        try:
            verify_result(res, self.job)
        except GridError:
            return False
        w = result_wallet(res)
        if w in self.results:
            return False                                 # anti-replay/dedup per job
        if len(self.results) >= GRID_MAX_RESULTS:
            return False
        self.results[w] = res
        return True

    def _tally(self) -> dict[str, list[str]]:
        t: dict[str, list[str]] = {}
        for w, r in self.results.items():
            t.setdefault(r["core"]["head"], []).append(w)
        return t

    def quorum(self) -> dict | None:
        """kworum k identycznych head → {head, winners[]} (q: wszyscy zgodni poza k?)."""
        k = self.job["core"]["quorum_k"]
        for head, ws in self._tally().items():
            if len(ws) >= k:
                return {"head": head, "winners": ws}
        return None

    def final_check_and_paylist(self) -> dict:
        """PRZED płatnością: finalny recompute kernela (1× robota zamawiającego).
        Zwrot: pay-lista intentów albo uczciwa STOP z powodem (złe kworum/fałsz)."""
        q = self.quorum()
        if q is None:
            return {"ok": False, "why": f"kworum {self.job['core']['quorum_k']} jeszcze nie zebrane"}
        truth = kernel_chain_hash(self.job["core"]["seed"], self.job["core"]["label"],
                                  self.job["core"]["iters"])
        if truth != q["head"]:
            return {"ok": False, "why": "kworum zbiegło się na FAŁSZYWY head — recompute rozbił spisek",
                    "truth": truth}
        return {"ok": True, "truth": truth, "winners": q["winners"],
                "pay": [{"to": w, "iskry": self.job["core"]["bounty"],
                         "note": f"{GRID_PAY_NOTE} {self.job['job'][:16]}"} for w in q["winners"]]}




class GridRegistry:
    """Rejestr wielu zadań na nodzie: kolektory per job + RATE-LIMIT per wallet
    globalnie (GRID_RATE_PER_MIN/min; kubełek jak w sentynelu: sybil sam gaśnie)."""

    def __init__(self):
        self.collectors: dict[str, JobCollector] = {}
        self._rate: dict[str, list[float]] = {}

    def register(self, job: dict) -> JobCollector:
        jid = verify_job(job, height=0, fresh_seeds=set())
        col = self.collectors.get(jid)
        if col is None:
            col = self.collectors[jid] = JobCollector(job)
        return col

    def note(self, res: dict, *, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        try:
            w = result_wallet(res)
        except GridError:
            return False
        hist = [t for t in self._rate.get(w, []) if now - t < 60.0]
        if len(hist) >= GRID_RATE_PER_MIN:
            return False                                 # kubełek anty-spam (sybil gasi)
        jid = res.get("core", {}).get("job", "")
        col = self.collectors.get(jid)
        if col is None:
            return False                                 # wynik do nieznanego zadania = stój
        if col.note(res, now=now):
            self._rate[w] = hist + [now]
            return True
        return False


def pay_intents_with_budget(pay: list[dict], poster_balance: int) -> dict:
    """Bilans zamiaru: czy zamawiającego stać? shortfall pokazany JAWNIE (nie cicho)."""
    need = sum(p["iskry"] for p in pay)
    out = {"need": need, "have": poster_balance, "ok": poster_balance >= need}
    if not out["ok"]:
        out["shortfall"] = need - poster_balance
    return out


def payload_for_wire(obj: dict) -> bytes:
    """kanon json na drut T_JOB/T_JOB_RES (AEAD zasłoni treść w locie — net/frame)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def payload_from_wire(raw: bytes) -> dict:
    try:
        obj = json.loads(raw.decode())
        assert isinstance(obj, dict) and len(raw) <= 32768
        return obj
    except Exception:
        raise GridError("brudna ramka siatki (json/sufit)") from None


# ---------------------------------------------------------------- selftest
if __name__ == "__main__":
    print("ai/fnx_ai.py — selftest AI-GRID v0: kernel, koperty, kworum, recompute, "
          "budget, rate-limit, wire\n")

    poster = Identity.generate("zamawiajacy_pow")
    w1, w2, w3 = (Identity.generate(f"pracownik_{i}") for i in (1, 2, 3))
    TIP0 = "aa" * 32

    # 1) koperta zadania + kernel deterministyczny na TRZECH równoległych 'maszynach'
    job = build_job(poster, kind="chain_hash", seed_hex=TIP0, label="embed-batch-7",
                    iters=50_000, bounty_iskry=25 * ISKRA + 1, quorum_k=2,
                    deadline_h=100)
    assert verify_job(job, height=42, fresh_seeds={TIP0}) == job["job"], "koperta+zpodpis OK"
    h_a = run_job(job)[0]
    h_b = kernel_chain_hash(TIP0, "embed-batch-7", 50_000)
    assert h_a == h_b, "kernel: dwie maszyny = TEN SAM head"
    print("  [OK] 1. koperta job sig-wire + blake-id; kernel: 2 maszyny liczą IDENTYCZNIE")

    # 2) walidatory łapią brud (podpis zepsuty, seed nieświeży, deadline minięty)
    bad = {**job, "sig": "00" * 64}
    try:
        verify_job(bad, height=42, fresh_seeds={TIP0})
        raise SystemExit("zepsuty podpis zadania przeszedł!")
    except GridError:
        pass
    try:
        verify_job(job, height=42, fresh_seeds={"ff" * 32})
        raise SystemExit("nieświeży seed przeszedł!")
    except GridError:
        pass
    try:
        verify_job(job, height=200, fresh_seeds={TIP0})
        raise SystemExit("martwe (po deadline) przeszło!")
    except GridError:
        pass
    print("  [OK] 2. verify_job: zły podpis / nieświeży seed / martwe-deadline = stój")

    # 3) pełny obieg: 3 roboty → kolektor → kworum 2z3 → finalny recompute → pay
    col = JobCollector(job)
    r1 = build_result(w1, job, h_a, ms=31)
    r2 = build_result(w2, job, h_a, ms=44)               # wolniejszy, ten sam wynik
    r_bluff = build_result(w3, job, "ff" * 32, ms=1)     # leniwy BLEFUJE innym head
    assert col.note(r1) and col.note(r2)
    assert col.note(r1) is False, "replay tego samego wyniku odpada (dedup)"
    assert col.note(r_bluff), "fałszywa odp. PRZYJĘTA do kubła (kworum ją przegłosuje…)"
    q = col.quorum()
    assert q is not None and q["head"] == h_a and set(q["winners"]) == {result_wallet(r1), result_wallet(r2)}, \
        "kworum 2 vs 1: prawda wygrywa liczebnie"
    cheque = col.final_check_and_paylist()
    assert cheque["ok"] and cheque["truth"] == h_a and len(cheque["pay"]) == 2
    assert all(p["to"] in (w1.wallet, w2.wallet) and p["iskry"] == 25 * ISKRA + 1
               for p in cheque["pay"])
    print("  [OK] 3. E2E: 3 wyniki (1 bluffs) → kworum 2z3 → recompute → pay-lista dla 2 pracowników")

    # 4) spisek kworum NA FAŁSZ = finalny recompute go rozbija, pay = STOP
    col2 = JobCollector(job)
    liars = [build_result(w, job, "ee" * 32, ms=i) for i, w in enumerate((w1, w2, w3))]
    for r in liars:
        col2.note(r)
    bad_cheque = col2.final_check_and_paylist()
    assert not bad_cheque["ok"] and "FAŁSZYWY" in bad_cheque["why"], \
        "kworum kłamców ≠ gotówka (recompute mówi prawdę)"
    print("  [OK] 4. spisek 3x ten sam fałsz → recompute zamawiającego: pay STOP, zero iskier")

    # 5) budget: stać vs shortfall widoczny jawnie
    okb = pay_intents_with_budget(cheque["pay"], 51 * ISKRA)
    assert okb["ok"] and okb["need"] == 2 * (25 * ISKRA + 1)
    nob = pay_intents_with_budget(cheque["pay"], ISKRA)
    assert not nob["ok"] and nob["shortfall"] == 2 * (25 * ISKRA + 1) - ISKRA
    print("  [OK] 5. budget: pay-intenty liczą need/have; shortfall pokazany JAWNIE")

    # 6) rate-limit sybili POZIOMEM registry: 1 wallet odpowiada na WIELE zadań
    reg = GridRegistry()
    jobs6 = [build_job(poster, kind="chain_hash", seed_hex=TIP0, label=f"batch-{i}",
                       iters=1000, bounty_iskry=10, quorum_k=2, deadline_h=100)
             for i in range(GRID_RATE_PER_MIN + 3)]
    for jb in jobs6:
        reg.register(jb)
    got6 = 0
    for i, jb in enumerate(jobs6):
        head6 = kernel_chain_hash(TIP0, f"batch-{i}", 1000)
        if reg.note(build_result(w1, jb, head6, ms=i), now=1000.0 + i):
            got6 += 1
    assert got6 == GRID_RATE_PER_MIN, "registry: kubełek 8/min/wallet (nadmiar sybili wylatuje)"
    print("  [OK] 6. rate-limit: 11 odpowiedzi tego samego walleta na różne zadania")
    print("           → registry przyjmuje dokładnie 8/min (sybil zapieka się kubełkiem)")

    # 7) drut: payload na ramkach T_JOB/T_JOB_RES to czyste koperty; typy ZAREJESTROWANE
    raw_j = payload_for_wire(job)
    raw_r = payload_for_wire(r1)
    assert payload_from_wire(raw_j)["job"] == job["job"] and payload_from_wire(raw_r)["core"]["head"] == h_a
    assert T_JOB in TYPES and T_JOB_RES in TYPES and T_JOB == 0x42 and T_JOB_RES == 0x43
    try:
        payload_from_wire(b"\x00\xff{nope")
        raise SystemExit("brudna ramka siatki przeszła!")
    except GridError:
        pass
    print("  [OK] 7. wire: kanon-json roundtrip; 0x42/0x43 zarejestrowane w TYPES; brud odrzucony")

    print("\nSELFTEST: PASS ✅  ai/fnx_ai.py — AI-GRID v0: zadania T_JOB przez mesh, pracownicy "
          "T_JOB_RES,\nkworum k-zbieżnych + FINALNY recompute przed pay, bluff/spisek odpada,"
          "\nrate-limit sybili, szyfrowane koperty sig (wzór presence D61); siatka = prawdziwa\n"
          "moc CPU użytkowników na własnym wire (0x42/0x43) — D69")
