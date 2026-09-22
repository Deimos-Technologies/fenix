# tools/real_e2e.py — DOWÓD FUNKCJONALNY (D68): cała sieć na ŻYWYCH procesach
"""
To NIE jest selftest w jednym procesie. To orkiestra PRAWDZIWYCH demonów
fenix_node (osobne procesy, osobne katalogi danych, prawdziwe gniazda TCP i IPC),
na których przeprowadzamy rzeczywiste scenariusze i sprawdzamy ARTEFAKTY:

  1) 3 nody łączą się przez seeds (A←B←C) — faktyczne handshaki AEAD po TCP;
  2) kopanie STAGGERED (doba DEV zbits=2 robi setki bloków/s — jednoczesne kopanie
     na 2 nodach = fabryka forków; tu: A kope, pauza, sync-zbieg; potem C kope,
     pauza, sync-zbieg) → wszystkie 3 ledgery ZBITOWO ten sam tip (hash), choć
     bloki wyprodukowały RÓŻNE nody — to jest decentralizacja, nie jeden plik;
  3) transakcja na żywo: C robi DONATE 1 FNX (tx podpisana W DEMONIE) → gossip
     C→B→A → A dobija ją blokiem → po sync skarbiec na B rośnie o DOKŁADNIE
     amount+fee_owner (1.00055 FNX — arytmetyka D15/D50, liczymy do iskry);
  4) usługi IPC z osobnego procesu-klienta (ten skrypt): census (licznik D61,
     ESTYMACJA — mówimy to głośno), price (pokój cenowy D65/D67), ban_status
     (D66) na A; pytanie o wallet C przez A (lusterko konsensusu);
  5) ghost: toggle na C przez IPC (duch D63 — stan wraca z demona);
  6) trwałość+rejoin: ubijamy A (SIGINT, czyste zejście), startujemy z tym samym
     katalogiem → chain.dat odczytany (wysokość NIE spadła) i A WRACA do mesha
     (seed=B, sync, ten sam tip co B/C);
  7) AI-GRID (D69): warstwa biblioteczna (ai/fnx_ai) ma własny selftest E2E;
     dopóki nie ma IPC siatki w demonie, tu sprawdzamy uczciwie tylko, że demony
     ZOSTAJĄ stabilne po całym scenariuszu (zero Traceback w logach);
     pełny przejazd T_JOB/T_JOB_RES po żywych procesach = roadmap D69 krok 2.

Wynik: FACT linie + JSON na stdout; rc=0 gdy WSZYSTKO działa; w razie wpadki
rc=1 z ostatnim stanem (logi w /tmp/fenix-real-e2e/). Zasada: żadnego "powinno
zadziałać" — samo "zadziałało, oto liczby".
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import pathlib as _pl

ROOT = _pl.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gui.backend_ipc import BackendIpc                          # noqa: E402
from chain.block import ISKRA, TREASURY_WALLET_DEV, fee_split  # noqa: E402
from ai.fnx_ai import kernel_chain_hash                        # noqa: E402

BASE = _pl.Path("/tmp/fenix-real-e2e")
PORTS = {"A": 46101, "B": 46102, "C": 46103}
PROXY_PORT = 46113                    # sniffowany kanał C→B (D70 drut-proof)
DONATE_AMT = ISKRA                                             # 1.0 FNX
JOB_LABEL = "real-e2e-grid-batch"
WIRE_MARKERS = (JOB_LABEL.encode(), b"fenix-ai-grid", b"real-e2e D68",
                b"FNX1", b'"amount"', b"chain_hash", b"winner")
FACTS: list[str] = []


def fact(line: str) -> None:
    FACTS.append(line)
    print(f"FACT  {line}", flush=True)


def fail(line: str) -> None:
    print(f"FAIL  {line}", flush=True)
    print(f"[real_e2e] LOGI: {BASE}")
    sys.exit(1)


class LiveNode:
    """Osobny proces demona fenix_node (dev-zbits=2, bez cover, sentinel off)."""

    def __init__(self, name: str, seeds: tuple[str, ...] = (),
                 ai_grid: bool = False):  # noqa: D107
        self.name = name
        self.dir = BASE / name
        self.dir.mkdir(parents=True, exist_ok=True)
        self.sock = str(self.dir / "node.ipc")
        self.log = open(BASE / f"{name}.log", "ab")
        cmd = [sys.executable, "-u", "-m", "net.fenix_node",
               "--host", "127.0.0.1", "--port", str(PORTS[name]),
               "--data-dir", str(self.dir), "--ipc", self.sock,
               "--zbits", "2", "--no-cover", "--sentinel", "off",
               # --no-mine jest KRYTYCZNE: domyślnie demon KOPJE od bootu! Bez tego
               # wszystkie nody kopią ~400 bloków/s od startu i mesh tonie w forkach
               # (kanarek RUN 3: h is 0→378 zanim klient zdążył spojrzeć; zbieg nigdy).
               "--no-mine"]
        if ai_grid:
            cmd += ["--ai-grid"]     # D69: TEN node liczy zadania własnym CPU (opt-in)
        if seeds:
            cmd += ["--seeds", ",".join(seeds)]
        self.proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=self.log,
                                     stderr=subprocess.STDOUT)

    def cli(self) -> BackendIpc:
        return BackendIpc(path=self.sock, timeout=4.0)

    def height(self) -> int:
        return int(self.cli().status()["height"])

    def tip(self) -> str:
        return str(self.cli().status()["tip"])

    def wait_ipc(self, timeout: float = 30.0) -> None:
        t0 = time.time()
        while time.time() - t0 < timeout:
            if os.path.exists(self.sock):
                try:
                    self.cli().status()
                    return
                except Exception:
                    pass
            if self.proc.poll() is not None:
                fail(f"node {self.name} umarł przy starcie (rc={self.proc.returncode})")
            time.sleep(0.3)
        fail(f"IPC {self.name} nie wstało w {timeout}s")

    def wait(self, fn, what: str, timeout: float = 60.0, step: float = 0.5):
        t0 = time.time()
        last = None
        while time.time() - t0 < timeout:
            try:
                last = fn()
                if last[0]:
                    return last[1]
            except Exception:
                pass
            time.sleep(step)
        fail(f"timeout {what} (ostatni stan: {last})")

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if not self.log.closed:
            self.log.close()


class TcpSniffer:
    """GŁUCHA rura TCP: C łączy się tu zamiast do B; przekazuje bajty 1:1 w obie
    strony i SKŁADA pełny strumień do pliku. To jest „kamera na drucie" (D70):
    nie zna żadnych kluczy — widzi DOKŁADNIE to, co widzi ISP/podsłuch."""

    def __init__(self, listen_port: int, upstream: tuple[str, int]):
        self.listen_port = listen_port
        self.upstream = upstream
        self.bytes = bytearray()
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._serve, name="sniffer",
                                   daemon=True)
        self._t.start()

    def _serve(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.listen_port))
        srv.listen(8)
        srv.settimeout(1.0)
        while not self._stop.is_set():
            try:
                cli, _ = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self._relay, args=(cli,), daemon=True).start()

    def _relay(self, cli: socket.socket) -> None:
        try:
            up = socket.create_connection(self.upstream, timeout=10)
        except OSError:
            cli.close()
            return

        def pump(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    chunk = src.recv(65536)
                    if not chunk:
                        break
                    self.bytes += chunk
                    dst.sendall(chunk)
            except OSError:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.close()
                    except OSError:
                        pass

        threading.Thread(target=pump, args=(cli, up), daemon=True).start()
        threading.Thread(target=pump, args=(up, cli), daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        (BASE / "wire_c_b.bin").write_bytes(bytes(self.bytes))


def mine_burst(node: LiveNode, min_gain: int, timeout: float = 60.0) -> int:
    """Kopie na `node` aż przyrośnie ≥min_gain bloków; zwraca wysokość po pauzie.

    DEV zbits=2 = błyskawica: pilnujemy stop co 0.05 s, żeby nie zalać mesha
    tysiącami bloków (staggered = zero fork-flappingu — patrz docstring modułu).
    """
    cli = node.cli()
    start = int(cli.status()["height"])
    cli.set_mining(True)
    t0 = time.time()
    h = start
    try:
        while time.time() - t0 < timeout:
            h = int(cli.status()["height"])
            if h >= start + min_gain:
                break
            time.sleep(0.05)
        else:
            fail(f"timeout kopania na {node.name} (h {start}→{h}, cel +{min_gain})")
    finally:
        cli.set_mining(False)
    # krótka chwila na dobicie ostatniej rundy minera (set_mining(False) wybudza
    # stop= natychmiast, ale gossip ostatniego bloku niech doleci do peerów)
    time.sleep(0.4)
    return int(cli.status()["height"])


def converge_all(nodes: tuple[LiveNode, ...], timeout: float = 150.0) -> tuple:
    """Wszystkie nody na TEN SAM tip (hash) i tę samą wysokość — konsensus, nie fluke.

    Kopanie jest zapauzowane → cel stoi w miejscu. Co ~8 s przypominamy pigułkę
    sync (op `sync` → request_sync_all: prosi peerów o ich łańcuch), bo gossip
    mógł coś uronić; adopt_chain bierze najdłuższy ważny, remis → mniejszy hash.
    """
    t0 = time.time()
    last_sync = 0.0
    last = None
    while time.time() - t0 < timeout:
        if time.time() - last_sync > 8.0:
            for n in nodes:
                try:
                    n.cli().sync()
                except Exception:
                    pass
            last_sync = time.time()
        try:
            tips = [n.tip() for n in nodes]
            hs = [n.height() for n in nodes]
            last = (hs, [t[:12] for t in tips])
            if len(set(tips)) == 1 and len(set(hs)) == 1:
                return hs[0], tips[0]
        except Exception:
            pass
        time.sleep(0.5)
    fail(f"timeout zbiegu konsensusu (ostatni stan: {last})")


def main() -> int:
    shutil.rmtree(BASE, ignore_errors=True)
    BASE.mkdir(parents=True)
    t0 = time.time()
    print(f"[real_e2e] start {time.strftime('%H:%M:%S')} — 3 demony, 1 klient IPC; "
          f"logi: {BASE}")

    sniff = TcpSniffer(PROXY_PORT, ("127.0.0.1", PORTS["B"]))  # kamera na C↔B
    A = LiveNode("A")                                # poster zadań (nie liczy)
    A.wait_ipc()
    B = LiveNode("B", seeds=("127.0.0.1:46101",), ai_grid=True)   # pracownik
    B.wait_ipc()
    C = LiveNode("C", seeds=(f"127.0.0.1:{PROXY_PORT}",), ai_grid=True)  # przez kamerę!
    C.wait_ipc()

    # 1) peers: B↔A i C↔B (łańcuch połączeń po TCP+AEAD)
    pa = A.wait(lambda: (A.cli().status()["peers"] >= 1, A.cli().status()["peers"]),
                "A.peers≥1")
    pb = B.wait(lambda: (B.cli().status()["peers"] >= 2, B.cli().status()["peers"]),
                "B.peers≥2", timeout=45)
    pc = C.wait(lambda: (C.cli().status()["peers"] >= 1, C.cli().status()["peers"]),
                "C.peers≥1")
    fact(f"P2P mesh żyje: peers A={pa} B={pb} C={pc} (seeds→handshake AEAD→połączone)")

    burn, owner, fee_total = fee_split(DONATE_AMT)
    exp_treasury_gain = DONATE_AMT + owner
    fact(f"rachunek D15/D50 dla donate 1 FNX: burn={burn} owner={owner} "
         f"→ skarbiec MUSI urosnąć o {exp_treasury_gain} iskier (liczymy do iskry)")

    # 2) kopanie staggered: najpierw A, potem C — bloki z RÓŻNYCH nodów, JEDEN tip
    h_a = mine_burst(A, 3)
    fact(f"A kopał w pojedynkę: h=0→{h_a} (burst dev zbits=2, błyskawica — pauza)")
    hA2, tipA2 = converge_all((A, B, C))
    fact(f"po sync: A/B/C na h={hA2}, wspólny tip {tipA2[:20]}… "
         f"(bloki A zaadoptowane przez B i C — księga leci przez mesh)")

    h_c = mine_burst(C, 2)
    hC2, tipC2 = converge_all((A, B, C))
    fact(f"C kopał w pojedynkę: h {hA2}→{h_c} → po sync A/B/C znów ZBITOWO zgodne "
         f"(h={hC2}, tip {tipC2[:20]}…) — łańcuch budują różne nody: decentralizacja")

    # 3) DONATE z C (tx podpisana W DEMONIE C) → skarbiec rośnie wszędzie
    price_a = A.cli().price()
    fact(f"pokój cenowy na A przed tx: cena {price_a['price_usd']} "
         f"ask {price_a['ask_usd']} bid {price_a['bid_usd']} "
         f"(podaż {price_a['supply_fnx']:.2f} FNX — krzywa z faktów łańcucha D65)")
    cwl = C.cli().profile()["wallet"]
    bal_t_before = B.cli().balance(TREASURY_WALLET_DEV)
    bal_c_before = A.cli().balance(cwl)
    don = C.cli().donate(DONATE_AMT, note="real-e2e D68")
    fact(f"DONATE z C wysłana z demona: txid {don['txid'][:20]}… kwota 1.0 FNX "
         f"(saldo C przed: {bal_c_before / ISKRA:.4f} FNX z nagród kopania)")
    # gossip C→B→A: A musi zobaczyć tx w mempoolu
    A.wait(lambda: (A.cli().status()["mempool"] >= 1, A.cli().status()["mempool"]),
           "A widzi donate C w mempool (gossip T_TX_SUBMIT przez B)", timeout=90)
    fact("tx C dotarła gosipem C→B→A: wisi w mempoolu A (czeka na blok)")
    h_d = mine_burst(A, 1)
    converge_all((A, B, C))
    bal_t_after = B.cli().balance(TREASURY_WALLET_DEV)
    bal_c_after = B.cli().balance(cwl)
    assert bal_t_after - bal_t_before == exp_treasury_gain, (
        f"skarbiec Δ={bal_t_after - bal_t_before} ≠ {exp_treasury_gain}")
    assert bal_c_before - bal_c_after == DONATE_AMT + fee_total, (
        f"saldo C Δ={bal_c_before - bal_c_after} ≠ {DONATE_AMT + fee_total}")
    fact(f"po bloku A (h={h_d}) i sync: skarbiec na B +{exp_treasury_gain} iskier "
         f"DOKŁADNIE jak D15/D50; saldo C −{DONATE_AMT + fee_total} iskier "
         f"(kwota+fee) — ekonomia zgodna do iskry na 3 nodach")

    # 3b) AI-GRID (D69 na drucie): A ogłasza zadanie przez IPC, B i C liczą
    # WŁASNYM CPU (wątki grid w ich demonach), wyniki podpisane wracają meshem,
    # A składa kworum 2, robi FINALNY recompute i wypłaca nagrody tx-ami.
    bwl = B.cli().profile()["wallet"]
    bal_b0 = A.cli().balance(bwl)
    bal_c0 = A.cli().balance(cwl)
    BOUNTY = ISKRA // 2                       # 0.5 FNX za policzenie
    ITERS = 30_000
    job = A.cli().grid_submit("real-e2e-grid-batch", ITERS, BOUNTY,
                              quorum_k=2, window_h=256)
    fact(f"AI-GRID: zadanie {job['job'][:16]}… ogłoszone z A (chain_hash {ITERS} iters, "
         f"bounty {BOUNTY / ISKRA:.2f} FNX, kworum 2; seed=tip {job['tip_hash'][:12]}…)")

    def _grid_done():
        stt = A.cli().grid_status()
        row = next((r for r in stt["jobs"] if r["job"] == job["job"][:16]), None)
        ok = bool(row and row.get("settle", {}).get("ok")
                  and row["settle"].get("paid") == 2)
        return (ok, row)

    rowA = A.wait(_grid_done, "kworum+pay zadania siatki", timeout=180)
    fact(f"AI-GRID: {rowA['results']} wyników od różnych walletów → kworum "
         f"{rowA['quorum_k']} → FINALNY recompute → settle paid={rowA['settle']['paid']} "
         f"(nagrody TX_TRANSFER w mempoolu A)")
    truth_local = kernel_chain_hash(job["tip_hash"], "real-e2e-grid-batch", ITERS)
    assert rowA["settle"]["truth"] == truth_local, \
        "recompute demona ≠ NIEZALEŻNY recompute harnessu!"
    assert set(rowA["settle"]["winners"]) == {bwl, cwl}, \
        f"zwycięzcy ≠ {{B,C}}: {rowA['settle']['winners']}"
    fact("settle.truth z demona == niezależny recompute harnessu; zwycięzcy = dokładnie "
         "wallets B i C (kernel deterministyczny, podpisy kopert zweryfikowane)")
    h_g = mine_burst(A, 1)
    converge_all((A, B, C))
    bal_b1 = B.cli().balance(bwl)
    bal_c1 = B.cli().balance(cwl)
    assert bal_b1 - bal_b0 == BOUNTY, f"nagroda B Δ={bal_b1 - bal_b0} ≠ {BOUNTY}"
    assert bal_c1 - bal_c0 == BOUNTY, f"nagroda C Δ={bal_c1 - bal_c0} ≠ {BOUNTY}"
    fact(f"po bloku A (h={h_g}) i sync: B +{BOUNTY} iskier i C +{BOUNTY} iskier "
         f"ZA WYKONANIE zadania — siatka AI na mocy użytkowników działa end-to-end (D69)")

    # 4) usługi IPC z osobnego procesu — census + ban_status + price (zgodność)
    cenA = A.cli().census()
    cenC = C.cli().census()
    fact(f"census A: online≈{cenA['online_estimate']} znane={cenA['known_wallets']} "
         f"zarejestrowani={cenA['registered_users']} (ESTYMACJA gossip — D61 głośno)")
    fact(f"census C: online≈{cenC['online_estimate']} znane={cenC['known_wallets']} "
         f"(drugi punkt obserwacji — różnice są uczciwą granicą, nie bugiem)")
    bsa = A.cli().ban_status()
    assert bsa["found"] and bsa["banned"] is False, "ban_status na A martwe"
    bsc = A.cli().ban_status(cwl)
    fact(f"ban_status na A: własny wallet czysty; wallet C found={bsc['found']} "
         f"banned={bsc['banned']} (D66 lusterko konsensusu na żywym IPC)")
    pr_b = B.cli().price()
    assert pr_b["price_usd"] == A.cli().price()["price_usd"], "cena rozjeżdża nody"
    fact(f"pokój cenowy zgodny A==B ({pr_b['price_usd']}) — krzywa liczy się "
         f"ze wspólnego łańcucha, każdy węzeł pokazuje to samo")

    # 5) ghost toggle na C (D63) — stan z demona, uczciwa odpowiedź
    g = C.cli().ghost(True)
    assert g["ghost"] is True
    g2 = C.cli().ghost(False)
    assert g2["ghost"] is False
    fact("toggle ducha na C: ON→OFF przez IPC; stan z demona zgodny (D63 przelata)")

    # 6) trwałość+rejoin (D71; dwa restarty, dwa RÓŻNE dowody):
    #    A2 BEZ SEEDS i odczyt h NATYCHMIAST po starcie → wysokość mogła przyjść
    #    TYLKO z chain.dat (sync nie zdążył; kanarek: wcześniejszy „dysk" był
    #    tak naprawdę pigułką sync — demona wtedy nie interesował zapis wcale).
    h_pre = A.height()
    A.stop()
    fact(f"A zatrzymane SIGINT-em (czyste zejście) przy h={h_pre}")
    cdat = A.dir / "chain.dat"
    if not (cdat.is_file() and cdat.stat().st_size > 64):
        fail(f"chain.dat po stopie A: brak/pusty ({cdat}) — D71 nie działa")
    A2 = LiveNode("A")                                   # BEZ seeds: izolacja od sieci
    A2.wait_ipc()
    h_disk = A2.height()
    A2.stop()
    assert h_disk == h_pre, f"chain.dat dał h={h_disk} ≠ {h_pre} (dysk kłamie)"
    fact(f"restart bez seeds: h={h_disk} przyszło WYŁĄCZNIE z chain.dat "
         f"({cdat.stat().st_size:,} B; replay zerozufaniowy) — łańcuch naprawdę na DYSKU")
    A3 = LiveNode("A", seeds=("127.0.0.1:46102",))       # teraz rejoin do mesha
    A3.wait_ipc()
    pa3 = A3.wait(lambda: (A3.cli().status()["peers"] >= 1,
                           A3.cli().status()["peers"]), "A3 wraca do mesha")
    hR, tipR = converge_all((A3, B, C))
    fact(f"A3 WRÓCIŁ do sieci (peers={pa3}) i po sync znów jeden tip "
         f"{tipR[:20]}… na h={hR} — demon odzyskuje pełnię po ubiciu")

    # 6b) DRUT-PROOF (D70): kamera na kanale C↔B widziała CAŁY ruch tej ścieżki —
    # żaden znacznik treści (label zadania, nota donate, wallet FNX1*, klucze
    # json) NIE WYSTĘPUJE w bajtach. Nagłówki FN są jawne ZGODNIE ze specem
    # (magic/typ/seq/len — meta); treść = CT(AEAD ChaCha20-Poly1305) ⊕ peleryna
    # FNX64 (tetracja do 10). Surowy heks = artefakt do raportu, nie napis.
    blob = bytes(sniff.bytes)
    if len(blob) < 20_000:
        fail(f"sniffer widział za mało ruchu: {len(blob)} B (spodziewane ≥20 KB)")
    leaked = [m for m in WIRE_MARKERS if m in blob]
    assert not leaked, f"PRZECIEK na drucie: {leaked}"
    magic_cnt = blob.count(b"FN\x02")
    hexa = blob[4096:4096 + 96].hex()
    uniq = len(set(blob))
    fact(f"DRUT-PROOF: sniffer C↔B złapał {len(blob):,} B; znaczniki treści "
         f"(label/nota/wallet/amount/winner): ZERO wystąpień; unikalne bajty "
         f"{uniq}/256; nagłówków FN widocznych: {magic_cnt} (meta jawne — specem tak)")
    fact(f"DRUT-HEX [artefakt]: {hexa[:96]}")

    # 7) stabilność po scenariuszu: zero traceback w logach demonów
    for name in ("A", "B", "C"):
        log_txt = (BASE / f"{name}.log").read_text(errors="replace")
        if "Traceback" in log_txt:
            fail(f"Traceback w logu {name}:\n{log_txt[-1500:]}")
    fact("logi demonów czyste: ZERO Traceback po całym scenariuszu")

    A3.stop(); B.stop(); C.stop()
    sniff.stop()
    dt = time.time() - t0
    summary = {"ok": True, "duration_s": round(dt, 1), "facts": FACTS,
               "artifacts": {**{n: str(BASE / f"{n}.log") for n in ("A", "B", "C")},
                             "wire": str(BASE / "wire_c_b.bin")}}
    print("\n--- JSON ---")
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    print(f"\nREAL-E2E: PASS ✅  {len(FACTS)} faktów z ŻYWYCH procesów "
          f"({dt:.0f} s) — D68")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    finally:
        # ostatnia deska: nie zostawiaj demonów-wiosek
        subprocess.run(["pkill", "-f", "net.fenix_node.*--port 4610"],
                       capture_output=True)
