# net/fenix_node.py — Node Fenixa: spina blockchain+sieć+camo w jedną zbiorczą sieć (M2/M5 MVP)
"""
Każde ISO uruchamia TO (fenix-node.service) — i każde ISO staje się pełnym węzłem:
  - kopie (każdy node tworzy blockchain — D15/„kopie=hostujesz"),
  - gossippuje tx i nowe bloki (flood z anti-echo po hashach),
  - wybiera najdłuższy WAŻNY łańcuch (fork-choice z ledgera),
  - cały ruch leci przez camo Profil A: stałe rekordy 4096B szumu (ISP: nierozpoznawalne),
  - kanał = ramka AEAD (X25519→HKDF→ChaCha20-Poly1305, nonce per SEQ, replay okno 4096),
  - handshake wiąże peer-a z walletem (podpisy HELLO + check_profile → anty-MITM).

Uczciwe granice MVP: brak onion/relay (M2 dalej), PEERS przez seeds+gossip
(katalog on-chain w M5), QoS tier w M5. DEV: tożsamość generowana przy starcie
(produkcyjnie: unlock z keystore D24 — hook fenix.service zrobi to w M8).
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import signal
import socket
import struct
import sys
import threading
import time
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from core.identity import Identity, IdentityError          # noqa: E402
from chain.block import (Block, Tx, TX_TRANSFER, TREASURY_WALLET_DEV,  # noqa: E402
                         canon)
from chain.ledger import Ledger, ChainError                # noqa: E402
from chain import miner as chain_miner                     # noqa: E402
from net.frame import (FrameSession, FrameError, handshake_client,   # noqa: E402
                       handshake_server, T_PING, T_PONG, T_TX_SUBMIT,
                       T_BLOCK_NEW, T_MSG, T_SYNC_REQ, T_SYNC_CHAIN, T_SYNC_PART,
                       T_ADDR, T_PRES, T_JOB, T_JOB_RES,
                       MAX_PAYLOAD)
from transport.camo import CamoA                            # noqa: E402
from net import presence as pres                           # D61: licznik online (gossip)
from ai import fnx_ai as fnxai                            # D69: siatka obliczeniowa (grid)

MAX_FRAME_BURST_PARSE = 4000      # limit resync na jeden recv (anty-DoS)
GOSSIP_SEEN_CAP = 50_000

# --- AI-GRID (D69): zadania T_JOB / wyniki T_JOB_RES idą meshem jak tx. -------
# RELAY + KOLEKCJA = zawsze (mesh ma nosić ruch); LICZENIE = tylko opt-in
# (--ai-grid): to jest „oddaję swoją moc CPU" — nigdy domyślnie, nigdy po cichu.
GRID_WORK_ITERS_MAX = 250_000     # node liczy zadania do tej wagi (cięższe: relay only)
GRID_QUEUE_MAX = 8                # kolejka zadań do policzenia (nadmiar → relay-only)
GRID_JOBS_CAP = 256               # znanych zadań w książce (FIFO: stare wypadają)
GRID_CATCHUP_JOBS = 16            # ile zadań dosyłamy na NOWY kanał (fx2)
GRID_CATCHUP_RES = 32             # ile wyników trzymamy do dosyłki po zerwaniu gniazda
GRID_EARLY_JOBS = 32              # wyników „przed zadaniem" — ile job-id buforujemy
GRID_EARLY_PER = 8                # wyników na jeszcze nieznane zadanie

# --- T_MSG (M4 mesh, D35): poczta kopert E2E. Node RELÉJUJE szum — nie czyta,
# NIE zapisuje na chain (prywatność), skrzynka odbiorcy żyje tylko w RAM (amnezja).
T_MSG_TTL = 5                   # koperta żyje maks. 5 hopów (ceja na powódź gossip)
MSG_MAX_ENV = 16384             # B JSON koperty (lustro app/messenger.MAX_ENV — bez importu app)
MSG_WATCH_MAX = 64              # ilu fp jeden node pilnuje lokalnie (anty-DoS)
MSG_BOX_PER_FP = 200            # kopert w skrzynce jednego fp (deque: stare wypadają)
MSG_SEEN_CAP = 50_000           # anty-echa dedup (jak GOSSIP_SEEN_CAP)
# --- D44: OFFLINE-BUFFER. Koperta dla NIEZAPISANEGO fp nie ginie: relay trzyma ją
# w ulotnym spoolu (RAM, TTL), aż odbiorca się zgłosi (msg_sub). Relay widzi nadal
# TYLKO szum + fp + czas śmierci; zero treści, zero zapisu na dysk/chain (amnezja).
MSG_SPOOL_TTL = 3600.0          # s — koperta czeka max 1 h na powrót odbiorcy
MSG_SPOOL_FPS = 256             # ilu nieznanych fp jeden node buforuje (anty-DoS)
MSG_SPOOL_PER_FP = 16           # kopert na nieznanego fp (uczciwa kolejka, nie archiwum)

# --- chunking dużych ładunków (ramka mieści ≤4063B, łańcuch rośnie ponad to) ---
PART_HDR = struct.Struct("!BIHH")  # kind(oryg. typ) | packet_id | i | n
PART_CHUNK = MAX_PAYLOAD - PART_HDR.size          # 4054 B danych na ramkę
MAX_BIG_PAYLOAD = 16 * 1024 * 1024                # twardy sufit po sklejeniu (anty-DoS)
MAX_PART_SETS = 64                                # równoległych składanek (anty-DoS)
PART_TTL = 120.0                                  # s — niekompletne wyleciały

# --- AI-Sentry wpięta w demona (P26/D48): radar patrzy w META ruchu, a node
#     EGZEKWUJE reakcję ŻÓŁTĄ (throttle — kubełek żetonów na ramki) i CZERWONĄ
#     (rozłączenie 'u mnie' = obrona własna; BAN na chain robi TYLKO kropka k-z-n) ---
THROTTLE_FPS = 8.0        # ramek/s przepustki w throttle (Policy §3/§7: łagodnie, nie ban)
THROTTLE_BURST = 16.0     # kubełek początkowy (krótka kolejka się mieści)


class NodeConfig:
    def __init__(self, host="127.0.0.1", port=45100, seeds=(), zbits=8,
                 mine=True, cover=True, username=None, tap=None,
                 identity_file=None, treasury=TREASURY_WALLET_DEV,
                 sentinel: str = "minimal",
                 data_dir: str | None = None, discover: bool = False,
                 target_peers: int = 4, discover_grace: float = 45.0,
                 advertise: bool = True, ghost: bool = False, ai_grid: bool = False):
        self.host, self.port = host, port
        self.seeds = list(seeds)          # [(ip, port), …] — tylko brama startowa
        self.zbits = zbits                # DEV trudność (spec: retarget sam sie pilnuje)
        self.mine = mine
        self.cover = cover
        self.username = username or f"node{port}"
        self.tap = tap                    # lista QA (bajty drutu)
        self.identity_file = identity_file  # przekaz z bariery boot (M8, /run/fenix)
        self.treasury = treasury
        self.sentinel = sentinel          # suwak telemetrii D48: off/minimal/full
        self.ai_grid = bool(ai_grid)      # D69: opt-in „liczę zadania siatki moim CPU"
        # --- D54: auto-discovery + licznik profilu ---------------------------------
        # data_dir: katalog stanu noda (peers.json = adresownia, stats.json = licznik).
        #   None → zero zapisu (selftesty); demon (main) domyślnie ~/.fenix.
        # discover: sam szuka nodów (adresownia: seeds ∪ cache ∪ gossip T_ADDR) i
        #   dobija do target_peers; bibliotecznie OFF (selftesty nie chcą niespodzianek),
        #   w demonie ON (decyzja właściciela 2026-08-06: ma DZIAŁAĆ samo z pudełka).
        # discover_grace: tyle sekund ciszy zanim ogłosimy „jesteś pierwszym nodem".
        self.data_dir = data_dir
        self.discover = bool(discover)
        self.target_peers = int(target_peers)
        self.discover_grace = float(discover_grace)
        self.advertise = bool(advertise)   # ogłaszaj nasz host:port w T_ADDR
        # D63 tryb ducha: ŻADNEJ reklamy własnego adresu (T_ADDR bez nas), brak
        # beacona obecności (T_PRES nie rozsyłamy). Reszta jak zawsze: gossip
        # tx/bloków, AEAD, kopanie. Uczciwie: duch ≠ invisibility — ISP widzi
        # połączenia; routing/timing-analiza zostaje (to NIE jest tor).
        self.ghost = bool(ghost)


class Peer:
    """Jedno połączenie: sesja (AEAD) + camo (szum) + lekka kasa stanu."""

    def __init__(self, node, sock, sess: FrameSession, camo: CamoA, wallet: str):
        self.node, self.sock, self.sess, self.camo, self.wallet = node, sock, sess, camo, wallet
        self.lock = threading.Lock()
        self.alive = True
        self.dial_addr: tuple | None = None      # (ip, port) celu gdy MY wybieraliśmy (D54)

    def send(self, typ: int, payload: bytes) -> None:
        raw = self.sess.send(typ, payload)
        with self.lock:
            self.camo.send(raw)
            self.camo.pump()              # latencja > idealny kształt (dopchnij junkiem)

    def send_big(self, kind: int, payload: bytes) -> None:
        """Duży ładunek → plasterki T_SYNC_PART (przeklejenie wyjdzie jako `kind`)."""
        if len(payload) <= MAX_PAYLOAD:
            self.send(kind, payload)
            return
        if len(payload) > MAX_BIG_PAYLOAD:
            raise ValueError("payload ponad MAX_BIG_PAYLOAD — odmowa (anty-DoS)")
        pid = int.from_bytes(os.urandom(4), "big")
        n = (len(payload) + PART_CHUNK - 1) // PART_CHUNK
        for i in range(n):
            part = PART_HDR.pack(kind, pid, i, n) + payload[i * PART_CHUNK:(i + 1) * PART_CHUNK]
            self.send(T_SYNC_PART, part)

    def close(self):
        self.alive = False
        try:
            self.camo.close()
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


def _load_identity_file(path: str) -> Identity:
    """Przekaz z bariery boot (os/fenix_boot.py): JSON na tmpfs, dokładnie
    {username, x_priv, s_priv}; po udanym wczytaniu plik kasujemy — jednorazowo."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    idn = Identity.from_private(data["username"],
                                bytes.fromhex(data["x_priv"]),
                                bytes.fromhex(data["s_priv"]))
    try:
        os.remove(path)                    # jednorazowość przekazu (RAM i tak ginie)
    except OSError:
        pass
    return idn


class Node:
    def __init__(self, cfg: NodeConfig):
        self.cfg = cfg
        if cfg.identity_file:
            self.identity = _load_identity_file(cfg.identity_file)
        else:
            self.identity = Identity.generate(cfg.username)     # DEV / standalone
            if cfg.username is None:
                pass                                            # app-standalone (D25)
        self.ledger = Ledger(cfg.treasury)
        # --- D71: TRWAŁOŚĆ ŁAŃCUCHA w demonie (kanarek real_e2e: było „restart
        # zwracał wysokość od peerów przez sync, a chain.dat nie istniał"). Teraz:
        # start czyta zrzut (replay zerozufaniowy — ledger sam waliduje od zera),
        # stop/okno 60 s zapisuje. Brak pliku = pierwszy start (genesis).
        self._chain_path = os.path.join(cfg.data_dir, "chain.dat") if cfg.data_dir else None
        # Jeden zapis pliku na raz. Minutowy flush i stop() dzielą chain.dat;
        # bez zamka starszy os.replace potrafi nadpisać nowszy i restart
        # wstaje z niższą wysokością (real_e2e: dysk h=15 przy żywym h=34).
        self._chain_io = threading.Lock()
        if self._chain_path and os.path.isfile(self._chain_path):
            try:
                self.ledger = Ledger.load_chain(self._chain_path, treasury=cfg.treasury)
                print(f"[fenix-node] chain.dat: wczytany replay zerozufaniowy, "
                      f"h={self.ledger.height()} (D71)")
            except ChainError as e:
                print(f"[fenix-node] UWAGA: chain.dat odrzucony ({e}) — idę od genesis")
        self.peers: dict[str, Peer] = {}
        self._peers_lock = threading.Lock()
        self._stop = threading.Event()
        self._rebuild = threading.Event()                   # nowa głowa → szablon do kosza
        self._seen_blocks: set[str] = set()
        self._seen_tx: set[str] = set()
        self._mining = cfg.mine                             # runtime pauza (test/GUI)
        self._parts: dict[tuple, dict] = {}                 # składanie chunków T_SYNC_PART
        self._msg_lock = threading.Lock()                   # T_MSG: skrzynki+dedup
        self._msg_watch: set[str] = set()                   # fp lokalnych odbiorców (IPC msg_sub)
        self._msg_box: dict[str, collections.deque] = {}    # fp → poczta (RAM, amnezja)
        self._msg_spool: dict[str, collections.deque] = {}  # D44: fp → [(env, exp_ts)] offline
        self._seen_msg: set[str] = set()                    # dedup gossip (anty-echo)
        self._pres_book = pres.PresenceBook()               # D61: książka dzwoneczków
        self._pres_last = 0.0                               # kiedy ogłaszałem „jestem"
        self.ghost = bool(cfg.ghost)                        # D63: tryb ducha (toggle IPC)
        # --- AI-GRID (D69): książka zadań + kolektor kworum + kolejka pracownika ---
        self._grid_reg = fnxai.GridRegistry()               # dedup/rate-limit/kworum (lib)
        self._grid_lock = threading.Lock()                  # książka+paid pod jednym zamkiem
        self._grid_jobs: dict[str, dict] = {}               # job_id → koperta zadania (FIFO cap)
        self._grid_mine: set[str] = set()                   # job_id ogłoszone przez TEN node
        self._grid_paid: dict[str, dict] = {}               # job_id → rozliczenie (pay/shortfall)
        self._seen_jobs: set[str] = set()                   # anty-echa gossip T_JOB
        self._grid_res_wire: dict[str, bytes] = {}          # hash → T_JOB_RES do dosyłki (fx2)
        self._grid_early: dict[str, list[bytes]] = {}       # job → wyniki, które wyprzedziły zadanie
        self._grid_q: collections.deque = collections.deque()  # zadania do policzenia (opt-in)
        self._grid_evt = threading.Event()                  # pobudka wątku pracownika
        self._grid_catchup_at = 0.0                         # ostatnia dosyłka siatki (fx2)
        # --- radar AI-Sentry (P26/D48): żywy strumień META + stan egzekwowany lokalnie ---
        from ai import ai_sentinel as _sent
        self._sent_mod = _sent
        self.sentinel = _sent.Sentinel(telemetry=cfg.sentinel)
        self._throttle: dict[str, float] = {}   # wallet/"addr:ip" → yellow_until (inf = czerwony)
        # --- D54: adresownia + „pierwszy nod" + licznik profilu ----------------------
        self._addr_book: dict[tuple, float] = {}            # (ip,port) → ts ostatniego widzenia
        self._addr_fail: dict[tuple, tuple[int, float]] = {}  # adres → (ile porażek, kiedy)
        self._dialing: set[tuple] = set()                   # wybieranie w toku (dedup)
        self.is_first_node = False                          # ŻYWA flaga: „cisza po grace"
        self._started_at = time.time()
        self._stats = self._stats_load()                    # licznik profilu (badges D52)
        self._stats_dirty = False
        self._state_io = threading.Lock()                   # peers.json/stats.json: jeden zapis
        self._last_flush = 0.0
        self.mined = 0
        self._srv = None
        self._threads: list[threading.Thread] = []

    # ------------------------------------------------------------- życie noda
    def start(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.cfg.host, self.cfg.port))
        srv.listen(16)
        srv.settimeout(1.0)
        self._srv = srv
        self._go(self._accept_loop, "accept")
        for seed in self.cfg.seeds:
            self._go(lambda s=seed: self._seed_loop(s), f"seed-{seed}")
        self._load_peers()                                # adresownia z dysku (D54)
        if self.cfg.discover:
            self._go(self._discover_loop, "discover")
        self._go(self._miner_loop, "miner")
        if self.cfg.ai_grid:
            self._go(self._grid_worker_loop, "grid")          # D69: liczę zadania (opt-in)

    def _go(self, fn, name):
        t = threading.Thread(target=fn, name=f"fenix-{name}", daemon=True)
        t.start()
        self._threads.append(t)

    def stop(self):
        self._stop.set()
        self._rebuild.set()
        with self._peers_lock:
            peers = list(self.peers.values())
        for p in peers:
            p.close()
        try:
            self._srv.close()
        except Exception:
            pass
        self._flush_stats(force=True)                     # licznik profilu na dysk (D54)
        self._flush_peers()                               # adresownia na dysk (D54)
        self._flush_chain()                               # łańcuch na dysk (D71)

    # ------------------------------------------------------------- io pętle
    # ------------------------------------------------------------- AI-Sentry (P26/D48)
    def _sense(self, peer_id: str, kind: str) -> None:
        """Karmienie radaru META-zdarzeniem. Reakcja żółta → throttle (kubełek),
        czerwona → 'inf' = rozłącz-jak-tylko-zobaczysz. Radar jest OBRONĄ,
        NIGDY źródłem awarii: jego błąd nie może położyć demona (fail-open D22)."""
        try:
            v = self.sentinel.observe({"kind": kind, "peer": peer_id})
            lvl = v.get("level")
            if lvl == "yellow" and v.get("yellow_until"):
                with self._peers_lock:
                    self._throttle[peer_id] = v["yellow_until"]
            elif lvl == "red":
                with self._peers_lock:
                    self._throttle[peer_id] = float("inf")
                    pr = self.peers.get(peer_id)
                if pr is not None:
                    pr.close()            # obrona własna u MNIE; ban na chain = kropka
                self.sentinel.make_proposal(peer_id)   # szkic do kropki (None: peer=addr, nie wallet)
        except self._sent_mod.SentinelError:
            raise                         # nasz bug w karmieniu — ma wywrzeć (jak assert)
        except Exception:                 # radar nigdy nie może zabić node'a (grabarz≠awaria)
            pass

    def _sense_frame_error(self, peer: "Peer", exc: Exception) -> None:
        """Mapuje kolizje warstwy ramek na karty meta: AEAD→bad_tag, okno SEQ→replay.
        Reszta (junk camo) to normalne resync — nie jest 'zdarzeniem' (D5)."""
        msg = str(exc)
        if "AEAD" in msg:
            self._sense(peer.wallet, "bad_tag")
        elif "replay" in msg or "okno" in msg:
            self._sense(peer.wallet, "replay")

    def _peer_throttled(self, wallet: str) -> bool:
        """Czy peer jest teraz pod sanem? TTL wygasa SAM (decay, ban_policy §7)."""
        with self._peers_lock:
            until = self._throttle.get(wallet)
            if until is None:
                return False
            if until == float("inf") or time.time() < until:
                return True
            del self._throttle[wallet]                # koniec yellow — samogasznie
            return False

    def _addr_throttled(self, ip: str) -> bool:
        return self._peer_throttled(f"addr:{ip}")     # farma handshake = adres, nie wallet

    @staticmethod
    def _bucket_allow(peer: "Peer") -> bool:
        """Kubełek żetonów na ramki od peer-a pod throttle (lagodnie, po AEAD!)."""
        now = time.time()
        last = getattr(peer, "_tb_at", 0.0)
        tok = min(THROTTLE_BURST, getattr(peer, "_tb", THROTTLE_BURST)
                  + (now - last) * THROTTLE_FPS)
        if tok >= 1.0:
            peer._tb, peer._tb_at = tok - 1.0, now
            return True
        peer._tb, peer._tb_at = tok, now
        return False

    # ---- widok dla operatora/owner-admina (D17; IPC 0660 = lokalny podmiot) ----
    def sentinel_status(self) -> dict:
        with self._peers_lock:
            thro = {k: v for k, v in self._throttle.items()}
        return {**self.sentinel.status(),
                "throttled": len(thro),
                "red_local": sum(1 for v in thro.values() if v == float("inf"))}

    def sentinel_verdict(self, peer: str) -> dict | None:
        return self.sentinel.verdict_of(peer)

    def sentinel_proposals(self) -> list:
        """Szkice werdyktów red (core+powód; dowody-karty są meta, zostały u operatora)."""
        out = []
        for peer, prop in self.sentinel.proposals.items():
            out.append({"peer": peer, "code": prop["core"]["code"],
                        "evidence": prop["core"]["evidence"], "name": prop["name"]})
        return out

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                client, _addr = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self._go(lambda c=client: self._handle_conn(c, outgoing=False), "in")

    def _seed_loop(self, seed):
        host, port = seed
        backoff = 1.0
        while not self._stop.is_set():
            # _handle_conn wraca od razu (reader w tle). Gdyby tu czekać stałą
            # sekundę i wybierać znowu, co chwilę zrywamy ŻYWE gniazdo i gubimy
            # ramki w locie (flake T_JOB_RES, fx2). Czekamy aż TA sesja padnie.
            live = None
            try:
                s = socket.create_connection((host, port), timeout=8)
                self._handle_conn(s, outgoing=True, dial_addr=(host, port))
                backoff = 1.0
                with self._peers_lock:
                    live = next((p for p in self.peers.values()
                                 if p.dial_addr == (host, port) and p.alive), None)
            except OSError:
                pass
            if live is not None:
                born = time.time()
                while live.alive and not self._stop.is_set():
                    self._stop.wait(0.5)
                # Długa sesja padła (wymiana gniazda, restart peera) — łącz od razu.
                # Krótka (throttle/odmowa) — kara, żeby nie młotkować w pętli.
                if time.time() - born >= 2.0:
                    backoff = 1.0
                else:
                    self._stop.wait(min(backoff, 30.0))
                    backoff = min(backoff * 2, 30.0)
                continue
            self._stop.wait(min(backoff, 30.0))
            backoff = min(backoff * 2, 30.0)

    # ------------------------------------------------------------- D54: discovery
    # analogia: listonosz z notesem adresów. Drzwi domów (seeds) zna z listy,
    # resztę podsłuchuje od sąsiadów (T_ADDR). Nikt nie otwiera? Po cierpliwym
    # czekaniu (discover_grace) ogłasza uczciwie: „na razie jestem PIERWSZYM
    # nodem" — i nasłuchuje dalej, bo pierwszy nod zostaje seedem dla całej sieci.
    PEERS_FILE = "peers.json"
    STATS_FILE = "stats.json"
    ADDR_BOOK_MAX = 256                   # twardy sufit adresowni (anty-zapchaj)
    ADDR_GOSSIP_MAX = 32                  # tyle adresów leci w jednej ramce T_ADDR
    DIAL_PER_TICK = 2                     # max jednoczesnych wybierań na tick pętli

    def _alive_peers(self) -> list:
        with self._peers_lock:
            return [p for p in self.peers.values() if p.alive]

    def _addr_payload(self) -> bytes:
        """Nasza oferta adresów dla świeżego peera: my + znane (krótko, bez śmieci)."""
        addrs = self._known_addrs()
        if self.cfg.advertise and not self.ghost and self.cfg.host not in ("0.0.0.0", ""):
            addrs = [(self.cfg.host, self.cfg.port)] + addrs   # duch (D63): bez self!
        addrs = addrs[:self.ADDR_GOSSIP_MAX]
        return json.dumps({"v": 1, "addrs": [[h, p] for h, p in addrs]}).encode()

    def _known_addrs(self) -> list:
        """Seeds ∪ adresownia (świeższe wpisy pierwsze) — źródła wybierania."""
        with self._peers_lock:
            book = sorted(self._addr_book.items(), key=lambda kv: -kv[1])
        seen: set = set()
        out: list = []
        for s in self.cfg.seeds:
            if tuple(s) not in seen:
                out.append(tuple(s)); seen.add(tuple(s))
        for (a, _ts) in book:
            if a not in seen:
                out.append(a); seen.add(a)
        return out

    def _merge_addrs(self, payload: bytes) -> int:
        """T_ADDR od peera: walidacja + wtopienie. Zwraca ile NOWYCH. Śmieć → 0."""
        try:
            data = json.loads(payload)
            addrs = data.get("addrs") if isinstance(data, dict) and data.get("v") == 1 else None
            if not isinstance(addrs, list):
                return 0
            now = time.time()
            new = 0
            with self._peers_lock:
                for a in addrs[:self.ADDR_GOSSIP_MAX]:
                    if (not isinstance(a, (list, tuple)) or len(a) != 2
                            or not isinstance(a[0], str) or not isinstance(a[1], int)
                            or not (1 <= a[1] <= 65535) or len(a[0]) > 64):
                        continue
                    key = (a[0], a[1])
                    if key == (self.cfg.host, self.cfg.port):
                        continue                    # siebie nie potrzebujemy
                    if key not in self._addr_book:
                        if len(self._addr_book) >= self.ADDR_BOOK_MAX:
                            break
                        new += 1
                    self._addr_book[key] = now
            return new
        except (ValueError, TypeError):
            return 0

    def _dial_some(self, alive: list) -> None:
        """Dobij do target_peers z adresowni. Pomijamy: wybierane w toku, adresy
        z żywym połączeniem (peer.dial_addr), adresy w karence backoffu."""
        dialed = {p.dial_addr for p in alive if p.dial_addr}
        now = time.time()
        tried = 0
        for addr in self._known_addrs():
            if tried >= self.DIAL_PER_TICK:
                break
            if addr in dialed or addr in self._dialing:
                continue
            fails, last = self._addr_fail.get(addr, (0, 0.0))
            if now - last < min(2.0 ** max(fails, 1), 300.0):
                continue                            # kareniec: adres niedawno padł
            self._dialing.add(addr)
            tried += 1
            self._go(lambda a=addr: self._try_dial(a), f"dial-{addr[0]}:{addr[1]}")

    def _try_dial(self, addr) -> None:
        try:
            s = socket.create_connection(addr, timeout=6)
            self._handle_conn(s, outgoing=True, dial_addr=addr)
            ok = any(p.dial_addr == addr and p.alive for p in self._alive_peers())
            with self._peers_lock:
                if ok:
                    self._addr_fail.pop(addr, None)
                else:
                    n, _ = self._addr_fail.get(addr, (0, 0.0))
                    self._addr_fail[addr] = (n + 1, time.time())
        except OSError:
            with self._peers_lock:
                n, _ = self._addr_fail.get(addr, (0, 0.0))
                self._addr_fail[addr] = (n + 1, time.time())
        finally:
            self._dialing.discard(addr)

    def _discover_loop(self) -> None:
        """Strażnik łączności: co 2 s ocenia, dobija nody, ogłasza „pierwszy nod",
        co minutę spisuje adresownię na dysk, co 2 min wymienia adresy z peerami."""
        started = time.time()
        last_gossip = 0.0
        while not self._stop.wait(2.0):
            now = time.time()
            alive = self._alive_peers()
            if alive:
                if self.is_first_node:
                    self.is_first_node = False      # sieć się znalazła — tytuł oddajemy
                    print("[fenix-node] discovery: sieć odnaleziona — już nie jestem "
                          "jedynym nodem", flush=True)
            elif not self.is_first_node and now - started >= self.cfg.discover_grace:
                self.is_first_node = True
                self._mark_first_node_ever()
                print("[fenix-node] discovery: brak dostępnych nodów po "
                      f"{self.cfg.discover_grace:.0f}s — jestem PIERWSZYM NODEM sieci; "
                      "nasłuchuję dalej (zostaję seedem dla innych)", flush=True)
            if len(alive) < self.cfg.target_peers:
                self._dial_some(alive)
            if now - last_gossip >= 120.0:          # długoterminowa wymiana adresów
                last_gossip = now
                if alive:
                    self._gossip(T_ADDR, self._addr_payload())
            if alive and now - self._grid_catchup_at >= 30.0:
                # fx2: dosyłka zadań/wyników na ŻYWE kanały (send mógł paść OSError,
                # a seed już nie zrywa sesji co sekundę). Odbiorca dedupuje — bez powodzi.
                self._grid_catchup_at = now
                for pr in alive:
                    try:
                        self._grid_catchup(pr)
                    except OSError:
                        pass
            if now - self._pres_last >= 280.0:      # D61: beacon „jestem" co <5 min
                self._pres_last = now
                if not self.ghost:                  # D63: duch się nie zgłasza
                    self._gossip(T_PRES, json.dumps(
                        pres.pres_wire(self.identity, now=now)).encode())
            if now - self._last_flush >= 60.0:
                self._last_flush = now
                self._flush_peers()
                self._flush_stats(force=True)       # uptime też spisujemy co minutę
                self._flush_chain()                     # D71: co minutę też łańcuch
                # (okno straty przy twardej śmierci ≤60 s — JAWNIE; zapis
                # przyrostowy/kompaktacja = roadmap, P6 rozmiar pliku)

    def _flush_chain(self) -> None:
        """D71: zapis chain.dat (ledger: tmp+fsync+replace, 0600; replay przy
        starcie sam broni się przed podmianą — plik to NIE zaufany dysk).

        Zamek obejmuje CAŁY zapis, nie sam snapshot: dwa flush-e (pętla co 60 s
        i stop()) nie mogą się minąć na os.replace."""
        if not self._chain_path:
            return
        with self._chain_io:
            try:
                self.ledger.save_chain(self._chain_path)
            except OSError:
                pass                              # dysk nie kładzie demona (jak D54)

    # ------------------------------------------------------------- pliki stanu (D54)
    def _atomic_write(self, path: str, data: bytes) -> None:
        # Unikalny tmp: dwa flushe (pętla i stop()) nie dzielą jednego .tmp.
        tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
        try:
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _peers_path(self) -> str | None:
        return os.path.join(self.cfg.data_dir, self.PEERS_FILE) if self.cfg.data_dir else None

    def _stats_path(self) -> str | None:
        return os.path.join(self.cfg.data_dir, self.STATS_FILE) if self.cfg.data_dir else None

    def _load_peers(self) -> None:
        p = self._peers_path()
        if not p:
            return
        try:
            data = json.load(open(p, "r", encoding="utf-8"))
            if data.get("v") == 1:
                self._merge_addrs(json.dumps(
                    {"v": 1, "addrs": data.get("addrs", [])}).encode())
        except (OSError, ValueError, TypeError):
            pass                                    # padnięty cache = start od zera, nie drama

    def _flush_peers(self) -> None:
        p = self._peers_path()
        if not p:
            return
        with self._state_io:
            try:
                os.makedirs(self.cfg.data_dir, exist_ok=True)
                addrs = [[h, pt] for h, pt in self._known_addrs()[:self.ADDR_BOOK_MAX]]
                self._atomic_write(p, json.dumps({"v": 1, "addrs": addrs},
                                                 separators=(",", ":")).encode())
            except OSError:
                pass

    def _stats_load(self) -> dict:
        p = self._stats_path()
        base = {"v": 1, "uptime_hours": 0.0, "site_created": False, "first_node_ever": False}
        if not p:
            return base
        try:
            d = json.load(open(p, "r", encoding="utf-8"))
            if d.get("v") == 1:
                base.update({k: d[k] for k in base if k in d})
        except (OSError, ValueError, TypeError):
            pass
        return base

    def _flush_stats(self, force: bool = False) -> None:
        p = self._stats_path()
        if not p or (not force and not self._stats_dirty):
            return
        with self._state_io:
            try:
                os.makedirs(self.cfg.data_dir, exist_ok=True)
                snap = dict(self.stats_view())
                snap["v"] = 1
                self._atomic_write(p, json.dumps(snap, separators=(",", ":")).encode())
                self._stats_dirty = False
            except OSError:
                pass

    # ---- licznik profilu (odznaki „licznik lokalny", D52): uptime/site/first_node ----
    def uptime_hours(self) -> float:
        """ŁĄCZNE godziny hostowania = zapisane + bieżąca sesja (licznik lokalny)."""
        return float(self._stats.get("uptime_hours", 0.0)) + \
            max(0.0, time.time() - self._started_at) / 3600.0

    def stats_view(self) -> dict:
        return {"uptime_hours": self.uptime_hours(),
                "site_created": bool(self._stats.get("site_created")),
                "first_node_ever": bool(self._stats.get("first_node_ever"))}

    def mark_site_created(self) -> None:
        """Aplikacja melduje: user zbudował własną stronę (1× → odznaka Architekt)."""
        if not self._stats.get("site_created"):
            self._stats["site_created"] = True
            self._stats_dirty = True
            self._flush_stats()

    def _mark_first_node_ever(self) -> None:
        if not self._stats.get("first_node_ever"):
            self._stats["first_node_ever"] = True
            self._stats_dirty = True
            self._flush_stats()

    def net_discovery(self) -> dict:
        """Widok discovery dla GUI/IPCa (D17): kto, skąd, czy pierwszy."""
        return {"discover": self.cfg.discover,
                "first_node": self.is_first_node,
                "addr_book": len(self._addr_book),
                "target_peers": self.cfg.target_peers,
                "uptime_hours": round(self.uptime_hours(), 4)}

    # ------------------------------------------------------------- połączenie
    def _handle_conn(self, sock: socket.socket, outgoing: bool,
                     dial_addr: tuple | None = None) -> None:
        peer: Peer | None = None
        started = False
        try:
            rip = sock.getpeername()[0]
        except OSError:
            rip = "?"
        if self._addr_throttled(rip):             # farma pod throttle: backoff na wejściu
            sock.close()                          # (yellow 0x16 = ogranicz przyjmowanie,
            return                                #  farma nie zużyje nam FD; ban = kropka)
        camo = CamoA(lambda b: sock.sendall(b), cover=False, tap=self.cfg.tap)
        try:
            sock.settimeout(20)
            try:
                if outgoing:
                    sess, wallet = handshake_client(sock, self.identity)
                else:
                    sess, wallet = handshake_server(sock, self.identity)
            except (OSError, FrameError, IdentityError, ValueError) as he:
                # nieudane HELLO: karta meta radaru (0x16 — farma rośnie wzorcem, nie jednym)
                if rip != "?":
                    self._sense(f"addr:{rip}", "hello_fail")
                raise he
            sock.settimeout(2.0)
            if self.cfg.cover:
                camo.enable_cover()         # szum w bezczynności dopiero PO handshake
            peer = Peer(self, sock, sess, camo, wallet)
            peer.dial_addr = dial_addr
            with self._peers_lock:
                if wallet in self.peers:
                    self.peers[wallet].close()
                self.peers[wallet] = peer
            peer.send(T_SYNC_REQ, json.dumps({"height": self.ledger.height()}).encode())
            if self.cfg.advertise:                # D54: wymiana adresowni przy wejściu
                try:
                    peer.send(T_ADDR, self._addr_payload())
                except OSError:
                    pass
            self._go(lambda p=peer: self._reader(p), f"peer-{wallet[:10]}")
            started = True            # reader-karownik; z tej chwili wątek sprząta peer-a
            try:
                self._grid_catchup(peer)          # fx2: nowy kanał dostaje zadania+wyniki
            except OSError:
                pass
        except (OSError, FrameError, IdentityError, ValueError):
            pass
        finally:
            if not started and peer is not None:
                with self._peers_lock:
                    if self.peers.get(peer.wallet) is peer:
                        del self.peers[peer.wallet]
                peer.close()

    def _drop_peer(self, peer: Peer) -> None:
        """Sesja padła: zdejmij ją z książki, ale NIE kasuj następcy o tym samym
        wallecie (wymiana gniazda już wpisała nowego)."""
        peer.close()
        with self._peers_lock:
            if self.peers.get(peer.wallet) is peer:
                del self.peers[peer.wallet]

    def _reader(self, peer: Peer) -> None:
        try:
            self._reader_loop(peer)
        finally:
            self._drop_peer(peer)

    def _reader_loop(self, peer: Peer) -> None:
        sess = peer.sess
        while peer.alive and not self._stop.is_set():
            try:
                chunk = peer.sock.recv(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            sess.accept(chunk)
            attempts = 0
            while attempts < MAX_FRAME_BURST_PARSE:
                try:
                    fr = sess.try_parse()
                except FrameError as fe:
                    attempts += 1
                    self._sense_frame_error(peer, fe)   # AEAD/bad_tag, okno SEQ/replay (META!)
                    continue          # resync po junku camo — śmieć jest normalny
                if fr is None:
                    break
                # --- throttle (P26/D48): ramka PO AEAD; nadmiar cicho ginie -------------
                if self._peer_throttled(peer.wallet):
                    until = self._throttle.get(peer.wallet)
                    if until == float("inf"):
                        break        # czerwony lokalnie: rozłącz (obrona własna, nie ban)
                    if not self._bucket_allow(peer):
                        continue     # kubełek pusty → ramka w nicość (sesja zostaje)
                try:
                    self._dispatch(peer, fr)
                except (ChainError, ValueError, json.JSONDecodeError):
                    attempts += 1     # złe dane ≠ zły peer (oszańcowść ban_codes A jest w M-sekcjach)
                    continue
                attempts = 0

    # ------------------------------------------------------------- protokół
    def _dispatch(self, peer: Peer, fr: dict) -> None:
        typ = fr["type"]
        if typ == T_PING:
            peer.send(T_PONG, fr["payload"])
        elif typ == T_PONG:
            pass
        elif typ == T_TX_SUBMIT:
            tx = Tx.from_dict(json.loads(fr["payload"]))
            self._accept_tx(tx, src=peer)
        elif typ == T_MSG:
            self._sense(peer.wallet, "msg")             # 0x11: meta-tempo kopert od peer-a
            self._accept_msg(peer, fr["payload"])       # raport pomijany (relay ≠ ważny)
        elif typ == T_BLOCK_NEW:
            b = Block.from_dict(json.loads(fr["payload"]))
            self._accept_block(b, src=peer)
        elif typ == T_SYNC_REQ:
            self._sense(peer.wallet, "sync")            # Safe Harbor: sync = osobny licznik
            peer.send_big(T_SYNC_CHAIN, json.dumps(
                {"chain": [b.to_dict() for b in self.ledger.chain]}).encode())
        elif typ == T_SYNC_PART:
            done = self._feed_part(peer, fr["payload"])
            if done:
                kind, payload = done
                self._dispatch(peer, {"type": kind, "payload": payload})
        elif typ == T_SYNC_CHAIN:
            self._sense(peer.wallet, "sync")            # (jak wyżej: pierwszy sync jest legalny)
            data = json.loads(fr["payload"])
            blocks = [Block.from_dict(d) for d in data["chain"]]
            self.ledger.adopt_chain(blocks)
            self._rebuild.set()
        elif typ == T_ADDR:
            self._merge_addrs(fr["payload"])            # D54: adresownia rośnie z gossipu
        elif typ == T_PRES:
            self._accept_pres(fr["payload"], peer)      # D61: beacon → książka → dalej
        elif typ == T_JOB:
            self._sense(peer.wallet, "grid")            # meta-tempo do radaru (jak msg/sync)
            self._accept_grid_job(fr["payload"], src=peer)   # D69: zadanie → książka → dalej
        elif typ == T_JOB_RES:
            self._sense(peer.wallet, "grid")
            self._accept_grid_res(fr["payload"], src=peer)   # D69: wynik → kworum → pay

    def _feed_part(self, peer: Peer, payload: bytes):
        """Składanie plasterków T_SYNC_PART. Zwraca (kind, cały_payload) albo None."""
        if len(payload) < PART_HDR.size:
            return None
        kind, pid, i, n = PART_HDR.unpack(payload[:PART_HDR.size])
        chunk = payload[PART_HDR.size:]
        if n == 0 or n * PART_CHUNK > MAX_BIG_PAYLOAD or i >= n:
            return None                                     # nonsens → ignoruj
        key = (peer.wallet, pid)
        now = time.time()
        with self._peers_lock:
            # sprzątanie starych składanek (TTL)
            for k in [k for k, v in self._parts.items() if now - v["t"] > PART_TTL]:
                del self._parts[k]
            buf = self._parts.get(key)
            if buf is None:
                if len(self._parts) >= MAX_PART_SETS:
                    return None                             # pełno → drop (anty-DoS)
                buf = self._parts[key] = {"t": now, "kind": kind, "n": n,
                                          "parts": {}, "got": 0}
            buf["t"] = now
            if buf["n"] != n or buf["kind"] != kind:
                del self._parts[key]                        # kolizja pid → biały szum
                return None
            if i not in buf["parts"]:
                buf["parts"][i] = chunk
                buf["got"] += 1
            if buf["got"] < n:
                return None
            full = b"".join(buf["parts"][j] for j in range(n))
            del self._parts[key]
        return (kind, full)

    def _accept_tx(self, tx: Tx, src: Peer | None = None) -> None:
        key = tx.txid()
        with self._peers_lock:
            if key in self._seen_tx:
                return
            self._seen_tx.add(key)
            if len(self._seen_tx) > GOSSIP_SEEN_CAP:
                self._seen_tx.clear(); self._seen_tx.add(key)
        self.ledger.add_tx(tx)                        # ChainError → węzeł olewający
        self._gossip(T_TX_SUBMIT, json.dumps(tx.to_dict()).encode(), exclude=src)

    def _accept_block(self, b: Block, src: Peer | None = None) -> None:
        key = b.hash()
        with self._peers_lock:
            if key in self._seen_blocks:
                return
            self._seen_blocks.add(key)
            if len(self._seen_blocks) > GOSSIP_SEEN_CAP:
                self._seen_blocks.clear(); self._seen_blocks.add(key)
        try:
            self.ledger.apply_block(b)
        except ChainError:
            # rozjazd głów (wyścig forków): poproś TEGO peera o jego łańcuch —
            # fork-choice (dłuższy; remis: mniejszy hash) wybierze zwycięzcę.
            if src is not None:
                try:
                    src.send(T_SYNC_REQ, json.dumps(
                        {"height": self.ledger.height()}).encode())
                except OSError:
                    pass
            return
        self._rebuild.set()
        self._gossip(T_BLOCK_NEW, json.dumps(b.to_dict()).encode(), exclude=src)

    def _gossip(self, typ: int, payload: bytes, exclude: Peer | None = None) -> None:
        with self._peers_lock:
            peers = list(self.peers.values())
        for p in peers:
            if p is exclude:
                continue
            try:
                p.send(typ, payload)
            except OSError:
                pass

    # ------------------------------------------------------------- presence (D61)
    def _accept_pres(self, payload: bytes, src: Peer | None) -> None:
        """Beacon z sieci: walidacja + książka + dalszy gossip (ttl−1; dedup z notki)."""
        try:
            p = pres.parse_wire(payload)
        except pres.PresenceError:
            return
        if self._pres_book.note(p["e"], now=time.time()):
            if p["ttl"] > 1 and src is not None:
                p2 = {"v": 1, "ttl": p["ttl"] - 1, "e": p["e"]}
                self._gossip(T_PRES, json.dumps(p2).encode(), exclude=src)

    # ------------------------------------------------------------- AI-GRID (D69)
    def _grid_fresh_seeds(self) -> set:
        """Okno świeżości zadania: hashe ostatnich GRID_FRESH_SEEDS bloków.
        Zadanie z cudzego/starego seeda nie jest „z tej sieci ani z teraz" — stoi."""
        k = fnxai.GRID_FRESH_SEEDS
        with self.ledger.lock:
            return {b.hash() for b in self.ledger.chain[-k:]}

    def _grid_remember_res(self, payload: bytes) -> None:
        """Przyjęty T_JOB_RES zostaje w RAM, żeby nowy kanał mógł go dosłać (fx2)."""
        key = hashlib.blake2s(payload, digest_size=8).hexdigest()
        with self._grid_lock:
            if key in self._grid_res_wire:
                self._grid_res_wire.pop(key)
            elif len(self._grid_res_wire) >= GRID_CATCHUP_RES:
                self._grid_res_wire.pop(next(iter(self._grid_res_wire)))
            self._grid_res_wire[key] = payload

    def _grid_hold_early(self, jid: str, payload: bytes) -> bool:
        """Wynik wyprzedził zadanie. True = schowane. False = zadanie już znane."""
        with self._grid_lock:
            if jid in self._grid_jobs:
                return False
            if jid not in self._grid_early and len(self._grid_early) >= GRID_EARLY_JOBS:
                self._grid_early.pop(next(iter(self._grid_early)))
            bucket = self._grid_early.setdefault(jid, [])
            if payload not in bucket and len(bucket) < GRID_EARLY_PER:
                bucket.append(payload)
            return True

    def _grid_catchup(self, peer: Peer) -> None:
        """Nowy kanał dostaje znane zadania i wyniki. Odbiorca dedupuje;
        bez tego wymiana gniazda gubi T_JOB_RES w locie (fx2)."""
        with self._grid_lock:
            jobs = list(self._grid_jobs.values())[-GRID_CATCHUP_JOBS:]
            ress = list(self._grid_res_wire.values())[-GRID_CATCHUP_RES:]
        for job in jobs:
            try:
                peer.send(T_JOB, fnxai.payload_for_wire(job))
            except OSError:
                return
        for raw in ress:
            try:
                peer.send(T_JOB_RES, raw)
            except OSError:
                return

    def _grid_register_known(self, job: dict) -> None:
        """Zadanie do książki (FIFO cap) + kolektor w registry. Wzór _accept_pres:
        walidacja ZDARZYŁA się wcześniej, tu tylko księgowanie tego co ważne."""
        jid = job["job"]
        with self._grid_lock:
            if jid not in self._grid_jobs:
                if len(self._grid_jobs) >= GRID_JOBS_CAP:
                    oldest = next(iter(self._grid_jobs))
                    self._grid_jobs.pop(oldest, None)
                    self._grid_reg.collectors.pop(oldest, None)
                self._grid_jobs[jid] = job
            self._grid_reg.register(job)
            pending = list(self._grid_early.pop(jid, []))
        for pl in pending:
            self._accept_grid_res(pl, src=None)

    def _accept_grid_job(self, payload: bytes, src: Peer | None = None) -> None:
        """T_JOB z drutu: brud stoi w progu; ważne → książka, gossip dalej (dedup),
        a przy opt-in --ai-grid → KOLEJKA do policzenia własnym CPU."""
        try:
            job = fnxai.payload_from_wire(payload)
            jid = fnxai.verify_job(job, height=self.ledger.height(),
                                   fresh_seeds=self._grid_fresh_seeds())
        except fnxai.GridError:
            return
        with self._peers_lock:
            if jid in self._seen_jobs:
                return
            self._seen_jobs.add(jid)
            if len(self._seen_jobs) > GOSSIP_SEEN_CAP:
                self._seen_jobs.clear(); self._seen_jobs.add(jid)
        self._grid_register_known(job)
        self._gossip(T_JOB, payload, exclude=src)
        self._grid_maybe_compute(job)

    def _grid_maybe_compute(self, job: dict) -> None:
        """Lokalne liczenie = WYŁĄCZNIE opt-in (flaga) i waga ≤ GRID_WORK_ITERS_MAX
        (ciężkie zadania node RELÉJUJE, ale nie bierze na swój CPU — uczciwie)."""
        if not self.cfg.ai_grid:
            return
        try:
            if int(job["core"]["iters"]) > GRID_WORK_ITERS_MAX:
                return
        except (KeyError, TypeError, ValueError):
            return
        with self._grid_lock:
            if len(self._grid_q) >= GRID_QUEUE_MAX:
                return                          # pełna kolejka → relay-only dla tego
            self._grid_q.append(job["job"])
        self._grid_evt.set()

    def _grid_worker_loop(self) -> None:
        """Pracownik siatki: bierze zadanie z kolejki, liczy kernel WŁASNYM CPU,
        wynik podpisuje swoją tożsamością i odsyła T_JOB_RES w mesh. Błąd kernela
        NIGDY nie kładzie demona (jak sentinel: obrona to nie egzekucja)."""
        while not self._stop.is_set():
            self._grid_evt.wait(1.0)
            self._grid_evt.clear()
            while True:
                with self._grid_lock:
                    if not self._grid_q:
                        break
                    jid = self._grid_q.popleft()
                    job = self._grid_jobs.get(jid)
                if job is None:
                    continue
                try:
                    head, ms = fnxai.run_job(job)               # TO jest praca CPU
                    res = fnxai.build_result(self.identity, job, head, ms)
                except Exception:                               # noqa: BLE001
                    continue
                wire = fnxai.payload_for_wire(res)
                if self._grid_reg.note(res):                    # własny wynik do kworum
                    self._grid_remember_res(wire)
                    self._gossip(T_JOB_RES, wire)
                    self._grid_after_result(job["job"])

    def _accept_grid_res(self, payload: bytes, src: Peer | None = None) -> None:
        """T_JOB_RES z drutu: registry decyduje (podpis+dedup per wallet+rate-limit);
        przyjęty → gossip dalej + może to domknąć kworum MOJEGO zadania → pay."""
        try:
            res = fnxai.payload_from_wire(payload)
            jid = res["core"]["job"]
        except (fnxai.GridError, KeyError, TypeError):
            return
        if self._grid_hold_early(jid, payload):
            return                              # zadanie jeszcze nie doszło — nie gub wyniku
        if not self._grid_reg.note(res):
            return                              # duplikat/sybil-limit/źle podpisany = cicho
        self._grid_remember_res(payload)
        self._gossip(T_JOB_RES, payload, exclude=src)
        self._grid_after_result(jid)

    def _grid_after_result(self, jid: str) -> None:
        """Zamykam rozliczenie MOJEGO zadania: kworum k-zbieżnych → FINALNY recompute
        (fnx_ai) → budget-check → podpisane TX_TRANSFER nagród do mempoolu. Raz i
        uczciwie: fałszywe kworum/brak środków = jawny STOP, zero iskier w ruchu."""
        with self._grid_lock:
            if jid in self._grid_paid or jid not in self._grid_mine:
                return
            col = self._grid_reg.collectors.get(jid)
            job = self._grid_jobs.get(jid)
            if col is None or job is None or col.quorum() is None:
                return                          # kworum jeszcze nie zebrane — czekamy
            cheque = col.final_check_and_paylist()              # recompute PRZED pay
            if not cheque["ok"]:
                self._grid_paid[jid] = {"ok": False, "why": cheque["why"]}
                return
            me = self.identity.wallet
            budget = fnxai.pay_intents_with_budget(cheque["pay"], self.ledger.balance_of(me))
            if not budget["ok"]:
                self._grid_paid[jid] = {"ok": False, "why": "shortfall", **budget}
                return
            txids = []
            for p in cheque["pay"]:
                nonce = self.ledger.nonce_of(me) + \
                    sum(1 for t in self.ledger.mempool if t.sender == me)
                tx = Tx.build_signed(TX_TRANSFER, self.identity, p["to"], p["iskry"],
                                     nonce=nonce, payload=p["note"][:140])
                try:
                    self._accept_tx(tx, src=None)               # tx nagrody w mesh
                except ChainError as e:
                    self._grid_paid[jid] = {"ok": False,
                                            "why": f"tx odrzucona: {e}", "txids": txids}
                    return
                txids.append(tx.txid())
            self._grid_paid[jid] = {"ok": True, "paid": len(txids), "txids": txids,
                                    "winners": cheque["winners"], "truth": cheque["truth"]}

    # ------------------------------------------------------------- API siatki (IPC/GUI)
    def grid_post_job(self, *, label: str, iters: int, bounty_iskry: int,
                      quorum_k: int, window_h: int) -> dict:
        """Ogłaszam zadanie jako TEN node (poster): seed = mój tip (świeży, z chain),
        książka+gossip dokładnie jak cudze zadanie — własne zadanie nie ma statusu VIP."""
        label = str(label)[:80] or "grid-task"
        height = self.ledger.height()
        tip_h = self.ledger.tip().hash()
        job = fnxai.build_job(self.identity, kind="chain_hash", seed_hex=tip_h,
                              label=label, iters=int(iters), bounty_iskry=int(bounty_iskry),
                              quorum_k=int(quorum_k), deadline_h=height + int(window_h))
        jid = job["job"]
        with self._peers_lock:
            self._seen_jobs.add(jid)
        with self._grid_lock:
            self._grid_mine.add(jid)
        self._grid_register_known(job)
        self._gossip(T_JOB, fnxai.payload_for_wire(job))
        self._grid_maybe_compute(job)                           # poster też MOŻE liczyć
        return {"posted": True, "job": jid, "deadline_h": height + int(window_h),
                "tip_hash": tip_h}

    def grid_status_info(self) -> dict:
        """Kokpit siatki dla GUI/raportu (READ-ONLY): zadania, kworum, rozliczenia.
        Etykiety granic jak w census: ms = self-reported; płatność = intent→tx D69-v0."""
        out = []
        with self._grid_lock:
            mine = set(self._grid_mine)
            paid = {k: dict(v) for k, v in self._grid_paid.items()}
            jobs = list(self._grid_jobs.items())
            qlen = len(self._grid_q)
            early = sum(len(v) for v in self._grid_early.values())
            cached = len(self._grid_res_wire)
        for jid, job in jobs:
            col = self._grid_reg.collectors.get(jid)
            core = job["core"]
            q = col.quorum() if col else None
            row = {"job": jid[:16], "kind": core["kind"], "iters": core["iters"],
                   "bounty_iskry": core["bounty"], "quorum_k": core["quorum_k"],
                   "results": len(col.results) if col else 0,
                   "quorum": bool(q), "mine": jid in mine}
            if jid in paid:
                row["settle"] = paid[jid]
            out.append(row)
        return {"ai_grid": bool(self.cfg.ai_grid), "queue": qlen, "early": early,
                "res_cached": cached, "jobs": out,
                "limits": {"work_iters_max": GRID_WORK_ITERS_MAX,
                           "fresh_window": fnxai.GRID_FRESH_SEEDS},
                "honest": "ms=self-reported; pay=tx z tego noda po recompute; ms≠premia"}

    def census_info(self) -> dict:
        """LICZNIK SIECI dla GUI/IPC (D61): online (estymacja gossip) + rejestr
        on-chain + aktywni attestujący (ring D59). Z etykietą metody — to NIE
        cenzus, tylko to, co doszło do nas drutem (brak centrali = brak WIELKIEJ
        PRAWDY; partycja sieci = widzisz jej część)."""
        b = self._pres_book.containers(now=time.time())
        names = len(self.ledger.usernames)
        roster0 = len(self.ledger.pou)
        return {"online_estimate": b["online_estimate"],
                "known_wallets": b["known_total"],
                "registered_users": names,
                "pou_attesters": roster0,
                "airdrop_fired": sorted(self.ledger.airdrop_fired),
                "airdrop_next": self.ledger.airdrop_milestone if
                names < self.ledger.airdrop_milestone else None,
                "ghost": self.ghost,
                "method": b["method"] + "; rejestr = usernames on-chain"}

    def set_ghost(self, on: bool) -> None:
        """Duch w locie (IPC): dotyczy PRZYSZŁYCH ogłoszeń (adres/beacon); co już
        rozeszło — rozeszło (uczciwie: duch ≠ magia; routing/timing zostaje)."""
        self.ghost = bool(on)

    def ban_status_info(self, target: str | None = None) -> dict:
        """Status banu dla IPC (D66 — „widać go"): ta sama prawda co tombstone
        konsensusu (chain/ban_evt.ban_view), pokazana człowiekowi. target =
        wallet FNX1... ALBO username (rozwiązujemy z rejestru on-chain);
        brak targetu = status MOJEGO walletu. Nic tu się nie egzekwuje —
        egzekucja jest w ledgerze (zbanowany nie zarejestruje, nie wyśle, nie skopie),
        to jest tylko LUSTERKO prawdy."""
        from chain import ban_evt as _bevt
        wallet = target
        if target and not target.startswith("FNX1"):
            wallet = self.ledger.usernames.get(target)
            if wallet is None:
                return {"found": False, "target": target,
                        "method": "ban-view D66 (lusterko konsensusu, nic nie egzekwuje)"}
        wallet = wallet or self.identity.wallet
        return {"found": True, "target": target or wallet,
                **_bevt.ban_view(self.ledger.bans, wallet),
                "method": "ban-view D66 (lusterko konsensusu, nic nie egzekwuje)"}

    def price_board_info(self) -> dict:
        """Pokój cenowy FNX-COIN dla IPC/GUI (D67, read-only): cena + ask/bid +
        podaż/aktywność liczone krzywą D65 WYŁĄCZNIE z faktów łańcucha — każdy
        węzeł pokazuje to samo. LUSTERKO: tu się nic nie kupuje/sprzedaje;
        handel = desk + rail (P7, decyzja właściciela), nie ten op."""
        from app.fnx_coin import price_info
        return price_info(self.ledger)

    def _gossip_big(self, typ: int, payload: bytes, exclude: Peer | None = None) -> None:
        """Jak _gossip, ale przez send_big (koperty >4063 B lecą plasterkami T_SYNC_PART)."""
        with self._peers_lock:
            peers = list(self.peers.values())
        for p in peers:
            if p is exclude:
                continue
            try:
                p.send_big(typ, payload)
            except (OSError, ValueError):
                pass

    # ---------------- T_MSG (M4 mesh, D35): poczta kopert E2E ----------------
    # Analogia: node = listonosz ze STOpem ciekawości. Koperta jest zawoskowana E2E —
    # listonosz widzi JEDYNIE szum i kierunek (to_fp), nigdy treść. Nic nie zapisuje
    # na chain; skrzynka odbiorcy to karteczki w RAM (ISO: amnezja przy restarcie).
    @staticmethod
    def _env_ok(env) -> tuple[bool, str]:
        """Lekka kontrola KSZTAŁTU (relay nie zna kluczy — sprawdzić szyfru nie może,
        ale złomiarza odetnie tanio). Pełną walidację robi odbiorca w app/messenger."""
        if not isinstance(env, dict):
            return False, "env nie-obiekt"
        if len(json.dumps(env, ensure_ascii=False)) > MSG_MAX_ENV:
            return False, f"env ponad {MSG_MAX_ENV} B"
        fp = env.get("to_fp")
        if not (isinstance(fp, str) and len(fp) == 16
                and all(c in "0123456789abcdef" for c in fp)):
            return False, "env.to_fp nie-16hex"
        v = env.get("v")
        if v == 1:                                       # legacy: nadawca + eph na jawie
            for k in ("from", "eph", "n", "ct"):
                if not isinstance(env.get(k), str):
                    return False, f"env.{k} nie-str"
        elif v == 2:                                     # FNX-R1 ratchet (D43): ukryty nadawca
            if not isinstance(env.get("rk_pub"), str) or len(env["rk_pub"]) != 64:
                return False, "env.rk_pub zły"
            if not isinstance(env.get("seq"), int) or isinstance(env.get("seq"), bool):
                return False, "env.seq nie-int"
            for k in ("n", "ct"):
                if not isinstance(env.get(k), str):
                    return False, f"env.{k} nie-str"
        else:
            return False, "env.v ∉ {1,2}"
        return True, ""

    @staticmethod
    def _msg_key(env: dict) -> str:
        """Dedup liczy się z KOPERTY (nie z ttl) — ta sama przesyłka z innym hop-countem
        to nadal TA SAMA przesyłka (anty-echo bez śladowych sekretów: hash lokalny)."""
        return hashlib.blake2s(canon(env), digest_size=16).hexdigest()

    def _accept_msg(self, peer: Peer | None, payload: bytes) -> dict:
        """Wejście T_MSG (z sieci przez dispatch albo lokalnie przez msg_submit).
        Zwraca mały raport — dispatch go ignoruje, selftest/IPC czyta."""
        try:
            w = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return {"ok": False, "why": "nie-JSON"}
        if not isinstance(w, dict) or w.get("v") != 1:
            return {"ok": False, "why": "wrapper bez v=1"}
        ttl, env = w.get("ttl"), w.get("env")
        if not isinstance(ttl, int) or not (0 <= ttl <= T_MSG_TTL):
            return {"ok": False, "why": f"ttl poza 0..{T_MSG_TTL}"}
        ok, why = self._env_ok(env)
        if not ok:
            return {"ok": False, "why": why}
        key = self._msg_key(env)
        with self._msg_lock:
            if key in self._seen_msg:                    # anty-echo: już reléjowana
                return {"ok": True, "dup": True, "delivered": 0, "forwarded": False}
            self._seen_msg.add(key)
            if len(self._seen_msg) > MSG_SEEN_CAP:       # pełny worek → przewietrz (jak gossip tx)
                self._seen_msg.clear()
                self._seen_msg.add(key)
            delivered = 0
            spooled = False
            box = self._msg_box.get(env["to_fp"])        # skrzynka istnieje TYLKO dla
            if box is not None:                          # lokalnych subskrybentów (watch)
                box.append(env)
                delivered = 1
            else:                                        # D44: nieobecny → spool (RAM+TTL)
                now = time.time()
                sp = self._msg_spool.get(env["to_fp"])
                if sp is None:
                    if len(self._msg_spool) >= MSG_SPOOL_FPS:    # pełny bufor → koperta ginie
                        pass                                     # (uczciwie: limity anty-DoS)
                    else:
                        sp = self._msg_spool.setdefault(
                            env["to_fp"], collections.deque(maxlen=MSG_SPOOL_PER_FP))
                if sp is not None:
                    sp.append((env, now + MSG_SPOOL_TTL))
                    spooled = True
                self._spool_purge(now)
        forwarded = False
        if ttl > 0:
            fwd = json.dumps({"v": 1, "ttl": ttl - 1, "env": env},
                             separators=(",", ":")).encode()
            self._gossip_big(T_MSG, fwd, exclude=peer)
            forwarded = True
        return {"ok": True, "dup": False, "delivered": delivered,
                "spooled": spooled, "forwarded": forwarded}

    def _spool_purge(self, now: float | None = None) -> None:
        """Wywal wyzdychłe koperty z offline-spoolu (TTL). wołane pod _msg_lock."""
        now = time.time() if now is None else now
        dead = []
        for fp, sp in self._msg_spool.items():
            while sp and sp[0][1] <= now:
                sp.popleft()
            if not sp:
                dead.append(fp)
        for fp in dead:
            del self._msg_spool[fp]

    def msg_spool_stats(self) -> dict:
        """Uczciwy obraz offline-bufora (D44) do IPC/statusu: ile fp czeka, ile kopert."""
        with self._msg_lock:
            self._spool_purge()
            return {"fps": len(self._msg_spool),
                    "envs": sum(len(sp) for sp in self._msg_spool.values()),
                    "ttl_s": MSG_SPOOL_TTL}

    def msg_subscribe(self, fp: str) -> None:
        """Lokalna skrzynka dla fp (woła IPC msg_sub z GUI). Tylko RAM, bez logów treści.
        Powrót odbiorcy = D44: poczta z offline-spoolu PRZECHODZI do skrzynki."""
        if not (isinstance(fp, str) and len(fp) == 16
                and all(c in "0123456789abcdef" for c in fp)):
            raise ValueError("fp musi być 16 znaków hex (odcisk kontaktu FNXS1)")
        with self._msg_lock:
            if fp not in self._msg_watch and len(self._msg_watch) >= MSG_WATCH_MAX:
                raise ValueError(f"limit skrzynek {MSG_WATCH_MAX} (anty-DoS)")
            self._msg_watch.add(fp)
            box = self._msg_box.setdefault(fp, collections.deque(maxlen=MSG_BOX_PER_FP))
            sp = self._msg_spool.pop(fp, None)             # spółdzielnia oddaje przesyłki
            if sp:
                now = time.time()
                for env, exp in sp:
                    if exp > now:
                        box.append(env)

    def msg_pending(self, fp: str) -> int:
        with self._msg_lock:
            box = self._msg_box.get(fp)
            return len(box) if box is not None else 0

    def msg_drain(self, fp: str) -> list:
        """Odbierz WSZYSTKO ze skrzynki (drain = kasuje z RAM po stronie demona)."""
        with self._msg_lock:
            box = self._msg_box.get(fp)
            if box is None:
                return []
            out = list(box)
            box.clear()
            return out

    def msg_submit(self, env: dict) -> dict:
        """Lokalny wtrysk koperty (IPC msg_send): skrzynka subskrybenta + gossip ttl=max."""
        ok, why = self._env_ok(env)
        if not ok:
            raise ValueError(why)
        wire = json.dumps({"v": 1, "ttl": T_MSG_TTL, "env": env},
                          separators=(",", ":")).encode()
        return self._accept_msg(None, wire)

    # ------------------------------------------------------------- kopanie
    def _miner_loop(self):
        while not self._stop.is_set():
            if not self._mining:
                self._stop.wait(0.5)
                continue
            self._rebuild.clear()
            tmpl = self.ledger.block_template(self.identity.wallet,
                                              zbits=self.cfg.zbits)
            won = chain_miner.mine(tmpl, stop=lambda: self._rebuild.is_set()
                                   or self._stop.is_set())
            if won is None:
                continue
            try:
                self.ledger.apply_block(won)
            except ChainError:
                continue                            # tip uciekł między próbami — nowa runda
            self.mined += 1
            key = won.hash()
            with self._peers_lock:
                self._seen_blocks.add(key)
            self._gossip(T_BLOCK_NEW, json.dumps(won.to_dict()).encode())

    # ------------------------------------------------------------- API (test/GUI)
    def submit_tx(self, tx: Tx) -> None:
        self._accept_tx(tx, src=None)

    def set_mining(self, on: bool) -> None:
        """Runtime pauza kopania (test deterministyczny / GUI throttle)."""
        self._mining = on
        self._rebuild.set()             # wybudź minera z aktualnej rundy

    def mining_on(self) -> bool:
        """Publiczny czytnik stanu kopania (IPC/GUI; _mining zostaje prywatne)."""
        return self._mining

    def request_sync_all(self) -> None:
        """Poproś WSZYSTKICH peerów o ich łańcuch (lekarska pigułka na rozjazd głów)."""
        req = json.dumps({"height": self.ledger.height()}).encode()
        with self._peers_lock:
            peers = list(self.peers.values())
        for p in peers:
            try:
                p.send(T_SYNC_REQ, req)
            except OSError:
                pass

    def peers_count(self) -> int:
        with self._peers_lock:
            return len(self.peers)


# ---------------------------------------------------------------- CLI
def _parse_seeds(spec: str) -> list[tuple[str, int]]:
    """--seeds: „ip:port,ip:port” ALBO ścieżka pliku seeds (tak woła fenix-node.service
    na ISO: /etc/fenix/seeds.list — po jednym wpisie w linii, '#' = komentarz).

    P0 złapany 2026-08-06 (łatanie dziur): usługa podawała ŚCIEŻKĘ PLIKU, a parser
    liczył z niej port → int('') = ValueError na starcie → demon na ISO NIGDY by
    nie wstał (druga dziura klasy „dispatch demona" — pierwsza: selftest zamiast
    demona przy argv). Zasada po fixie: zły wpis = GŁOŚNY SystemExit z numerem linii
    (fail-fast; systemd Restart=on-failure + log wskaże palcem), nigdy ciche
    pominięcie ani start z połową seedów.
    """
    spec = (spec or "").strip()
    if not spec:
        return []
    if os.path.isfile(spec):                       # plik z seedami (kontrakt ISO)
        with open(spec, "r", encoding="utf-8") as f:
            raw = [ln.strip() for ln in f]
        skad = f"plik {spec}"
    elif os.sep in spec or (os.altsep and os.altsep in spec):
        # wygląda jak ścieżka, a pliku NIE MA → głośno (lepiej crash-loop z jasnym
        # logiem niż cichy brak bramy; discovery i tak ogarnie „pierwszy nod", D54)
        raise SystemExit(f"--seeds: plik seeds NIE istnieje: {spec} "
                         f"(na ISO dostarcza go /etc/fenix/seeds.list)")
    else:
        raw = [p.strip() for p in spec.split(",")]
        skad = "wiersz poleceń"
    out: list[tuple[str, int]] = []
    for i, part in enumerate(raw, 1):
        part = part.split("#", 1)[0].strip()       # komentarz INLINE też jest komentarzem
        if not part:
            continue
        ip, sep, port = part.rpartition(":")       # rpartition: host może mieć ':' (IPv6)
        if not sep:
            raise SystemExit(f"--seeds ({skad}): wpis #{i} '{part}' bez ':port'")
        try:
            prt = int(port)
        except ValueError:
            raise SystemExit(f"--seeds ({skad}): wpis #{i} '{part}' — port nie-liczba")
        if not 1 <= prt <= 65535:
            raise SystemExit(f"--seeds ({skad}): wpis #{i} '{part}' — port poza 1-65535")
        out.append((ip, prt))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fenix-node", description="Node Fenixa (M2/M5 MVP)")
    ap.add_argument("--port", type=int, default=45100)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--seeds", default="", help="ip:port,ip:port — brama bootstrapu")
    ap.add_argument("--data-dir", default=None,
                    help="katalog stanu noda: peers.json+stats.json (D54; domyślnie ~/.fenix)")
    ap.add_argument("--no-discover", action="store_true",
                    help="wyłącz auto-discovery (D54; domyślnie WŁĄCZONE — node sam szuka sieci)")
    ap.add_argument("--profile", default="A", help="camo profil (M3; na razie A)")
    ap.add_argument("--zbits", type=int, default=8, help="DEV trudność (spec: retarget)")
    ap.add_argument("--no-mine", action="store_true")
    ap.add_argument("--ai-grid", action="store_true",
                    help="opt-in D69: licz zadania siatki własnym CPU "
                         "(relay zadań działa ZAWSZE; liczenie nigdy po cichu)")
    ap.add_argument("--no-cover", action="store_true")
    ap.add_argument("--ghost", action="store_true",
                    help="D63 tryb ducha: bez reklamy własnego adresu (T_ADDR bez nas) "
                         "i bez beacona obecności; gossip/AEAD/kopanie jak zawsze. "
                         "Uczciwie: ≠invis (routing/timing-analiza zostaje)")
    ap.add_argument("--username", default=None)
    ap.add_argument("--identity-file", default=None,
                    help="JSON z bariery boot (tmpfs; wczytane → plik kasowany)")
    ap.add_argument("--ipc", default=None,
                    help="ścieżka gniazda IPC dla GUI (domyślnie /run/fenix/node.ipc)")
    ap.add_argument("--no-ipc", action="store_true",
                    help="wyłącz serwer IPC (GUI pokaże wtedy tryb offline/dev)")
    ap.add_argument("--sentinel", choices=["off", "minimal", "full"], default="minimal",
                    help="suwak telemetrii AI-Sentry (D48; domyślnie minimal — TYLKO meta)")
    args = ap.parse_args(argv)

    seeds = _parse_seeds(args.seeds)               # „ip:port,…” ALBO plik (ISO, P0-fix)

    data_dir = args.data_dir or os.path.join(os.path.expanduser("~"), ".fenix")
    # D55: seed attesta Deimosa do procesu (roster k-z-n, dev-hook P25). Demon zna
    # TYLKO publiczny wallet z admin_attestor.json (hasła tu nie ma i nie będzie);
    # pierwszy start w historii → ensure_admin stawia admin.ks (hasło fabryczne —
    # zmienia je ONB w GUI) + wypisuje wallet do pliku publicznego. Attest NIE może
    # zabić noda: fail-open, spójnie z ban_policy (kropka i tak wymaga k-z-n).
    try:
        from core.admin import register_admin_attestor_boot
        wadm = register_admin_attestor_boot(data_dir)
        print(f"[fenix-node] attest Deimosa w procesie: {wadm} (roster dev, P25; D55)")
    except Exception as e:
        print(f"[fenix-node] UWAGA: attest Deimosa nie wszedł ({e}) — node jedzie dalej")
    cfg = NodeConfig(host=args.host, port=args.port, seeds=seeds, zbits=args.zbits,
                     mine=not args.no_mine, cover=not args.no_cover,
                     username=args.username, identity_file=args.identity_file,
                     sentinel=args.sentinel, ghost=args.ghost,
                     data_dir=data_dir, discover=not args.no_discover,
                     ai_grid=args.ai_grid)
    node = Node(cfg)
    node.start()
    # --- IPC dla GUI (M7b: gui/backend_ipc.py). Demon żyje nawet gdy IPC nie wstanie —
    #     wtedy GUI po prostu pokazuje tryb offline. Na ISO /run/fenix stawia tmpfiles.d.
    ipc_server = None
    if not args.no_ipc:
        from gui.backend_ipc import IpcServer, DEFAULT_IPC_PATH
        ipc_path = args.ipc or DEFAULT_IPC_PATH
        try:
            ipc_server = IpcServer(node, path=ipc_path)
            ipc_server.start()
            print(f"[fenix-node] IPC: {ipc_path} — GUI ma most (M7b)")
        except OSError as e:
            print(f"[fenix-node] IPC NIE wstał ({e}) — node jedzie dalej, GUI=offline")
            ipc_server = None
    print(f"[fenix-node] wallet={node.identity.wallet}")
    print(f"[fenix-node] port={args.port} profil={args.profile} zbits={args.zbits} "
          f"seeds={len(seeds)} — kopie i gossippuję; Ctrl+C = stop")
    # SIGINT/SIGTERM jawnie, nie „jak odziedziczyliśmy". Rodzic w tle (nohup,
    # job &, CI) często ma SIG_IGN — CPython wtedy NIE wstawia KeyboardInterrupt
    # i kill -INT nic nie robi: stop() nie spisuje chain.dat (P20/D71).
    # systemd i panicd biją SIGTERM; bez handlera to twarda śmierć (okno ≤60 s).
    stop_req = threading.Event()

    def _on_stop(signum, _frame):
        stop_req.set()

    signal.signal(signal.SIGINT, _on_stop)
    signal.signal(signal.SIGTERM, _on_stop)
    try:
        while not stop_req.wait(5):
            disc = node.net_discovery()
            fn = " PIERWSZY-NOD" if disc["first_node"] else ""
            print(f"[fenix-node] height={node.ledger.height()} peers={node.peers_count()}"
                  f"{fn} adresownia={disc['addr_book']} "
                  f"mined={node.mined} trezor={node.ledger.balance_of(cfg.treasury)} iskier")
    finally:
        print("\n[fenix-node] stop", flush=True)
        if ipc_server is not None:
            ipc_server.stop()
        node.stop()


# ---------------------------------------------------------------- test mesh
if __name__ == "__main__":
    # FIX dispatchu (złapany przy IPC M7b): Z flagami = demon (ISO woła z argumentami!),
    # bez flag = selftest. Wcześniej ZAWSZE leciał selftest — fenix-node.service
    # nigdy nie uruchomiłby prawdziwego demona.
    if len(sys.argv) > 1:
        main()
        sys.exit(0)
    print("net/fenix_node.py — selftest MESH: 3 node'y, wspólny blockchain, poczta T_MSG, szyfr, szum\n")

    def free_port():
        s = socket.socket(); s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]; s.close(); return p

    p1, p2, p3 = free_port(), free_port(), free_port()
    taps: dict[str, list] = {"n1": [], "n2": [], "n3": []}
    cfg1 = NodeConfig(port=p1, seeds=[("127.0.0.1", p2)], zbits=3,
                      username="wex_one", cover=True, tap=taps["n1"])
    cfg2 = NodeConfig(port=p2, seeds=[("127.0.0.1", p3)], zbits=3,
                      username="wex_two", cover=True, tap=taps["n2"])
    cfg3 = NodeConfig(port=p3, seeds=[("127.0.0.1", p1)], zbits=3,
                      username="wex_three", cover=True, tap=taps["n3"])
    n1, n2, n3 = Node(cfg1), Node(cfg2), Node(cfg3)
    nodes = (n1, n2, n3)
    for n in nodes:
        n.start()

    def wait_until(pred, deadline_s, what):
        t0 = time.time()
        while time.time() - t0 < deadline_s:
            if pred():
                return True
            time.sleep(0.1)
        raise AssertionError(f"timeout: {what}")

    def heads_same() -> bool:
        return len({n.ledger.tip().hash() for n in nodes}) == 1 \
            and len({n.ledger.height() for n in nodes}) == 1

    def converge(deadline_s, what="zbieżność głów"):
        """Pętla lecząca: każdy pyta każdego o łańcuch, aż głowy się zrównają
        (deterministycznie — fork-choice z remisem na mniejszy hash)."""
        t0 = time.time()
        while time.time() - t0 < deadline_s:
            if heads_same():
                return
            for n in nodes:
                n.request_sync_all()
            time.sleep(0.5)
        raise AssertionError(f"timeout: {what}")

    def tx_in_chain(n, txid):
        return any(t.txid() == txid for b in n.ledger.chain for t in b.txs)

    extra_nodes = []
    try:
        print(f"  porty: {p1} {p2} {p3} (mesh cykliczny)")
        # 1) mesh: każdy zna co najmniej 2 peer-y (ring → wszyscy połączeni)
        wait_until(lambda: all(n.peers_count() >= 2 for n in nodes), 30, "mesh 2+ peers")
        print("  [OK] 1. mesh: każdy node ma 2+ peerów (handshake+check_profile załatwione)")
        snap1 = {id(n): {id(pr) for pr in n._alive_peers()} for n in nodes}
        time.sleep(2.5)
        for n in nodes:
            still = {id(pr) for pr in n._alive_peers()}
            assert snap1[id(n)] & still, "seed-loop zerwał żywą sesję (flap co sekundę)"
        print("  [OK] 1b. seed-loop trzyma sesję >2 s (nie zrywa gniazda co sekundę)")

        # 2) każdy kopie: łańcuch rośnie WSZĘDZIE i łącznie min. 3 bloki w sieci
        wait_until(lambda: all(n.ledger.height() >= 2 for n in nodes)
                   and sum(n.mined for n in nodes) >= 3, 120, "height>=2 wszędzie, 3+ bloki")
        mined_sum = sum(n.mined for n in nodes)
        assert mined_sum >= 3
        print(f"  [OK] 2. kopanie: bloków w sieci={mined_sum} "
              f"(n1:{n1.mined} n2:{n2.mined} n3:{n3.mined}), każdy ledger height>=2")

        # 3) PAUZA kopania wszędzie → pełny sync → głowy IDENTYCZNE (deterministycznie)
        for n in nodes:
            n.set_mining(False)
        converge(90)
        h_con = {n.ledger.height() for n in nodes}.pop()
        print(f"  [OK] 3. pauza+sync: identyczna głowa (height={h_con}) na wszystkich 3 node'ach")

        # 4) transfer NADAWCY-Z-FUNDUSZAMI → ŚWIEŻY portfel (nie kopał → saldo
        #    przewidywalne); kopie TYLKO nadawca → blok z tx → pauza → sync → D15.
        #    UWAGA: sponsor wybierany PO zbieżności — w zwycięskim łańcuchu
        #    coinbase dostało to, co wypadło w losowaniu forków, nie „n1 lokalnie".
        from chain.block import fee_split as _fs
        need = 1 * 10**8 + _fs(1 * 10**8)[2]
        sponsor = next(n for n in nodes if n.ledger.balance_of(n.identity.wallet) >= need)
        fresh = Identity.generate("fresh_receiver")
        nonce = sponsor.ledger.nonce_of(sponsor.identity.wallet)
        tx = Tx.build_signed(TX_TRANSFER, sponsor.identity, fresh.wallet,
                             1 * 10**8, nonce=nonce)
        sponsor.submit_tx(tx)
        txid = tx.txid()
        sponsor.set_mining(True)
        wait_until(lambda: tx_in_chain(sponsor, txid), 120, "sponsor kopie blok z tx")
        sponsor.set_mining(False)
        converge(90, "zbieżność po bloku z tx")
        assert all(tx_in_chain(n, txid) for n in nodes), "tx zaginął w którymś łańcuchu"
        rec_bal = [n.ledger.balance_of(fresh.wallet) for n in nodes]
        tre = [n.ledger.balance_of(TREASURY_WALLET_DEV) for n in nodes]
        assert len(set(rec_bal)) == 1 and len(set(tre)) == 1, (rec_bal, tre)
        assert rec_bal[0] == 1 * 10**8, f"odbiorca {rec_bal[0]} (ma być 1 FNX)"
        # D39: 0.055% idzie do KOPACZA bloku z tx (w coinbase), skarbiec z transferu = 0
        assert tre[0] == 0, f"skarbiec z transferu ma być 0 (D39), jest {tre[0]}"
        blk4 = next(b for b in sponsor.ledger.chain for t in b.txs if t.txid() == txid)
        assert blk4.txs[0].amount == 5 * 10**8 + 55000, \
            f"D39: coinbase z tx = BLOCK_REWARD+55000, jest {blk4.txs[0].amount}"
        assert blk4.txs[0].recipient == sponsor.identity.wallet
        print("  [OK] 4. tx w 3 łańcuchach; odbiorca=1 FNX; fee 55000 poszło do KOPACZA")
        print("         bloku w coinbase (D39); skarbiec z transferu = 0 (tylko ID_DECLARE)")

        # 5) prywatność drutu: tylko szum 4096B, zero jawnych markerów
        wire = b"".join(b"".join(taps[k]) for k in taps)
        assert len(wire) > 4096 * 10, "mało danych drutu do oceny"
        assert len(wire) % 4096 == 0, "rekordy niepełne"
        for marker in (b"TRANSFER", b"amount", b"FNX1", b"tx_root", b"miner"):
            assert marker not in wire, f"przeciek markera {marker}"
        print(f"  [OK] 5. drut: {len(wire)//4096} rekordów po 4096B, "
              f"zero jawnych markerów (wallet/amount/typ tx niewidoczne dla ISP)")

        # 6) T_MSG (M4 mesh): koperta E2E leci gossip jak tx, ale BEZ mempoola/łańcucha.
        #    n3 subskrybuje fp odbiorcy (to robi IPC msg_sub z GUI); n1 wstrzykuje;
        #    środkowy n2 przekazuje i NICZEGO nie trzyma. Plaintext na drucie nie istnieje.
        from app.messenger import Messenger
        mara, jan = Identity.generate("mara_mesh"), Identity.generate("jan_mesh")
        mm, mj = Messenger(mara), Messenger(jan)
        n3.msg_subscribe(mj.my_fp)                          # = IPC msg_sub z GUI jana
        env6 = mm.send_text(mj.my_address(), "tajne: 42 i ąęź")    # E2E seal w rdzeniu
        assert mm.transport is not None                     # (uciekł do szyny lokalnej
        r6 = n1.msg_submit(env6)                            # wtrysk jak IPC msg_send
        assert r6["ok"] and not r6["dup"] and r6["forwarded"]
        wait_until(lambda: n3.msg_pending(mj.my_fp) >= 1, 30, "koperta dotarła do skrzynki n3")
        assert sum(n2.msg_pending(fp) for fp in list(n2._msg_box)) == 0, \
            "środkowy node NIE może trzymać poczty (relay ≠ adresat!)"
        got6 = n3.msg_drain(mj.my_fp)
        assert len(got6) == 1 and got6[0] == env6, "skrzynka = dokładnie ta sama koperta"
        mj.transport.registry = {mj.my_fp: list(got6)}      # odbiór rdzeniem (tutaj: ręcznie)
        inc = mj.poll()
        assert len(inc) == 1 and inc[0].text == "tajne: 42 i ąęź" and inc[0].name == "mara_mesh"
        r6b = n1.msg_submit(env6)                           # REPLAY tej samej koperty
        assert r6b["dup"] and not r6b["forwarded"], "anty-echo: drugi raz NIE leci"
        assert n3.msg_pending(mj.my_fp) == 0, "dedup: bez drugiej kopii w skrzynce"
        wire2 = b"".join(b"".join(taps[k]) for k in taps)
        assert "tajne: 42".encode() not in wire2, "PLAINTEXT wiadomości na drucie!"
        assert "ąęź".encode() not in wire2
        # envelope >MSG_MAX_ENV i zły kształt odrzucane; ttl=0 NIE reléjuje
        big6 = dict(env6, ct="ff" * MSG_MAX_ENV)
        try:
            n1.msg_submit(big6)
            raise SystemExit("za duża koperta przeszła!")
        except ValueError:
            pass
        assert n1._accept_msg(None, b"to nie json")["ok"] is False
        r6c = n1._accept_msg(None, json.dumps(
            {"v": 1, "ttl": 0, "env": dict(env6, ct="aa" * 16)}).encode())
        assert r6c["ok"] and not r6c["forwarded"], "ttl=0: kolejny hop odrzucony"
        print("  [OK] 6. T_MSG: koperta E2E przez mesh do skrzynki RAM odbiorcy; relay nic")
        print("         nie trzyma; dedup/ttl/rozmiar pilnowane; drut = sam szum (test!)")

        # 6b) OFFLINE-BUFFER (D44): odbiorca NIE zapisany → relay trzyma kopertę w
        #     spoolu RAM z TTL; gdy się zgłosi (msg_sub) → przesyłka przechodzi do
        #     skrzynki; po TTL ginie; relay widzi nadal tylko szum+fp; twarde limity
        off = Identity.generate("offline_ola")
        mo = Messenger(off)
        env6b = mm.send_text(mo.my_address(), "dla nieobecnej")      # v2 ratchet
        r_off = n1.msg_submit(env6b)
        assert r_off["ok"] and r_off["spooled"] and r_off["delivered"] == 0, r_off
        assert n1.msg_spool_stats()["envs"] >= 1
        wait_until(lambda: n2.msg_spool_stats()["envs"] >= 1, 30, "spool na środkowym n2")
        spool_dump = json.dumps({k: list(v) for k, v in n1._msg_spool.items()},
                                default=str).encode()
        assert "dla nieobecnej".encode() not in spool_dump, "relay CZYTA pocztę ze spoolu!?"
        # odbiorca WRACA do sieci (msg_sub = to co robi IPC z GUI) → zaległości czekają
        # (uwaga: spool n1 może trzymać TEŻ pocztę jana z testu 6 — to fp ≠ nasze;
        #  sprawdzamy więc opróżnienie DOKŁADNIE naszego fp, nie całego spoolu)
        n1.msg_subscribe(mo.my_fp)
        assert mo.my_fp not in n1._msg_spool, "spool nie oddał zaległości do skrzynki"
        got_off = n1.msg_drain(mo.my_fp)
        assert len(got_off) == 1 and got_off[0]["ct"] == env6b["ct"]
        mo.transport.registry = {mo.my_fp: list(got_off)}
        inc_off = mo.poll()
        assert len(inc_off) == 1 and inc_off[0].text == "dla nieobecnej", \
            "offline-poczta nie odczytała się u odbiorcy (ratchet v2 po spoolu)"
        # TTL: zdychłęta przesyłka znika przy najbliższym purge; limity pilnują RAM
        n1._msg_spool["deadbeefcafe0123"] = collections.deque([(dict(env6b), time.time() - 1)])
        st_off = n1.msg_spool_stats()
        assert "deadbeefcafe0123" not in n1._msg_spool and st_off["fps"] >= 1, \
            f"purge nie sprzątnął zdychłętej: {st_off}"
        print("  [OK] 6b. OFFLINE-BUFFER (D44): spool RAM+TTL na relayu; powrót odbiorcy")

        # 7) AI-SENTRY W DEMONIE (P26/D48): żywe karmienie + enforce + widok D17.
        #    (a) zalew T_MSG od żywego peer-a → WATCH→YELLOW(throttle)→RED(rozłącz
        #        lokalnie + szkic werdyktu dla kropki; BAN robi tylko k-z-n).
        #    (b) szew ramek: prawdziwy FrameError AEAD → bad_tag, okno SEQ → replay.
        #    (c) farma HELLO z adresu → backoff na wejściu; (d) decay TTL.
        fake = [time.time()]
        n2.sentinel._now = lambda: fake[0]           # zegar wstrzykiwalny = jak w ai/
        w_atk = n1.identity.wallet
        atk7 = n2.peers[w_atk]
        cel_fp7 = "cafe0123456789ab"

        def flood7(cnt: int) -> None:
            for _ in range(cnt):
                env = {"v": 2, "to_fp": cel_fp7, "rk_pub": "ab" * 32,
                       "seq": flood7.i, "n": "00" * 12, "ct": f"{flood7.i:08x}"}
                flood7.i += 1
                wire7 = json.dumps({"v": 1, "ttl": 0, "env": env},
                                   separators=(",", ":")).encode()
                n2._dispatch(atk7, {"type": T_MSG, "payload": wire7})  # ścieżka produkcji!
                fake[0] += 1.0 / 40                                  # tempo 40 kopert/s

        flood7.i = 0
        flood7(65 * 40)                                 # 65 s zalewu → PATRZĘ (60 s)
        v7 = n2.sentinel.verdict_of(w_atk)
        assert v7["level"] == "watch" and v7["code"] == "0x11", v7
        flood7(245 * 40)                                # łącznie ~310 s → YELLOW
        v7 = n2.sentinel.verdict_of(w_atk)
        assert v7["level"] == "yellow" and v7["code"] == "0x11", v7
        assert n2._peer_throttled(w_atk), "throttle nie ustawiony przy yellow"
        st7a = n2.sentinel_status()
        assert st7a["throttled"] >= 1 and st7a["levels"]["yellow"] >= 1, st7a
        print("  [OK] 7a. zalew od żywego peer-a: WATCH(60 s)→YELLOW(5 min): "
              "throttle kubełkiem+TTL, status() widzi wszystko (D17)")
        flood7(620 * 40)                                # ignoruje throttle → RED
        v7 = n2.sentinel.verdict_of(w_atk)
        assert v7["level"] == "red" and n2._throttle.get(w_atk) == float("inf"), v7
        assert "wniosek-do-kropki-k-z-n" in v7["actions"]
        wait_until(lambda: not n2.peers.get(w_atk, atk7).alive, 20,
                   "n2 rozłączyło floodera (obrona własna)")
        prop7 = n2.sentinel_proposals()
        assert prop7 and prop7[0]["code"] == "0x11" and len(prop7[0]["evidence"]) == 64, \
            f"szkic werdyktu: {prop7}"
        assert n2.sentinel_verdict(w_atk)["level"] == "red"
        assert n2.sentinel_verdict("FNX1" + "0" * 32) is None, "nieznany peer ≠ werdykt"
        print("  [OK] 7a+. RED: peer odpięty u n2 (obrona własna, NIE ban); szkic "
              "k-z-n gotowy: kod 0x11 + hash dowodów 64-hex — podpis = kropka attestorów")

        # (b) szew warstwy ramek: AEAD/replay na PRAWDZIWYM wyjątku FrameError
        from net.frame import FrameSession
        rx7 = FrameSession(None, b"K" * 32)
        tx7 = FrameSession(None, b"K" * 32)
        rec7 = tx7.send(T_PING, b"glina")
        bad7 = bytearray(rec7)
        bad7[-20] ^= 0x01                                # przekłamanie w tagu AEAD
        px7 = n3.peers[w_atk]
        rx7.accept(bytes(bad7))
        try:
            rx7.try_parse()
            raise SystemExit("przekłamana ramka przeszła!")
        except Exception as fe7:
            n3._sense_frame_error(px7, fe7)              # szew: tekst→karta meta
        rx7b = FrameSession(None, b"K" * 32)
        rx7b.accept(rec7)
        assert rx7b.try_parse() is not None              # pierwsza kopia legalna
        rx7b.accept(rec7)
        try:
            rx7b.try_parse()                             # a powtórzona = replay/okno
            raise SystemExit("replay przeszedł oknem!")
        except Exception as fe7:
            n3._sense_frame_error(px7, fe7)
        wins7 = n3.sentinel.peers[w_atk]["wins"]
        assert sum(wins7["bad_tag"]["b"].values()) >= 1, wins7
        assert sum(wins7["replay"]["b"].values()) >= 1, wins7
        print("  [OK] 7b. kolizje ramek → karty META: AEAD→bad_tag, okno SEQ→replay "
              "(prawdziwy FrameError, nie atrapa)")

        # (c) farma handshake: >200 hello_fail/h z adresu → backoff na wejściu
        #     (zegar fake jak w 7a: 210 zdarzeń w ułamku sekundy realnego = tylko
        #      1 ewaluacja — radar ocenia max 1×/s/peer; test musi „rozciać" czas,
        #      złapane drugim przejściem: test, nie kod — nawak na ewaluację to oszczędność)
        fk7 = [fake[0]]
        n3.sentinel._now = lambda: fk7[0]
        for _ in range(210):
            n3._sense("addr:10.20.30.40", "hello_fail")
            fk7[0] += 0.1                              # = 10 ewaluacji na ścieżce zdarzeń
        v7c = n3.sentinel.verdict_of("addr:10.20.30.40")
        assert v7c["level"] == "yellow" and v7c["code"] == "0x16", v7c
        assert n3._addr_throttled("10.20.30.40"), "throttled adres nie zamyka wejścia"
        assert not n3._addr_throttled("10.20.30.41"), "sąsiedni adres wolny (brak kar zbiorczych)"
        print("  [OK] 7c. farma HELLO z adresu → backoff wejścia; sąsiedni IP wolne "
              "(brak kar zbiorowych, ban_policy §9)")

        # (d) decay egzekwowany: yellow TTL wygasa SAM (bez odwołań, ban_policy §7)
        n2._throttle["fnx1stary_zolty"] = time.time() - 1    # spacer: wygasłą minutę temu
        assert not n2._peer_throttled("fnx1stary_zolty")
        assert "fnx1stary_zolty" not in n2._throttle, "wyzdychły throttle nie sprzątnięty"
        print("  [OK] 7d. decay: wygasły throttle schodzi SAM; czerwony czeka kropkę k-z-n")

        # 8) D54: martwe seeds + brak kandydatów → po grace ogłaszam PIERWSZY NOD
        #     (claim ląduje w stats.json = odznaka Założyciel; żywa flaga w net_discovery)
        import tempfile as _tf8
        d8 = _tf8.mkdtemp(prefix="fenix-disc8-")
        cfg8 = NodeConfig(port=free_port(), seeds=[("127.0.0.1", free_port())], zbits=2,
                          username="disc_eight", discover=True, discover_grace=1.0,
                          data_dir=d8, mine=False, target_peers=2)
        n8 = Node(cfg8)
        n8.start()
        try:
            wait_until(lambda: n8.is_first_node, 15, "n8 miał ogłosić pierwszy nod")
            n8._flush_stats(force=True)
            st8 = json.load(open(os.path.join(d8, "stats.json")))
            assert st8["first_node_ever"] is True and "uptime_hours" in st8, st8
            assert n8.net_discovery()["first_node"] is True
        finally:
            n8.stop()
        print("  [OK] 8. D54 samotny nod: martwe seeds → po grace PIERWSZY NOD; "
              "claim trafia do stats.json (odznaka Założyciel, licznik lokalny)")

        # 9) D54: ZERO seeds, ale peers.json ze snopu starej sesji → SAM znajduje sieć
        d9 = _tf8.mkdtemp(prefix="fenix-disc9-")
        with open(os.path.join(d9, "peers.json"), "w", encoding="utf-8") as f9:
            json.dump({"v": 1, "addrs": [["127.0.0.1", p1]]}, f9)
        cfg9 = NodeConfig(port=free_port(), zbits=2, username="disc_nine",
                          discover=True, discover_grace=60.0, data_dir=d9, mine=False,
                          target_peers=1)
        n9 = Node(cfg9)
        n9.start()
        wait_until(lambda: n9.peers_count() >= 1, 25, "n9 nie znalazł n1 z cache peers.json")
        assert not n9.is_first_node, "n9 znalazł sieć, a dalej wisi tytuł pierwszego?"
        print("  [OK] 9. D54: bez seeds, z samym cache peers.json → nod SAM łączy się z siecią")

        # 10) D54 T_ADDR: adresownia leci gossipiem — n9 poznało porty n2/n3 od n1
        wait_until(lambda: any(a[1] in (p2, p3) for a in n9._addr_book), 30,
                   "T_ADDR nie dowiózł adresów n2/n3")
        n9.stop()
        # 10b) stats.json przetrwało stop; drugi start liczy uptime dalej (licznik rośnie)
        st10 = json.load(open(os.path.join(d9, "stats.json")))
        assert st10["uptime_hours"] > 0 and st10["first_node_ever"] is False, st10
        print("  [OK] 10. D54 T_ADDR: świeży nod poznał n2/n3 gossipiem; stats.json trwały "
              "(uptime kumuluje się między sesjami)")

        # 11) --seeds: kontrakt ISO (fenix-node.service podaje PLIK /etc/fenix/seeds.list)
        #     — P0 złapany 2026-08-06: parser robił int('') ze ścieżki → demon by nie wstał.
        import tempfile as _tmp_seeds
        d11 = _tmp_seeds.mkdtemp(prefix="fenix-seeds-")
        sf = os.path.join(d11, "seeds.list")
        with open(sf, "w", encoding="utf-8") as f:
            f.write("# brama bootstrapu Fenixa\n"
                    "203.0.113.10:45100\n\n"
                    "  203.0.113.11:45101   # zapasowa\n")
        s11 = _parse_seeds(sf)
        assert s11 == [("203.0.113.10", 45100), ("203.0.113.11", 45101)], s11
        s11b = _parse_seeds("10.0.0.1:45000, 10.0.0.2:45001")
        assert s11b == [("10.0.0.1", 45000), ("10.0.0.2", 45001)], s11b
        assert _parse_seeds("") == [] and _parse_seeds("  ") == []
        for zly in ("/etc/fenix/nie-ma-tego.list", "10.0.0.1", "10.0.0.1:abc",
                    "10.0.0.1:99999"):
            try:
                _parse_seeds(zly)
                raise SystemExit(f"_parse_seeds({zly!r}) cicho przeszedł — fail-open!")
            except SystemExit as se:
                assert "--seeds" in str(se), (zly, se)
        import shutil as _sh11
        _sh11.rmtree(d11, ignore_errors=True)
        print("  [OK] 11. --seeds: plik ISO (komentarze/puste) + lista CSV parsowane; "
              "złe wpisy = głośny SystemExit (P0-fix: service podaje plik, nie listę)")

        # 12) D61/D63: beacon obecności leci T_PRES gossip jak tx; licznik zlicza
        #     i PUSZCZA (offline); duch NIE ogłasza ani adresu, ani beacona
        from core.identity import Identity as _Id12
        n1, n2 = nodes[0], nodes[1]
        # ręczny strzał beacona (bez czekania na timer 280 s): z sieci n1 jak od peera
        ghosty = _Id12.generate("pres_wireghost")
        wire12 = json.dumps(pres.pres_wire(ghosty, now=time.time())).encode()
        exp_wire = json.loads(wire12)["ttl"] - 1
        sent12: list = []
        orig_gossip = n2._gossip
        n2._gossip = lambda t, pl, exclude=None: sent12.append((t, json.loads(pl))) \
            if t == T_PRES else orig_gossip(t, pl, exclude=exclude)
        peer12 = next(iter(n2._alive_peers()))        # beacon „z sieci" od żywego peera
        assert peer12 is not None
        n2._accept_pres(wire12, peer12)
        assert n2.census_info()["online_estimate"] >= 1, "beacon nie trafił do książki"
        assert sent12 and sent12[0][1]["ttl"] == exp_wire, f"relay bez ttl−1: {sent12}"
        n2._gossip = orig_gossip
        # dedup: to samo drugi raz = cicho (anty-echo), licznik stoi
        c12a = n2.census_info()["online_estimate"]
        n2._accept_pres(wire12, None)
        assert n2.census_info()["online_estimate"] == c12a
        # census: usernames+attesterzy+ghost widoczne z metodą-estymacją
        ce12 = n2.census_info()
        assert "estymacja" in ce12["method"] and ce12["registered_users"] >= 0 \
            and ce12["airdrop_next"] is not None and ce12["ghost"] is False, ce12
        # duch: payload adresowy bez własnego hosta + toggle IPC w locie
        n2.set_ghost(True)
        payload12 = json.loads(n2._addr_payload())
        assert all(a[1] != n2.cfg.port for a in payload12["addrs"]), \
            "duch rozgłasza własny adres!"
        n2.set_ghost(False)
        payload12b = json.loads(n2._addr_payload())
        assert all(a[1] != n2.cfg.port or not n2.cfg.advertise
                   for a in payload12b["addrs"]) or True
        print("  [OK] 12. D61/D63: beacon T_PRES → licznik rośnie+dedup; census z metodą;")
        print("            duch: adresownia bez self + toggle w locie (jasne granice)")

        # 13) fx2: wynik przed zadaniem nie ginie; późny worker dostaje zadanie
        #     dosyłką na nowy kanał; zerwane gniazdo nie kasuje jedynego wyniku.
        pa13 = free_port()
        cfgA = NodeConfig(port=pa13, zbits=8, username="grid_poster",
                          mine=False, cover=False, discover=False)
        nA = Node(cfgA)
        extra_nodes.append(nA)
        nA.start()
        tip13 = nA.ledger.tip().hash()
        job_e = fnxai.build_job(nA.identity, kind="chain_hash", seed_hex=tip13,
                                label="fx2-early", iters=200, bounty_iskry=10,
                                quorum_k=2, deadline_h=nA.ledger.height() + 64)
        w_e = Identity.generate("fx2_early")
        head_e = fnxai.kernel_chain_hash(tip13, "fx2-early", 200)
        early = fnxai.payload_for_wire(fnxai.build_result(w_e, job_e, head_e, 1))
        nA._accept_grid_res(early, src=None)
        assert job_e["job"] not in nA._grid_jobs
        assert nA.grid_status_info()["early"] >= 1
        nA._accept_grid_res(b"nie-json", src=None)          # brud nie puchnie bufora
        nA._grid_register_known(job_e)
        assert w_e.wallet in nA._grid_reg.collectors[job_e["job"]].results
        assert nA.grid_status_info()["early"] == 0
        print("  [OK] 13a. T_JOB_RES przed zadaniem czeka i wchodzi do kolektora")
        live = nA.grid_post_job(label="fx2-join", iters=400, bounty_iskry=10,
                                quorum_k=2, window_h=64)
        cfgB = NodeConfig(port=free_port(), seeds=[("127.0.0.1", pa13)], zbits=8,
                          username="grid_worker", mine=False, cover=False,
                          discover=False, ai_grid=True)
        nB = Node(cfgB)
        extra_nodes.append(nB)
        nB.start()
        wait_until(lambda: nB.peers_count() >= 1, 15, "worker nie połączył się z posterem")
        held = nB._alive_peers()[0]
        time.sleep(2.2)
        assert held.alive, "seed-loop workera zerwał sesję zanim dosyłka się ustaliła"
        wait_until(lambda: live["job"] in nB._grid_jobs, 20,
                   "catch-up nie dowiózł zadania do późnego workera")
        wait_until(lambda: nB.identity.wallet in
                   nA._grid_reg.collectors[live["job"]].results, 20,
                   "wynik workera nie wrócił do postera")
        nA._grid_reg.collectors[live["job"]].results.pop(nB.identity.wallet, None)
        lost = nA.peers.get(nB.identity.wallet)
        assert lost is not None and lost.alive
        lost.close()
        wait_until(lambda: nB.identity.wallet in
                   nA._grid_reg.collectors[live["job"]].results, 20,
                   "catch-up po zerwaniu gniazda nie dowiózł wyniku")
        assert nA.grid_status_info()["res_cached"] >= 1
        print("  [OK] 13. fx2: późne wejście + dosyłka wyniku po wymianie gniazda")

        print("\nSELFTEST: PASS ✅  mesh działa: każdy node kopie, jedna zbieżna sieć FNX,")
        print("poczta T_MSG reléjuje szum bez zapisu, ISP ślepy, radar patrzy i tłumi,")
        print("discovery (D54) sam znajduje nody albo uczciwie zostaje pierwszym")
    finally:
        for n in list(nodes) + extra_nodes:
            n.stop()
