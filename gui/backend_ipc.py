# gui/backend_ipc.py — most GUI↔demon fenix-node: lokalne gniazdo, protokół NDJSON (M7b)
"""
Dlaczego i jak (analogia: GUI to „recepcja", demon to „maszynownia"):
  GUI i fenix-node to DZIELNE procesy. Dziś recepcja gada z własnym notesem
  (współdzielony Ledger — tryb dev/desktop). Ten plik to telefon wewnętrzny:
  gniazdo Unix `/run/fenix/node.ipc` (tmpfs=RAM; katalog stawia tmpfiles.d, 0770
  root:fenix — demon pisze jako fenix, GUI czyta jako fenix, obcy nie wejdą).

PROTOKÓŁ — NDJSON: jedna linia = jedna prośba, jedna linia = jedna odpowiedź.
 请求:  {"op": "status", "id": 7, "p": {...}}
  odp:   {"ok": true,  "id": 7, ...}   albo   {"ok": false, "id": 7, "err": "..."}
Debug ręcznie: `nc -U /run/fenix/node.ipc` (lub socat) i wpisz JSON. Zero magii.

ZASADY BEZPIECZEŃSTWA:
  - tylko LOKALNIE (gniazdo unix, chmod 0660, brak TCP z zewnątrz),
  - biała lista opów (status/peers/mining/submit/balance/nonce/sync) — nie przyjmujemy
    ścieżek, poleceń shella, ani kluczy; odpowiedzi NIE zawierają sekretów (test!),
  - MAX_LINE 64 KiB na linię, timeout 5 s na połączenie (anty-DoS, anty-wiszenie),
  - klient jednopołączeniowy (1 prośba = 1 connect) + backoff 3 s po awarii:
    demon leży → GUI płynie dalej w trybie dev, bez freeze i bez spamu connect.

Dwie strony mostu + pan pośrodku:
  IpcServer   — wystawia Node (duck-typing: ledger, peers_count, set_mining,
                mining_on, submit_tx, request_sync_all, mined). Start ze strony demona:
                `python3 -m net.fenix_node --ipc /run/fenix/node.ipc` (domyślnie ON).
  BackendIpc  — klient z GUI (gui/fenix_gui.py: dashboard/submit/mining toggle).
  IpcError    — jeden typ błędu po stronie klienta.
"""
from __future__ import annotations

import json
import socket
import threading
import time
import os
import sys
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from chain.block import Tx                    # noqa: E402
from chain.ledger import Ledger, ChainError   # noqa: E402
from chain import tx_ring as txr              # noqa: E402

DEFAULT_IPC_PATH = "/run/fenix/node.ipc"
MAX_LINE = 64 * 1024            # sufit linii NDJSON (anty-DoS)
CONN_TIMEOUT = 5.0              # s na stronie serwera; klient ma własny (krótszy)
POOL_PAGE_MAX = 200             # max outputów na stronę op=pool (paging anty-64KiB)
PROTO_OPS = ("status", "peers", "mining", "submit", "balance", "nonce", "sync",
             "pool", "pool_decoys", "pool_mine", "pool_kis",
             "msg_sub", "msg_send", "msg_poll",
             "sentinel", "sentinel_peer", "sentinel_proposals",   # widok owner-admina (D17)
             "profile", "donate", "netinfo", "site_created",      # D52/D50/D54: profil+datki+discovery
             "census", "ghost",                                  # D61/D63: licznik sieci + duch
             "ban_status", "price",                             # D66/D67: widok banu + pokój cenowy (read-only)
             "grid_submit", "grid_status")                      # D69: siatka AI (post zadania + kokpit)

MSG_MAX_ENV = 16384         # B JSON koperty (lustro net/fenix_node.MSG_MAX_ENV)


def _fp_ok(fp) -> bool:
    """16 znaków hex — odcisk kontaktu FNXS1 (te same reguły co w demonie)."""
    return (isinstance(fp, str) and len(fp) == 16
            and all(c in "0123456789abcdef" for c in fp))


class IpcError(Exception):
    """Błąd IPC (klient): demon martwy / odmówił / odpowiedź nieprawidłowa."""


def _json_line(d: dict) -> bytes:
    return json.dumps(d, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


# -------------------------------------------------------------------------- serwer (maszynownia)
class IpcServer:
    """Serwer IPC nad żywym Node. Duck-typing → selftest goni go na FakeNode.

    CZYSTO: _dispatch nie dotyka socketów (testowalny 1:1), IO jest w _handle.
    """

    def __init__(self, node, path: str = DEFAULT_IPC_PATH):
        self.node = node
        self.path = path
        self._srv: socket.socket | None = None
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    # ------------- życie -------------
    def start(self) -> None:
        if os.path.exists(self.path):
            os.unlink(self.path)                # gniazdo-zombie po crashu
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.path)
        os.chmod(self.path, 0o660)              # tylko właściciel+grupa (fenix)
        srv.listen(8)
        srv.settimeout(0.5)
        self._srv = srv
        t = threading.Thread(target=self._accept_loop, name="fenix-ipc", daemon=True)
        t.start()
        self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        try:
            self._srv.close()
        except (OSError, AttributeError):
            pass
        try:
            if os.path.exists(self.path):
                os.unlink(self.path)
        except OSError:
            pass

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break                            # listener zamknięty przez stop()
            t = threading.Thread(target=self._handle, args=(conn,),
                                 name="fenix-ipc-conn", daemon=True)
            t.start()
            self._threads.append(t)

    def _handle(self, conn: socket.socket):
        """Wiele próśb na jednym połączeniu (server-side loop), każda ≤ MAX_LINE."""
        conn.settimeout(CONN_TIMEOUT)
        try:
            f = conn.makefile("rb")
            while not self._stop.is_set():
                line = f.readline(MAX_LINE + 2)
                if not line:
                    break                        # klient zamknął (normalny koniec prośby)
                if len(line) > MAX_LINE:
                    conn.sendall(_json_line({"ok": False, "err": "linia za długa"}))
                    continue
                try:
                    req = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    conn.sendall(_json_line({"ok": False, "err": "nie-JSON"}))
                    continue
                conn.sendall(_json_line(self._dispatch(req)))
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    # ------------- dispatch (CZYSTA logika — zero IO) -------------
    def _dispatch(self, req) -> dict:
        if not isinstance(req, dict):
            return {"ok": False, "err": "request musi być obiektem JSON"}
        op, p, rid = req.get("op"), req.get("p") or {}, req.get("id")
        if op not in PROTO_OPS:
            return {"ok": False, "id": rid, "err": f"nieznany op: {op!r}"}
        if not isinstance(p, dict):
            return {"ok": False, "id": rid, "err": "p musi być obiektem"}
        try:
            body = getattr(self, f"_op_{op}")(p)
            return {"ok": True, "id": rid, **body}
        except Exception as e:  # noqa: BLE001 — serwer IPC NIE MOŻE paść od jednej prośby
            return {"ok": False, "id": rid, "err": str(e)}

    # ------------- opy (biała lista) -------------
    def _op_status(self, _p: dict) -> dict:
        snap = self.node.ledger.snapshot()
        return {"height": snap["height"], "tip": snap["tip"],
                "peers": self.node.peers_count(), "mining": self.node.mining_on(),
                "mined": self.node.mined, "mempool": len(snap["mempool"]),
                "pool_size": snap["pool_size"], "key_images": snap["key_images"],
                "usernames": len(snap["usernames"])}

    def _op_peers(self, _p: dict) -> dict:
        return {"peers": self.node.peers_count()}

    def _op_mining(self, p: dict) -> dict:
        self.node.set_mining(bool(p.get("on")))
        return {"mining": self.node.mining_on()}

    def _op_submit(self, p: dict) -> dict:
        txd = p.get("tx")
        if not isinstance(txd, dict):
            raise IpcError("p.tx musi być dict-em transakcji")
        tx = Tx.from_dict(txd)
        self.node.submit_tx(tx)                  # ChainError wypływa → ok:false dla GUI
        return {"txid": tx.txid()}

    def _op_balance(self, p: dict) -> dict:
        wallet = p.get("wallet")
        if not isinstance(wallet, str) or not wallet:
            raise IpcError("p.wallet wymagany (str)")
        return {"balance": self.node.ledger.balance_of(wallet)}

    def _op_nonce(self, p: dict) -> dict:
        wallet = p.get("wallet")
        if not isinstance(wallet, str) or not wallet:
            raise IpcError("p.wallet wymagany (str)")
        led = self.node.ledger
        # mempol-aware jak add_tx (anonse w kolejce też zjadają nonce — Ethereum-style)
        exp = led.nonce_of(wallet) + sum(1 for t in led.mempool if t.sender == wallet)
        return {"nonce": exp}

    def _op_sync(self, _p: dict) -> dict:
        self.node.request_sync_all()
        return {"sync": True}

    # ------------- msg (M4 mesh): demon to listonosz — koperty E2E, NIE czyta ----
    def _op_msg_sub(self, p: dict) -> dict:
        fp = p.get("fp")
        if not _fp_ok(fp):
            raise IpcError("msg_sub: fp = 16 znaków hex (odcisk FNXS1)")
        self.node.msg_subscribe(fp)          # ValueError (limit) → ok:false dla GUI
        return {"subscribed": fp}

    def _op_msg_send(self, p: dict) -> dict:
        env = p.get("env")
        if not isinstance(env, dict):
            raise IpcError("msg_send: p.env musi być obiektem koperty")
        if len(json.dumps(env, ensure_ascii=False)) > MSG_MAX_ENV:
            raise IpcError(f"msg_send: koperta ponad {MSG_MAX_ENV} B (za długa wiadomość?)")
        r = self.node.msg_submit(env)        # ValueError (kształt) → ok:false
        return {"delivered": r.get("delivered", 0), "dup": bool(r.get("dup"))}

    def _op_msg_poll(self, p: dict) -> dict:
        fp = p.get("fp")
        if not _fp_ok(fp):
            raise IpcError("msg_poll: fp = 16 znaków hex (odcisk FNXS1)")
        return {"envs": self.node.msg_drain(fp)}     # drain = kasuje w demonie (amnezja)

    # ------------- AI-Sentry (P26/D48): WIDOK operatora — zero treści, zero przycisków ----
    def _op_sentinel(self, _p: dict) -> dict:
        """Liczby radaru demona (META): poziomy, karty, throttle. Owner/admin lokalnie (D17)."""
        return {"sentinel": self.node.sentinel_status()}

    def _op_sentinel_peer(self, p: dict) -> dict:
        """Werdykt dla JEDNEGO peera (id z mesh/handshake); None = radar go nie zna."""
        peer = p.get("peer")
        if not isinstance(peer, str) or not peer:
            raise IpcError("sentinel_peer: p.peer wymagany (str — wallet albo addr:IP)")
        return {"verdict": self.node.sentinel_verdict(peer)}

    def _op_sentinel_proposals(self, _p: dict) -> dict:
        """Szkice werdyktów red (core+powód+hash dowodów; NIGDY karty treści).
        Podpisuje je kropka attestorów POZA demonem — demon tylko pokazuje (D18)."""
        return {"proposals": self.node.sentinel_proposals()}

    # ------------- profil + datki + discovery (D52/D50/D54): publiczne pola, zero sekretów
    def _op_profile(self, _p: dict) -> dict:
        """Odznaki MOJEGO profilu liczone z konsensusu + licznika lokalnego (D52)."""
        from chain import badges as bd
        me = self.node.identity.wallet
        pan = bd.badge_panel(self.node.ledger, me, stats=self.node.stats_view(),
                             now_ts=self.node.ledger.tip().timestamp)
        return {"wallet": me, "username": self.node.identity.username,
                "badges": pan,
                "donated_iskry": int(self.node.ledger.donations.get(me, 0)),
                "stats": self.node.stats_view()}

    def _op_donate(self, p: dict) -> dict:
        """TX_DONATE do skarbca ownera; kwota = WYBÓR użytkownika (D50: nic nie dyktujemy)."""
        amt = p.get("amount_iskry")
        if not isinstance(amt, int) or isinstance(amt, bool) or amt <= 0:
            raise IpcError("donate: amount_iskry musi być dodatnią liczbą iskier (kwota Twoja)")
        note = p.get("note")
        if note is not None and not isinstance(note, str):
            raise IpcError("donate: note ma być napisem (albo pomiń)")
        from chain import donate as don
        from chain.block import TX_DONATE
        me = self.node.identity.wallet
        nonce = self.node.ledger.nonce_of(me) + \
            sum(1 for t in self.node.ledger.mempool if t.sender == me)
        tx = Tx.build_signed(TX_DONATE, self.node.identity, self.node.ledger.treasury,
                             amt, nonce=nonce, payload=don.donate_payload(note or ""))
        self.node.submit_tx(tx)              # ChainError (środki/składnia) → ok:false dla GUI
        return {"txid": tx.txid(), "amount_iskry": amt}

    def _op_netinfo(self, _p: dict) -> dict:
        """Discovery noda (D54): czy pierwszy, rozmiar adresowni, cel peerów, uptime."""
        return self.node.net_discovery()

    def _op_census(self, _p: dict) -> dict:
        """Licznik sieci (D61): online≈ (gossip-estymacja), registered (usernames),
        attestujący PoU, kamień milowy airdropu. Z etykietą metody — nie cenzus."""
        return self.node.census_info()

    def _op_ghost(self, p: dict) -> dict:
        """Duch D63: przełącznik na żywo (jak mining_on — localhost, 0660)."""
        self.node.set_ghost(bool(p.get("on")))
        return {"ghost": self.node.ghost}

    def _op_price(self, _p: dict) -> dict:
        """Pokój cenowy FNX-COIN (D67): krzywa z faktów łańcucha — READ-ONLY.
        Handel (desk+rail) = P7; tu jest szyba wystawowa, nie kasa."""
        return self.node.price_board_info()

    def _op_grid_submit(self, p: dict) -> dict:
        """AI-GRID (D69): ogłaszam zadanie; poster = wallet TEGO demona. Nagrody
        wypłaca demon PO kworum+recompute (osobne TX_TRANSFER; shortfall = jawny
        STOP, zero cichej emisji — tak samo jak donate: podpis w demonie, nie w GUI)."""
        from ai import fnx_ai as fnxai
        try:
            iters = int(p.get("iters"))
            bounty = int(p.get("bounty_iskry"))
            k = int(p.get("quorum_k", 2))
            win = int(p.get("window_h", 256))
        except (TypeError, ValueError):
            raise IpcError("grid_submit: iters/bounty_iskry/quorum_k/window_h = liczby") from None
        label = p.get("label", "grid-task")
        if not isinstance(label, str):
            raise IpcError("grid_submit: label ma być napisem")
        if not (1 <= iters <= fnxai.GRID_MAX_ITERS and bounty > 0 and 2 <= k <= 32
                and 1 <= win <= 4096):
            raise IpcError("grid_submit: poza siatką (iters 1..2M, kworum 2..32, "
                           "okno 1..4096 bloków)")
        return self.node.grid_post_job(label=label, iters=iters, bounty_iskry=bounty,
                                       quorum_k=k, window_h=win)

    def _op_grid_status(self, _p: dict) -> dict:
        """Kokpit siatki (READ-ONLY): zadania/kworum/rozliczenia + jawne granice v0."""
        return self.node.grid_status_info()

    def _op_ban_status(self, p: dict) -> dict:
        """Status banu (D66): target = wallet FNX1... albo username (albo pomiń = ja).
        Lusterko konsensusu — nic się tu nie egzekwuje, egzekwuje ledger."""
        t = p.get("target")
        if t is not None and (not isinstance(t, str) or not (1 <= len(t) <= 64)):
            raise IpcError("ban_status: target = wallet/username do 64 znaków (albo pomiń)")
        return self.node.ban_status_info(t)

    def _op_site_created(self, p: dict) -> dict:
        """Aplikacja melduje: user zbudował stronę (odznaka Architekt, licznik lokalny)."""
        url = p.get("url")
        if url is not None and (not isinstance(url, str) or len(url) > 200):
            raise IpcError("site_created: url max 200 znaków (albo pomiń)")
        self.node.mark_site_created()
        return {"site_created": True}

    # ------------- pool (M7c): TYLKO dane łańcucha — zero sekretów ----------------
    def _op_pool(self, p: dict) -> dict:
        """Surowy pool stronami (Δ deterministyczny sort po sp): {total, outs:[sp/ep/amt]}."""
        offset, limit = p.get("offset", 0), p.get("limit", POOL_PAGE_MAX)
        if not isinstance(offset, int) or offset < 0:
            raise IpcError("pool: offset musi być int ≥ 0")
        if not isinstance(limit, int) or not (1 <= limit <= POOL_PAGE_MAX):
            raise IpcError(f"pool: limit 1..{POOL_PAGE_MAX}")
        items = sorted(self.node.ledger.pool.items())
        # v1: amt jawny; v2 (3b): amt=None (chain nie zna kwoty) + C/blob dla scanu GUI
        return {"total": len(items),
                "outs": [{"sp": k, "ep": v["ep"], "amt": v.get("amt"),
                          **({"v": 2, "C": v["C"], "blob": v["blob"]}
                             if "C" in v else {"v": 1})}
                         for k, v in items[offset:offset + limit]]}

    def _op_pool_decoys(self, p: dict) -> dict:
        """Memberowie ringa dla nominału (same sp-hexe, jak pick_ring_candidates)."""
        amt = p.get("amt")
        if not isinstance(amt, int) or amt <= 0:
            raise IpcError("pool_decoys: amt musi być int > 0")
        return {"members": txr.pick_ring_candidates(self.node.ledger.pool, amt)}

    def _op_pool_kis(self, _p: dict) -> dict:
        """Rejestr key-images (publiczne dane łańcucha — filtr „wydane" liczy GUI
        LOKALNIE po scanie C/blob; nic sekretnego na drucie)."""
        return {"kis": sorted(self.node.ledger.key_images)}

    def _op_pool_mine(self, _p: dict) -> dict:
        """Moje niewydane coiny wg TOŻSAMOŚCI DEMONA (ISO: ta sama co GUI).
        Zwraca TYLKO sp/ep/amt — spend_hint klucz-wydania NIGDY nie opuszcza demona;
        GUI policzy priv_ot lokalnie skanem (drut IPC utrzymany bez-sekretowy)."""
        outs = [{"sp": k, "ep": v["ep"], "amt": v["amt"]}
                for k, v in self.node.ledger.pool.items() if "amt" in v]   # v1-only (3a);
        # monety v2 GUI znajdzie scanem C/blob po op pool (M7d; demona konto nie dotyczy)
        mine = txr.scan_payload_for(self.node.identity, outs)
        kis = self.node.ledger.key_images
        return {"mine": [{"sp": c["sp"], "ep": c["ep"], "amt": c["amt"]}
                         for c in mine
                         if txr.key_image_of(c["spend_hint"], c["sp"]).hex() not in kis]}


# -------------------------------------------------------------------------- klient (recepcja/GUI)
class BackendIpc:
    """Klient z GUI. Jeden request = jedno połączenie (demon to małe biuro,
    nie portal). Po awarii: backoff — nie spamujemy connect co tick odświeżania."""

    def __init__(self, path: str = DEFAULT_IPC_PATH, timeout: float = 2.0,
                 backoff_s: float = 3.0, clock=time.monotonic):
        self.path, self.timeout = path, timeout
        self.backoff_s, self._clock = backoff_s, clock
        self._down_until = 0.0
        self._next_id = 1

    # ------------- rdzeń -------------
    def request(self, op: str, **params) -> dict:
        now = self._clock()
        if now < self._down_until:
            raise IpcError(f"demon offline (retry za {self._down_until - now:.1f} s)")
        try:
            resp = self._round_trip(op, params)
        except IpcError:
            raise
        except (OSError, socket.timeout) as e:
            self._down_until = now + self.backoff_s
            raise IpcError(f"brak demona pod {self.path} ({e})") from None
        self._down_until = 0.0                   # sukces zdejmuje backoff
        if resp.get("ok") is not True:
            raise IpcError(str(resp.get("err", "demon odmówił bez powodu")))
        return resp

    def try_request(self, op: str, **params) -> dict | None:
        """Miękka wersja do dashboardów: błąd → None (GUI wtedy płynie w trybie dev)."""
        try:
            return self.request(op, **params)
        except IpcError:
            return None

    def _round_trip(self, op: str, params: dict) -> dict:
        rid = self._next_id
        self._next_id += 1
        line = _json_line({"op": op, "id": rid, "p": params})
        if len(line) > MAX_LINE:
            raise IpcError("request przekracza MAX_LINE")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(self.timeout)
            s.connect(self.path)
            s.sendall(line)
            resp_line = s.makefile("rb").readline(MAX_LINE + 2)
            if not resp_line:
                raise IpcError("demon zamknął bez odpowiedzi")
            if len(resp_line) > MAX_LINE:
                raise IpcError("odpowiedź przekracza MAX_LINE")
            try:
                resp = json.loads(resp_line.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise IpcError("odpowiedź demona nie-JSON") from None
            if not isinstance(resp, dict):
                raise IpcError("odpowiedź demona nie-obiekt")
            return resp
        finally:
            s.close()

    # ------------- opy wygodne -------------
    def status(self) -> dict:
        return self.request("status")

    def try_status(self) -> dict | None:
        return self.try_request("status")

    def is_up(self) -> bool:
        return self.try_status() is not None

    def peers(self) -> int:
        return int(self.request("peers")["peers"])

    def set_mining(self, on: bool) -> bool:
        return bool(self.request("mining", on=bool(on))["mining"])

    def submit_tx_dict(self, txd: dict) -> str:
        return str(self.request("submit", tx=txd)["txid"])

    def balance(self, wallet: str) -> int:
        return int(self.request("balance", wallet=wallet)["balance"])

    def nonce(self, wallet: str) -> int:
        return int(self.request("nonce", wallet=wallet)["nonce"])

    def sync(self) -> bool:
        return bool(self.request("sync")["sync"])

    # ------------- pool (M7c) -------------
    def pool_page(self, offset: int = 0, limit: int = POOL_PAGE_MAX) -> dict:
        return self.request("pool", offset=offset, limit=limit)

    def pool_decoys(self, amt: int) -> list:
        return list(self.request("pool_decoys", amt=amt)["members"])

    def pool_mine(self) -> list:
        return list(self.request("pool_mine")["mine"])

    def pool_kis(self) -> list:
        return list(self.request("pool_kis")["kis"])

    # ------------- profil/donate/discovery (D52/D50/D54) -------------
    def census(self) -> dict:
        return self.request("census")          # D61: licznik sieci (estymacja+rejestr)

    def ghost(self, on: bool) -> dict:
        return self.request("ghost", on=bool(on))   # D63: duch w locie

    def price(self) -> dict:
        """D67: pokój cenowy FNX-COIN z demona (read-only)."""
        return self.request("price")

    # ------------- AI-GRID (D69) -------------
    def grid_submit(self, label: str, iters: int, bounty_iskry: int,
                    quorum_k: int = 2, window_h: int = 256) -> dict:
        """D69: ogłoś zadanie w siatce (poster = wallet demona; pay po kworum+recompute)."""
        return self.request("grid_submit", label=label, iters=int(iters),
                            bounty_iskry=int(bounty_iskry), quorum_k=int(quorum_k),
                            window_h=int(window_h))

    def grid_status(self) -> dict:
        """D69: kokpit siatki (read-only): zadania, wyniki, rozliczenia."""
        return self.request("grid_status")

    def ban_status(self, target: str | None = None) -> dict:
        """D66: status banu (wallet/username/ja) — lusterko konsensusu dla GUI."""
        return self.request("ban_status", target=target) if target else self.request("ban_status")

    def profile(self) -> dict:
        return self.request("profile")

    def donate(self, amount_iskry: int, note: str = "") -> dict:
        return self.request("donate", amount_iskry=int(amount_iskry), note=note)

    def netinfo(self) -> dict:
        return self.request("netinfo")

    def site_created(self, url: str | None = None) -> bool:
        p: dict = {}
        if url is not None:
            p["url"] = url
        return bool(self.request("site_created", **p)["site_created"])

    # ------------- msg (M4) -------------
    def msg_sub(self, fp: str) -> bool:
        return self.request("msg_sub", fp=fp)["subscribed"] == fp

    def msg_send_env(self, env: dict) -> dict:
        return self.request("msg_send", env=env)

    def msg_poll_envs(self, fp: str) -> list:
        return list(self.request("msg_poll", fp=fp)["envs"])


class MsgIpcTransport:
    """Transport messengera przez demona (mesh T_MSG). Duck-type dokładnie jak
    LocalTransport z app/messenger — rdzeń M4 nie pozna różnicy, a koperta leci
    prawdziwą siecią P2P. Demon widzi TYLKO szyfr (test drutu w fenix_node)."""

    def __init__(self, ipc, my_fp: str):
        self.ipc = ipc
        self.my_fp = my_fp
        self.ipc.msg_sub(my_fp)              # zakłada skrzynkę po stronie demona

    def send_env(self, env: dict) -> None:
        self.ipc.msg_send_env(env)

    def poll_envs(self) -> list:
        return self.ipc.msg_poll_envs(self.my_fp)


# -------------------------------------------------------------------------- selftest (headless)
if __name__ == "__main__":
    import os as _os
    import stat as _stat
    import tempfile as _tf

    print("gui/backend_ipc.py — selftest: dispatch czysty, NDJSON po unix-sock,\n"
          "anty-DoS, backoff klienta, E2E z prawdziwym Node, zero sekretów na drucie\n")

    from core.identity import Identity
    from chain.block import ISKRA, TX_TRANSFER
    from chain.miner import mine

    # --- FakeNode: duck-typowana maszynownia do testów czystego dispatchu ---
    class FakeNode:
        def __init__(self):
            self.ledger = Ledger()
            self.identity = Identity.generate("fake_ipc")   # potrzebne opom pool_mine
            self.mined = 2
            self._mining = True
            self.submitted: list[Tx] = []
            self.syncs = 0
            self.msg_box: dict[str, list] = {}              # poczta T_MSG (RAM)

        def peers_count(self): return 3
        def mining_on(self): return self._mining
        def set_mining(self, on): self._mining = bool(on)
        def submit_tx(self, tx): self.submitted.append(tx)
        def request_sync_all(self): self.syncs += 1

        # poczta T_MSG (duck-type jak net/fenix_node.Node) — skrzynki w dict, RAM
        def msg_subscribe(self, fp): self.msg_box.setdefault(fp, [])
        def msg_submit(self, env):
            self.msg_box.setdefault(env["to_fp"], []).append(env)
            return {"delivered": 1, "dup": False}
        def msg_drain(self, fp):
            out = list(self.msg_box.get(fp, []))
            self.msg_box[fp] = []
            return out

        # D52/D54 duck-type: profil/discovery (jak net/fenix_node.Node)
        def net_discovery(self):
            return {"discover": True, "first_node": False, "addr_book": 7,
                    "target_peers": 4, "uptime_hours": 0.002}

        def stats_view(self):
            return {"uptime_hours": 0.002, "site_created": False, "first_node_ever": False}

        def mark_site_created(self):
            self._site = True

    fn = FakeNode()
    srv = IpcServer(fn)          # dispatch-only (bez startu: socket-free)
    ala = Identity.generate("ala_ipc")
    bob = Identity.generate("bob_ipc")

    # 1) dispatch: śmieci odrzucane (non-dict, zły op, p non-dict)
    r = srv._dispatch("string zamiast obiektu")
    assert r["ok"] is False and "obiekt" in r["err"]
    assert srv._dispatch({"op": "hack", "id": 1})["ok"] is False
    assert srv._dispatch({"op": "status", "p": "nie-dict"})["ok"] is False
    print("  [OK] 1. dispatch: non-dict/nieznany op/złe p → ok:false (serwer nie pada)")

    # 2) status: pełne pola + ZERO sekretów w odpowiedzi
    r = srv._dispatch({"op": "status", "id": 9})
    assert r["ok"] and r["id"] == 9
    for k in ("height", "tip", "peers", "mining", "mined", "mempool",
              "pool_size", "key_images", "usernames"):
        assert k in r, f"brak pola {k}"
    assert r["peers"] == 3 and r["mined"] == 2 and r["mining"] is True
    blob = json.dumps(r).lower()
    for kill in ("priv", "secret", "seed", "passkey"):
        assert kill not in blob, f"Sekret '{kill}' w odpowiedzi IPC!"
    print("  [OK] 2. status: 9 pól; drut IPC bez priv/secret/seed/passkey")

    # 3) mining toggle + sync + peers przez dispatch
    r = srv._dispatch({"op": "mining", "p": {"on": False}, "id": 3})
    assert r["ok"] and r["mining"] is False and fn._mining is False
    srv._dispatch({"op": "sync"})
    assert fn.syncs == 1
    assert srv._dispatch({"op": "peers"})["peers"] == 3
    print("  [OK] 3. mining on/off + sync + peers: dispatch steruje maszynownią")

    # 4) submit/nonce/balance przechodzą walidację; śmieciowy tx → ok:false
    won = mine(fn.ledger.block_template(ala.wallet, zbits=2), max_tries=200_000)
    assert won is not None
    fn.ledger.apply_block(won)          # sukces = None; porażka = ChainError (nie assertuj zwrotu!)
    # coinbase NIE bije nonce (nonce=0); op nonce = chain+mempool (jak add_tx)
    assert srv._dispatch({"op": "nonce", "p": {"wallet": ala.wallet}})["nonce"] == 0
    bal = srv._dispatch({"op": "balance", "p": {"wallet": ala.wallet}})["balance"]
    assert bal == 5 * ISKRA
    tx = Tx.build_signed(TX_TRANSFER, ala, bob.wallet, ISKRA, nonce=0)
    r = srv._dispatch({"op": "submit", "p": {"tx": tx.to_dict()}})
    assert r["ok"] and r["txid"] == tx.txid() and fn.submitted[-1].txid() == tx.txid()
    assert srv._dispatch({"op": "submit", "p": {"tx": {"zly": "tx"}}})["ok"] is False
    assert srv._dispatch({"op": "balance", "p": {}})["ok"] is False
    print("  [OK] 4. nonce/balance/submit: poprawny tx przechodzi, śmieć → ok:false")

    # 5) E2E po prawdziwym unix-sockiecie: start, status, perms 0660
    d5 = _tf.mkdtemp(prefix="fenix-ipc-")
    sock = _os.path.join(d5, "node.ipc")
    server = IpcServer(fn, path=sock)
    server.start()
    assert _stat.S_IMODE(_os.stat(sock).st_mode) == 0o660, "gniazdo musi być 0660"
    cli = BackendIpc(path=sock, timeout=2.0)
    st = cli.status()
    assert st["peers"] == 3 and cli.is_up() and cli.peers() == 3
    assert cli.balance(ala.wallet) == 5 * ISKRA
    print("  [OK] 5. E2E unix-socket: status/peers/balance żywe; gniazdo 0660")

    # 6) anty-DoS: śmieć i za długa linia → ok:false, serwer DALEJ żyje
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock)
    s.sendall(b"to nie jest json\n")
    assert json.loads(s.makefile("rb").readline(MAX_LINE + 10).decode())["ok"] is False
    s.close()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock)
    s.sendall(b"X" * (MAX_LINE + 5) + b"\n")
    assert "za długa" in json.loads(s.makefile("rb").readline(MAX_LINE + 10).decode())["err"]
    s.close()
    assert cli.is_up(), "serwer padł po ataku śmieciowym!"
    print("  [OK] 6. anty-DoS: nie-JSON + >64 KiB odrzucone; serwer żyje dalej")

    # 7) klient: demon martwy → IpcError dla request, None dla try_*, backoff liczony zegarem
    class _Clk:
        def __init__(self): self.t = 1000.0
        def __call__(self): return self.t

    clk = _Clk()
    cli_dead = BackendIpc(path=_os.path.join(d5, "nie-ma.ipc"), backoff_s=3.0, clock=clk)
    try:
        cli_dead.status()
        raise SystemExit("status u martwego demona przeszedł!")
    except IpcError as e:
        assert "brak demona" in str(e)
    assert cli_dead.try_status() is None          # backoff: natychmiastowy IpcError wewnątrz
    connects_before = cli_dead._next_id
    clk.t += 3.5                                    # backoff minął
    assert cli_dead.try_status() is None          # nadal martwe, ale już po rzetelnym connect
    assert cli_dead._next_id > connects_before    # …czyli connect naprawdę był ponowiony
    print("  [OK] 7. klient: martwy demon → IpcError/None; backoff 3 s z zegara wstrzykiwanego")

    # 8) E2E z PRAWDZIWYM Node (mesh klasą, bez seedów, mining tylko ręczny)
    from net.fenix_node import Node, NodeConfig

    d8 = _tf.mkdtemp(prefix="fenix-ipc-node-")
    sock8 = _os.path.join(d8, "node.ipc")
    port = 45_777
    node = Node(NodeConfig(host="127.0.0.1", port=port, seeds=(), zbits=2,
                           mine=False, cover=False, username="ipc_node"))
    node.start()
    real_srv = IpcServer(node, path=sock8)
    real_srv.start()
    try:
        cli8 = BackendIpc(path=sock8, timeout=3.0)
        assert cli8.status()["mining"] is False          # node wystartował z pauzą
        cli8.set_mining(True)
        assert node.mining_on() is True and cli8.status()["mining"] is True
        cli8.set_mining(False)
        won8 = mine(node.ledger.block_template(node.identity.wallet, zbits=2),
                    max_tries=200_000)
        node.ledger.apply_block(won8)
        tx8 = Tx.build_signed(TX_TRANSFER, node.identity, bob.wallet, ISKRA, nonce=0)
        txid8 = cli8.submit_tx_dict(tx8.to_dict())
        assert txid8 == tx8.txid()
        assert any(t.txid() == txid8 for t in node.ledger.mempool), "tx z IPC nie wszedł do mempoola demona!"
        # po submicie: nonce op = chain(0)+mempool(1) = 1 — Ethereum-style (patrz _op_nonce)
        assert cli8.nonce(node.identity.wallet) == 1
        assert cli8.status()["mempool"] >= 1
        # D66: op ban_status przez ŻYWE IPC (czysty→zbanowany→po wykupie) + walidacja targetu
        from chain import ban_evt as _bevt8
        bs0 = cli8.ban_status()
        assert bs0["found"] and bs0["banned"] is False and bs0["target"] == node.identity.wallet
        _c8 = _bevt8.ban_core(bob.wallet, "0x12", *_bevt8.REASONS_RED["0x12"][1:],
                              _bevt8.evidence_hash_of({"ipc": "D66"}))
        _bevt8.apply_ban(node.ledger.bans, _c8, node.ledger.height())
        bs1 = cli8.ban_status(bob.wallet)
        assert bs1["banned"] and bs1["code"] == "0x12" and bs1["slug"] == "INVALIDTAG_STORM"
        _bevt8.apply_unban(node.ledger.bans, bob.wallet, node.ledger.height())
        bs2 = cli8.ban_status(bob.wallet)
        assert bs2["banned"] is False and bs2["history"] is True, "po wykupie: historia, nie plomba"
        no8 = cli8.ban_status("duch-username")
        assert no8["found"] is False, "username nieznany = uczciwe found:false"
        try:
            cli8.request("ban_status", target=123)
            raise SystemExit("target int przeszedł!")
        except IpcError:
            pass
        print("  [OK] 8b. D66: op ban_status ŻYWE IPC — mój/cudzy/zbanowany/historia/nieznany/zły typ")
        # D67: op price ŻYWE IPC — krzywa z demona = krzywa lokalna (ta sama księga)
        pr8 = cli8.price()
        from app.fnx_coin import price_info as _pi8
        assert pr8["price_cents"] == _pi8(node.ledger)["price_cents"] \
            and pr8["ask_cents"] > pr8["price_cents"] >= pr8["bid_cents"] >= 1, \
            "pokój cenowy IPC: ta sama cena co lokalna + ask>mid>=bid"
        print("  [OK] 8c. D67: op price ŻYWE IPC — cena/ask/bid zgodne z lokalną krzywą, read-only")
    finally:
        real_srv.stop()
        node.stop()
    server.stop()

    # 9) po stop() gniazdo sprzątnięte, klient grzecznie dostaje błąd
    assert not _os.path.exists(sock), "gniazdo powinno zniknąć po stop()"
    try:
        cli.status()
        raise SystemExit("status po stop serwera przeszedł!")
    except IpcError:
        pass
    print("  [OK] 9. stop(): gniazdo sprzątnięte; klient → uczciwy IpcError")

    # 10) pool ops (M7c): scan demona → TYLKO sp/ep/amt (hint zostaje), paging, decoys
    from chain.stealth import derive_stealth
    st_mine = derive_stealth(fn.identity.sig_pub_b, fn.identity.x_pub_b)
    st_other = derive_stealth(bob.sig_pub_b, bob.x_pub_b)
    fn.ledger.pool[st_mine["stealth_pub"]] = {"ep": st_mine["eph_pub"], "amt": 2 * ISKRA}
    fn.ledger.pool[st_other["stealth_pub"]] = {"ep": st_other["eph_pub"], "amt": 2 * ISKRA}
    r = srv._dispatch({"op": "pool", "p": {"offset": 0, "limit": 1}})
    assert r["ok"] and r["total"] == 2 and len(r["outs"]) == 1
    assert set(r["outs"][0].keys()) == {"sp", "ep", "amt", "v"}   # marker wersji (v1/v2)
    r2 = srv._dispatch({"op": "pool", "p": {"offset": 1, "limit": 5}})
    assert r2["ok"] and len(r2["outs"]) == 1, "druga strona = reszta"
    assert srv._dispatch({"op": "pool", "p": {"offset": -1}})["ok"] is False
    assert srv._dispatch({"op": "pool", "p": {"limit": 10_000}})["ok"] is False
    r3 = srv._dispatch({"op": "pool_decoys", "p": {"amt": 2 * ISKRA}})
    assert r3["ok"] and len(r3["members"]) == 2
    assert srv._dispatch({"op": "pool_decoys", "p": {"amt": -5}})["ok"] is False
    r4 = srv._dispatch({"op": "pool_mine"})
    assert r4["ok"] and len(r4["mine"]) == 1 and r4["mine"][0]["amt"] == 2 * ISKRA
    blob10 = json.dumps(r4).lower()
    for kill in ("hint", "priv", "secret", "seed"):
        assert kill not in blob10, f"SEKRET '{kill}' w pool_mine (drut IPC!)"
    # pool_kis: publiczne key-images (filtr „wydane" liczy GUI po scanie mgły)
    fn.ledger.key_images.add("ab" * 32)
    r_kis = srv._dispatch({"op": "pool_kis"})
    assert r_kis["ok"] and r_kis["kis"] == ["ab" * 32], "pool_kis ma zwracać rejestr ki"
    assert "ab" * 32 not in json.dumps(srv._dispatch({"op": "pool_mine"}))
    print("  [OK] 10. pool ops (M7c): paging deterministyczny, decoys wg nominału,\n"
          "         pool_mine tylko demona-tożsamość; spend_hint NIGDY nie leci drutem;\n"
          "         pool_kis = publiczne key-images (filtr v2 po stronie GUI, M7d)")

    # 11) msg ops (M4): sub/poll walidują fp; send odrzuca za dużą kopertę PRZED node;
    #     roundtrip FakeNode: send → poll; drain = wyczyszczone; MsgIpcTransport duck-type
    assert srv._dispatch({"op": "msg_sub", "p": {"fp": "xyz"}})["ok"] is False
    assert srv._dispatch({"op": "msg_sub", "p": {"fp": "ab" * 8}})["ok"] is True
    assert "ab" * 8 in fn.msg_box, "subskrypcja nie założyła skrzynki w node"
    big11 = {"v": 1, "to_fp": "cd" * 8, "from": "FNXS1" + "0" * 8, "eph": "e" * 64,
             "n": "0" * 24, "ct": "ff" * MSG_MAX_ENV}
    r_big = srv._dispatch({"op": "msg_send", "p": {"env": big11}})
    assert r_big["ok"] is False and "ponad" in r_big["err"], "za duża koperta przeszła IPC!"
    env11 = {"v": 1, "to_fp": "ab" * 8, "from": "FNXS1" + "0" * 8, "eph": "e" * 64,
             "n": "0" * 24, "ct": "ff" * 8}
    r11 = srv._dispatch({"op": "msg_send", "p": {"env": env11}})
    assert r11["ok"] and r11["delivered"] == 1
    r12 = srv._dispatch({"op": "msg_poll", "p": {"fp": "ab" * 8}})
    assert r12["ok"] and r12["envs"] == [env11]
    assert srv._dispatch({"op": "msg_poll", "p": {"fp": "ab" * 8}})["envs"] == [], \
        "drain nie wyczyścił skrzynki (koperty leżałyby w RAM demona!)"
    assert srv._dispatch({"op": "msg_poll", "p": {}})["ok"] is False
    assert srv._dispatch({"op": "msg_send", "p": {"env": "nie-dict"}})["ok"] is False
    blob11 = json.dumps(r12).lower()
    for kill in ("priv", "secret", "seed", "text"):
        assert kill not in blob11, f"'{kill}' na drucie IPC msg (koperta = sam szyfr!)"
    # MsgIpcTransport: dokładny duck-type messengera na żywym dispatchu
    class _StubMsgIpc:
        def __init__(self, server): self.server = server
        def msg_sub(self, fp):
            assert self.server._dispatch({"op": "msg_sub", "p": {"fp": fp}})["ok"]
            return True
        def msg_send_env(self, env):
            r = self.server._dispatch({"op": "msg_send", "p": {"env": env}})
            if not r["ok"]:
                raise IpcError(r["err"])
            return r
        def msg_poll_envs(self, fp):
            return list(self.server._dispatch({"op": "msg_poll", "p": {"fp": fp}})["envs"])

    t11 = MsgIpcTransport(_StubMsgIpc(srv), "ef" * 8)
    env11b = dict(env11, to_fp="ef" * 8, ct="aa" * 8)
    t11.send_env(env11b)
    assert t11.poll_envs() == [env11b] and t11.poll_envs() == []
    print("  [OK] 11. msg ops (M4): walidacja fp/rozmiaru; roundtrip przez dispatch;")
    print("           drain czyści RAM demona; MsgIpcTransport = duck-type messengera")

    # 12) D52/D54: profile = odznaki z konsensusu+licznika; netinfo z demona; donate
    #     buduje PRAWIDŁOWY TX_DONATE (kwota użytkownika, skarbiec, podpis wiąże wallet);
    #     walidacja: 0/ujemna/bool/tekst → ok:false; site_created melduje licznik
    r12p = srv._dispatch({"op": "profile"})
    assert r12p["ok"] and r12p["wallet"] == fn.identity.wallet
    assert set(r12p["badges"].keys()) == {"earned", "locked"}, r12p["badges"].keys()
    assert r12p["donated_iskry"] == 0 and r12p["stats"]["first_node_ever"] is False
    blob12 = json.dumps(r12p).lower()
    for kill in ("priv", "secret", "seed", "passkey"):
        assert kill not in blob12, f"'{kill}' w profilu IPC!"
    r12n = srv._dispatch({"op": "netinfo"})
    assert r12n["ok"] and r12n["target_peers"] == 4 and r12n["first_node"] is False
    for bad_amt in (0, -5, True, "100", None):
        r_bad = srv._dispatch({"op": "donate", "p": {"amount_iskry": bad_amt}})
        assert r_bad["ok"] is False, f"donate {bad_amt!r} przeszedł!"
    n_sub = len(fn.submitted)
    r12d = srv._dispatch({"op": "donate", "p": {"amount_iskry": 3 * ISKRA,
                                                "note": "test"}})
    assert r12d["ok"] and len(fn.submitted) == n_sub + 1, r12d
    txd = fn.submitted[-1]
    assert txd.type == 0x14 and txd.recipient == fn.ledger.treasury \
        and txd.amount == 3 * ISKRA and txd.verify_signature(), "TX_DONATE z IPC zły lub niepodpisany!"
    r12s = srv._dispatch({"op": "site_created", "p": {"url": "fnx://ala.strona"}})
    assert r12s["ok"] and r12s["site_created"] is True and fn._site is True
    print("  [OK] 12. profile/netinfo/donate/site_created: odznaki bez sekretów; donate")
    print("           kwotą użytkownika do skarbca (podpis wiąże wallet); złe kwoty odrzucone")

    # 13) P20/D56: demon jako OSOBNY PROCES z prawdziwymi argv (lekcja dispatch-demona!)
    #     + klient BackendIpc dokładnie ten, którego używa GUI — pełna runda opów przez
    #     gniazdo unix; potem SIGINT i demon ma zejść CZYSTO (peers.json flush, zero Traceback).
    import subprocess as _sp
    import tempfile as _tf
    import time as _tm
    import signal as _sig
    import shutil as _sh13
    dd13 = _tf.mkdtemp(prefix="fenix-live20-")
    log13_path = _os.path.join(dd13, "demon.log")
    log13 = open(log13_path, "w+", encoding="utf-8")
    import socket as _sk13
    s13 = _sk13.socket()
    s13.bind(("127.0.0.1", 0))
    port13 = s13.getsockname()[1]
    s13.close()
    sock13 = _os.path.join(dd13, "node.ipc")
    repo13 = str(_pl.Path(__file__).resolve().parents[1])
    proc = _sp.Popen([sys.executable, "-u", "-m", "net.fenix_node",
                      "--host", "127.0.0.1", "--port", str(port13),
                      "--data-dir", dd13, "--zbits", "2", "--no-cover",
                      "--no-discover", "--ipc", sock13],
                     stdout=log13, stderr=_sp.STDOUT, cwd=repo13)
    try:
        deadline = _tm.time() + 40
        while _tm.time() < deadline and not _os.path.exists(sock13):
            assert proc.poll() is None, \
                "demon umarł przed wystawieniem IPC (P20!) — patrz demon.log"
            _tm.sleep(0.2)
        assert _os.path.exists(sock13), "gniazdo IPC nie powstało w 40 s (P20!)"
        cli = BackendIpc(path=sock13, timeout=6.0, backoff_s=0.2)
        assert cli.is_up(), "klient GUI nie widzi ŻYWEGO demona (P20!)"
        assert cli.peers() >= 0                                  # op peers: liczba z demona
        st = cli.status()
        assert isinstance(st, dict) and st.get("ok") is True, st
        ni = cli.netinfo()
        assert ni.get("ok") is True and ni.get("target_peers") == 4 and \
            ni.get("first_node") is False, ni                    # discover OFF w teście
        sen = cli.request("sentinel")                            # op białej listy (D17)
        assert isinstance(sen, dict) and sen.get("ok") is True   # radar w procesie demona
        assert cli.msg_sub("ab" * 8) is True                     # skrzynka RAM w demone
        env13 = {"v": 1, "to_fp": "ab" * 8, "from": "FNXS1" + "0" * 8, "eph": "e" * 64,
                 "n": "0" * 24, "ct": "ff" * 8}
        r13 = cli.msg_send_env(env13)
        assert r13.get("delivered") == 1, r13
        assert cli.msg_poll_envs("ab" * 8) == [env13]            # roundtrip 2 procesy!
        assert cli.msg_poll_envs("ab" * 8) == []                 # drain czyści RAM
        # donate z ŻYWEGO demona = prawdziwe saldo: kopanie (zbits=2) musi dorzucić
        # nagrody, nim TX się zbuduje — uczciwa odmowa „brak środków" już złapana
        wal13 = cli.profile()["wallet"]
        for _ in range(60):
            if cli.balance(wal13) >= 3 * ISKRA:
                break
            _tm.sleep(0.25)
        assert cli.balance(wal13) >= 3 * ISKRA, "kopanie demona nie doładowało salda w 15 s"
        rd13 = cli.donate(2 * ISKRA, note="P20 live")
        assert isinstance(rd13, dict) and rd13.get("ok") is True, rd13
        assert cli.site_created("fnx://p20.live") is True        # licznik w demonie (+stats)
    finally:
        if proc.poll() is None:
            proc.send_signal(_sig.SIGINT)                        # jak Ctrl+C operatora
        try:
            rc13 = proc.wait(timeout=25)
        except _sp.TimeoutExpired:
            proc.kill()
            raise SystemExit("demon NIE zszedł czysto na SIGINT (P20!)")
        log13.flush()
        log13.close()
        txt13 = open(log13_path, encoding="utf-8", errors="replace").read()
        assert "Traceback" not in txt13, f"Traceback w logu demona (P20!):\n{txt13[-800:]}"
        assert "attest Deimosa w procesie" in txt13, "log bez attesta D55 (regresja z argv!)"
        assert rc13 == 0, f"demon zszedł rc={rc13} na SIGINT (P20!)"
        for f13 in ("admin.ks", "admin_attestor.json", "stats.json"):
            assert _os.path.exists(_os.path.join(dd13, f13)), f"brak {f13} po żywym demone (D54/D55)"
        _sh13.rmtree(dd13, ignore_errors=True)
    print("  [OK] 13. P20/D56: ŻYWY demon (osobny proces, prawdziwe argv) + klient GUI:")
    print("           status/peers/netinfo/sentinel/msg-roundtrip/donate/site_created;")
    print("           SIGINT = czyste zejście, attest D55 w logu, zero Traceback")

    print("\nSELFTEST: PASS ✅  gui/backend_ipc.py — most GUI↔demon działa (NDJSON/unix,\n"
          "dispatch czysty, anty-DoS, backoff, E2E z Node, poczta T_MSG, zero sekretów,\n"
          "żywe 2 procesy (P20))")
