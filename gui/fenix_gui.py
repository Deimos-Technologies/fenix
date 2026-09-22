# gui/fenix_gui.py — FenixOS GUI (M7): „przejrzyste, łatwe i ładne" okno po username (D28/D29)
"""
Dwie warstwy, zgodnie z regułą projektu (logika testowalna headless / widok leniwy):

  FenixController — czysta LOGIKA: profil, saldo, resolver username (z rejestru
      on-chain!), walidacja edycji profilu, skan prywatnego poola, suwak paranoii
      A/B/C (D29), sterowanie Mullvad (fenix-vpn). NIC z Tkintera tu nie wchodzi —
      selftest goni to bez ekranu.
  FenixApp(tk.Tk) — WIDOK: ciemny motyw, sidebar (Dashboard/Portfel/Kontakty/Sieć/
      Ustawienia), badge rangi (WYŚWIETLANA, nie edytowalna — D28), avatar z inicjałów,
      wątk roboczy + after() (nigdy nie zamrażamy UI).

D28 w GUI: pokazujemy USERNAME, nie UID (test to sprawdza). Username edytowalny
(on-chain claim/rename, fee z chain/usernames), avatar jako ref-hex 64B.
D29 suwak paranoii: A szum-camo (domyślny) → B DNS-camo/(mimikra) → C + Mullvad WG
z kill switchem (C NIE wejdzie, gdy VPN leży — test).
IPC do demona fenix-node (M7b): gui/backend_ipc.py — demon żyje → dashboard/saldo/
nonce/submit/mining przez unix-socket /run/fenix/node.ipc; demon martwy → tryb dev
na współdzielonym ledgerze i GUI UCZCIWIE to pokazuje („demon OFF-LINE").
Backlog: messenger M4 (panel Kontakty ma już resolver+TOFU-sloty).
"""
from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
import pathlib as _pl
from dataclasses import dataclass, field
from typing import Callable, Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from core.identity import Identity, valid_username, RANKS, rank_tier            # noqa: E402
from chain.block import (ISKRA, Tx, TX_TRANSFER, TX_ID_DECLARE, TX_SHIELD,          # noqa: E402
                         TX_CONTACT_REF, TX_RANK_UP, TX_DONATE)
from chain import usernames as uname
from chain import ban_evt as bevt                                             # noqa: E402
from chain import tx_ring as txr                                                 # noqa: E402
from chain import ranks as rks                                                   # noqa: E402  rangi z konsensusu
from chain import contact_ref as cref                                            # noqa: E402  P21/D45 nick→kontakt
from chain.ledger import Ledger, ChainError                                      # noqa: E402
from gui import panic_button as pbtn                                             # noqa: E402  D27 w GUI
from gui import pool_panel as poolp                                              # noqa: E402  M7c Pool
from gui.backend_ipc import BackendIpc, IpcError                                  # noqa: E402  M7b IPC

GUI_TICK_MS = 2000          # odświeżanie dashboardu/sieci
APP_TITLE = "FenixOS — twoje okno w sieci"

# --- motyw Feniksa (ciemny, „ładny" wg brief) ---
C_BG = "#0e1116"
C_CARD = "#171b22"
C_CARD2 = "#1d222b"
C_TEXT = "#e6e9ef"
C_MUTED = "#8a93a5"
C_ACCENT = "#ff7a1a"        # fenix-orange
C_OK = "#35d07f"
C_WARN = "#ffb454"
C_BAD = "#ff5e5e"
C_CYAN = "#2fd4c4"
RANK_COLORS = {"ghost": "#6b7280", "donor": "#cd7f32", "vip": "#c0c0c0",
               "vip+": "#d4d4ff", "svip": "#ffd166", "elite": "#ff7a1a",
               "selite": "#ff5e5e", "fenix": "#f8f8ff"}

# --- suwak paranoii (D29) ---
PARANOIA = {
    "A": {"nazwa": "A — szum (domyślna)",
          "opis": "Padding+kowadła rekordowe, jitter, ruch indistinguishable od TLS. "
                  "Najszybsza. Dla codziennego użytku.",
          "warstwy": ["camo"]},
    "B": {"nazwa": "B — kamuflaż DNS",
          "opis": "A + Profil D: bootstrap/seeds przez DNS (Mullvad resolver, base32 "
                  "qname↔TXT). Wolniejszy start. (mimikra TLS: roadmap D29)",
          "warstwy": ["camo", "dnscamo"]},
    "C": {"nazwa": "C — maksymalna (VPN + wszystko)",
          "opis": "B + tunel Mullvad WireGuard (fenixwg0) z KILL SWITCHEM: padnie VPN "
                  "→ NIC nie wycieknie. Wymaga działającego fenix-vpn.",
          "warstwy": ["camo", "dnscamo", "mullvad-wg"]},
}


class FenixGuiError(Exception):
    """Błąd sterownika GUI — jeden typ."""


# -------------------------------------------------------------------------- VPN kontroler
class VpnCtl:
    """Sterowanie fenix-vpn przez komendę (domyślnie `python3 -m transport.mullvad`).
    Runner wstrzykiwalny — selftest nie woła prawdziwego shella."""

    def __init__(self, runner: Callable[[list], tuple] | None = None):
        self._runner = runner or self._real_runner
        self._country = "pl"

    @staticmethod
    def _real_runner(argv: list) -> tuple[int, str]:
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=90, cwd=str(_pl.Path(__file__).resolve().parents[1]))
            return p.returncode, p.stdout + p.stderr
        except (OSError, subprocess.SubprocessError) as e:
            return 127, str(e)

    def _cmd(self, *args: str) -> list:
        return [sys.executable, "-m", "transport.mullvad", *args]

    def status(self) -> tuple[str, str]:
        """Zwraca ('up'|'down', detal)."""
        rc, out = self._runner(self._cmd("status"))
        txt = (out or "").strip()
        if rc == 0 and "handshake" in txt.lower():
            return "up", txt
        return "down", txt or "tunel nieaktywny"

    def up(self, country: str | None = None) -> tuple[bool, str]:
        rc, out = self._runner(self._cmd("up", "--country", country or self._country))
        return rc == 0, out.strip()

    def down(self) -> tuple[bool, str]:
        rc, out = self._runner(self._cmd("down"))
        return rc == 0, out.strip()


# -------------------------------------------------------------------------- kontroler (logika)
@dataclass
class FenixController:
    """Logika GUI. ledger=None → dev: własny Ledger (desktop demo; produkcja: IPC backlog)."""
    identity: Identity
    ledger: Ledger | None = None
    vpn: VpnCtl | None = None
    node_peers: Callable[[], int] = lambda: 0          # dev-fallback (gdy brak IPC)
    ipc: object | None = None                          # BackendIpc; None = tryb dev
    data_dir: str | None = None                        # ~/.fenix (ONB admina D55); None=domyślne
    _paranoia: str = field(default="A", init=False)

    def __post_init__(self):
        self.ledger = self.ledger or Ledger()
        self.vpn = self.vpn or VpnCtl()

    # ---------------- profil (D28) ----------------
    def profile(self) -> dict:
        """Co GUI POKAZUJE o mnie. KLUCZOWE (D28): NIGDY UID/wallet w display_name.
        Ranga: chain (TX_RANK_UP, aktywna po 6 confs) ma PRIORYTET nad lokalną etykietą;
        pending pokazujemy jako „oczekuje (x/6)"."""
        names = [n for n, w in self.ledger.usernames.items() if w == self.identity.wallet]
        tip_ts = self.ledger.tip().timestamp          # D51: ważność rang LICZYMY z łańcucha
        chain_r = rks.active_rank(self.ledger.ranks, self.ledger.height(),
                                  self.identity.wallet, now_ts=tip_ts)
        pend = rks.pending_rank(self.ledger.ranks, self.ledger.height(),
                                self.identity.wallet)
        base = self.identity.rank
        eff = chain_r if rank_tier(chain_r) > rank_tier(base) else base
        return {"display_name": self.identity.username,      # ← username, nie uid!
                "onchain_name": names[0] if names else None,
                "rank": eff,
                "rank_tier": rank_tier(eff),
                "rank_color": RANK_COLORS[eff],
                "onchain_rank": chain_r,                     # uczciwie: co mówi konsensus
                "rank_pending": pend,                        # (rank, x/6) albo None
                "rank_ttl_s": rks.rank_time_left(self.ledger.ranks, self.ledger.height(),
                                                 self.identity.wallet, now_ts=tip_ts),  # D51
                "avatar": ""}

    def set_rank(self, _new_rank: str) -> None:
        """D28: ranga NIE jest samo-edytowalna (śćiernij i zastrzeżenie owner). ZAWSZE odmowa."""
        raise FenixGuiError("ranga pochodzi z konsensusu (TX_RANK_UP) — nie można jej edytować samemu (D28)")

    # ---------------- admin Deimos: ONB (D53/D55) ----------------
    def _admin_dir(self) -> str:
        import os as _o
        return self.data_dir or _o.path.join(_o.path.expanduser("~"), ".fenix")

    def admin_status(self) -> dict:
        """Stan konta admina dla widoku: czy ONB potrzebny (fabryczne hasło żyje?).
        Nigdy nie rzuca — status to dekoracja, nie brama (widok musi żyć zawsze)."""
        from gui import settings_admin as _sadm
        from core.admin import admin_status as _astatus
        d = self._admin_dir()
        try:
            st = _astatus(d)
            st["onboarding_needed"] = _sadm.needs_onboarding(d)
        except Exception as e:                              # np. prawa dostępu — meldujemy
            st = {"exists": None, "default_password": None,
                  "onboarding_needed": None, "error": str(e)}
        st["data_dir"] = d
        return st

    def admin_onboard(self, current: str, new: str, new_panic: str) -> str:
        """Wymuszona zmiana hasła admina (D55). Błąd = FenixGuiError po polsku."""
        from gui import settings_admin as _sadm
        try:
            return _sadm.run_onboarding(self._admin_dir(), current, new, new_panic)
        except _sadm.OnboardingError as e:
            raise FenixGuiError(str(e)) from None

    def validate_username_edit(self, new_name: str) -> tuple[bool, str, int, str]:
        """(ok, komunikat, fee_iskry, op) — przed złożeniem tx. Używa chain/usernames.
        D66: NA WEJŚCIU lusterko tombstone — zbanowany DOWIE SIĘ czemu (kod+powód+
        furtka), zanim kliknie 'zarejestruj'. (Egzekucja i tak siedzi w konsensusie:
        tx zbanowanego walletu nigdy nie wejdzie do mempoolu/bloku — tu pomagamy
        ZROZUMIEĆ, nie dorabiamy prawa.)"""
        if bevt.is_banned(self.ledger.bans, self.identity.wallet):
            return (False, bevt.ban_banner_pl(bevt.ban_view(
                self.ledger.bans, self.identity.wallet)), 0, "banned")
        try:
            op, name, _av, fee = uname.validate_username_payload(
                uname.username_payload("claim" if not self.profile()["onchain_name"] else "rename",
                                       new_name),
                self.ledger.usernames, self.identity.wallet)
            return True, f"OK: {op} → fee {fee / ISKRA:g} FNX", fee, op
        except uname.UsernameError as e:
            return False, str(e), 0, ""

    def build_username_tx(self, new_name: str, avatar: str = "") -> Tx:
        """Podpisany TX_ID_DECLARE gotowy do rozsyłki (broadcast: submit_signed)."""
        ok, msg, _fee, op = self.validate_username_edit(new_name)
        if not ok:
            raise FenixGuiError(msg)
        fee = uname.CLAIM_FEE if op == "claim" else uname.RENAME_FEE
        tx = Tx.build_signed(TX_ID_DECLARE, self.identity, "FNX-NAMES", fee,
                             nonce=self.nonce_next(),
                             payload=uname.username_payload(op, new_name, avatar))
        return tx

    def resolve_username(self, name: str) -> str | None:
        """username → wallet (z rejestru on-chain; None gdy brak)."""
        return self.ledger.usernames.get(name)

    def ban_status_line(self, target: str | None = None) -> str:
        """D66: jednolinijkowy status banu do pokazania człowiekowi.
        target = username (rozwiązujemy z rejestru) albo wallet FNX1...;
        brak targetu = MOJ wallet (np. czerwona kartka na dashboardzie)."""
        wallet = target
        if target and not target.startswith("FNX1"):
            wallet = self.ledger.usernames.get(target)
            if wallet is None:
                return f"{target}: username nieznany w rejestrze on-chain"
        return bevt.ban_banner_pl(bevt.ban_view(
            self.ledger.bans, wallet or self.identity.wallet))

    # ---------------- D67: pokój cenowy + karty Sieci (READ-ONLY widoki) ----------------
    def exchange_card(self) -> dict:
        """Pokój cenowy FNX-COIN do pokazania w GUI (D67). IPC (demon) > lokalny
        ledger (dev). SZYBA WYSTAWOWA: tu się NIC nie kupuje/sprzedaje — handel
        = desk + rail (P7, decyzja właściciela); dlatego karta mówi to głośno."""
        info, src = None, "dev-lokalny"
        if self.ipc is not None:
            try:
                info = self.ipc.price()
                src = "demon (IPC)"
            except Exception:
                info, src = None, "dev-lokalny (IPC padło)"
        if info is None:
            from app.fnx_coin import price_info
            info = price_info(self.ledger)
        st = info["stats"]
        lines = [f"cena: {info['price_usd']}  ·  kupno(ask): {info['ask_usd']}  ·  "
                 f"sprzedaż(bid): {info['bid_usd']}",
                 f"podaż: {info['supply_fnx']:,.2f} FNX  ·  wysokość: {st['height']}",
                 f"użytkownicy: {st['users']}  ·  attesterzy PoU: {st['attesters']}"
                 f"  ·  głosy: {st['votes_cast']}",
                 f"model: {info['model']}",
                 "handel: SZYBA read-only — desk+rail = P7 (LEGAL_NOTICE uczciwie)"]
        return {"src": src, "info": info, "lines": lines}

    def set_ghost_gui(self, on: bool) -> tuple[bool, str]:
        """Duch D63 W DEMONIE z GUI (D67). Dev bez IPC: uczciwa odmowa (jak mining)."""
        if self.ipc is None:
            return False, "brak IPC — duch sterowalny tylko w żywym fenix-node"
        try:
            r = self.ipc.ghost(bool(on))
            return True, f"tryb ducha: {'ON (adres/beacon nie są reklamowane; granice: routing/timing)' if r['ghost'] else 'OFF'}"
        except Exception as e:
            return False, str(e)

    def network_extra_card(self) -> dict:
        """D67: licznik sieci + stan ducha + MÓJ status banu — karty na stronie Sieć
        i kartka na Dashboardzie. Wszystko read-only z demona/lokalnie."""
        cen, ghost = None, None
        if self.ipc is not None:
            try:
                cen = self.ipc.census()
                ghost = cen.get("ghost")
            except Exception:
                cen = None
        return {"census": cen, "ghost": ghost,
                "my_ban_line": self.ban_status_line(),
                "note": ("licznik = ESTYMACJA z gossip (D61), nie cenzus; "
                         "duch ≠ tor (routing/timing zostaje — D63 jasne granice)")}

    # ---------------- pętla nick→wallet→kontakt (P21/D45) ----------------
    def build_contact_ref_tx(self, addr: str | None = None) -> Tx:
        """TX_CONTACT_REF: publikuję MOJĄ tabliczkę (domyślnie = mój adres czatu FNXS1).
        Od tego bloku każdy w sieci rozwiązuje mój nick → adres (bez karteczki)."""
        addr = addr or self.messenger().my_address()
        try:
            payload = cref.contact_payload("set", addr)
            _op, _a, fee_req = cref.validate_contact_payload(payload, self.identity.wallet)
        except cref.ContactRefError as e:
            raise FenixGuiError(str(e)) from None
        return Tx.build_signed(TX_CONTACT_REF, self.identity, "FNX-CONTACT", fee_req,
                               nonce=self.nonce_next(), payload=payload)

    def resolve_contact(self, username: str) -> str | None:
        """username → FNXS1 (pętla nick→wallet→ref on-chain; None = brak nicka albo ref)."""
        w = self.ledger.usernames.get((username or "").strip())
        return self.ledger.contact_refs.get(w) if w else None

    def msg_send_to(self, who: str, text: str) -> str:
        """Wyślij po ADRESIE FNXS1 albo po NICKU on-chain (auto-rozpoznanie pola)."""
        who = (who or "").strip()
        if not who.startswith("FNXS1"):
            addr = self.resolve_contact(who)
            if addr is None:
                raise FenixGuiError(f"brak kontaktu on-chain dla '{who}' — albo literówka "
                                    "w nicku, albo znajomy nie opublikował jeszcze ref "
                                    "(TX_CONTACT_REF w zakładce Konto)")
            who = addr
        return self.msg_send(who, text)

    # ---------------- ranga z konsensusu (TX_RANK_UP, D28) ----------------
    def buy_rank_tx(self, rank: str) -> tuple[Tx, str]:
        """(tx, opis). Kupno/upgrade/przedłużenie rangi: upgrade = dopłata RÓŻNICY ceny;
        RENEW (D51) = pełna cena tej samej rangi, +30 dni do ważności; mempool liczy się
        do bazy (zamówienia w kolejce); aktywacja po 6 potwierdzeniach."""
        rank = (rank or "").strip()
        import time as _t
        now_m = int(_t.time())                          # jak mempool: polityka lokalna
        virtual = {w: dict(v) for w, v in self.ledger.ranks.items()}
        for t in self.ledger.mempool:
            if t.type == TX_RANK_UP:
                try:
                    rk_t, _a_t, ren_t = rks.validate_rank_payload(
                        t.payload, virtual, t.sender, now_ts=now_m)
                    rks.apply_rank(virtual, rk_t, 0, t.sender, ts=now_m, renew=ren_t)
                except rks.RankError:
                    continue
        try:
            _rn, due, renew = rks.validate_rank_payload(rks.rank_payload(rank), virtual,
                                                        self.identity.wallet, now_ts=now_m)
        except rks.RankError as e:
            raise FenixGuiError(str(e)) from None
        tx = Tx.build_signed(TX_RANK_UP, self.identity, "FNX-RANKS", due,
                             nonce=self.nonce_next(), payload=rks.rank_payload(rank))
        if renew:
            return tx, (f"ranga '{rank}': przedłużenie = pełna cena {due / ISKRA:g} FNX "
                        f"(+30 dni ważności; bez resetu potwierdzeń)")
        return tx, (f"ranga '{rank}': dopłata różnicy {due / ISKRA:g} FNX; "
                    f"aktywna po {rks.RANK_ACTIVATION_CONFS} potwierdzeniach bloku")

    # ---------------- messenger E2E (M4, D35) ----------------
    _msg: object | None = field(default=None, init=False)     # app.messenger.Messenger (lazy)

    def messenger(self):
        """Leniwy rdzeń M4 z app/messenger na MOJEJ tożsamości. Transport:
        ŻYWY demon (IPC) → MsgIpcTransport (koperty lecą prawdziwym mesh T_MSG);
        martwy demon → LocalTransport (dev). Tofu w RAM (amnezja); na ISO kontakty
        lądują w kontenerze D24."""
        if self._msg is None:
            from app.messenger import Messenger
            m = Messenger(self.identity)
            if self.ipc is not None and self.node_status() is not None:
                try:
                    from gui.backend_ipc import MsgIpcTransport
                    m.transport = MsgIpcTransport(self.ipc, m.my_fp)
                except Exception:      # demon odmówił skrzynki → spokojny fallback
                    pass
            self._msg = m
        return self._msg

    def msg_transport(self) -> str:
        """Etykieta transportu do pokazania w GUI (uczciwie: mesh czy lokalny)."""
        t = self.messenger().transport
        if t.__class__.__name__ == "MsgIpcTransport":
            return "mesh T_MSG — koperty lecą przez demona (P2P)"
        return "lokalny (dev: demon off-line — mesh włączy się z ON-LINE)"

    def msg_me(self) -> dict:
        """Mój adres FNXS1 + odcisk (do pokazania/publikacji)."""
        m = self.messenger()
        return {"addr": m.my_address(), "fp": m.my_fingerprint()}

    def msg_send(self, to_addr: str, text: str) -> str:
        """Szyfruje E2E i oddaje transportowi → fp odbiorcy (16 hex). Błędy już po polsku."""
        return self.messenger().send_text((to_addr or "").strip(), text)["to_fp"]

    def msg_poll(self) -> list:
        """Nowe wiadomości. TOFU-pinowanie nowych kontaktów robi rdzeń (D28/D35)."""
        return self.messenger().poll()

    def msg_contacts(self) -> list:
        """TOFU-pinowane kontakty (fp jest tożsamością, username to tylko etykieta)."""
        return self.messenger().contacts()

    # ---------------- walizka TF1 na kontaktach (D40) ----------------
    def msg_tofu_protect(self, passkey: str, path: str, kdf=None) -> str:
        """Zamknij kontakty czatu w walizce TF1 (szyfr hasłem, jak KS1 na keystore).
        Od tej chwili plik na dysku = martwy szum dla złodzieja; save() trzyma szyfr."""
        from app.messenger import MessengerError
        try:
            tofu = self.messenger().tofu
            tofu.path = path
            tofu.protect(passkey, kdf=kdf)
        except MessengerError as e:
            raise FenixGuiError(str(e)) from None
        return (f"kontakty czatu szyfrowane Twoim hasłem (TF1) → {path}; "
                "bez hasła plik to szum (zapis: 0600 + shred jak zawsze)")

    def msg_tofu_unlock(self, passkey: str, path: str) -> str:
        """Otwórz walizkę TF1 hasłem i podepnij kontakty do komunikatora."""
        from app.messenger import MessengerError, TofuStore
        try:
            ts = TofuStore(path, passkey=passkey)
        except MessengerError as e:
            raise FenixGuiError(str(e)) from None
        self.messenger().tofu = ts
        return f"walizka TF1 odblokowana: {len(ts.pin)} kontaktów z powrotem w pamięci"

    def msg_tofu_status(self, path: str | None = None) -> str:
        """Etykieta stanu walizki do GUI (uczciwie: RAM-only / TF1 / jawny plik)."""
        from app.messenger import TofuStore
        tofu = self.messenger().tofu
        if not tofu.path:
            return "kontakty tylko w RAM (amnezja; włącz TF1 by przetrwały zaszyfrowane)"
        if tofu.encrypted or (path and TofuStore.is_encrypted(path)):
            return f"walizka TF1 AKTYWNA → {tofu.path} (szyfr hasłem)"
        return f"plik JAWNY → {tofu.path} (dev; zalecane msg_tofu_protect)"

    # ---------------- sieć / IPC do demona ----------------
    def node_status(self) -> dict | None:
        """Żywy status demona fenix-node. None = IPC martwy/nieskonfigurowany → tryb dev."""
        if self.ipc is None:
            return None
        try:
            return self.ipc.status()
        except IpcError:
            return None

    def set_mining(self, on: bool) -> tuple[bool, str]:
        """Toggle kopania W DEMONIE. Dev: uczciwa odmowa (lokalny mempool nic nie kopie)."""
        if self.ipc is None:
            return False, "brak IPC — kopanie sterowalne tylko w żywym fenix-node"
        try:
            state = self.ipc.set_mining(on)
            return True, f"mining demona: {'ON' if state else 'OFF'}"
        except IpcError as e:
            return False, str(e)

    def request_sync(self) -> tuple[bool, str]:
        """Poproś demona o sync z peerami (lekarska pigułka na rozjazd głów)."""
        if self.ipc is None:
            return False, "brak IPC (dev: brak peerów do sync)"
        try:
            self.ipc.sync()
            return True, "poproszono peerów o ich łańcuchy"
        except IpcError as e:
            return False, str(e)

    # ---------------- portfel ----------------
    def balance_iskry(self) -> int:
        """Saldo do decyzji UI: demon żywy → przez IPC; inaczej dev-ledger."""
        if self.ipc is not None:
            try:
                return self.ipc.balance(self.identity.wallet)
            except IpcError:
                pass
        return self.ledger.balance_of(self.identity.wallet)

    def nonce_next(self) -> int:
        """Nonce następnego tx = chain + mempool (jak Ledger.add_tx, Ethereum-style)."""
        if self.ipc is not None:
            try:
                return self.ipc.nonce(self.identity.wallet)
            except IpcError:
                pass
        led = self.ledger
        return led.nonce_of(self.identity.wallet) + sum(
            1 for t in led.mempool if t.sender == self.identity.wallet)

    def my_pool_coins(self) -> list[dict]:
        """Moje outputy w prywatnym poolu (scan stealth przez tx_ring)."""
        return txr.scan_payload_for(self.identity,
                                    [{"sp": k, "ep": v["ep"], "amt": v["amt"]}
                                     for k, v in self.ledger.pool.items()])

    def wallet_send_check(self, to_name: str, amount_iskry: int) -> tuple[bool, str]:
        """Walidacja przelewu PRZED złożeniem (draft; rozsyłka = submit_signed)."""
        from chain.block import fee_split
        target = self.resolve_username(to_name) or (to_name if to_name.startswith("FNX1") else None)
        if not target:
            return False, f"nie znaleziono '{to_name}' w rejestrze on-chain"
        if amount_iskry <= 0:
            return False, "kwota musi być > 0"
        _, _, total = fee_split(amount_iskry)
        if self.balance_iskry() < amount_iskry + total:
            return False, f"brak środków: potrzeba {(amount_iskry + total) / ISKRA:g} FNX (kwota+fee)"
        return True, f"OK: {amount_iskry / ISKRA:g} FNX → {to_name} (+fee {total / ISKRA:g})"

    def submit_signed(self, tx: Tx) -> str:
        """Rozsyłka podpisanego tx: demon żywy → IPC (gossip); martwy → dev-mempool."""
        if self.ipc is not None:
            try:
                return self.ipc.submit_tx_dict(tx.to_dict())
            except IpcError:
                pass                            # offline → spadamy na dev (uczciwie w UI)
        try:
            self.ledger.add_tx(tx)
        except ChainError as e:
            raise FenixGuiError(str(e)) from None
        return tx.txid()

    def submit_transfer(self, to_name: str, amount_iskry: int) -> str:
        """Podpisany transfer: walidacja → submit_signed (IPC do demona lub dev-mempool)."""
        ok, msg = self.wallet_send_check(to_name, amount_iskry)
        if not ok:
            raise FenixGuiError(msg)
        target = self.resolve_username(to_name) or to_name
        tx = Tx.build_signed(TX_TRANSFER, self.identity, target, amount_iskry,
                             nonce=self.nonce_next())
        return self.submit_signed(tx)

    # ---------------- odznaki profilu (D52) + donate (D50) + discovery (D54) ----------------
    def profile_badges(self) -> dict:
        """Panel odznak MOJEGO profilu. Demon żywy → liczenie w demonie (gwarantuje
        wspólny licznik D54); martwy → dev: z własnego ledgera, licznik lokalny = brak."""
        if self.ipc is not None:
            r = self.ipc.try_request("profile")
            if r is not None:
                return {"badges": r["badges"], "donated_iskry": r["donated_iskry"],
                        "stats": r["stats"], "daemon": True}
        from chain import badges as bd
        pan = bd.badge_panel(self.ledger, self.identity.wallet, stats=None,
                             now_ts=self.ledger.tip().timestamp)
        return {"badges": pan, "donated_iskry": int(self.ledger.donations.get(
            self.identity.wallet, 0)), "stats": {"uptime_hours": 0.0,
                "site_created": False, "first_node_ever": False}, "daemon": False}

    def donate_tx(self, amount_iskry: int, note: str = "") -> str:
        """Datek do skarbca ownera — kwota WYŁĄCZNIE wybór użytkownika (D50).
        Zwraca opis po polsku; błędy = FenixGuiError z komunikatem dla ludzi."""
        from chain import donate as don
        from chain.block import fee_split
        if not isinstance(amount_iskry, int) or amount_iskry <= 0:
            raise FenixGuiError("kwota datku musi być dodatnią liczbą iskier")
        if self.ipc is not None:
            bal = self.ipc.balance(self.identity.wallet)
        else:
            bal = self.balance_iskry()
        _, _, fee = fee_split(amount_iskry)
        if bal < amount_iskry + fee:
            raise FenixGuiError(f"brak środków: potrzeba {(amount_iskry + fee) / ISKRA:g} FNX "
                                f"(kwota {amount_iskry / ISKRA:g} + fee)")
        if note:
            try:
                don.donate_payload(note)        # waliduje długość PRZED podpisem
            except don.DonateError as e:
                raise FenixGuiError(str(e)) from None
        if self.ipc is not None:
            try:
                self.ipc.donate(amount_iskry, note=note)
                # TX buduje i podpisuje demon (nasza tożsamość żyje tam); saldo liczy konsensus
                return (f"datek {amount_iskry / ISKRA:g} FNX poszedł do skarbca ownera — "
                        "dziękujemy! (załapie się w następnym bloku)")
            except (IpcError, ChainError) as e:
                raise FenixGuiError(str(e)) from None
        tx = Tx.build_signed(TX_DONATE, self.identity, self.ledger.treasury, amount_iskry,
                             nonce=self.nonce_next(), payload=don.donate_payload(note))
        self.submit_signed(tx)
        return (f"datek {amount_iskry / ISKRA:g} FNX w dev-mempoolu — po bloku wpadnie "
                "skarbcowi (D50: 100% dla ownera)")

    def mark_site_created(self, url: str = "") -> str:
        """Odznaka Architekt (licznik lokalny D52/D54): meldujemy gotową stronę (1×)."""
        if self.ipc is not None:
            try:
                self.ipc.site_created(url or None)
                return "odznaka 'Architekt' odnotowana w liczniku noda (D52)"
            except IpcError as e:
                raise FenixGuiError(str(e)) from None
        return "tryb dev: licznik noda nie żyje — odznaka 'Architekt' zapisze się przy demenie"

    def net_discovery(self) -> dict | None:
        """Stan discovery demona (D54): first_node/adresownia/uptime; None = brak demona."""
        if self.ipc is not None:
            return self.ipc.try_request("netinfo")
        return None

    # ---------------- dashboard ----------------
    def dashboard(self) -> dict:
        st = self.node_status()
        if st is not None:                      # produkcja: demon fenix-node ON-LINE
            return {"height": st["height"], "tip": st["tip"][:12],
                    "balance_fnx": self.balance_iskry() / ISKRA,
                    "pool_size": st["pool_size"], "key_images": st["key_images"],
                    "usernames": st["usernames"], "mempool": st["mempool"],
                    "peers": st["peers"], "daemon": True,
                    "mining": st["mining"], "mined": st["mined"]}
        snap = self.ledger.snapshot()           # dev: współdzielony ledger (desktop)
        return {"height": snap["height"], "tip": snap["tip"][:12],
                "balance_fnx": self.balance_iskry() / ISKRA,
                "pool_size": snap["pool_size"], "key_images": snap["key_images"],
                "usernames": len(snap["usernames"]), "mempool": len(snap["mempool"]),
                "peers": self.node_peers(), "daemon": False, "mining": None, "mined": None}

    # ---------------- paranoia (D29) ----------------
    def paranoia(self) -> dict:
        return {"profile": self._paranoia, **PARANOIA[self._paranoia]}

    def set_paranoia(self, profile: str, vpn_active: bool | None = None) -> tuple[bool, str]:
        """C wymaga działającego VPN (kill switch). B wymaga skonfigurowanego dnscamo
        (bridge — D33; bez niego uczciwie warnujemy, ale wpuszczamy z opisem)."""
        if profile not in PARANOIA:
            raise FenixGuiError("paranoia ∈ {A, B, C}")
        if profile == "C":
            active = vpn_active if vpn_active is not None else self.vpn.status()[0] == "up"
            if not active:
                return False, ("profil C wymaga działającego fenix-vpn (kill switch). "
                               "Podnieś tunel w Ustawieniach → VPN.")
        if profile == "B":
            return True, "profil B aktywny. UWAGA: dnscamo wymaga własnej domeny-mostu (D33 backlog)"
        return True, f"profil {profile} aktywny"

    def apply_paranoia(self, profile: str, vpn_active: bool | None = None) -> tuple[bool, str]:
        ok, msg = self.set_paranoia(profile, vpn_active)
        if ok:
            self._paranoia = profile
        return ok, msg


# -------------------------------------------------------------------------- WIDOK (leniwe tk)
def _import_tk():
    import tkinter as tk
    from tkinter import ttk
    return tk, ttk


class FenixApp:
    """Widok. Tworzyć TYLKO przy dostępnym DISPLAY/X11 (selftest headless go omija)."""

    def __init__(self, controller: FenixController, force_onboarding: bool = False):
        self.tk, self.ttk = _import_tk()
        self.ctl = controller
        self.force_onboarding = force_onboarding
        self.root = self.tk.Tk()
        self.root.title(APP_TITLE)
        self.root.configure(bg=C_BG)
        self.root.geometry("1040x640")
        self.root.minsize(940, 560)
        self._jobs: queue.Queue = queue.Queue()
        self._panel = None
        self._nav_btns: dict = {}
        self._build_style()
        self._build_shell()
        self.show("Dashboard")
        self._poll()
        if force_onboarding:
            self.root.after(150, self._onboarding_gate)

    # ---------- ONB admina (D55): bramka bez „pomiń" ----------
    def _onboarding_gate(self):
        """Modal: fabryczne hasło Deimosa żyje → najpierw ONB, potem reszta aplikacji.
        Jak naklejka na routerze: zdejmujemy ją RAZ, przy pierwszym starcie."""
        try:
            st = self.ctl.admin_status()
        except Exception:
            return                                # status nie żyje → nie blokuj aplikacji
        if not st.get("onboarding_needed"):
            return
        tk, ttk = self.tk, self.ttk
        top = tk.Toplevel(self.root)
        top.title("Fenix — ONB admina (D55)")
        top.configure(bg=C_CARD)
        top.transient(self.root)
        top.grab_set()                            # modal: reszta okna głucha
        top.protocol("WM_DELETE_WINDOW", lambda: None)     # X = nie uciekniesz
        pad = {"padx": 18, "pady": 4}
        ttk.Label(top, text="🔥 Pierwszy start: konto admina Deimos ma hasło FABRYCZNE\n"
                            "(jawne w repo — jak naklejka „admin/admin” na spodzie routera).\n"
                            "Zanim pójdziesz dalej: ZDEJMIJ NAKLEJKĘ — ustaw własne hasło.",
                  background=C_CARD, foreground=C_BAD, font=("DejaVu Sans", 10, "bold"),
                  justify="left").pack(anchor="w", **pad)
        ents = {}
        for lbl, key in (("Aktualne (fabryczne) hasło:", "cur"),
                         ("Nowe hasło (min. 10 znaków):", "new"),
                         ("Nowe hasło paniki (inne niż hasło!):", "pan")):
            ttk.Label(top, text=lbl, background=C_CARD).pack(anchor="w", **pad)
            e = ttk.Entry(top, width=30, show="•")
            e.pack(anchor="w", **pad)
            ents[key] = e
        info = ttk.Label(top, text="", background=C_CARD, foreground=C_MUTED,
                         wraplength=430, justify="left")
        info.pack(anchor="w", **pad)

        def _go():
            try:
                msg = self.ctl.admin_onboard(ents["cur"].get(), ents["new"].get(),
                                             ents["pan"].get())
            except FenixGuiError as ex:
                info.configure(text=f"odmowa: {ex}", foreground=C_BAD)
                return
            info.configure(text=msg, foreground=C_OK)
            top.after(900, top.destroy)           # krótka chwila na przeczytanie OK
            self.show("Dashboard")                # odśwież: czerwony meldunek znika

        ttk.Button(top, text="Ustaw własne hasło (bez tego nie idziemy dalej)",
                   style="Accent.TButton", command=_go).pack(anchor="w", **pad)
        ttk.Label(top, text="Nie ma tu „pomiń” (D55). Po zmianie możesz ją powtórzyć "
                            "w Ustawieniach kiedy chcesz.",
                  background=C_CARD, foreground=C_MUTED, wraplength=430,
                  justify="left").pack(anchor="w", **pad)
        ents["cur"].focus_set()
        top.wait_window()                         # blokuj do skutku

    # ---------- szkielet ----------
    def _build_style(self):
        st = self.ttk.Style(self.root)
        st.theme_use("clam")
        st.configure(".", background=C_BG, foreground=C_TEXT, fieldbackground=C_CARD,
                     bordercolor=C_CARD2, font=("DejaVu Sans", 10))
        st.configure("TFrame", background=C_BG)
        st.configure("Card.TFrame", background=C_CARD)
        st.configure("TLabel", background=C_BG, foreground=C_TEXT)
        st.configure("Card.TLabel", background=C_CARD, foreground=C_TEXT)
        st.configure("Muted.TLabel", background=C_CARD, foreground=C_MUTED)
        st.configure("H1.TLabel", background=C_CARD, foreground=C_TEXT, font=("DejaVu Sans", 18, "bold"))
        st.configure("TButton", background=C_CARD2, foreground=C_TEXT, padding=6)
        st.map("TButton", background=[("active", "#242b38")])
        st.configure("Accent.TButton", background=C_ACCENT, foreground="#141414",
                     font=("DejaVu Sans", 10, "bold"))
        st.map("Accent.TButton", background=[("active", "#ff8f3d")])
        st.configure("Nav.TButton", background=C_BG, foreground=C_MUTED, padding=(12, 8))
        st.configure("NavOn.TButton", background=C_CARD, foreground=C_ACCENT, padding=(12, 8))

    def _build_shell(self):
        self.sidebar = self.ttk.Frame(self.root, style="TFrame", width=170)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        tk_logo = self.ttk.Label(self.sidebar, text="🔥 FENIX", font=("DejaVu Sans", 15, "bold"),
                                 foreground=C_ACCENT)
        tk_logo.pack(pady=(18, 16), padx=14, anchor="w")
        for name in ("Dashboard", "Portfel", "Pool", "Kontakty", "Sieć", "Ustawienia"):
            b = self.ttk.Button(self.sidebar, text=name, style="Nav.TButton",
                                command=lambda n=name: self.show(n))
            b.pack(fill="x", padx=10, pady=2)
            self._nav_btns[name] = b
        # --- PANIC (D27) + czysty ekran: zawsze na dole sidebara, zawsze pod ręką ---
        self._panic_ctl = pbtn.PanicController(clean_hooks=[self._clean_screen])
        self._panic_bar = pbtn.build_panic_bar(self)
        self.root.bind("<Shift-Escape>", lambda _e: self._clean_screen())
        self.content = self.ttk.Frame(self.root, style="TFrame")
        self.content.pack(side="left", fill="both", expand=True, padx=16, pady=14)
        self.statusbar = self.ttk.Label(self.root, text="", style="Muted.TLabel",
                                        background=C_CARD2, anchor="w", padding=(10, 5))
        self.statusbar.pack(side="bottom", fill="x")

    def show(self, name: str):
        for n, b in self._nav_btns.items():
            b.configure(style="NavOn.TButton" if n == name else "Nav.TButton")
        for w in self.content.winfo_children():
            w.destroy()
        {"Dashboard": self._p_dashboard, "Portfel": self._p_wallet,
         "Pool": self._p_pool,
         "Kontakty": self._p_contacts, "Sieć": self._p_network,
         "Ustawienia": self._p_settings}[name]()

    def _card(self, parent, title=""):
        f = self.ttk.Frame(parent, style="Card.TFrame", padding=14)
        f.pack(fill="both", expand=True, pady=6)
        if title:
            self.ttk.Label(f, text=title, style="H1.TLabel").pack(anchor="w", pady=(0, 8))
        return f

    # ---------- panele ----------
    def _p_dashboard(self):
        prof = self.ctl.profile()
        card = self._card(self.content, f"Witaj, {prof['display_name']}")
        top = self.ttk.Frame(card, style="Card.TFrame")
        top.pack(fill="x")
        av = self.tk.Canvas(top, width=64, height=64, bg=C_CARD, highlightthickness=0)
        av.create_oval(4, 4, 60, 60, fill=C_ACCENT, outline="")
        av.create_text(32, 32, text=prof["display_name"][:2].upper(),
                       fill="#141414", font=("DejaVu Sans", 18, "bold"))
        av.pack(side="left")
        box = self.ttk.Frame(top, style="Card.TFrame")
        box.pack(side="left", padx=14)
        self.ttk.Label(box, text=prof["display_name"], style="H1.TLabel").pack(anchor="w")
        badge = self.ttk.Label(box, text=f" ● ranga: {prof['rank']} (tier {prof['rank_tier']})",
                               foreground=prof["rank_color"], background=C_CARD,
                               font=("DejaVu Sans", 10, "bold"))
        badge.pack(anchor="w")
        if prof.get("rank_ttl_s") is not None:              # D51: ranga wygasa — uczciwie mówimy
            dni = prof["rank_ttl_s"] / 86400
            self.ttk.Label(box, text=f"⏳ ważność rangi: {dni:.1f} dni (renew = pełna cena)",
                           style="Muted.TLabel").pack(anchor="w")
        note = "nazwa on-chain: " + (prof["onchain_name"] or "— (nie zarezerwowana)")
        self.ttk.Label(box, text=note, style="Muted.TLabel").pack(anchor="w")
        # --- ADMIN (D53/D55): fabryczne hasło = dziura; meldunek czerwony, zawsze ---
        try:
            ast = self.ctl.admin_status()
            if ast.get("default_password"):
                self.ttk.Label(box, text="⚠ DZIURA: admin Deimos ma FABRYCZNE hasło "
                                         "(jawne w repo) — Ustawienia: zmień TERAZ (ONB)",
                               foreground=C_BAD, background=C_CARD,
                               font=("DejaVu Sans", 10, "bold"), wraplength=640,
                               justify="left").pack(anchor="w", pady=(6, 0))
        except Exception:
            pass                       # status admina NIGDY nie wywraca dashboardu
        # --- BAN (D66): moja plomba = czerwona kartka, zawsze czytelna z konsensusu ---
        try:
            bl = self.ctl.ban_status_line()
            if "ZBANOWANY" in bl:
                self.ttk.Label(box, text=bl, foreground=C_BAD, background=C_CARD,
                               font=("DejaVu Sans", 10, "bold"), wraplength=640,
                               justify="left").pack(anchor="w", pady=(6, 0))
        except Exception:
            pass                       # status banu NIGDY nie wywraca dashboardu
        # --- odznaki profilu (D52): liczone z konsensusu + licznika noda, grafiki PNG ---
        bc = self._card(card, "Odznaki (liczone z faktów — chain = konsensus, ★local = licznik noda)")
        brow = self.ttk.Frame(bc, style="Card.TFrame")
        brow.pack(fill="x")
        self._badge_imgs: list = []                  # trzymaj referencje (Tk GC zjada PNG)
        try:
            pinfo = self.ctl.profile_badges()
            earned = pinfo["badges"]["earned"]
            bdir = _pl.Path(__file__).resolve().parent / "assets" / "badges"
            if not earned:
                self.ttk.Label(brow, text="brak odznak — pierwsze cele: kupno rangi, 100 h "
                                          "noda, datek skarbcowi, własna strona",
                               style="Muted.TLabel").pack(anchor="w")
            for b in earned[:12]:
                cell = self.ttk.Frame(brow, style="Card.TFrame")
                cell.pack(side="left", padx=6, pady=2)
                img_path = bdir / b.get("icon", "")
                img = None
                try:
                    if img_path.exists():
                        img = self.tk.PhotoImage(file=str(img_path))
                except Exception:                       # brak/X11 — spadamy na emoji+D28
                    img = None
                if img is not None:
                    self._badge_imgs.append(img)
                    self.tk.Label(cell, image=img, bg=C_CARD).pack()
                else:
                    self.ttk.Label(cell, text={"chain": "🏅", "local": "⭐"}[b["verify"]],
                                   font=("DejaVu Sans", 22)).pack()
                tag = "chain" if b["verify"] == "chain" else "★local"
                self.ttk.Label(cell, text=f"{b['name']}\n[{tag}] {b.get('why', '')}",
                               style="Muted.TLabel", justify="center").pack()
            don_tick = pinfo.get("donated_iskry", 0)
            if don_tick:
                self.ttk.Label(bc, text=f"💝 datki do skarbca łącznie: {don_tick / ISKRA:g} FNX",
                               style="Muted.TLabel").pack(anchor="w", pady=(4, 0))
        except Exception as e:                          # odznaki NIGDY nie wywalą dashboardu
            self.ttk.Label(brow, text=f"odznaki chwilowo niedostępne ({e})",
                           style="Muted.TLabel").pack(anchor="w")
        # --- discovery (D54): pierwszy nod melduje się na dashboardzie ---
        try:
            nd = self.ctl.net_discovery()
            if nd:
                line = ("🥇 Jesteś PIERWSZYM NODEM — sieć jeszcze pusta; nasłuchujesz "
                        "i seedujesz innych" if nd.get("first_node")
                        else f"🌐 discovery: adresownia {nd.get('addr_book', 0)} adresów, "
                             f"cel {nd.get('target_peers', '?')} peerów")
                self.ttk.Label(card, text=line, style="Muted.TLabel").pack(anchor="w", pady=(6, 0))
        except Exception:
            pass
        self._dash_daemon = self.ttk.Label(box, text="", style="Card.TLabel",
                                           font=("DejaVu Sans", 10, "bold"))
        self._dash_daemon.pack(anchor="w", pady=(4, 0))
        self._dash_labels = {}
        grid = self.ttk.Frame(card, style="Card.TFrame")
        grid.pack(fill="x", pady=14)
        for i, (key, label) in enumerate((("balance_fnx", "Saldo [FNX]"), ("height", "Wysokość"),
                                          ("pool_size", "Pool (prywatny)"), ("usernames", "Username on-chain"),
                                          ("peers", "Peerów"), ("mempool", "Mempool"))):
            c = self.ttk.Frame(grid, style="Card.TFrame", padding=10)
            c.grid(row=i // 3, column=i % 3, padx=8, pady=8, sticky="ew")
            self.ttk.Label(c, text=label, style="Muted.TLabel").pack()
            v = self.ttk.Label(c, text="—", font=("DejaVu Sans", 14, "bold"), style="Card.TLabel")
            v.pack()
            self._dash_labels[key] = v
        self._refresh_dash()

        # --- KURS FNX-COIN (D65/D67): szyba wystawowa read-only z faktów łańcucha ---
        try:
            xc = self.ctl.exchange_card()
            kc = self._card(card, f"Kurs FNX-COIN (źródło: {xc['src']})")
            for li in xc["lines"]:
                self.ttk.Label(kc, text=li, style="Muted.TLabel",
                               wraplength=660, justify="left").pack(anchor="w")
        except Exception:
            pass                       # kurs NIGDY nie wywraca dashboardu

    def _p_wallet(self):
        card = self._card(self.content, "Portfel")
        row = self.ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x")
        self.ttk.Label(row, text="Do (username lub FNX1…):").pack(side="left")
        self._w_to = self.ttk.Entry(row, width=28, font=("DejaVu Sans Mono", 9))
        self._w_to.pack(side="left", padx=8)
        self.ttk.Label(row, text="Kwota FNX:").pack(side="left")
        self._w_amt = self.ttk.Entry(row, width=10)
        self._w_amt.pack(side="left", padx=8)
        self.ttk.Button(row, text="Sprawdź", style="Accent.TButton",
                        command=self._wallet_check).pack(side="left")
        self.ttk.Button(row, text="Wyślij (dev-mempool)",
                        command=self._wallet_send).pack(side="left", padx=6)
        self._w_info = self.ttk.Label(card, text="", style="Muted.TLabel", wraplength=700)
        self._w_info.pack(anchor="w", pady=10)
        coins = self.ctl.my_pool_coins()
        self.ttk.Label(card, text=f"Prywatne coiny (pool): {len(coins)} szt., razem "
                                  f"{sum(c['amt'] for c in coins) / ISKRA:g} FNX",
                       style="Muted.TLabel").pack(anchor="w")
        self.ttk.Label(card, text="Transfer publiczny = widać nadawcę. Prywatny (TX_RING) — "
                                  "zakładka POOL obok.", style="Muted.TLabel").pack(anchor="w", pady=4)
        # --- DONATE do skarbca ownera (D50): kwota = Twój wybór, 100% do skarbca ---
        dcard = self._card(card, "Wesprzyj ownera (dobrowolny datek FNX — D50)")
        drow = self.ttk.Frame(dcard, style="Card.TFrame")
        drow.pack(fill="x")
        self.ttk.Label(drow, text="Kwota FNX (ile chcesz):").pack(side="left")
        self._d_amt = self.ttk.Entry(drow, width=10)
        self._d_amt.pack(side="left", padx=8)
        self.ttk.Label(drow, text="Karteczka (JAWNA, max 140 zn.; zostaw puste):").pack(side="left")
        self._d_note = self.ttk.Entry(drow, width=28)
        self._d_note.pack(side="left", padx=8)
        self.ttk.Button(drow, text="Donate 💝", style="Accent.TButton",
                        command=self._wallet_donate).pack(side="left")
        self._d_info = self.ttk.Label(dcard, text="", style="Muted.TLabel", wraplength=700)
        self._d_info.pack(anchor="w", pady=6)
        self.ttk.Label(dcard, text="Cały datek + część ownerska fee idzie do skarbca ownera "
                                   "(ante up! odznaka Dobroczyńca liczy się z konsensusu).",
                       style="Muted.TLabel").pack(anchor="w")

    # ---------- zakładka POOL (M7c): moje coiny + prywatna wysyłka ----------
    def _pool_ctl(self):
        return poolp.PoolController(self.ctl.identity, ledger=self.ctl.ledger, ipc=self.ctl.ipc)

    def _p_pool(self):
        card = self._card(self.content, "Pool prywatny (TX_RING)")
        row0 = self.ttk.Frame(card, style="Card.TFrame")
        row0.pack(fill="x")
        self.ttk.Label(row0, text="Mój adres prywatny (do odbioru):").pack(side="left")
        self._p_addr = self.ttk.Entry(row0, width=74, font=("DejaVu Sans Mono", 9))
        self._p_addr.pack(side="left", padx=8)
        try:
            self._p_addr.insert(0, poolp.PoolController(self.ctl.identity).my_address())
        except Exception:  # noqa: BLE001 — adres to nic tajnego; nigdy nie wywal UI
            self._p_addr.insert(0, "—")
        self._p_addr.configure(state="readonly")
        self.ttk.Button(row0, text="Kopiuj", command=self._pool_copy).pack(side="left")
        self._p_coins = self.ttk.Label(card, text="", style="Muted.TLabel", justify="left")
        self._p_coins.pack(anchor="w", pady=8)
        row = self.ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x")
        self.ttk.Label(row, text="Do (FNXS1…):").pack(side="left")
        self._p_to = self.ttk.Entry(row, width=60, font=("DejaVu Sans Mono", 9))
        self._p_to.pack(side="left", padx=8)
        self.ttk.Label(row, text="FNX:").pack(side="left")
        self._p_amt = self.ttk.Entry(row, width=9)
        self._p_amt.pack(side="left", padx=8)
        self.ttk.Button(row, text="Plan", command=self._pool_plan).pack(side="left")
        self.ttk.Button(row, text="Wyślij prywatnie", style="Accent.TButton",
                        command=self._pool_send).pack(side="left", padx=6)
        self._p_info = self.ttk.Label(card, text="", style="Muted.TLabel",
                                      wraplength=780, justify="left")
        self._p_info.pack(anchor="w", pady=8)
        fogc = self._card(card, "Mgła v2 (kwoty ukryte — CLSAG+pseudoOut, D38/D39)")
        self._p_fog = self.ttk.Label(fogc, text="Mgła (v2): skanuję…",
                                     style="Muted.TLabel", justify="left")
        self._p_fog.pack(anchor="w")
        rowf = self.ttk.Frame(fogc, style="Card.TFrame")
        rowf.pack(fill="x", pady=6)
        self.ttk.Button(rowf, text="Wtop w mgłę", command=self._pool_mint2).pack(side="left")
        self.ttk.Button(rowf, text="Wyślij w mgle", command=self._pool_send2).pack(side="left", padx=6)
        self.ttk.Button(rowf, text="Wypłać z mgły", command=self._pool_unshield).pack(side="left")
        self.ttk.Label(card, text=("UCZCIWIE: tryb v1 (3a) — kwoty JAWNE, ukryte są POWIĄZANIA "
                                   "(LSAG ring ≥5 + stealth); wydane coiny zostają wabikami. "
                                   "Mgła v2 (3b) — kwoty UKRYTE: chain widzi tylko punkty C, "
                                   "bilans pilnuje MLSAG+pseudoOut+range-proof; wypłata = kwota "
                                   "Y jawna (jak z→t w Zcash). Fee 0.055% idzie do KOPACZA (D39)."),
                       style="Muted.TLabel", wraplength=780, justify="left").pack(anchor="w", pady=4)
        self._refresh_pool()

    def _refresh_pool(self):
        if not hasattr(self, "_p_coins"):
            return
        pc = self._pool_ctl()
        self._job("pool-scan", pc.my_coins, self._pool_scan_done)
        self._job("pool-scan2", pc.my_hidden_coins, self._pool_fog_done)

    def _pool_scan_done(self, result):
        if not isinstance(result, list):
            self._p_coins.configure(text=f"pool: {result[1] if isinstance(result, tuple) else result}",
                                    foreground=C_BAD)
            return
        coins = result
        lines = [poolp.coins_summary(coins)] + [
            f"  {c['amt'] / ISKRA:g} FNX · sp {c['sp'][:12]}… · ep {c['ep'][:12]}…"
            for c in coins[:20]]
        self._p_coins.configure(text="\n".join(lines), foreground=C_TEXT)

    def _pool_copy(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self._p_addr.get())
        self.statusbar.configure(text="  adres FNXS1 w schowku — wklej go znajomemu tam, "
                                    "gdzie nikt nie podsłuchuje")

    def _pool_fog_done(self, result):
        if not hasattr(self, "_p_fog"):
            return
        if not isinstance(result, list):
            self._p_fog.configure(
                text=f"Mgła (v2): {result[1] if isinstance(result, tuple) else result}",
                foreground=C_BAD)
            return
        tot = sum(c["amt"] for c in result)
        self._p_fog.configure(
            text=(f"Mgła (v2): {len(result)} monet · Σ {tot / ISKRA:g} FNX ukrytych — "
                  "łańcuch widzi martwe punkty C, kwoty znasz tylko Ty (scan C/blob)"),
            foreground=C_OK if result else C_TEXT)

    def _pool_mint2(self):
        amt = self._pool_amount()
        if amt is None:
            return
        pc = self._pool_ctl()
        self._p_info.configure(text="wtapiam w mgłę (TX_SHIELD v2: pool dostaje C/blob, "
                                    "kwoty NIE ma nigdzie na jawie)…", foreground=C_WARN)
        self._job("pool-mint2", lambda: pc.submit(pc.build_shield2_tx(amt)),
                  self._pool_send_done)

    def _pool_send2(self):
        amt = self._pool_amount()
        if amt is None:
            return
        pc = self._pool_ctl()
        self._p_info.configure(text="buduję RING v2 w mgle (MLSAG+pseudoOut+range-proofy)…",
                               foreground=C_WARN)
        self._job("pool-send2", lambda: pc.send_hidden(self._p_to.get().strip(), amt),
                  self._pool_send_done)

    def _pool_unshield(self):
        amt = self._pool_amount()
        if amt is None:
            return
        pc = self._pool_ctl()
        self._p_info.configure(text="buduję UNSHIELD v2 (mgła → moje konto; kwota Y jawna, jak z→t)…",
                               foreground=C_WARN)
        self._job("pool-unshield", lambda: pc.unshield(amt), self._pool_send_done)

    def _pool_amount(self) -> int | None:
        try:
            return int(float(self._p_amt.get()) * ISKRA)
        except ValueError:
            self._p_info.configure(text="kwota: liczba (np. 1.5)", foreground=C_BAD)
            return None

    def _pool_plan(self):
        amt = self._pool_amount()
        if amt is None:
            return
        try:
            plan = self._pool_ctl().plan_send(self._p_to.get().strip(), amt)
            ins = ", ".join(f"{c['amt'] / ISKRA:g}" for c in plan["inputs"])
            self._p_info.configure(
                text=(f"OK: wejścia [{ins}] = Σ {plan['sum_in'] / ISKRA:g} FNX → "
                      f"{plan['amount'] / ISKRA:g} FNX odbiorcy, fee {plan['fee'] / ISKRA:g}, "
                      f"reszta {plan['change'] / ISKRA:g} FNX wraca do Ciebie. Ring ≥5 wabików "
                      f"na wejście — tłum wystarczający."),
                foreground=C_OK)
        except poolp.PoolError as e:
            self._p_info.configure(text=str(e), foreground=C_BAD)

    def _pool_send(self):
        amt = self._pool_amount()
        if amt is None:
            return
        pc = self._pool_ctl()
        self._p_info.configure(text="buduję TX_RING (podpisuję pierścienie)…",
                               foreground=C_WARN)
        self._job("pool-send", lambda: pc.send_private(self._p_to.get().strip(), amt),
                  self._pool_send_done)

    def _pool_send_done(self, result):
        ok = isinstance(result, str)
        self._p_info.configure(
            text=(f"TX_RING rozsyłany: {result[:16]}… (kopnięcie = następny blok)" if ok
                  else f"BŁĄD: {result}"),
            foreground=C_OK if ok else C_BAD)
        self._refresh_pool()

    def _p_contacts(self):
        card = self._card(self.content, "Kontakty / resolver username (on-chain)")
        row = self.ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x")
        self.ttk.Label(row, text="Znajdź username:").pack(side="left")
        self._c_name = self.ttk.Entry(row, width=24)
        self._c_name.pack(side="left", padx=8)
        self.ttk.Button(row, text="Szukaj", style="Accent.TButton", command=self._contact_find).pack(side="left")
        self._c_info = self.ttk.Label(card, text="", style="Muted.TLabel", wraplength=700, justify="left")
        self._c_info.pack(anchor="w", pady=10)
        known = sorted(self.ctl.ledger.usernames.keys())
        self.ttk.Label(card, text="Zarejestrowane username (widok publiczny łańcucha): "
                                  + (", ".join(known) if known else "—"),
                       style="Muted.TLabel", wraplength=700).pack(anchor="w")

        # ---------------- czat E2E (rdzeń M4 na tej samej tożsamości, D35) ----------------
        me = self.ctl.msg_me()
        mc = self._card(self.content,
                        "Wiadomości E2E (rdzeń M4 · ChaCha20-Poly1305 + podpis Ed25519)")
        r1 = self.ttk.Frame(mc, style="Card.TFrame")
        r1.pack(fill="x", pady=(0, 4))
        self.ttk.Label(r1, text="Twój adres FNXS1 (podajesz jak numer telefonu):").pack(side="left")
        e_me = self.ttk.Entry(r1, width=48, font=("DejaVu Sans Mono", 9))
        e_me.insert(0, me["addr"])
        e_me.configure(state="readonly")
        e_me.pack(side="left", padx=8)
        self.ttk.Button(r1, text="Kopiuj", command=self._msg_copy_addr).pack(side="left")
        self.ttk.Label(mc, text="Twój odcisk: " + me["fp"] +
                                "   (przy pierwszym kontakcie porównaj go z rozmówcą DRUGIM kanałem — TOFU, D28)",
                       style="Muted.TLabel", wraplength=700, justify="left").pack(anchor="w")
        r2 = self.ttk.Frame(mc, style="Card.TFrame")
        r2.pack(fill="x", pady=(10, 4))
        self.ttk.Label(r2, text="Do (adres FNXS1):").pack(side="left")
        self._m_to = self.ttk.Entry(r2, width=56, font=("DejaVu Sans Mono", 9))
        self._m_to.pack(side="left", padx=8)
        r3 = self.ttk.Frame(mc, style="Card.TFrame")
        r3.pack(fill="x")
        self._m_text = self.ttk.Entry(r3, width=52)
        self._m_text.pack(side="left")
        self.ttk.Button(r3, text="Wyślij", style="Accent.TButton",
                        command=self._msg_send).pack(side="left", padx=8)
        self.ttk.Button(r3, text="Odśwież skrzynkę", command=self._msg_poll).pack(side="left")
        self._m_info = self.ttk.Label(
            mc, text="Koperta opuszcza rdzeń ZASZYFROWANA — przekaźniki widzą szum. "
                     f"Transport: {self.ctl.msg_transport()}.",
            style="Muted.TLabel", wraplength=700, justify="left")
        self._m_info.pack(anchor="w", pady=(8, 0))
        self._m_log = self.ttk.Label(mc, text="", style="Muted.TLabel",
                                     justify="left", wraplength=700)
        self._m_log.pack(anchor="w", pady=(8, 0))
        self._m_me = me  # do kopiowania adresu

    def _msg_copy_addr(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self._m_me["addr"])
        self.statusbar.configure(text="  adres FNXS1 w schowku — podaj go znajomemu kanałem, "
                                      "którego nikt nie podsłuchuje")

    def _msg_send(self):
        try:
            # pole „Do" przyjmuje ADRES FNXS1 albo NICK on-chain (P21/D45 auto-rozpoznanie)
            fp = self.ctl.msg_send_to(self._m_to.get(), self._m_text.get())
            fpw = "-".join(fp[i:i + 4] for i in range(0, 16, 4))
            self._m_info.configure(text=f"wysłano do {fpw} — koperta zaszyfrowana E2E ✓",
                                   foreground=C_OK)
            self._m_text.delete(0, "end")
        except Exception as ex:      # MessengerError/IdentityError/FenixGuiError — po polsku
            self._m_info.configure(text=f"nie wysłano: {ex}", foreground=C_BAD)

    def _msg_poll(self):
        msgs = self.ctl.msg_poll()
        lines = []
        for m in msgs:
            tag = "  ← NOWY kontakt: porównaj odcisk drugim kanałem!" if m.new_contact else ""
            lines.append(f"◂ {m.name} [{m.fp}]{tag}\n   {m.text}")
        cs = self.ctl.msg_contacts()
        if cs:
            lines.append("— zaufane kontakty (TOFU): "
                         + ", ".join(f"{c['name']} ({c['fp']})" for c in cs))
        self._m_log.configure(text="\n".join(lines) if lines else "skrzynka pusta",
                              foreground=C_MUTED if not lines else C_OK)

    def _p_network(self):
        card = self._card(self.content, "Sieć FNX")
        self._n_info = self.ttk.Label(card, text="", style="Muted.TLabel", justify="left")
        self._n_info.pack(anchor="w")
        row = self.ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x", pady=10)
        self.ttk.Button(row, text="⛏ Mining start", style="Accent.TButton",
                        command=lambda: self._job("mine-on", lambda: self.ctl.set_mining(True),
                                                  self._mine_done)).pack(side="left")
        self.ttk.Button(row, text="Mining stop",
                        command=lambda: self._job("mine-off", lambda: self.ctl.set_mining(False),
                                                  self._mine_done)).pack(side="left", padx=8)
        self.ttk.Button(row, text="⇄ Sync od peerów",
                        command=lambda: self._job("sync", self.ctl.request_sync,
                                                  self._mine_done)).pack(side="left")
        # --- LICZNIK + DUCH (D61/D63/D67): estymacja online + toggle ducha z demona ---
        ccard = self._card(card, "Licznik sieci (D61) + tryb ducha (D63)")
        self._n_census = self.ttk.Label(ccard, text="", style="Muted.TLabel",
                                        wraplength=660, justify="left")
        self._n_census.pack(anchor="w")
        grow = self.ttk.Frame(ccard, style="Card.TFrame")
        grow.pack(fill="x", pady=8)
        self._g_btn_txt = self.tk.StringVar(value="👻 Duch: przełącz")
        self.ttk.Button(grow, textvariable=self._g_btn_txt,
                        command=self._ghost_click).pack(side="left")
        self.ttk.Label(grow, text="(granice ducha: routing/timing zostaje — nie tor!)",
                       style="Muted.TLabel").pack(side="left", padx=10)
        self._refresh_network()

    def _ghost_click(self):
        try:
            cur = bool(self.ctl.network_extra_card().get("ghost"))
        except Exception:
            cur = False
        self._job("ghost", lambda: self.ctl.set_ghost_gui(not cur), self._mine_done)

    def _mine_done(self, result):
        ok, msg = result if isinstance(result, tuple) else (False, str(result))
        self.statusbar.configure(text=f"  {'OK' if ok else 'BŁĄD'}: {msg}")
        self._refresh_network()

    def _p_settings(self):
        card = self._card(self.content, "Ustawienia")
        # --- profil ---
        self.ttk.Label(card, text="Profil (D28: username+avatar edytowalne; RANGA tylko do odczytu)",
                       font=("DejaVu Sans", 10, "bold"), style="Card.TLabel").pack(anchor="w")
        row = self.ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x", pady=4)
        self.ttk.Label(row, text="Nowy username:").pack(side="left")
        self._s_name = self.ttk.Entry(row, width=22)
        self._s_name.pack(side="left", padx=8)
        self.ttk.Button(row, text="Waliduj", command=self._user_validate).pack(side="left")
        self.ttk.Button(row, text="Złóż tx (claim/rename)", style="Accent.TButton",
                        command=self._user_submit).pack(side="left", padx=6)
        self._s_info = self.ttk.Label(card, text="", style="Muted.TLabel", wraplength=700)
        self._s_info.pack(anchor="w", pady=6)
        # --- paranoia ---
        self.ttk.Label(card, text="Suwak paranoii (D29)", font=("DejaVu Sans", 10, "bold"),
                       style="Card.TLabel").pack(anchor="w", pady=(14, 4))
        self._p_var = self.tk.StringVar(value=self.ctl.paranoia()["profile"])
        for key in ("A", "B", "C"):
            p = PARANOIA[key]
            rb = self.ttk.Radiobutton(card, text=p["nazwa"], value=key, variable=self._p_var,
                                      command=self._paranoia_apply)
            rb.pack(anchor="w")
            self.ttk.Label(card, text="    " + p["opis"], style="Muted.TLabel",
                           wraplength=700).pack(anchor="w")
        self._p_info = self.ttk.Label(card, text="", style="Muted.TLabel", wraplength=700)
        self._p_info.pack(anchor="w", pady=6)
        # --- VPN ---
        self.ttk.Label(card, text="Mullvad VPN (kill switch przed tunelem)",
                       font=("DejaVu Sans", 10, "bold"), style="Card.TLabel").pack(anchor="w", pady=(14, 4))
        row2 = self.ttk.Frame(card, style="Card.TFrame")
        row2.pack(fill="x")
        self.ttk.Button(row2, text="VPN status", command=self._vpn_status).pack(side="left")
        self.ttk.Button(row2, text="VPN up", style="Accent.TButton",
                        command=lambda: self._job("vpn-up", self.ctl.vpn.up, self._vpn_done)).pack(side="left", padx=8)
        self.ttk.Button(row2, text="VPN down",
                        command=lambda: self._job("vpn-down", self.ctl.vpn.down, self._vpn_done)).pack(side="left")
        self.ttk.Label(card, text="Konto Mullvad (16 cyfr, kupne za gotówkę/XMR — nie email). "
                                  "Zapis → /run/fenix/vpn.env: TYLKO RAM, nie dysk (M7b):",
                       style="Muted.TLabel", wraplength=700).pack(anchor="w", pady=(10, 2))
        row3 = self.ttk.Frame(card, style="Card.TFrame")
        row3.pack(fill="x")
        self._v_acc = self.ttk.Entry(row3, width=20, show="•")
        self._v_acc.pack(side="left")
        self.ttk.Button(row3, text="Zapisz do vpn.env", style="Accent.TButton",
                        command=self._vpn_env_save).pack(side="left", padx=8)
        self.ttk.Button(row3, text="Zapomnij konto", command=self._vpn_env_forget).pack(side="left")
        self._v_info = self.ttk.Label(card, text="", style="Muted.TLabel", wraplength=700)
        self._v_info.pack(anchor="w", pady=6)
        # --- ADMIN DEIMOS (D53/D55): zmiana hasła fabrycznego — ONB bez „pomiń" ---
        self.ttk.Label(card, text="Admin Deimos — hasło (ONB, D55)",
                       font=("DejaVu Sans", 10, "bold"), style="Card.TLabel").pack(anchor="w", pady=(16, 4))
        try:
            _ast = self.ctl.admin_status()
            _fab = _ast.get("default_password")
            _stxt = ("⚠ hasło FABRYCZNE aktywne — wpisz je jako „aktualne” (Anon123!), "
                     "potem własne ×2 pola. Po zmianie fabryczne jest MARTWE."
                     if _fab else
                     "hasło admina: własne ✓ — tu możesz je zmienić ponownie "
                     "(aktualne = Twoje, nie fabryczne).")
            self._a_state = self.ttk.Label(card, text=_stxt, wraplength=700, justify="left")
            self._a_state.configure(foreground=C_BAD if _fab else C_OK)
        except Exception:
            self._a_state = self.ttk.Label(card, text="status admina niedostępny",
                                           style="Muted.TLabel")
        self._a_state.pack(anchor="w")
        for lbl, attr in (("Aktualne hasło:", "_a_cur"), ("Nowe hasło (min. 10 znaków):", "_a_new"),
                          ("Nowe hasło paniki (inne niż hasło!):", "_a_pan")):
            r = self.ttk.Frame(card, style="Card.TFrame")
            r.pack(fill="x", pady=2)
            self.ttk.Label(r, text=lbl).pack(side="left")
            e = self.ttk.Entry(r, width=26, show="•")
            e.pack(side="left", padx=8)
            setattr(self, attr, e)
        self.ttk.Button(card, text="Zmień hasło admina (ONB)", style="Accent.TButton",
                        command=self._admin_change).pack(anchor="w", pady=6)
        self._a_info = self.ttk.Label(card, text="", style="Muted.TLabel", wraplength=700)
        self._a_info.pack(anchor="w", pady=(0, 6))

    # ---------- akcje ----------
    def _wallet_check(self):
        try:
            amt = int(float(self._w_amt.get()) * ISKRA)
        except ValueError:
            self._w_info.configure(text="kwota: liczba (np. 1.5)", foreground=C_BAD)
            return
        ok, msg = self.ctl.wallet_send_check(self._w_to.get().strip(), amt)
        self._w_info.configure(text=msg, foreground=C_OK if ok else C_BAD)

    def _wallet_send(self):
        try:
            txid = self.ctl.submit_transfer(self._w_to.get().strip(),
                                            int(float(self._w_amt.get()) * ISKRA))
            self._w_info.configure(text=f"tx w mempoolu (dev): {txid[:16]}…", foreground=C_OK)
        except (ValueError, FenixGuiError) as e:
            self._w_info.configure(text=str(e), foreground=C_BAD)

    def _wallet_donate(self):
        """DONATE do skarbca ownera (D50): kwota z pola — użytkownika wybór."""
        try:
            amt = int(float(self._d_amt.get()) * ISKRA) if self._d_amt.get().strip() else 0
            if amt <= 0:
                raise ValueError("podaj kwotę > 0")
            msg = self.ctl.donate_tx(amt, note=self._d_note.get().strip())
            self._d_info.configure(text=msg, foreground=C_OK)
        except (ValueError, FenixGuiError) as e:
            self._d_info.configure(text=str(e), foreground=C_BAD)

    def _admin_change(self):
        """ONB/zmiana hasła Deimosa (D55): walidacja + dowód + weryfikacja w settings_admin."""
        try:
            msg = self.ctl.admin_onboard(self._a_cur.get(), self._a_new.get(),
                                         self._a_pan.get())
            self._a_info.configure(text=msg, foreground=C_OK)
            for e in (self._a_cur, self._a_new, self._a_pan):
                e.delete(0, "end")
            try:
                self._a_state.configure(text="hasło admina: własne ✓ (fabryczne martwe)",
                                        foreground=C_OK)
            except Exception:
                pass
        except FenixGuiError as ex:
            self._a_info.configure(text=f"odmowa: {ex}", foreground=C_BAD)

    def _contact_find(self):
        name = self._c_name.get().strip()
        w = self.ctl.resolve_username(name)
        if not w:
            self._c_info.configure(text=f"„{name}”: nie znaleziono w rejestrze on-chain",
                                   foreground=C_BAD)
        else:
            self._c_info.configure(
                text=f"„{name}” → {w}\nTOFU: przy pierwszej rozmowie porównaj odcisk klucza "
                     f"drugim kanałem (anty-impersonacja, D28).",
                foreground=C_OK)

    def _user_validate(self):
        ok, msg, _f, _op = self.ctl.validate_username_edit(self._s_name.get().strip())
        self._s_info.configure(text=msg, foreground=C_OK if ok else C_BAD)

    def _user_submit(self):
        try:
            tx = self.ctl.build_username_tx(self._s_name.get().strip())
            try:
                txid = self.ctl.submit_signed(tx)
                gdzie = "demona (gossip)" if self.ctl.node_status() else "dev-mempoolu"
                self._s_info.configure(text=f"tx w {gdzie}: {txid[:16]}… (kopnięcie = następny blok)",
                                       foreground=C_OK)
            except FenixGuiError as e:
                self._s_info.configure(text=f"podpisany tx gotowy; mempool: {e}", foreground=C_WARN)
        except FenixGuiError as e:
            self._s_info.configure(text=str(e), foreground=C_BAD)

    def _paranoia_apply(self):
        ok, msg = self.ctl.apply_paranoia(self._p_var.get(),
                                          vpn_active=self.ctl.vpn.status()[0] == "up")
        self._p_info.configure(text=msg, foreground=C_OK if ok else C_BAD)

    def _vpn_status(self):
        state, detail = self.ctl.vpn.status()
        self._v_info.configure(text=f"stan: {state.upper()} — {detail[:180]}",
                               foreground=C_OK if state == "up" else C_WARN)

    def _vpn_done(self, result):
        ok, out = result
        self._v_info.configure(text=("OK: " if ok else "BŁĄD: ") + out[:220],
                               foreground=C_OK if ok else C_BAD)
        self._vpn_status()

    # ---------- panic (D27) + czysty ekran ----------
    def _clean_screen(self):
        """„Czysty ekran” — kurtyna, NIE pożar: chowa wszystkie widoki i niszczy
        widgety (wpisane dane znikają z RAM widgetów). Klik w menu przywraca panel."""
        for w in self.content.winfo_children():
            w.destroy()
        for attr in ("_dash_labels", "_n_info"):
            if hasattr(self, attr):
                delattr(self, attr)     # _refresh_* nie wolno dotykać martwych widgetów
        self.ttk.Label(self.content,
                       text="🧹 Ekran wyczyszczony.\nWybierz sekcję z menu, aby wrócić.",
                       style="Muted.TLabel", justify="center",
                       font=("DejaVu Sans", 13)).pack(expand=True)
        self.statusbar.configure(text="  czysty ekran — widoki zniszczone, sesja żywa")

    def _panic_done(self, result):
        rep = result if isinstance(result, dict) else {}
        tag = "DRY" if rep.get("dry") else "PANIKA"
        self.statusbar.configure(
            text=f"  {tag}: shred={len(rep.get('shredded', []))} poweroff={rep.get('poweroff')}")

    # ---------- vpn.env (M7b) ----------
    def _vpn_env_save(self):
        try:
            path = pbtn.write_vpn_env(self._v_acc.get().strip())
            self._v_acc.delete(0, "end")          # numer znika z pola (i z RAM widgetu)
            self._v_info.configure(
                text=f"zapisano {path} (0600, wyłącznie RAM). Teraz kliknij „VPN up\".",
                foreground=C_OK)
        except pbtn.PanicButtonError as e:
            self._v_info.configure(text=str(e), foreground=C_BAD)
        except OSError as e:
            self._v_info.configure(
                text=f"nie mogę zapisać vpn.env: {e} (na ISO /run/fenix stawia tmpfiles.d)",
                foreground=C_BAD)

    def _vpn_env_forget(self):
        gone = pbtn.forget_vpn_env()
        self._v_info.configure(
            text=("vpn.env zniszczony (2× nadpis) — FenixOS nie zna już numeru konta" if gone
                  else "brak vpn.env (nic do zapomnienia / brak uprawnień)"),
            foreground=C_OK)

    # ---------- praca w tle + polling ----------
    def _job(self, tag: str, fn, done_cb):
        def wrap():
            try:
                self._jobs.put((tag, fn(), None))
            except Exception as e:  # noqa: BLE001 — UI nie może umrzeć przez wątek
                self._jobs.put((tag, None, e))
        threading.Thread(target=wrap, daemon=True).start()
        self._job_cbs = getattr(self, "_job_cbs", {})
        self._job_cbs[tag] = done_cb

    def _poll(self):
        try:
            while True:
                tag, res, err = self._jobs.get_nowait()
                cb = getattr(self, "_job_cbs", {}).get(tag)
                if cb:
                    cb(res if err is None else (False, str(err)))
        except queue.Empty:
            pass
        self._refresh_dash()
        self._refresh_network()
        self.root.after(GUI_TICK_MS, self._poll)

    def _refresh_dash(self):
        if not hasattr(self, "_dash_labels"):
            return
        d = self.ctl.dashboard()
        for k, v in self._dash_labels.items():
            v.configure(text=f"{d[k]:g}" if isinstance(d[k], float) else str(d[k]))
        if hasattr(self, "_dash_daemon"):
            on = d.get("daemon")
            self._dash_daemon.configure(
                text=("● demon ON-LINE (IPC · /run/fenix/node.ipc)" if on
                      else "● demon OFF-LINE — tryb dev (współdzielony ledger)"),
                foreground=C_OK if on else C_WARN)
        vpn_state = self.ctl.vpn.status()[0]
        self.statusbar.configure(
            text=f"  tip {d['tip']}… · h={d['height']} · VPN: {vpn_state} · paranoia: "
                 f"{self.ctl.paranoia()['profile']} · ranga: {self.ctl.profile()['rank']}")

    def _refresh_network(self):
        if not hasattr(self, "_n_info"):
            return
        d = self.ctl.dashboard()
        if d["daemon"]:
            stan = (f"demon: ON-LINE (IPC) · mining: {'ON' if d['mining'] else 'OFF'} "
                    f"· wykopane przez ten węzeł: {d['mined']}")
        else:
            stan = ("demon: OFF-LINE — tryb dev (współdzielony ledger). "
                    "Produkcja: włączony fenix-node.service wystawia IPC sam.")
        self._n_info.configure(text=(
            f"{stan}\nwysokość: {d['height']}\ngłowa: {d['tip']}…\npeerowie: {d['peers']}\n"
            f"mempool: {d['mempool']} tx\n"
            f"pool prywatny: {d['pool_size']} outputów / {d['key_images']} key-images\n"
            f"usernames on-chain: {d['usernames']}"))
        if hasattr(self, "_n_census"):
            try:
                ex = self.ctl.network_extra_card()
                if ex["census"]:
                    c = ex["census"]
                    self._n_census.configure(text=(
                        f"online≈ {c['online_estimate']} (estymacja) · znane portfele: "
                        f"{c['known_wallets']} · zarejestrowani: {c['registered_users']} · "
                        f"attesterzy PoU: {c['pou_attesters']}\n"
                        f"airdrop 1M: {'ODPALONY ' + str(c['airdrop_fired']) if c.get('airdrop_fired') else 'przed kamieniem (' + str(c.get('airdrop_next')) + ')'}\n"
                        f"{ex['note']}"))
                    self._g_btn_txt.set("👻 Duch: WŁĄCZONY (klik = wyłącz)" if ex["ghost"]
                                        else "👻 Duch: wyłączony (klik = włącz)")
                else:
                    self._n_census.configure(text="dev: brak demona — licznik i duch "
                                                  "sterowalne z żywym fenix-node (D61/D63)")
                    self._g_btn_txt.set("👻 Duch: niedostępny (dev)")
            except Exception:
                pass                   # licznik NIGDY nie wywraca strony Sieć

    def run(self):
        self.root.mainloop()


# -------------------------------------------------------------------------- CLI / dev-demo
def _cli() -> None:
    """Dev-demo z prawdziwym kontrolerem (DISPLAY wymagany do okna; --no-window = sam kontroler)."""
    demo = "--demo" in sys.argv
    show = "--no-window" not in sys.argv
    ipc = BackendIpc()   # leniwy: demon żyje → ON-LINE; martwy → dev (bez freeze, backoff 3 s)
    if demo:
        from chain.miner import mine as _mine
        L = Ledger()
        me = Identity.generate("demo_user")
        for _ in range(2):
            won = _mine(L.block_template(me.wallet, zbits=2), max_tries=200_000)
            assert won
            L.apply_block(won)
        ctl = FenixController(identity=me, ledger=L, ipc=ipc)
    else:
        ctl = FenixController(identity=_identity_loader(), ledger=Ledger(), ipc=ipc)
    if show:
        # D55: prawdziwe okno (nie --demo, nie --no-window) = bramka ONB admina.
        FenixApp(ctl, force_onboarding=not demo).run()
    else:
        print(json.dumps({"profil": ctl.profile(), "dashboard": ctl.dashboard(),
                          "paranoia": ctl.paranoia()["profile"]}, ensure_ascii=False, indent=1))


def _identity_loader() -> Identity:
    """Wczytaj tożsamość z keystora D24 (jak fenix_boot). Bez keystora → świeża dev."""
    ks_path = _pl.Path("/home/fenix/.fenix/keystore.ks1")
    if ks_path.exists():
        from core.keystore import Keystore
        import getpass
        p1 = getpass.getpass("passkey: ")
        ks = Keystore.load(str(ks_path))
        return ks.unlock_identity(p1)
    name = input("username (nowa tożsamość dev): ").strip() or "dev_user"
    return Identity.generate(name)



# -------------------------------------------------------------------------- selftest (headless)
if __name__ == "__main__" and len(sys.argv) > 1:
    _cli()
    sys.exit(0)

if __name__ == "__main__":
    import os as _os
    print("gui/fenix_gui.py — selftest headless: kontroler D28/D29 + portfel + resolver\n")

    from chain.miner import mine

    L = Ledger()
    ala = Identity.generate("ala_gui")
    bob = Identity.generate("bob_gui")
    ctl = FenixController(identity=ala, ledger=L,
                          vpn=VpnCtl(runner=lambda argv: (0, "interface: fnxwg0\n  latest handshake: 3 seconds ago\n") if argv[-1] == "up" or argv[-1] == "status" else (0, "ok")))

    def kop():
        won = mine(L.block_template(ala.wallet, zbits=2), max_tries=200_000)
        assert won is not None
        L.apply_block(won)

    for _ in range(3):
        kop()

    # 1) profil: display_name = username BEZ UID (D28!)
    prof = ctl.profile()
    assert prof["display_name"] == "ala_gui"
    assert ctl.identity.uid not in json.dumps(prof), "UID WYCIEKŁ do profilu GUI (D28!)"
    assert prof["rank"] == "ghost" and prof["rank_color"] == RANK_COLORS["ghost"]
    print("  [OK] 1. profil: username bez UID w display_name (D28); ranga ghost+badge kolor")

    # 2) ranga nie-edytowalna
    try:
        ctl.set_rank("fenix")
        raise SystemExit("set_rank przeszedł!")
    except FenixGuiError:
        pass
    print("  [OK] 2. ranga NIE samo-edytowalna (D28: tylko konsensus TX_RANK_UP)")

    # 3) walidacja edycji username (claim)
    ok, msg, fee, op = ctl.validate_username_edit("super-ala")
    assert ok and op == "claim" and fee == uname.CLAIM_FEE
    bad, bmsg, _, _ = ctl.validate_username_edit("Zla Nazwa")
    assert not bad
    print(f"  [OK] 3. walidacja edycji: claim fee={fee / ISKRA:g} FNX; zła nazwa odrzucona ({bmsg[:40]})")

    # 4) złóż claim → kopnięcie → resolver działa; walidacja przechodzi w tryb rename
    tx = ctl.build_username_tx("super-ala")
    L.add_tx(tx)
    kop()
    assert ctl.resolve_username("super-ala") == ala.wallet
    ok2, _, fee2, op2 = ctl.validate_username_edit("mega-ala")
    assert ok2 and op2 == "rename" and fee2 == uname.RENAME_FEE
    print("  [OK] 4. claim on-chain → resolver 'super-ala'→wallet; edycja teraz jako rename")

    # 5) transfer do boba: draft-check + submit do wspólnego mempoolu
    t2 = Tx.build_signed(TX_TRANSFER, ala, bob.wallet, 2 * ISKRA, nonce=1)
    L.add_tx(t2); kop()
    ok3, msg3 = ctl.wallet_send_check("super-ala", ISKRA)   # do SIEBIE przez username (test resolvera)
    assert ok3
    txid = ctl.submit_transfer("super-ala", ISKRA)
    assert any(t.txid() == txid for t in L.mempool)
    ok4, _ = ctl.wallet_send_check("nieznany-user", ISKRA)
    assert not ok4
    print("  [OK] 5. przelew po USERNAME: walidacja+submit; nieznana nazwa odrzucona")

    # 6) pool: shield do ali + scan znajduje dokładnie moje coiny
    from chain.stealth import derive_stealth
    st = derive_stealth(ala.sig_pub_b, ala.x_pub_b)
    shtx = Tx.build_signed(TX_SHIELD, ala, "FNX-SHIELD", 2 * ISKRA, nonce=3,
                           payload=txr.shield_payload([{"sp": st["stealth_pub"], "ep": st["eph_pub"]}]))
    L.add_tx(shtx); kop()
    mine_coins = ctl.my_pool_coins()
    assert len(mine_coins) == 1 and mine_coins[0]["amt"] == 2 * ISKRA
    bob_ctl = FenixController(identity=bob, ledger=L)
    assert bob_ctl.my_pool_coins() == []
    print("  [OK] 6. scan poola: GUI widzi moje shield-coiny (bob widzi zero)")

    # 7) paranoia: A zawsze; C wymaga VPN (stub mówi up); C z vpn down → odmowa
    okA, _ = ctl.apply_paranoia("A")
    assert okA and ctl.paranoia()["profile"] == "A"
    okC, _ = ctl.apply_paranoia("C", vpn_active=True)
    assert okC and ctl.paranoia()["profile"] == "C"
    failC, why = ctl.set_paranoia("C", vpn_active=False)
    assert not failC and "kill switch" in why
    try:
        ctl.set_paranoia("Z")
        raise SystemExit("paranoia Z przeszła!")
    except FenixGuiError:
        pass
    print("  [OK] 7. suwak paranoii: A zawsze; C tylko z VPN (kill switch); Z odrzucone")

    # 8) vpn status parse: stub z handshake → up; bez → down
    ctl_up = FenixController(identity=bob, ledger=L,
                             vpn=VpnCtl(runner=lambda a: (0, "interface: fnxwg0\n  latest handshake: 7 seconds ago\n")))
    assert ctl_up.vpn.status()[0] == "up"
    ctl_down = FenixController(identity=bob, ledger=L,
                               vpn=VpnCtl(runner=lambda a: (1, "")))
    assert ctl_down.vpn.status()[0] == "down"
    print("  [OK] 8. vpn_status: handshake→up, brak→down (runner wstrzykiwalny)")

    # 9) dashboard: pola z snapshotem
    d = ctl.dashboard()
    assert d["height"] == L.height() and d["usernames"] == 1 and d["pool_size"] == 1
    assert d["balance_fnx"] == L.balance_of(ala.wallet) / ISKRA
    print("  [OK] 9. dashboard: height/usernames/pool/balance zgodne z ledgerem")

    # 10) widok: tylko jeśli jest DISPLAY (headless → uczciwy SKIP, nie FAIL)
    if _os.environ.get("DISPLAY"):
        app = FenixApp(ctl)
        app.root.update()
        app.show("Ustawienia")
        app.root.update()
        app.root.destroy()
        print("  [OK] 10. widok: FenixApp + wszystkie panele złożone pod DISPLAY")
    else:
        assert "FenixApp" in globals() and hasattr(FenixApp, "_p_settings")
        print("  [OK] 10. widok: SKIP (headless; FenixApp def gotowy do X11/openbox na ISO)")

    # 11) panic w GUI (D27): PanicController podpięty; FenixApp ma _clean_screen/_panic_done;
    #     hook czystego ekranu realnie odpala
    calls: list[str] = []
    pc = pbtn.PanicController(clean_hooks=[lambda: calls.append("a")], log=lambda *_: None)
    assert pc.clean_screen() == 1 and calls == ["a"]
    assert hasattr(FenixApp, "_clean_screen") and hasattr(FenixApp, "_panic_done")
    assert hasattr(FenixApp, "_build_shell")
    print("  [OK] 11. panic (D27): kontroler+hook czystego ekranu; FenixApp ma _clean_screen/_panic_done")

    # 12) vpn.env z GUI (M7b): walidacja konta + metody save/forget podpięte w Ustawieniach
    okv, digits = pbtn.validate_account("1234 5678 9012 3456")
    assert okv and digits == "1234567890123456"
    okb, _ = pbtn.validate_account("12345")
    assert not okb
    assert hasattr(FenixApp, "_vpn_env_save") and hasattr(FenixApp, "_vpn_env_forget")
    print("  [OK] 12. vpn.env (M7b): walidacja 16 cyfr; _vpn_env_save/_forget w Ustawieniach")

    # --- stuby IPC (API z gui/backend_ipc.BackendIpc) ---
    class _StubIpc:
        """Udaje ŻYWEGO demona (każde wołanie udaje się, dane z kapelusza)."""
        def __init__(self):
            self.submitted: list = []
            self.mining: list = []

        def status(self):
            return {"height": 42, "tip": "ab" * 20, "peers": 7, "mining": True,
                    "mined": 3, "mempool": 2, "pool_size": 0, "key_images": 0,
                    "usernames": 1}

        def balance(self, wallet): return 5 * ISKRA
        def nonce(self, wallet): return 2
        def submit_tx_dict(self, txd): self.submitted.append(txd); return "ff" * 32
        def set_mining(self, on): self.mining.append(on); return on
        def sync(self): return True

    class _DeadIpc:
        """Udaje MARTWEGO demona (każde wołanie = IpcError)."""
        def status(self): raise IpcError("demon martwy")
        def balance(self, w): raise IpcError("demon martwy")
        def nonce(self, w): raise IpcError("demon martwy")
        def submit_tx_dict(self, txd): raise IpcError("demon martwy")
        def set_mining(self, on): raise IpcError("demon martwy")
        def sync(self): raise IpcError("demon martwy")

    # 13) IPC ON-LINE: dashboard/zasoby z demona; submit idzie MOSTEM, nie do dev-mempoolu
    stub_ipc = _StubIpc()
    ctl_i = FenixController(identity=bob, ledger=L, ipc=stub_ipc)
    d_i = ctl_i.dashboard()
    assert d_i["daemon"] is True and d_i["peers"] == 7 and d_i["height"] == 42
    assert d_i["balance_fnx"] == 5 and d_i["mining"] is True and d_i["mined"] == 3
    assert ctl_i.nonce_next() == 2
    assert ctl_i.balance_iskry() == 5 * ISKRA
    before = len(L.mempool)
    txid_i = ctl_i.submit_transfer("super-ala", ISKRA)
    assert txid_i == "ff" * 32 and len(stub_ipc.submitted) == 1
    assert len(L.mempool) == before, "przy żywym IPC tx NIE może lądować w dev-mempolu!"
    ok_m, _ = ctl_i.set_mining(False)
    assert ok_m and stub_ipc.mining[-1] is False
    ok_s, _ = ctl_i.request_sync()
    assert ok_s
    print("  [OK] 13. IPC ON-LINE: dashboard/saldo/nonce/submit/mining lecą mostem (nie dev)")

    # 14) IPC martwy → czysty fallback dev, zero crashy, daemon=OFF-LINE pokazane uczciwie
    ctl_d = FenixController(identity=ala, ledger=L, ipc=_DeadIpc())
    d_d = ctl_d.dashboard()
    assert d_d["daemon"] is False and d_d["height"] == L.height()
    txid_d = ctl_d.submit_transfer("super-ala", ISKRA)
    assert any(t.txid() == txid_d for t in L.mempool), "offline: tx ma spaść do dev-mempoolu"
    ok_d, msg_d = ctl_d.set_mining(True)
    assert not ok_d and "demon" in msg_d.lower()
    ok_d2, msg_d2 = ctl_d.request_sync()
    assert not ok_d2 and "demon" in msg_d2.lower()
    print("  [OK] 14. IPC martwy: płynny fallback dev (daemon=OFF-LINE uczciwie), submit do mempoolu")

    # 15) pool w GUI (M7c): PoolController na danych FenixController; FNXS1;
    #     plan z cienkim tłumem odrzucony po polsku; zakładka _p_pool zamontowana
    pool_ctl = poolp.PoolController(identity=ala, ledger=ctl.ledger, ipc=None)
    coins15 = pool_ctl.my_coins()
    assert len(coins15) == 1 and coins15[0]["amt"] == 2 * ISKRA, "shield z testu 6"
    addr15 = pool_ctl.my_address()
    assert addr15.startswith("FNXS1")
    assert poolp.decode_stealth_address(addr15)[0] == ala.sig_pub_b
    try:
        pool_ctl.plan_send(addr15, ISKRA)          # 1 FNX — środki są, ale tłum = 1 (<5)
        raise SystemExit("cienki tłum przeszedł w GUI-Pool!")
    except poolp.PoolError as e:
        assert "za cienki tłum" in str(e)
    assert hasattr(FenixApp, "_p_pool") and "Pool" != ""
    print("  [OK] 15. pool (M7c): PoolController na danych kontrolera; FNXS1+plan+cienki tłum; zakładka w GUI")

    # 16) czat E2E w GUI (M4, D35): kontroler liczy ME/FP; ala→bob po wspólnej szynie LOCAL;
    #     drut NIE niesie plaintextu; TOFU pinuje; replay koperty drop; podszywka pod username
    #     = OSOBNY kontakt (fp jest tożsamością, nie etykieta)
    from app.messenger import Messenger, LocalTransport
    reg: dict = {}
    ma, mb = Messenger(ala), Messenger(bob)
    ma.transport, mb.transport = LocalTransport(reg, ma.my_fp), LocalTransport(reg, mb.my_fp)
    ctl._msg, bob_ctl._msg = ma, mb
    me16 = ctl.msg_me()
    assert me16["addr"].startswith("FNXS1") and len(me16["fp"].replace("-", "")) == 16
    assert ctl.msg_contacts() == []
    fp_to = ctl.msg_send(bob_ctl.msg_me()["addr"], "siema bob!")
    env1 = dict(reg[fp_to][-1])
    assert env1["ct"] and env1["v"] == 2 and "rk_pub" in env1, "koperta v2 (ratchet FNX-R1)"
    assert "from" not in env1 and "eph" not in env1, "v2 zdradza nadawcę na drucie!"
    assert "siema bob" not in json.dumps(reg), "PLAINTEXT wyciekł na drut (koperta szyfruje?)!"
    got16 = bob_ctl.msg_poll()
    assert len(got16) == 1 and got16[0].text == "siema bob!" and got16[0].new_contact
    cs16 = bob_ctl.msg_contacts()
    assert len(cs16) == 1 and cs16[0]["name"] == "ala_gui" and cs16[0]["msgs"] == 1
    reg[mb.my_fp].append(env1)                      # REPLAY tej samej koperty
    assert bob_ctl.msg_poll() == [] and mb.stats["replay"] + mb.stats["bad_aead"] >= 1, \
        "powtórzona koperta nie została zignorowana (v2: dedup na łańcuchu ratchetu)"
    eve = Identity.generate("ala_gui")              # podszywka: ta sama ETYKIETA, inne klucze
    mev = Messenger(eve)
    mev.transport = LocalTransport(reg, mev.my_fp)
    ctl_e = FenixController(identity=eve, ledger=L)
    ctl_e._msg = mev
    ctl_e.msg_send(bob_ctl.msg_me()["addr"], "to ja, ala!")
    got17 = bob_ctl.msg_poll()
    assert got17[0].new_contact and got17[0].name == "ala_gui"
    assert len(bob_ctl.msg_contacts()) == 2, "podszywka NIE może wejść na konto ali (D28/D35)"
    assert hasattr(FenixApp, "_msg_send") and hasattr(FenixApp, "_msg_poll")
    print("  [OK] 16. czat E2E (M4): drut bez plaintextu; TOFU pin; replay drop; podszywka = OSOBNY kontakt")

    # 17) transport mesh (M4): ŻYWY IPC → messenger jedzie MsgIpcTransport-em (skrzynka
    #     demona, węzeł nie czyta); MARTWY IPC → cichy fallback LocalTransport; E2E ala→bob
    #     przez wspólny "demon"-wabik; plaintext nie pojawia się w poczcie demona
    class _StubIpcMsg:
        """Udaje demona z pocztą T_MSG (ops msg_*; skrzynki w RAM jak net/fenix_node)."""
        def __init__(self):
            self.box, self.subs = {}, set()
        def status(self):
            return {"height": 42, "tip": "ab" * 20, "peers": 7, "mining": False,
                    "mined": 0, "mempool": 0, "pool_size": 0, "key_images": 0, "usernames": 1}
        def msg_sub(self, fp):
            self.subs.add(fp); self.box.setdefault(fp, []); return True
        def msg_send_env(self, env):
            fp = env["to_fp"]
            if fp not in self.subs:
                return {"delivered": 0, "dup": False}
            self.box[fp].append(env); return {"delivered": 1, "dup": False}
        def msg_poll_envs(self, fp):
            out = list(self.box.get(fp, [])); self.box[fp] = []; return out

    demon17 = _StubIpcMsg()
    ctl_a17 = FenixController(identity=ala, ledger=L, ipc=demon17)
    ctl_b17 = FenixController(identity=bob, ledger=L, ipc=demon17)
    assert ctl_a17.msg_transport().startswith("mesh")
    assert ctl_b17.msg_transport().startswith("mesh")
    assert demon17.subs == {ctl_a17.messenger().my_fp, ctl_b17.messenger().my_fp}, \
        "oba GUI powinny założyć skrzynki w demonie (msg_sub przy starcie transportu)"
    ctl_a17.msg_send(ctl_b17.msg_me()["addr"], "leci przez demona!")
    poczta_demona = json.dumps(demon17.box)
    assert "leci przez demona" not in poczta_demona, "demon WIDZI plaintext — koperta nie szyfruje!"
    got17b = ctl_b17.msg_poll()
    assert len(got17b) == 1 and got17b[0].text == "leci przez demona!" and got17b[0].new_contact
    # martwy demon → spokojny fallback lokalny (bez crasha, etykieta uczciwa)
    ctl_d17 = FenixController(identity=ala, ledger=L, ipc=_DeadIpc())
    assert ctl_d17.msg_transport().startswith("lokalny")
    print("  [OK] 17. transport mesh (M4): ON-LINE → MsgIpcTransport (skrzynka demona, sam szum),")
    print("           OFF-LINE → fallback lokalny; E2E ala→bob przez demon-wabik")

    # 18) mgła v2 w GUI (M7d): mint z poziomu kontrolera → kopnięcie → my_hidden_coins
    #     widzi kwoty (scan C/blob); pool NIE zna amt; cienki tłum mgły odrzucony po polsku;
    #     wiersze/funkcje panelu v2 zamontowane w widoku
    pc18 = poolp.PoolController(identity=ala, ledger=L, ipc=None)
    for _ in range(2):
        L.add_tx(pc18.build_shield2_tx(1 * ISKRA))
    kop()
    fog18 = pc18.my_hidden_coins()
    assert len([c for c in fog18 if c["amt"] == 1 * ISKRA]) >= 2, "GUI nie skanuje mgły (C/blob)"
    assert all("amt" not in L.pool[c["sp"]] for c in fog18), "pool poznał kwotę mgły!"
    try:
        pc18.plan_hidden_send(bob_ctl.msg_me()["addr"], 1 * ISKRA)
        raise SystemExit("cienki tłum mgły przeszedł z GUI!")
    except poolp.PoolError as e:
        assert "tłum" in str(e).lower() and "mgle" in str(e).lower(), str(e)
    for m in ("_pool_mint2", "_pool_send2", "_pool_unshield", "_pool_fog_done"):
        assert hasattr(FenixApp, m), m
    print("  [OK] 18. mgła v2 w GUI (M7d): mint z panelu; scan C/blob pokazuje monety; pool bez amt;")
    print("           cienki tłum mgły odrzucony po polsku; przyciski mgły zamontowane")

    # 19) walizka TF1 z GUI (D40): protect → plik = szum (kontakty szyfrowane hasłem);
    #     unlock ZŁYM hasłem odrzucone; dobrym → kontakty wracają; statusy uczciwe
    import os as _os19
    import shutil as _sh19
    import tempfile as _tf19
    from core.keystore import KDFParams as _KDFP
    d19 = _tf19.mkdtemp(prefix="fenix-gui-tf1-")
    p19 = _os19.path.join(d19, "tofu.tf1")
    assert "tylko w RAM" in bob_ctl.msg_tofu_status()
    s19 = bob_ctl.msg_tofu_protect("haslo-mocne-9", p19, kdf=_KDFP.fast_for_tests())
    assert "TF1" in s19 and _os19.path.exists(p19)
    raw19 = open(p19, "rb").read()
    assert raw19.startswith(b"TF1") and "ala_gui".encode() not in raw19, \
        "walizka TF1 przecieka username kontaktu!"
    assert "TF1 AKTYWNA" in bob_ctl.msg_tofu_status()
    try:
        FenixController(identity=bob, ledger=L).msg_tofu_unlock("zle-haslo-99", p19)
        raise SystemExit("GUI otworzyło walizkę złym hasłem!")
    except FenixGuiError as e:
        assert "złe hasło" in str(e), str(e)
    ctl19b = FenixController(identity=bob, ledger=L)
    s19b = ctl19b.msg_tofu_unlock("haslo-mocne-9", p19)
    assert "2 kontakt" in s19b, s19b
    assert sorted(c["fp"] for c in ctl19b.msg_contacts()) == \
        sorted(c["fp"] for c in bob_ctl.msg_contacts()), "kontakty po unlock ≠ przed protect"
    bob_ctl.messenger().tofu.path = None         # walizka zdemontowana: z powrotem RAM-only
    _sh19.rmtree(d19, ignore_errors=True)
    print("  [OK] 19. walizka TF1 z GUI (D40): protect szyfruje plik hasłem (szum wobec złodzieja);")
    print("           złe hasło odrzucone; dobrym → 2 kontakty z powrotem; status uczciwy")

    # 20) P21/D45 nick→kontakt on-chain + D46 ranga z konsensusu: claim → ref → wyślij
    #     po NICKU; kupno vip z GUI → pending → aktywna po 6 confs → profil ją pokazuje
    t_claim20 = bob_ctl.build_username_tx("bobczat")
    L.add_tx(t_claim20)
    kop()
    t_ref20 = bob_ctl.build_contact_ref_tx()                      # tabliczka = mój adres czatu
    L.add_tx(t_ref20)
    kop()
    addr20 = ctl.resolve_contact("bobczat")
    assert addr20 == bob_ctl.messenger().my_address(), "pętla nick→wallet→FNXS1 nie zbiegła (GUI)"
    assert ctl.resolve_contact("duch_bez_nicka") is None
    fp20 = ctl.msg_send_to("bobczat", "ping po samym nicku!")     # bez wklejania adresu!
    got20 = bob_ctl.msg_poll()
    assert len(got20) == 1 and got20[0].text == "ping po samym nicku!" and got20[0].name == "ala_gui"
    print("  [OK] 20a. P21/D45: claim → TX_CONTACT_REF → msg po NICKU (bez karteczki z adresem)")
    tx_v, opis_v = ctl.buy_rank_tx("vip")
    assert "dopłata różnicy 5" in opis_v, opis_v
    L.add_tx(tx_v)
    kop()
    p20a = ctl.profile()
    assert p20a["rank_pending"] and p20a["rank_pending"][0] == "vip", \
        f"pending nie pokazany: {p20a}"
    assert p20a["onchain_rank"] == "ghost", "ranga aktywna za wcześnie (prematura!)"
    for _ in range(rks.RANK_ACTIVATION_CONFS - 1):
        kop()
    p20b = ctl.profile()
    assert p20b["onchain_rank"] == "vip" and p20b["rank"] == "vip" and p20b["rank_pending"] is None
    try:
        ctl.buy_rank_tx("donor")
        raise SystemExit("downgrade rangi z GUI przeszedł!")
    except FenixGuiError as e:
        assert "nie jest wyższa" in str(e)
    try:
        ctl.buy_rank_tx("fenix")
        raise SystemExit("fenix z TX przeszedł — systemowa wyciekła!")
    except FenixGuiError as e:
        assert "SYSTEMOWA" in str(e)
    print("  [OK] 20b. D46: ranga GUI = konsensus (pending x/6 → aktywna; downgrade+fenix odrzucone)")

    # 21) D52 odznaki + D50 donate z GUI (kontroler, dev): panel bez demona = chain-only;
    #     donate kwotą użytkownika ląduje w skarbcu (licznik DONOR rośnie); odznaki
    #     pojawiają się z faktów; renew rangi z GUI = pełna cena (D51)
    p21 = ctl.profile_badges()
    assert p21["daemon"] is False and set(p21["badges"]) == {"earned", "locked"}, p21
    codes21 = {b["code"] for b in p21["badges"]["earned"]}
    assert "rank_owner" in codes21, codes21          # vip kupiony w teście 20
    assert p21["donated_iskry"] == 0
    bal21 = ctl.balance_iskry()
    tre21_0 = L.balance_of(L.treasury)
    msg21 = ctl.donate_tx(int(2.5 * ISKRA), note="test donate")
    assert "skarbca" in msg21 or "datek" in msg21, msg21
    kop()
    assert L.donations[ctl.identity.wallet] == int(2.5 * ISKRA), "donate nie wszedł do rejestru"
    assert L.balance_of(L.treasury) > tre21_0, "skarbiec nie urósł z datku"
    p21b = ctl.profile_badges()
    codes21b = {b["code"] for b in p21b["badges"]["earned"]}
    assert "donor_t1" in codes21b, codes21b
    assert p21b["donated_iskry"] == int(2.5 * ISKRA)
    locked21 = {b["code"] for b in p21b["badges"]["locked"]}
    assert {"host_100h", "webmaster", "donor_t3"} <= locked21, locked21
    assert all(b["verify"] in ("chain", "local") for b in p21b["badges"]["earned"])
    from chain.block import fee_split as _fs21
    _fee21 = _fs21(int(2.5 * ISKRA))[2]
    assert ctl.balance_iskry() == bal21 - int(2.5 * ISKRA) - _fee21 + 5 * ISKRA, \
        "bilans po dacie ≠ kwota+fee+5 FNX nagrody bloku (kop na własny wallet)"
    # walidacje: 0 / ujemna / za długa karteczka
    for bad in (0, -5):
        try:
            ctl.donate_tx(bad)
            raise SystemExit(f"donate {bad} z GUI przeszedł!")
        except FenixGuiError:
            pass
    try:
        ctl.donate_tx(ISKRA, note="x" * 141)
        raise SystemExit("za długa karteczka przeszła!")
    except FenixGuiError:
        pass
    # renew vip z GUI (D51): pełna cena, ważność rośnie
    until21 = L.ranks[ctl.identity.wallet]["until"]
    _tx_r, opis_r = ctl.buy_rank_tx("vip")
    assert "pełna cena" in opis_r, opis_r
    L.add_tx(_tx_r); kop()
    assert L.ranks[ctl.identity.wallet]["until"] > until21, "renew z GUI nie wydłużył ważności"
    # site_created w dev = uczciwy komunikat (licznik żyje w demonie)
    assert "dev" in ctl.mark_site_created()
    print("  [OK] 21. D52 odznaki + D50 donate + D51 renew z GUI: donate 2.5 FNX → DONOR I")
    print("           z konsensusu; złe kwoty/karteczki odrzucone; renew wydłuża ważność")

    # 22) D53/D55: ONB admina z poziomu kontrolera (bez X11 — czysta logika)
    import tempfile as _tmp22
    import shutil as _sh22
    d22 = _tmp22.mkdtemp(prefix="fenix-gui-admin-")
    ctl22 = FenixController(identity=ala, ledger=L, data_dir=d22)
    st22 = ctl22.admin_status()
    assert st22["onboarding_needed"] is True and st22["data_dir"] == d22, st22
    try:
        ctl22.admin_onboard("Anon123!", "krotkie", "x")
        raise SystemExit("słaby ONB przeszedł z GUI!")
    except FenixGuiError as e22:
        assert "znaków" in str(e22), e22
    msg22 = ctl22.admin_onboard("Anon123!", "Moje!Haslo-2026", "Panika!Moja-77")
    assert "ZMIENIONE" in msg22, msg22
    st22b = ctl22.admin_status()
    assert st22b["onboarding_needed"] is False and st22b["default_password"] is False, st22b
    msg22c = ctl22.admin_onboard("Moje!Haslo-2026", "Jeszcze!Lepsze-9a", "Panika!Lepsza-4")
    assert "ZMIENIONE" in msg22c, msg22c
    _sh22.rmtree(d22, ignore_errors=True)
    print("  [OK] 22. D53/D55 ONB admina z kontrolera: fabryczne meldowane → zmiana → czysty status;")
    print("           słabe hasła i złe aktualne odrzuca FenixGuiError po polsku")

    # 23) D66: status banu WIDOCZNY z kontrolera — przy rejestracji i lookupu
    _core23 = bevt.ban_core(ctl.identity.wallet, "0x11", *bevt.REASONS_RED["0x11"][1:],
                            bevt.evidence_hash_of({"demo": "D66"}))
    bevt.apply_ban(L.bans, _core23, L.height())
    ok23, msg23, fee23, op23 = ctl.validate_username_edit("nowy-nick-23")
    assert not ok23 and op23 == "banned" and fee23 == 0, "rejestracja ze zbanowanego = stój"
    assert "ZBANOWANY" in msg23 and "0x11" in msg23 and "PROTO_FLOOD" in msg23,         "użytkownik DOWIE SIĘ czemu (kod+etykieta+powód), nie suche 'błąd'"
    line23 = ctl.ban_status_line()                          # mój wallet
    assert "ZBANOWANY" in line23 and "wykup" in line23
    clean23 = ctl.ban_status_line("bobczat")                # lookup po username (bob z kroku 20)
    assert "NIE jest zbanowany" in clean23, clean23
    unk23 = ctl.ban_status_line("duch-nieznany")
    assert "nieznany" in unk23
    bevt.apply_unban(L.bans, ctl.identity.wallet, L.height())
    hist23 = ctl.ban_status_line()
    assert "NIE jest zbanowany" in hist23 and "wykup" in hist23,         "historia pokazana uczciwie (był ban — wykupany), nie zamiotiona"
    ok23b, _, _, op23b = ctl.validate_username_edit("nowy-nick-23")
    assert ok23b and op23b in ("claim", "rename"), "po zdjęciu plomby rejestracja znowu idzie"
    print("  [OK] 23. D66: status banu widać z GUI — rejestracja mówi CZEMU (kod+powód+furtką),")
    print("           lookup po username i po wykupie rozróżnia: zbanowany/czysty/historia")

    # 24) D67: pokój cenowy + karty Sieci z kontrolera (dev + przez stub IPC)
    class _Ipc24:
        def __init__(self, ledger):
            self._l = ledger
            self.ghost_calls = []
        def price(self):
            from app.fnx_coin import price_info
            return price_info(self._l)
        def census(self):
            return {"online_estimate": 3, "known_total": 7, "registered_users": 2,
                    "pou_attesters": 0, "airdrop_fired": [], "airdrop_next": 1_000_000,
                    "ghost": False, "method": "stub-D67"}
        def ghost(self, on):
            self.ghost_calls.append(bool(on))
            return {"ghost": bool(on)}
    xc24 = ctl.exchange_card()                      # bez IPC = dev-lokalny
    assert xc24["src"].startswith("dev") and xc24["info"]["price_cents"] >= 1
    assert any("handel: SZYBA read-only" in li for li in xc24["lines"]), \
        "karta UCZY: szyba, nie kasa (handel=P7)"
    ctl24 = FenixController(identity=bob, ledger=L, ipc=_Ipc24(L))
    xc24b = ctl24.exchange_card()
    assert xc24b["src"] == "demon (IPC)" and xc24b["info"]["price_cents"] == xc24["info"]["price_cents"], \
        "ta sama krzywa przez IPC i lokalnie (konsensus ceny z GUI)"
    nx0 = ctl.network_extra_card()                  # dev: census None + ban line mimo to
    assert nx0["census"] is None and nx0["ghost"] is None and "NIE jest zbanowany" in nx0["my_ban_line"]
    nx1 = ctl24.network_extra_card()
    assert nx1["census"]["online_estimate"] == 3 and nx1["ghost"] is False
    ok24, msg24 = ctl.set_ghost_gui(True)           # dev = uczciwa odmowa
    assert not ok24 and "brak IPC" in msg24
    ok24b, msg24b = ctl24.set_ghost_gui(True)
    assert ok24b and ctl24.ipc.ghost_calls == [True] and "ON" in msg24b
    print("  [OK] 24. D67: pokój cenowy z GUI (dev = demon, ta sama cena), karta mówi")
    print("           SZYBA/read-only; karty Sieci: census+duch+ban-status; toggle uczciwy w dev")

    print("\nSELFTEST: PASS ✅  gui/fenix_gui.py — kontroler D28/D29 + panic D27 + vpn.env + czat M4/mesh + mgła v2 + walizka TF1 + kontakt po nicku (P21) + ranga on-chain + status banu D66 + pokój cenowy/karty D67; widok czeka na X11")
    print("RUN (tryb dev):  python3 -m gui.fenix_gui --demo   (na maszynie z DISPLAY)")

