# chain/ledger.py — stan FNX: salda, nonce, mempool, walidacja bloków (M5 MVP)
"""
Zasady ekonomiczne (D15/D39): fee transferu = 0.001% BURN + 0.055% dla KOPACZA
bloku (D39: górnik zarabia na potwierdzaniu cudzych tx — coinbase =
BLOCK_REWARD + Σ fee minera). Skarbiec (D14) = fee z TX_ID_DECLARE (anty-squatting).
Nagroda za blok: BLOCK_REWARD (ROBOCZE — fnx_spec §12 zostawia emisję/halving
do decyzji; tu: stała robocza 5 FNX, wyraźnie oznaczona jako OTWARTA).
Miner fee (D39): część ownerska fee od TRANSFER/SHIELD/RING/UNSHIELD (motywacja
kopania; ID_DECLARE → skarbiec — anty-squatting nie jest pracą kopacza).

Model konta: saldo + nonce per wallet. Fork-choice: najdłuższy WAŻNY łańcuch
(podsumowana praca = liczba bloków × zbits średnie — uproszczone MVP; spec:
total work dokładnie w M5). Retarget: co 144 bloki, zmiana zbits clamp ±2 (×4/÷4).
"""
from __future__ import annotations

import json as _json
import os as _os
import threading
import time

import chain.pow as fpow
from chain.block import (Block, Tx, TREASURY_WALLET_DEV, COINBASE_SENDER,
                         TX_COINBASE, TX_TRANSFER, TX_RING, TX_SHIELD, TX_UNSHIELD,
                         TX_ID_DECLARE, TX_CONTACT_REF, TX_RANK_UP, KNOWN_TX,
                         TX_BAN_EVT, TX_DONATE, TX_POU_ATTEST, TX_VOTE_EVT, TX_AIRDROP,
                         fee_split, ISKRA,
                         canon as ccanon, h32 as ch32)
from chain import tx_ring as txr
from chain import tx_hidden as txh                     # v2: konsensus ukrytych kwot (3b, D38)
from chain import clsag as cx
from chain import usernames as uname
from chain import contact_ref as cref                  # P21/D45: wallet → kontakt FNXS1
from chain import ranks as rks                         # rangi z konsensusu (D16/D28, TX_RANK_UP)
from chain import ban_evt as bevt                      # tombstone k-z-n (D18/D22/D30, TX_BAN_EVT)
from chain import donate as don                        # TX_DONATE 0x14 do skarbca ownera (D50)
from chain import pou                                  # TX_POU_ATTEST 0x04: dziennik obecności (D58)
from chain import vote_evt as vevt                     # TX_VOTE_EVT 0x07: urna dla VOTER (D60)
from chain import airdrop as adrop                     # TX_AIRDROP 0x15: kamień milowy 1M (D62)

BLOCK_REWARD = 5 * ISKRA          # ⚠️ ROBOCZE (fnx_spec §12: emisja OTWARTA)
RETARGET_EVERY = 144              # bloków między retargetami (spec)
RETARGET_CLAMP = 2                # ±2 bity = ×4/÷4 (spec)
BLOCK_TIME_TARGET = 60            # sekund (spec T=60s)
MEMPOOL_CAP = 2000
MAX_BLOCK_TXS = 200
CHAIN_DAT_MAGIC = b"FCD1"      # Fenix Chain Dat v1 (P6: restart bez pełnego resyncu)


class ChainError(Exception):
    """Klasa błędów konsensusu — jeden typ, zero orakli dla podsłuchu."""


class Ledger:
    def __init__(self, treasury: str = TREASURY_WALLET_DEV,
                 airdrop_milestone: int | None = None):
        self.treasury = treasury
        # próg kamienia milowego airdropu (D62) — domyślny 1M; testy dev podają mały
        self.airdrop_milestone = airdrop_milestone or adrop.MILESTONE_USERS
        g = Block.genesis(treasury)
        self.chain: list[Block] = [g]
        self.balances: dict[str, int] = {}
        self.nonces: dict[str, int] = {}
        self.mempool: list[Tx] = []
        self.seen_tx: set[str] = set()
        # --- pool prywatny: outputy stealth + rejestr key-images (D31) ---
        # v1 (3a): {"ep": hex, "amt": iskry} — kwota jawna (migracja działa dalej)
        # v2 (3b, D38): {"ep", "C", "blob", "v":2} — kwota ZNIKŁA za bramką (brak amt!)
        self.pool: dict[str, dict] = {}      # stealth_pub_hex -> entry (v1 lub v2)
        self.key_images: set[str] = set()    # I = priv_ot·Hp(P); powtórka = double-spend
        # --- rejestr username (D28): identyfikacja ludzka zamiast walletów ---
        self.usernames: dict[str, str] = {}  # name -> wallet (first-come-first-served)
        # --- kontakty publiczne (P21/D45): wallet -> FNXS1 (pętla nick→wallet→adres) ---
        self.contact_refs: dict[str, str] = {}
        # --- rangi z konsensusu (D16/D28): wallet -> {"rank","height"} (6 confs do aktywnej) ---
        self.ranks: dict[str, dict] = {}
        # --- tombstone (D18/D22/D30): wallet -> {"active","height","code","evidence",
        #     "unban_used", ...}; WYŁĄCZNIE werdykty red z kropką k-z-n (ban_evt) ---
        self.bans: dict[str, dict] = {}
        # --- datki do skarbca ownera (D50): wallet -> suma iskier (odznaki DONOR, D52) ---
        self.donations: dict[str, int] = {}
        # --- PoU (D58): wallet -> {"w": [window_id...], "last_ts": int}; VOTER = 30 dni ---
        self.pou: dict[str, dict] = {}
        # --- głosy (D60): topic -> wallet -> choice; brama = VOTER z self.pou (§13) ---
        self.votes: dict[str, dict] = {}
        # --- airdrop (D62): odstrzelone kamienie milowe + dziennik zdarzeń ---
        self.airdrop_fired: set[int] = set()
        self.airdrops: list[dict] = []
        self.lock = threading.RLock()

    # ---------------------------------------------------------------- podstawa
    def tip(self) -> Block:
        return self.chain[-1]

    def height(self) -> int:
        return self.chain[-1].height

    def balance_of(self, wallet: str) -> int:
        return self.balances.get(wallet, 0)

    def nonce_of(self, wallet: str) -> int:
        return self.nonces.get(wallet, 0)

    # ---------------------------------------------------------------- trudność
    def required_zbits(self) -> int:
        """Retarget co 144 bloki: porównaj czas okna z 144×60 s, clamp ±2 bity."""
        with self.lock:
            tip = self.tip()
            if tip.height < RETARGET_EVERY or tip.height % RETARGET_EVERY != 0:
                return tip.zbits if tip.height > 0 else 8   # dev-start: 8 (target ~s)
            win = self.chain[-RETARGET_EVERY:]
            actual = max(1, win[-1].timestamp - win[0].timestamp)
            expected = RETARGET_EVERY * BLOCK_TIME_TARGET
            delta = round((actual / expected - 1) * -1 * 1.0)   # wolniej → łatwiej
            # praktycznie: ratio→log2 z przycinkiem (MVP: schodkowo)
            ratio = expected / actual
            delta = max(-RETARGET_CLAMP, min(RETARGET_CLAMP, round_log2(ratio)))
            return max(1, tip.zbits + delta)

    # ---------------------------------------------------------------- mempool
    def _mempool_key_images(self) -> set[str]:
        kis: set[str] = set()
        for t in self.mempool:
            if t.type in (TX_RING, TX_UNSHIELD):        # unshield też strzela ki (D38)
                try:
                    for i in txr.parse_payload(t.payload).get("in", []):
                        kis.add(i.get("ki", ""))
                except txr.TxRingError:
                    pass
                try:
                    for ki in txh.ring2_kis(t.payload):        # v2 ma swoje dedup!
                        kis.add(ki)
                except txh.TxHiddenError:
                    continue
        return kis

    def _pool_lookup_with_mempool(self, sp_hex: str) -> int | None:
        """Nominał dla ringów v1 — wpis v2 NIE ma amt (lookup odpowie None → odrzut
        membera, bo v1 gra tylko z v1; mieszanych ringów nie ma, D38)."""
        if sp_hex in self.pool:
            return self.pool[sp_hex].get("amt")
        for t in self.mempool:  # shield jeszcze nie kopnięty, ale w kolejce — uznajemy
            if t.type == TX_SHIELD:
                try:
                    for o in txr.validate_shield_payload(t.payload):
                        if o["sp"] == sp_hex:
                            return int(t.amount)
                except txr.TxRingError:
                    continue
        return None

    def _pool_lookup_c_with_mempool(self, sp_hex: str) -> dict | None:
        """Zobowiązanie C dla ringów v2 — wpis v1 odpowiada None (ring v2 bierze
        członków TYLKO z v2, D38). Mempoolowi shield/ring v2 też uznajemy."""
        e = self.pool.get(sp_hex)
        if e is not None:
            return e if "C" in e else None
        for t in self.mempool:
            try:
                if t.type == TX_SHIELD:
                    for o in txh.validate_shield2(t.payload, t.amount):
                        if o["sp"] == sp_hex:
                            return {"C": o["C"]}
                elif t.type == TX_RING:
                    for o in txh.parse_ring2(t.payload)["out"]:
                        if o["sp"] == sp_hex:
                            return {"C": o["C"]}
                elif t.type == TX_UNSHIELD:
                    for o in txh.parse_unshield2(t.payload)["out"]:
                        if o["sp"] == sp_hex:
                            return {"C": o["C"]}
            except txh.TxHiddenError:
                continue
        return None

    def _virtual_bans(self) -> dict:
        """Rejestr banów jak PO zastosowaniu BAN_EVT siedzących w MEMPOOLU
        (w kolejności wpływu) — walidacja mempoola widzi te same konflikty
        co przyszły blok (ban w kolejce już zamyka wallet, wykup w kolejce
        blokuje drugi wykup)."""
        v = {w: dict(e) for w, e in self.bans.items()}
        for t in self.mempool:
            if t.type == TX_BAN_EVT:
                try:
                    op, w = bevt.validate_ban_payload(t.payload, v, sender=t.sender)
                except bevt.BanEvtError:
                    continue
                p = bevt.parse_ban_payload(t.payload)
                if op == "ban":
                    bevt.apply_ban(v, p["core"], 0)
                else:
                    bevt.apply_unban(v, w, 0)
        return v

    def add_tx(self, tx: Tx) -> None:
        with self.lock:
            # ---------------- TX_RING: pool → pool, anonimowe (bez konta/nonce) ----------
            if tx.type in (TX_RING, TX_UNSHIELD):
                if tx.amount != 0 or tx.sender:
                    raise ChainError("ring/unshield: amount=0 i sender pusty (anonimowość)")
                try:
                    if tx.type == TX_UNSHIELD:
                        payload_u = txh.parse_unshield2(tx.payload)
                        kis, _w, _a = txh.verify_unshield2(
                            payload_u, self._pool_lookup_c_with_mempool)
                    elif txh.payload_v(tx.payload) == 1:
                        payload = txr.parse_payload(tx.payload)
                        kis = txr.validate_ring_tx(payload, self._pool_lookup_with_mempool)
                    else:                                    # v2: pełna mgła (3b, D38)
                        payload = txh.parse_ring2(tx.payload)
                        kis = cx.verify_hidden_tx(payload, self._pool_lookup_c_with_mempool)
                except txr.TxRingError as e:
                    raise ChainError(f"ring: {e}") from None
                except (cx.ClsagError, txh.TxHiddenError) as e:
                    raise ChainError(f"ring/unshield v2: {e}") from None
                seen_kis = self._mempool_key_images()
                for ki in kis:
                    if ki in self.key_images or ki in seen_kis:
                        raise ChainError("ring: key image już widziany (double-spend)")
                if tx.txid() in self.seen_tx or any(t.txid() == tx.txid() for t in self.mempool):
                    raise ChainError("tx już widziany")
                if len(self.mempool) >= MEMPOOL_CAP:
                    raise ChainError("mempool pełny")
                self.mempool.append(tx)
                return
            # ---------------- TX_BAN_EVT: op=ban = systemowe (k-z-n), op=unban = konto ----
            if tx.type == TX_BAN_EVT:
                try:
                    op_b = bevt.parse_ban_payload(tx.payload).get("op")
                except bevt.BanEvtError as e:
                    raise ChainError(f"ban-evt: {e}") from None
                if op_b == "ban":
                    if tx.amount != 0 or tx.sender or tx.sig:
                        raise ChainError("ban-evt: amount=0, sender i sig puste "
                                         "(moc dowodowa = kropka k-z-n w payload)")
                    try:
                        bevt.validate_ban_payload(tx.payload, self._virtual_bans())
                    except bevt.BanEvtError as e:
                        raise ChainError(f"ban-evt: {e}") from None
                    if tx.txid() in self.seen_tx or \
                            any(t.txid() == tx.txid() for t in self.mempool):
                        raise ChainError("tx już widziany")
                    if len(self.mempool) >= MEMPOOL_CAP:
                        raise ChainError("mempool pełny")
                    self.mempool.append(tx)
                    return
                # op == "unban": podpisuje ZBANOWANY wallet (wyjątek tombstone) — dalej ścieżka konta
            if tx.type not in (TX_TRANSFER, TX_SHIELD, TX_ID_DECLARE,
                               TX_CONTACT_REF, TX_RANK_UP, TX_BAN_EVT, TX_DONATE,
                               TX_POU_ATTEST, TX_VOTE_EVT):
                raise ChainError("mempool: TRANSFER/SHIELD/RING/ID_DECLARE/CONTACT_REF/RANK_UP/"
                                 "BAN_EVT/DONATE/POU_ATTEST/VOTE_EVT w tej wersji")
            # tombstone: zbanowany wallet jest martwy dla WSZYSTKIEGO prócz wykupu (D18)
            if tx.type != TX_BAN_EVT and bevt.is_banned(self.bans, tx.sender):
                raise ChainError("sender zbanowany (tombstone; jedyna droga: wykup TX_BAN_EVT)")
            if tx.type == TX_BAN_EVT:                       # op == "unban"
                try:
                    bevt.validate_ban_payload(tx.payload, self._virtual_bans(),
                                              sender=tx.sender)
                except bevt.BanEvtError as e:
                    raise ChainError(f"ban-evt: {e}") from None
                if tx.amount != bevt.UNBAN_FEE_ISKRY:
                    raise ChainError(f"ban-evt: wykup = dokładnie {bevt.UNBAN_FEE_ISKRY} iskier "
                                     "(D30; kwota ROBOCZA — fnx_spec §12/P5)")
            if tx.type == TX_ID_DECLARE:
                # walidacja vs chain ∪ mempool (claim w kolejce już rezerwuje nazwę!)
                virtual = dict(self.usernames)
                for t in self.mempool:
                    if t.type == TX_ID_DECLARE:
                        try:
                            p = uname.parse_username_payload(t.payload)
                            virtual[p.get("name", "")] = t.sender
                        except uname.UsernameError:
                            continue
                try:
                    op, _n, _a, fee_req = uname.validate_username_payload(tx.payload, virtual, tx.sender)
                except uname.UsernameError as e:
                    raise ChainError(f"username: {e}") from None
                if tx.amount != fee_req:
                    raise ChainError(f"username: fee={fee_req} iskier wymagane dla {op}")
            if tx.type == TX_CONTACT_REF:
                try:                                       # slot per-wallet (bez kolizji między kontami)
                    op_c, _a_c, fee_req = cref.validate_contact_payload(tx.payload, tx.sender)
                except cref.ContactRefError as e:
                    raise ChainError(f"contact-ref: {e}") from None
                if tx.amount != fee_req:
                    raise ChainError(f"contact-ref: fee={fee_req} iskier wymagane dla {op_c}")
            if tx.type == TX_RANK_UP:
                # zakupy w MEMPOOLU też liczą się do bazy ceny (kolejność = nonce!)
                now_m = int(time.time())          # mempool = polityka lokalna (zegar OK)
                virtual_r = {w: dict(v) for w, v in self.ranks.items()}
                for t in self.mempool:
                    if t.type == TX_RANK_UP:
                        try:
                            rk_t, _a_t, ren_t = rks.validate_rank_payload(
                                t.payload, virtual_r, t.sender, now_ts=now_m)
                            rks.apply_rank(virtual_r, rk_t, 0, t.sender, ts=now_m, renew=ren_t)
                        except rks.RankError:
                            continue
                try:
                    _rn, amt_req, renew_m = rks.validate_rank_payload(
                        tx.payload, virtual_r, tx.sender, now_ts=now_m)
                except rks.RankError as e:
                    raise ChainError(f"ranga: {e}") from None
                if tx.amount != amt_req:
                    if renew_m:
                        raise ChainError(f"ranga: przedłużenie = pełna cena {amt_req} iskier (D51)")
                    raise ChainError(f"ranga: wymagana dopłata różnicy {amt_req} iskier "
                                     f"(upgrade = nowa cena − aktualna)")
            if tx.type == TX_DONATE:
                try:                                       # datek WYŁĄCZNIE do skarbca ownera (D50)
                    don.validate_donate(tx, self.treasury)
                except don.DonateError as e:
                    raise ChainError(f"donate: {e}") from None
            if tx.type == TX_POU_ATTEST:
                # dziennik obecności (D58): okno rezerwuje też MEMPOOL (1 wpis/okno);
                # ref-czas w mempoolu = zegar lokalny (polityka), w bloku = timestamp
                now_p = int(time.time())
                winq = []
                for t in self.mempool:
                    if t.type == TX_POU_ATTEST and t.sender == tx.sender:
                        try:
                            winq.append(pou.parse_payload(t.payload)["window"])
                        except pou.PouError:
                            continue
                try:
                    win_m = pou.parse_payload(tx.payload)["window"]
                    req_m = pou.draw_witnesses(self.pou, self.tip().hash(), win_m, tx.sender)
                    pou.validate_pou_payload(tx.payload, self.pou, tx.sender,
                                             now_ts=now_p, mempool_windows=winq,
                                             required=req_m)      # D59: ring z łańcucha
                except pou.PouError as e:
                    raise ChainError(f"pou: {e}") from None
                if tx.amount != pou.POU_FEE_ISKRY:
                    raise ChainError(f"pou: fee = dokładnie {pou.POU_FEE_ISKRY} iskier "
                                     "(antyspam; ⚠️ ROBOCZA — fnx_spec §12/P5)")
            if tx.type == TX_VOTE_EVT:
                # urna (D60): dedup vs chain ∪ mempool (jak usernames) + brama VOTER
                now_v = int(time.time())           # mempool = polityka lokalna (zegar OK)
                virtual_v = {t: dict(m) for t, m in self.votes.items()}
                for t in self.mempool:
                    if t.type == TX_VOTE_EVT:
                        try:
                            pv = vevt.parse_payload(t.payload)
                            virtual_v.setdefault(pv["topic"], {})[t.sender] = pv["choice"]
                        except vevt.VoteError:
                            continue
                try:
                    vevt.validate_vote_payload(tx.payload, virtual_v, tx.sender)
                except vevt.VoteError as e:
                    raise ChainError(f"vote: {e}") from None
                if tx.amount != vevt.VOTE_FEE_ISKRY:
                    raise ChainError(f"vote: fee = dokładnie {vevt.VOTE_FEE_ISKRY} iskier "
                                     "(antyspam; ⚠️ ROBOCZA — fnx_spec §12/P5)")
                if not pou.pou_status(self.pou.get(tx.sender), now_v)["voter"]:
                    raise ChainError("vote: głos tylko dla VOTER (30 dni PoU, pokrycie ≥80% "
                                     "dni, żywy ≤72 h — legitymacja z ostatniego znanego "
                                     "rejestru; mempool może ją przeliczyć nowszym blokiem)")
            if tx.type == TX_SHIELD:
                try:
                    if txh.payload_v(tx.payload) == 1:
                        outs = txr.validate_shield_payload(tx.payload)
                        if len(outs) != 1:
                            raise ChainError("shield v1: DOKŁADNIE 1 wyjście "
                                             "(hardening anty-inflacyjny; wiele → v2)")
                    else:                                    # v2: C związane ze spaleniem
                        outs = txh.validate_shield2(tx.payload, tx.amount)
                    for o in outs:
                        if o["sp"] in self.pool:
                            raise ChainError("shield: output już w poolu")
                except txr.TxRingError as e:
                    raise ChainError(f"shield: {e}") from None
                except txh.TxHiddenError as e:
                    raise ChainError(f"shield v2: {e}") from None
            if tx.amount <= 0:
                raise ChainError("amount musi być > 0")
            if not tx.verify_signature():
                raise ChainError("podpis tx nieprawidłowy / klucze≠sender")
            # nonce spójny Z MEMPOOLEM: łańcuch + już oczekujące tx-y nadawcy
            # (inaczej dwa przelewy przed kopnięciem bloku miałyby ten sam nonce/txid —
            #  pierwszy depozyt giełdowy ten test zdemaskował: ledger zmieniony,
            #  nie test — protokół powinien się zachowywać jak Ethereum).
            exp_nonce = self.nonces.get(tx.sender, 0) + \
                sum(1 for t in self.mempool if t.sender == tx.sender)
            if tx.nonce != exp_nonce:
                raise ChainError("zły account nonce (replay/double-spend)")
            if tx.txid() in self.seen_tx or any(t.txid() == tx.txid() for t in self.mempool):
                raise ChainError("tx już widziany")
            _, _, fee_total = fee_split(tx.amount)
            if self.balance_of(tx.sender) < tx.amount + fee_total:
                raise ChainError("brak środków (amount+fee)")
            if len(self.mempool) >= MEMPOOL_CAP:
                raise ChainError("mempool pełny")
            self.mempool.append(tx)

    # ---------------------------------------------------------------- szablon
    def _miner_fees_of(self, txs: list) -> int:
        """Część ownerska fee idąca do KOPACZA bloku (D39). ID_DECLARE pomijane
        (anty-squatting → skarbiec). Walidator liczy to samo deterministycznie."""
        total = 0
        for t in txs:
            try:
                if t.type == TX_ID_DECLARE:
                    continue
                if t.type == TX_RING:
                    if txh.payload_v(t.payload) == 1:
                        fee_v = int(txr.parse_payload(t.payload)["fee"])
                    else:                                # v2: parse_payload wymaga v=1!
                        fee_v = int(txh.parse_ring2(t.payload)["fee"])
                    total += fee_split(fee_v)[1]
                elif t.type == TX_UNSHIELD:
                    total += fee_split(int(txh.parse_unshield2(t.payload)["fee"]))[1]
                elif t.type in (TX_TRANSFER, TX_SHIELD):
                    total += fee_split(t.amount)[1]
                # TX_COINBASE nie płaci fee (sam jest nagrodą)
            except (txr.TxRingError, txh.TxHiddenError, KeyError, ValueError, TypeError):
                continue
        return total

    def _filt_mempool_pou(self, txs: list) -> list:
        """Szablon bloku: tx-y PoU liczone od razu przeciw ringowi z tip.hash()
        (jak w add_tx). Łańcuch ruszył po dodaniu tx? ring się zmienił → tx odpada
        TU, zamiast budować nieważny blok (D59). Inne typy nietknięte."""
        out: list = []
        winq: dict[str, list] = {}
        now_t = int(time.time())
        for t in txs:
            if t.type != TX_POU_ATTEST:
                out.append(t)
                continue
            try:
                win = pou.parse_payload(t.payload)["window"]
                req = pou.draw_witnesses(self.pou, self.tip().hash(), win, t.sender)
                pou.validate_pou_payload(t.payload, self.pou, t.sender, now_ts=now_t,
                                         mempool_windows=tuple(winq.get(t.sender, [])),
                                         required=req)
            except pou.PouError:
                continue
            winq.setdefault(t.sender, []).append(win)
            out.append(t)
        return out

    def block_template(self, miner_wallet: str, zbits: int | None = None) -> Block:
        with self.lock:
            z = self.required_zbits() if zbits is None else zbits
            slice_txs = self._filt_mempool_pou(self.mempool[:MAX_BLOCK_TXS])
            cb = Tx(type=TX_COINBASE, sender=COINBASE_SENDER,
                    recipient=miner_wallet,
                    amount=BLOCK_REWARD + self._miner_fees_of(slice_txs))   # D39
            txs = [cb] + slice_txs
            # D62: kamień milowy airdropu wisi w powietrzu? kopacz wychwytuje
            # otwarty strzał (odbiorca+kwota = matematyka z prev; 1/kamień)
            plan = adrop.plan_airdrop(self.usernames, self.bans, set(self.airdrop_fired),
                                      self.tip().hash(), milestone=self.airdrop_milestone)
            if plan is not None:
                txs = [cb, Tx(type=TX_AIRDROP, sender="", recipient=plan[0],
                              amount=plan[1],
                              payload=adrop.airdrop_payload(self.airdrop_milestone))] + slice_txs
            return Block(prev=self.tip().hash(), height=self.height() + 1,
                         timestamp=int(time.time()), zbits=z,
                         algo=fpow.DEFAULT_ALGO, miner=miner_wallet, txs=txs)

    # ---------------------------------------------------------------- walidacja
    def _validate_economics(self, b: Block, balances: dict, nonces: dict,
                            pool_add: dict | None = None,
                            ki_local: set | None = None,
                            names: dict | None = None,
                            refs: dict | None = None,
                            ranks: dict | None = None,
                            bans: dict | None = None,
                            donations: dict | None = None,
                            pou_reg: dict | None = None,
                            votes: dict | None = None,
                            fired: set | None = None,
                            drops: list | None = None) -> None:
        pool_add = pool_add if pool_add is not None else {}
        ki_local = ki_local if ki_local is not None else set()
        names = names if names is not None else dict(self.usernames)
        refs = refs if refs is not None else dict(self.contact_refs)
        ranks = ranks if ranks is not None else {w: dict(v) for w, v in self.ranks.items()}
        bans = bans if bans is not None else {w: dict(v) for w, v in self.bans.items()}
        donations = donations if donations is not None else dict(self.donations)
        # pou_reg: kopia GŁĘBOKA list okien — apply_pou mutuje "w" w miejscu,
        # a odrzucony blok NIE może zostawić śladu w prawdziwym rejestrze.
        # (UWAGA: nie wolno nazwać tego "pou" — przykryłoby import modułu pou!)
        pou_reg = pou_reg if pou_reg is not None else \
            {w: {"w": list(v.get("w", [])), "last_ts": int(v.get("last_ts", 0))}
             for w, v in self.pou.items()}
        votes = votes if votes is not None else {t: dict(m) for t, m in self.votes.items()}
        fired = fired if fired is not None else set(self.airdrop_fired)
        drops = drops if drops is not None else [dict(d) for d in self.airdrops]
        seen_coinbase = 0
        coinbase_amt = -1                       # sprawdzimy PO pętli (D39: +fee minera)
        miner_fees = 0
        for i, tx in enumerate(b.txs):
            if tx.type not in KNOWN_TX:
                raise ChainError("nieznany typ tx")
            if tx.type == TX_COINBASE:
                seen_coinbase += 1
                if i != 0 or seen_coinbase > 1:
                    raise ChainError("coinbase dokładnie jeden i tylko na [0]")
                if tx.recipient != b.miner:
                    raise ChainError("zły odbiorca coinbase")
                if bevt.is_banned(bans, tx.recipient):
                    raise ChainError("kopacz zbanowany — coinbase do tombstone (D18)")
                coinbase_amt = tx.amount
                balances[tx.recipient] = balances.get(tx.recipient, 0) + tx.amount
                continue
            # ---------------- TX_BAN_EVT op=ban: wydarzenie systemowe k-z-n ----
            # (bez konta/nonce/fee; moc dowodowa = kropka attestorów w payload)
            if tx.type == TX_BAN_EVT:
                try:
                    if bevt.parse_ban_payload(tx.payload).get("op") == "ban":
                        if tx.amount != 0 or tx.sender or tx.sig:
                            raise ChainError("ban-evt: amount=0, sender i sig puste")
                        try:
                            bevt.validate_ban_payload(tx.payload, bans)
                        except bevt.BanEvtError as e:
                            raise ChainError(f"ban-evt: {e}") from None
                        bevt.apply_ban(bans, bevt.parse_ban_payload(tx.payload)["core"],
                                       b.height)
                        continue
                except bevt.BanEvtError as e:
                    raise ChainError(f"ban-evt: {e}") from None
                # op == "unban": spada do ścieżki konta niżej (podpis+nonce+środki)
            # ---------------- TX_AIRDROP: zdarzenie SYSTEMOWE kamienia milowego ----
            # (bez konta/nonce/fee; moc dowodowa = matematyka blake2s(prev‖kamień), D62)
            if tx.type == TX_AIRDROP:
                if tx.sender or tx.sig:
                    raise ChainError("airdrop: zdarzenie systemowe — sender i sig puste")
                try:
                    adrop.validate_airdrop_tx(tx.amount, tx.recipient, tx.payload,
                                              names, bans, fired, b.prev,
                                              milestone=self.airdrop_milestone)
                except adrop.AirdropError as e:
                    raise ChainError(f"airdrop: {e}") from None
                balances[tx.recipient] = balances.get(tx.recipient, 0) + tx.amount
                fired.add(self.airdrop_milestone)
                drops.append({"milestone": self.airdrop_milestone,
                              "recipient": tx.recipient, "amount": tx.amount,
                              "height": b.height, "prev": b.prev})
                continue
            # ---------------- TX_RING: pool → pool, bez konta ----------------
            if tx.type == TX_RING:
                if tx.amount != 0 or tx.sender:
                    raise ChainError("ring: amount=0 i sender pusty")

                def _lookup(sp: str) -> int | None:
                    if sp in self.pool:
                        return self.pool[sp].get("amt")      # wpis v2 → None (v1≠v2, D38)
                    if sp in pool_add:
                        return pool_add[sp].get("amt")
                    return None

                def _lookup_c(sp: str) -> dict | None:
                    e = self.pool.get(sp)
                    if e is not None:
                        return e if "C" in e else None
                    e2 = pool_add.get(sp)
                    if e2 is not None:
                        return e2 if "C" in e2 else None
                    return None
                try:
                    if txh.payload_v(tx.payload) == 1:
                        payload = txr.parse_payload(tx.payload)
                        kis = txr.validate_ring_tx(payload, _lookup)
                        new_outs = [{"ep": o["ep"], "amt": o["amt"], "sp": o["sp"]}
                                    for o in txr.ring_outputs(payload)]
                    else:                                    # v2: pełna mgła (3b, D38)
                        payload = txh.parse_ring2(tx.payload)
                        kis = cx.verify_hidden_tx(payload, _lookup_c)
                        new_outs = [{**o} for o in txh.ring2_outputs(payload)]
                except txr.TxRingError as e:
                    raise ChainError(f"ring: {e}") from None
                except (cx.ClsagError, txh.TxHiddenError) as e:
                    raise ChainError(f"ring v2: {e}") from None
                for ki in kis:
                    if ki in self.key_images or ki in ki_local:
                        raise ChainError("ring: key image już użyty (double-spend)")
                ki_local.update(kis)
                for o in new_outs:
                    if o["sp"] in self.pool or o["sp"] in pool_add:
                        raise ChainError("ring: output już istnieje")
                    pool_add[o["sp"]] = {k: v for k, v in o.items() if k != "sp"}
                fee = int(payload["fee"])
                _, owner, _ = fee_split(fee)
                miner_fees += owner                              # D39: fee buduje kopaczy
                # reszta fee (burn + dust z zaokrągleń) nikomu — deflacja
                continue
            # ---------------- TX_UNSHIELD: mgła → konto (kwota Y publiczna) ------
            if tx.type == TX_UNSHIELD:
                if tx.amount != 0 or tx.sender:
                    raise ChainError("unshield: amount=0 i sender pusty (anonimowość)")

                def _lookup_uc(sp: str) -> dict | None:
                    e = self.pool.get(sp)
                    if e is not None:
                        return e if "C" in e else None
                    e2 = pool_add.get(sp)
                    if e2 is not None:
                        return e2 if "C" in e2 else None
                    return None
                try:
                    payload_u = txh.parse_unshield2(tx.payload)
                    kis, to_w, amtu = txh.verify_unshield2(payload_u, _lookup_uc)
                except (cx.ClsagError, txh.TxHiddenError) as e:
                    raise ChainError(f"unshield v2: {e}") from None
                for ki in kis:
                    if ki in self.key_images or ki in ki_local:
                        raise ChainError("unshield: key image już użyty (double-spend)")
                ki_local.update(kis)
                for o in txh.unshield2_outputs(payload_u):      # reszta WRACA do mgły
                    if o["sp"] in self.pool or o["sp"] in pool_add:
                        raise ChainError("unshield: output już istnieje")
                    pool_add[o["sp"]] = {k: v for k, v in o.items() if k != "sp"}
                balances[to_w] = balances.get(to_w, 0) + amtu   # Y widoczne (z→t jak Zcash)
                _, owner_u, _ = fee_split(int(payload_u["fee"]))
                miner_fees += owner_u                            # D39
                continue
            # tombstone: zbanowany wallet jest martwy dla wszystkiego POZA wykupem (D18)
            if tx.type != TX_BAN_EVT and bevt.is_banned(bans, tx.sender):
                raise ChainError("sender zbanowany (tombstone) — tx odrzucone; "
                                 "jedyna droga: wykup TX_BAN_EVT op=unban")
            if not tx.verify_signature():
                raise ChainError("podpis tx w bloku nieważny")
            exp = nonces.get(tx.sender, 0)
            if tx.nonce != exp:
                raise ChainError("zły account nonce w bloku")
            burn, owner, total = fee_split(tx.amount)
            if balances.get(tx.sender, 0) < tx.amount + total:
                raise ChainError("double-spend/brak środków w bloku")
            balances[tx.sender] -= tx.amount + total
            if tx.type == TX_SHIELD:
                try:
                    if txh.payload_v(tx.payload) == 1:
                        # hardening (D38): v1 kredytował KAŻDEMU wyjściu pełne tx.amount
                        # → N× pieniądza z 1× spalenia. v1 = DOKŁADNIE 1 wyjście.
                        shield_outs = txr.validate_shield_payload(tx.payload)
                        if len(shield_outs) != 1:
                            raise ChainError("shield v1: DOKŁADNIE 1 wyjście "
                                             "(hardening anty-inflacyjny; wiele → v2)")
                        for o in shield_outs:
                            if o["sp"] in self.pool or o["sp"] in pool_add:
                                raise ChainError("shield: output już istnieje")
                            pool_add[o["sp"]] = {"ep": o["ep"], "amt": tx.amount}
                    else:                                    # v2: C==commit(amt,r_pub)
                        for sp, entry in txh.shield2_pool_entries(
                                txh.validate_shield2(tx.payload, tx.amount)).items():
                            if sp in self.pool or sp in pool_add:
                                raise ChainError("shield v2: output już istnieje")
                            pool_add[sp] = entry
                except txr.TxRingError as e:
                    raise ChainError(f"shield: {e}") from None
                except txh.TxHiddenError as e:
                    raise ChainError(f"shield v2: {e}") from None
                # shield: NIE kredytujemy konta odbiorcy — moneta idzie do poola (stealth)
            elif tx.type == TX_ID_DECLARE:
                try:
                    op, name, _avatar, fee_req = uname.validate_username_payload(
                        tx.payload, names, tx.sender)
                except uname.UsernameError as e:
                    raise ChainError(f"username: {e}") from None
                if tx.amount != fee_req:
                    raise ChainError(f"username: fee={fee_req} iskier wymagane dla {op}")
                uname.apply_username(names, op, name, tx.sender)
                # declare: NIE kredytujemy nikogo — fee idzie burn+skarbiec (anty-squatting)
            elif tx.type == TX_CONTACT_REF:
                try:
                    op_c, addr_c, fee_req = cref.validate_contact_payload(tx.payload, tx.sender)
                except cref.ContactRefError as e:
                    raise ChainError(f"contact-ref: {e}") from None
                if tx.amount != fee_req:
                    raise ChainError(f"contact-ref: fee={fee_req} iskier wymagane dla {op_c}")
                cref.apply_contact_ref(refs, op_c, addr_c, tx.sender)
                # ref: NIE kredytujemy nikogo — tabliczka jest jawna, fee → skarbiec
            elif tx.type == TX_RANK_UP:
                try:                                       # czas z BLOKU — konsensus deterministyczny
                    rank_w, amt_req, renew_w = rks.validate_rank_payload(
                        tx.payload, ranks, tx.sender, now_ts=b.timestamp)
                except rks.RankError as e:
                    raise ChainError(f"ranga: {e}") from None
                if tx.amount != amt_req:
                    raise ChainError(f"ranga: wymagana dopłata różnicy {amt_req} iskier")
                rks.apply_rank(ranks, rank_w, b.height, tx.sender, ts=b.timestamp, renew=renew_w)
                # ranga: NIE kredytujemy nikogo — prawo do range od wysokości b.height+6,
                # ważność do b.timestamp+30d (D51); renew dokłada do stosu (≤60d)
            elif tx.type == TX_BAN_EVT:                        # op == "unban" (płaci zbanowany)
                try:
                    bevt.validate_ban_payload(tx.payload, bans, sender=tx.sender)
                except bevt.BanEvtError as e:
                    raise ChainError(f"ban-evt: {e}") from None
                if tx.amount != bevt.UNBAN_FEE_ISKRY:
                    raise ChainError(f"ban-evt: wykup = dokładnie {bevt.UNBAN_FEE_ISKRY} iskier")
                bevt.apply_unban(bans, tx.sender, b.height)
                balances[self.treasury] = balances.get(self.treasury, 0) + tx.amount
                # wykup CAŁY do skarbca (D30); ppm-owner niżej też skarbiec (usługa rejestru)
            elif tx.type == TX_DONATE:                           # datek do skarbca ownera (D50)
                try:
                    don.validate_donate(tx, self.treasury)
                except don.DonateError as e:
                    raise ChainError(f"donate: {e}") from None
                don.apply_donate(donations, tx.sender, tx.amount)
                balances[self.treasury] = balances.get(self.treasury, 0) + tx.amount
                # CAŁY amount do skarbca (D50: „100% dla ownera"); fee ownerskie też niżej
            elif tx.type == TX_POU_ATTEST:                       # dziennik obecności (D58)
                try:                       # czas + RING z b.prev (seed): deterministyczny replay (D59)
                    win_p = pou.parse_payload(tx.payload)["window"]
                    req_b = pou.draw_witnesses(pou_reg, b.prev, win_p, tx.sender)
                    win_p = pou.validate_pou_payload(tx.payload, pou_reg, tx.sender,
                                                     now_ts=b.timestamp, required=req_b)
                except pou.PouError as e:
                    raise ChainError(f"pou: {e}") from None
                if tx.amount != pou.POU_FEE_ISKRY:
                    raise ChainError(f"pou: fee = dokładnie {pou.POU_FEE_ISKRY} iskier "
                                     "(antyspam; ⚠️ ROBOCZA — fnx_spec §12/P5)")
                pou.apply_pou(pou_reg, tx.sender, win_p, b.timestamp)
                # attest: NIE kredytujemy nikogo — usługa rejestru; ppm-owner → skarbiec
            elif tx.type == TX_VOTE_EVT:                         # urna dla VOTER (D60)
                try:
                    tp_v, ch_v = vevt.validate_vote_payload(tx.payload, votes, tx.sender)
                except vevt.VoteError as e:
                    raise ChainError(f"vote: {e}") from None
                if tx.amount != vevt.VOTE_FEE_ISKRY:
                    raise ChainError(f"vote: fee = dokładnie {vevt.VOTE_FEE_ISKRY} iskier")
                # brama z BLOKU: VOTER liczony z rejestru PoU i b.timestamp (replay bit-w-bit)
                if not pou.pou_status(pou_reg.get(tx.sender), b.timestamp)["voter"]:
                    raise ChainError("vote: głos tylko dla VOTER (30 dni PoU ≥80% dni, "
                                     "żywy ≤72 h w chwili bloku — fnx_spec §6/§13)")
                vevt.apply_vote(votes, tp_v, tx.sender, ch_v)
                # głos: NIE kredytujemy nikogo — usługa rejestru; ppm-owner → skarbiec
            else:
                balances[tx.recipient] = balances.get(tx.recipient, 0) + tx.amount
            if tx.type in (TX_ID_DECLARE, TX_CONTACT_REF, TX_RANK_UP, TX_BAN_EVT, TX_DONATE,
                           TX_POU_ATTEST, TX_VOTE_EVT):
                # D39/D30/D50: skarbiec finansuje się z usług rejestru i datków
                # (nie z transferów/kopania)
                balances[self.treasury] = balances.get(self.treasury, 0) + owner
            else:
                miner_fees += owner                              # D39: fee buduje kopaczy
            # burn: NIGDZIE nie zapisujemy — deflacja to jest absolutny brak
            nonces[tx.sender] = exp + 1
        # ---------------- D39: coinbase = nagroda + TYLKO zebrane fee minera --------
        if coinbase_amt != BLOCK_REWARD + miner_fees:
            raise ChainError(f"coinbase {coinbase_amt} ≠ BLOCK_REWARD+fee minera "
                             f"{BLOCK_REWARD + miner_fees} (D39)")

    def validate_block(self, b: Block) -> None:
        if b.height != self.height() + 1 or b.prev != self.tip().hash():
            raise ChainError("prev/height nie pasuje do głowy")
        if not fpow.verify(b.algo, b.pow_preimage(b.nonce), b.zbits):
            raise ChainError("PoW nieważny")
        if abs(int(time.time()) - b.timestamp) > 4 * 3600:
            raise ChainError("timestamp poza oknem ±4h (zegary dryfują — okno szerokie)")
        if len(b.txs) > MAX_BLOCK_TXS + 1:
            raise ChainError("za dużo tx")
        balances = dict(self.balances)
        nonces = dict(self.nonces)
        self._validate_economics(b, balances, nonces)

    def apply_block(self, b: Block) -> None:
        with self.lock:
            balances = dict(self.balances)
            nonces = dict(self.nonces)
            pool_add: dict = {}
            ki_local: set = set()
            names = dict(self.usernames)
            refs = dict(self.contact_refs)
            ranks = {w: dict(v) for w, v in self.ranks.items()}
            bans = {w: dict(v) for w, v in self.bans.items()}
            donations = dict(self.donations)
            pou_reg = {w: {"w": list(v.get("w", [])), "last_ts": int(v.get("last_ts", 0))}
                       for w, v in self.pou.items()}
            votes = {t: dict(m) for t, m in self.votes.items()}
            fired = set(self.airdrop_fired)
            drops = [dict(d) for d in self.airdrops]
            self.validate_block(b)
            self._validate_economics(b, balances, nonces, pool_add, ki_local, names,
                                     refs, ranks, bans, donations, pou_reg, votes,
                                     fired, drops)
            self.balances, self.nonces = balances, nonces
            self.pool.update(pool_add)
            self.key_images |= ki_local
            self.usernames = names
            self.contact_refs = refs
            self.ranks = ranks
            self.bans = bans
            self.donations = donations
            self.pou = pou_reg
            self.votes = votes
            self.airdrop_fired = fired
            self.airdrops = drops
            self.chain.append(b)
            for tx in b.txs[1:]:
                self.seen_tx.add(tx.txid())
                self.mempool = [t for t in self.mempool if t.txid() != tx.txid()]
            # mempool: tx-y świeżo zbanowanych walletów odpadają (tombstone, D18)
            if any(e.get("active") for e in self.bans.values()):
                self.mempool = [t for t in self.mempool
                                if not bevt.is_banned(self.bans, t.sender)]

    def adopt_chain(self, blocks: list[Block]) -> bool:
        """Fork-choice: dłuższy WAŻNY łańcuch wygrywa; przy równej długości —
        deterministyczny remis: MNIEJSZY hash głowy wygrywa globalnie (zbieżność).
        Zwraca True przy przejęciu."""
        with self.lock:
            if not blocks or blocks[0].hash() != self.chain[0].hash():
                raise ChainError("obcy genesis (inna sieć!)")
            if len(blocks) < len(self.chain):
                return False
            if len(blocks) == len(self.chain) and blocks[-1].hash() >= self.tip().hash():
                return False
            other = Ledger(self.treasury, airdrop_milestone=self.airdrop_milestone)
            for b in blocks[1:]:
                other.apply_block(b)       # wszystko musi się złożyć od zera
            if len(other.chain) < len(self.chain):
                return False
            if len(other.chain) == len(self.chain) and \
                    other.tip().hash() >= self.tip().hash():
                return False
            self.chain, self.balances, self.nonces = other.chain, other.balances, other.nonces
            self.pool, self.key_images = other.pool, other.key_images
            self.usernames = other.usernames
            self.contact_refs, self.ranks = other.contact_refs, other.ranks
            self.bans = other.bans                                      # tombstone też (D18)
            self.donations = other.donations                            # licznik datków też (D50)
            self.pou = other.pou                                        # dziennik obecności (D58)
            self.votes = other.votes                                    # księga głosów (D60)
            self.airdrop_fired = other.airdrop_fired                    # kamienie też (D62)
            self.airdrops = other.airdrops
            self.mempool = [t for t in self.mempool if t.txid() not in other.seen_tx]
            self.seen_tx |= other.seen_tx
            return True

    # ---------------------------------------------------------------- snapshot
    def snapshot(self) -> dict:
        with self.lock:
            return {"height": self.height(), "tip": self.tip().hash(),
                    "treasury": self.treasury,
                    "balances": dict(self.balances), "nonces": dict(self.nonces),
                    "pool_size": len(self.pool), "key_images": len(self.key_images),
                    "pool": dict(self.pool), "usernames": dict(self.usernames),
                    "donations": dict(self.donations),
                    "pou": {w: {"w": list(v.get("w", [])),
                                "last_ts": int(v.get("last_ts", 0))}
                            for w, v in self.pou.items()},              # D58
                    "votes": {t: dict(m) for t, m in self.votes.items()},  # D60
                    "airdrops": [dict(d) for d in self.airdrops],
                    "airdrop_fired": sorted(self.airdrop_fired),            # D62
                    "mempool": [t.to_dict() for t in self.mempool]}

    # ---------------------------------------------------------------- chain.dat
    def save_chain(self, path: str) -> int:
        """Zrzut CAŁEGO łańcucha na dysk (P6 → D42). Format: b"FCD1" +
        blake2s(canon(payload)) + kanoniczny JSON {"v":1, "blocks":[…]}.
        Atomowo: tmp + fsync + os.replace, 0600 (jak wszystkie nasze pliki).
        Zwraca liczbę bajtów zapisanych."""
        with self.lock:
            payload = {"v": 1, "blocks": [b.to_dict() for b in self.chain]}
        blob = ccanon(payload)
        raw = CHAIN_DAT_MAGIC + bytes.fromhex(ch32(blob)) + blob
        # Unikalny tmp: dwa zapisy (flush co 60 s i stop()) nie dzielą jednego
        # pliku .tmp — inaczej wolniejszy pisarz ucina nowszy zrzut w połowie.
        tmp = f"{path}.{_os.getpid()}.{threading.get_ident()}.tmp"
        try:
            fd = _os.open(tmp, _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o600)
            with _os.fdopen(fd, "wb") as f:
                f.write(raw)
                f.flush()
                _os.fsync(f.fileno())
            _os.replace(tmp, path)
        except BaseException:
            try:
                _os.unlink(tmp)
            except OSError:
                pass
            raise
        _os.chmod(path, 0o600)
        return len(raw)

    @classmethod
    def load_chain(cls, path: str, treasury: str = TREASURY_WALLET_DEV) -> "Ledger":
        """Wczytaj chain.dat ZEROZUFANIOWO (plik to NIE zaufany dysk — to OBCRY
        łańcuch jak z sieci): (1) magia + blake2s pilnują bajtów (wykrycie
        uszkodzenia jest NATYCHMIAST, nie po minutach replayu); (2) genesis
        musi być nasz; (3) KAŻDY blok przechodzi apply_block od zera — PoW,
        linki, ekonomia D39, key-images, range-proofy. Podmiana salda w pliku
        = błąd walidacji, nigdy „fałszywy start"."""
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except OSError as e:
            raise ChainError(f"chain.dat nieczytelny: {e}") from None
        if not raw.startswith(CHAIN_DAT_MAGIC):
            raise ChainError("chain.dat: zła magia (to nie nasz zrzut)")
        digest, blob = raw[4:36], raw[36:]
        if ch32(blob) != digest.hex():
            raise ChainError("chain.dat: suma kontrolna ≠ (plik nadpisany/ucięty)")
        try:
            payload = _json.loads(blob)
        except ValueError as e:
            raise ChainError(f"chain.dat: zepsuty JSON: {e}") from None
        if not isinstance(payload, dict) or payload.get("v") != 1 or \
                not isinstance(payload.get("blocks"), list) or not payload["blocks"]:
            raise ChainError("chain.dat: zły format")
        L = cls(treasury)
        try:
            b0 = Block.from_dict(payload["blocks"][0])
        except Exception as e:
            raise ChainError(f"chain.dat: genesis nieczytelny: {e}") from None
        if b0.hash() != L.chain[0].hash():
            raise ChainError("chain.dat: obcy genesis (inna sieć!)")
        for d in payload["blocks"][1:]:
            L.apply_block(Block.from_dict(d))     # pełny konsensus, jak adopt_chain
        return L


def round_log2(x: float) -> int:
    import math
    return int(round(math.log2(x))) if x > 0 else 0


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
    from core.identity import Identity
    from chain.miner import mine

    print("chain/ledger.py — selftest: 3 kopacze, wspólny łańcuch, fee D15\n")
    TRE = TREASURY_WALLET_DEV
    L1, L2, L3 = Ledger(TRE), Ledger(TRE), Ledger(TRE)
    assert L1.tip().hash() == L2.tip().hash() == L3.tip().hash(), "jeden genesis"
    print("  [OK] 1. identyczny genesis na 3 ledgerach (jedna sieć)")

    ala = Identity.generate("ala_kopacz")
    bob = Identity.generate("bob_kopacz")

    # ala kopie blok i wszyscy go przyjmują
    tmpl = L1.block_template(ala.wallet, zbits=4)
    won = mine(tmpl, max_tries=200_000)
    assert won is not None
    h1 = won.hash()
    for L in (L1, L2, L3):
        L.apply_block(won)
    assert L2.balance_of(ala.wallet) == BLOCK_REWARD
    print(f"  [OK] 2. blok wykopany i zaakceptowany na 3 ledgerach (h={h1[:12]}…)")

    # transfer 1 FNX; fee dokładnie 0.001% burn + 0.055% KOPACZOWI bloku (D15/D39)
    tx = Tx.build_signed(TX_TRANSFER, ala, bob.wallet, 1 * ISKRA, nonce=0)
    L1.add_tx(tx)
    burn, owner, total = fee_split(1 * ISKRA)
    assert (burn, owner) == (1000, 55000), (burn, owner)
    tmpl2 = L1.block_template(ala.wallet, zbits=4)
    won2 = mine(tmpl2, max_tries=400_000)
    assert won2.txs[0].amount == BLOCK_REWARD + owner, \
        "D39: coinbase = BLOCK_REWARD + fee minera (ala kopie = dostaje 0.055%)"
    for L in (L1, L2, L3):
        L.apply_block(won2)
    for L in (L1, L2, L3):
        assert L.balance_of(bob.wallet) == 1 * ISKRA
        assert L.balance_of(TRE) == 0, "skarbiec tylko z ID_DECLARE (D39), nie z transferu"
        assert L.balance_of(ala.wallet) == 2 * BLOCK_REWARD + owner - (1 * ISKRA + total), \
            "ala: 2×nagroda + zwrot fee minera − (kwota + całe fee) = −kwota − sam burn"
    print(f"  [OK] 3. fee split (D39): burn={burn} (znika), kopacz dostaje {owner} w coinbase")
    print("  [OK]    salda identyczne na wszystkich 3 ledgerach po 2 blokach")

    # double-spend tego samego nonce = odrzut
    try:
        L1.add_tx(Tx.build_signed(TX_TRANSFER, ala, bob.wallet, ISKRA, nonce=0))
        raise AssertionError("double-spend przyjęty!")
    except ChainError:
        print("  [OK] 4. double-spend (powtórzony nonce) odrzucony")

    # blok z sfałszowanym coinbase (za dużo) = odrzut
    evil = L1.block_template(ala.wallet, zbits=4)
    evil.txs[0].amount = 999 * ISKRA
    won3 = mine(evil, max_tries=400_000)
    try:
        L1.apply_block(won3)
        raise AssertionError("coinbase-kradzież przyjęta!")
    except ChainError:
        print("  [OK] 5. coinbase 999 FNX odrzucony (limit nagrody)")

    # adopt: krótszy łańcuch nie wygrywa
    assert L1.adopt_chain(L2.chain[:1]) is False
    print("  [OK] 6. fork-choice: krótsza gałąź odrzucona")

    # 7) chain.dat (P6/D42): save → load (replay pełnym konsensusem) → stan identyczny;
    #    plik 0600; flip bajtu → suma; podmiana treasury-fix → ekonomia; śmieci → magia
    import os as _o7, tempfile as _t7
    d7 = _t7.mkdtemp(prefix="fenix-chaindat-")
    p7 = _o7.path.join(d7, "chain.dat")
    n7 = L1.save_chain(p7)
    assert n7 == _o7.path.getsize(p7) and _o7.stat(p7).st_mode & 0o777 == 0o600
    Ld = Ledger.load_chain(p7)
    assert (Ld.height(), Ld.tip().hash()) == (L1.height(), L1.tip().hash())
    assert Ld.balances == L1.balances and Ld.nonces == L1.nonces
    assert Ld.pool == L1.pool and Ld.key_images == L1.key_images
    assert Ld.usernames == L1.usernames, "replay ≠ stan (Rozjazd = krytyczny!)"
    print(f"  [OK] 7. chain.dat: {n7} B zapisane; load = replay konsensusem, stan bit-w-bit")
    raw7 = bytearray(open(p7, "rb").read())
    raw7[-10] ^= 0x01                                   # flip w środku payloadu
    open(p7, "wb").write(bytes(raw7))
    try:
        Ledger.load_chain(p7)
        raise SystemExit("nadpisane chain.dat przeszło!")
    except ChainError as e:
        assert "suma kontrolna" in str(e)
    # złodziej „naprawia" sumę po podmianie bloku (np. coinbase) → walidacja łapie
    import json as _j7
    blob7 = bytes(raw7[36:])
    pay7 = _j7.loads(blob7)
    pay7["blocks"][1]["txs"][0]["amount"] = 999 * 10**8
    blob7b = ccanon(pay7)
    open(p7, "wb").write(b"FCD1" + bytes.fromhex(ch32(blob7b)) + blob7b)
    try:
        Ledger.load_chain(p7)
        raise SystemExit("podmieniony blok z poprawną sumą przeszedł!")
    except ChainError:
        pass
    open(p7, "wb").write("GDYZIE-JESTES-LAŃCUCHU".encode())
    try:
        Ledger.load_chain(p7)
        raise SystemExit("plik-śmieć przeszedł!")
    except ChainError as e:
        assert "magia" in str(e)
    _o7.remove(p7); _o7.rmdir(d7)
    print("  [OK] 8. złodziej z plikiem: flip bajtu ≠ suma; dobra suma ≠ obejście")
    print("           (blok podmieniony odpada na EKONOMII — replay = pełny konsensus)")

    print("\nSELFTEST: PASS ✅  ledger FNX (M5 MVP) trzyma spójność między kopaczami")
