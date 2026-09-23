# chain/block.py — Tx i Block FNX: format, haszowanie, PoW-check (fnx_spec v0.1)
"""
Model konta (nie UTXO): saldo + nonce per wallet (proste i wystarczające do M5-MVP).
Typy tx w tej wersji: COINBASE (nagroda) i TRANSFER (z fee wg D15).
Rezerwowe typy spec (ID_DECLARE/POU_ATTEST/RANK_UP/BAN_EVT/VOTE_EVT/BLOB_REF/BOND_*)
= stałe niżej, implementujemy je po kolei w M5 — rejestr MA znać kody od dziś.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

ISKRA = 10 ** 8                      # 1 FNX = 10^8 iskier (D15)

# --- typy tx (fnx_spec §tx) ----------------------------------------------------
TX_COINBASE = 0x01
TX_TRANSFER = 0x02
TX_ID_DECLARE = 0x03      # M5 (rejestracja username on-chain)
TX_POU_ATTEST = 0x04      # M5 (PoU — losowe okna, świadkowie)
TX_RANK_UP = 0x05         # M5 (rangi D16)
TX_BAN_EVT = 0x06         # M6/M5 (D18, wpis konsensusu k-z-n)
TX_VOTE_EVT = 0x07
TX_BLOB_REF = 0x08
TX_BOND_LOCK = 0x09
TX_BOND_SLASH = 0x0A
TX_RING = 0x10           # M5b/3a: prywatny transfer pool→pool (ring+stealth; kwoty jawne do 3b/CLSAG)
TX_SHIELD = 0x11         # M5b: konto → pool prywatny (debet jak transfer, wyjście stealth, amt jawny)
TX_UNSHIELD = 0x12       # M5b/3b: mgła → konto (wyjście; kwota Y publiczna jak w Zcash z→t, D38)
TX_CONTACT_REF = 0x13    # M5c: wallet → kontakt FNXS1 (P21, D45; pętla nick→wallet→adres)
TX_DONATE = 0x14         # M5d: dobrowolny datek do skarbca ownera (D50; kwota użytkownika)
TX_AIRDROP = 0x15        # M5e: kamień milowy 1M użytkowników (D62; zdarzenie systemowe)
KNOWN_TX = {TX_COINBASE, TX_TRANSFER, TX_SHIELD, TX_RING, TX_UNSHIELD, TX_ID_DECLARE,
            TX_CONTACT_REF, TX_RANK_UP, TX_BAN_EVT, TX_DONATE,
            TX_POU_ATTEST, TX_VOTE_EVT, TX_AIRDROP}                      # D58/D60/D62

# --- fee wg D15/D39: od każdego transferu 0.001% BURN + 0.055% ---------------
# D15: burn znika na zawsze (deflacja). D39: 0.055% idzie do MINERA bloku
# (górnik zarabia na potwierdzaniu cudzych tx — motywacja kopania); skarbiec
# (D14) dalej finansowany fee z TX_ID_DECLARE (anty-squatting username).
FEE_BURN_PPM = 10        # 0.001%  = 10  ppm   → znika na zawsze (deflacja)
FEE_OWNER_PPM = 550      # 0.055%  = 550 ppm   → adres skarbca (D15)

# --- genesis deterministyczny (identyczny na każdej maszynie = jedna sieć) -----
GENESIS_TS = 1_760_000_000                     # stały znacznik startu sieci FNX
GENESIS_SENDER = "FNX-GENESIS"
COINBASE_SENDER = "FNX-COINBASE"
TREASURY_WALLET_DEV = "FNX1" + "0" * 32        # DEV-skarbiec; M5: zimny multisig ownera (D14/D15)


def canon(d: dict) -> bytes:
    """Kanonizacja JSON — jeden obiekt = jeden ciąg bajtów w całej sieci."""
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


def h32(data: bytes) -> str:
    return hashlib.blake2s(data, digest_size=32).hexdigest()


def fee_split(amount_iskry: int) -> tuple[int, int, int]:
    """(burn, owner, total) — total schodzi z nadawcy, burn nikomu, owner skarbcowi."""
    burn = amount_iskry * FEE_BURN_PPM // 10 ** 6
    owner = amount_iskry * FEE_OWNER_PPM // 10 ** 6
    return burn, owner, burn + owner


@dataclass
class Tx:
    type: int
    sender: str
    recipient: str
    amount: int                      # iskry
    nonce: int = 0                   # licznik tx nadawcy (account nonce)
    sig_pub: str = ""
    x_pub: str = ""
    sig: str = ""
    payload: str = ""                # opcjonalne dane (TX_SHIELD/TX_RING: JSON sterowany typem)

    def core_dict(self) -> dict:
        return {"type": self.type, "sender": self.sender, "recipient": self.recipient,
                "amount": self.amount, "nonce": self.nonce,
                "sig_pub": self.sig_pub, "x_pub": self.x_pub,
                "payload": self.payload}

    def txid(self) -> str:
        return h32(canon(self.core_dict()))

    def to_dict(self) -> dict:
        return {**self.core_dict(), "sig": self.sig}

    @classmethod
    def from_dict(cls, d: dict) -> "Tx":
        return cls(type=int(d["type"]), sender=d["sender"], recipient=d["recipient"],
                   amount=int(d["amount"]), nonce=int(d["nonce"]),
                   sig_pub=d.get("sig_pub", ""), x_pub=d.get("x_pub", ""),
                   sig=d.get("sig", ""), payload=d.get("payload", ""))

    @classmethod
    def build_signed(cls, typ: int, identity, recipient: str, amount: int,
                     nonce: int, payload: str = "") -> "Tx":
        tx = cls(type=typ, sender=identity.wallet, recipient=recipient,
                 amount=amount, nonce=nonce,
                 sig_pub=identity.sig_pub_b.hex(), x_pub=identity.x_pub_b.hex(),
                 payload=payload)
        tx.sig = identity.sign(canon(tx.core_dict())).hex()
        return tx

    def verify_signature(self) -> bool:
        """Podpis musi schodzić z kluczy, których hash = sender-owi (Filar 1)."""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from core.crypto.fenix_crypto import wallet_address
        try:
            if wallet_address(bytes.fromhex(self.sig_pub),
                              bytes.fromhex(self.x_pub)) != self.sender:
                return False
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.sig_pub)).verify(
                bytes.fromhex(self.sig), canon(self.core_dict()))
            return True
        except (ValueError, InvalidSignature):
            return False


@dataclass
class Block:
    ver: int = 1
    prev: str = ""
    height: int = 0
    timestamp: int = 0
    zbits: int = 0
    algo: int = 1                    # chain/pow.py (1=argon2-lite, 2=sha256d)
    miner: str = ""
    nonce: int = 0
    txs: list = field(default_factory=list)

    # --- korzone i hasze ---
    def tx_root(self) -> str:
        hs = [bytes.fromhex(t.txid()) for t in self.txs] or [b"\x00" * 32]
        while len(hs) > 1:
            if len(hs) % 2:
                hs.append(hs[-1])
            hs = [hashlib.blake2s(hs[i] + hs[i + 1], digest_size=32).digest()
                  for i in range(0, len(hs), 2)]
        return hs[0].hex()

    def header_fields(self) -> dict:
        return {"ver": self.ver, "prev": self.prev, "height": self.height,
                "timestamp": self.timestamp, "zbits": self.zbits, "algo": self.algo,
                "miner": self.miner, "tx_root": self.tx_root()}

    def pow_preimage(self, nonce: int) -> bytes:
        return canon({**self.header_fields(), "nonce": nonce})

    def hash(self) -> str:
        return h32(self.pow_preimage(self.nonce))

    def to_dict(self) -> dict:
        return {**self.header_fields(), "nonce": self.nonce,
                "txs": [t.to_dict() for t in self.txs]}

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        return cls(ver=int(d["ver"]), prev=d["prev"], height=int(d["height"]),
                   timestamp=int(d["timestamp"]), zbits=int(d["zbits"]),
                   algo=int(d["algo"]), miner=d["miner"], nonce=int(d["nonce"]),
                   txs=[Tx.from_dict(t) for t in d["txs"]])

    @classmethod
    def genesis(cls, treasury: str) -> "Block":
        cb = Tx(type=TX_COINBASE, sender=GENESIS_SENDER, recipient=treasury, amount=0)
        return cls(prev="0" * 64, height=0, timestamp=GENESIS_TS, zbits=0,
                   algo=1, miner=treasury, nonce=0, txs=[cb])
