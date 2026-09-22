# net/presence.py — D61: LICZNIK SIECI (kto online / co rośnie) — estymator gossip
"""
Analogia: przechodnie na korytarzu fabryki z delikatnymi dzwoneczkami u butów.
Co 5 minut każdy zgłasza „jestem" (podpisany dzwonek z kubłem/oknem czasowym);
kto milknie na 10 minut — spada z licznika. Nikt nie składa raportu do centrali
(brak centrali!): każdy szum płynie gossip jak plotka i KAŻDY nod liczy u siebie.

Uczciwie (jak P17/dryf PoU — granice głośno):
  • to ESTYMACJA lokalna, nie cenzus — liczysz tyle, ile sygnałów doszło gossip;
    partycja sieci = widzisz połowę licznika (to cecha, nie bug: brak centrali
    = brak WIELKIEJ PRAWWDY); pokazujemy w GUI z etykietą „≈" i metodą,
  • licznik „zarejestrowanych" = usernames on-chain (żywa, jawna metryka — nie
    anonimowi-gohowie; proxy opisane wprost),
  • „online" = wallet-e node'ów (jeden człowiek może mieć N nodów; liczymy
    sygnały, nie ludzi — jak licznik klaksonów, nie kierowców),
  • tryb ducha (D63): duch NIE ogłasza obecności → nie dzieje się w liczniku
    (jego wolność; inni liczą siebie dalej),
  • anty-spam: sygnał PODPISANY kluczem walletu + dedup per (wallet,kubło);
    obrzucanie sygnałami z N walletów = wyliczysz N walletów, ale każdy z
    prawdziwym kluczem — to niezniszczalne bez captchy i jest jawne.
"""
from __future__ import annotations

import sys
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from chain.block import canon                            # noqa: E402
from core.crypto.fenix_crypto import wallet_address      # noqa: E402

BUCKET_S = 300                     # kubło obecności: 5 min (odświeżasz co <5 min)
FRESH_BUCKETS = 2                  # „online" = sygnał z ostatnich 2 kublów (10 min)
PRES_TTL = 4                       # hopów gossip beacona (widok > sąsiedzi)
MAX_BOOK = 65536                   # anty-pamięć-DoS: sufit walletów w książce


class PresenceError(Exception):
    """Błędy beacona — jedna klasa, komunikaty po polsku."""


def pres_core(wallet: str, bucket: int) -> dict:
    return {"v": 1, "op": "presence", "wallet": wallet, "bucket": bucket}


def _validate_core(core: dict) -> None:
    if not isinstance(core, dict) or core.get("v") != 1 or core.get("op") != "presence":
        raise PresenceError("core: brak v=1/op=presence")
    w = core.get("wallet")
    if not isinstance(w, str) or len(w) != 36 or not w.startswith("FNX1"):
        raise PresenceError("wallet: zły kształt")
    b = core.get("bucket")
    if not isinstance(b, int) or isinstance(b, bool) or b < 0:
        raise PresenceError("bucket ma być int ≥ 0")


def pres_entry(identity, bucket: int) -> dict:
    core = pres_core(identity.wallet, bucket)
    return {"sig_pub": identity.sig_pub_b.hex(), "x_pub": identity.x_pub_b.hex(),
            "sig": identity.sign(canon(core)).hex()}     # sign() zwraca BYTES (jak pou)


def verify_pres(entry: dict, core: dict) -> str | None:
    """Zwraca wallet sygnatariusza (związany z kluczami) albo None przy fałszu."""
    try:
        _validate_core(core)
        sp, xp, sg = entry["sig_pub"], entry["x_pub"], entry["sig"]
        if wallet_address(bytes.fromhex(sp), bytes.fromhex(xp)) != core["wallet"]:
            return None
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(sp)).verify(
            bytes.fromhex(sg), canon(core))
        return core["wallet"]
    except Exception:
        return None


def pres_wire(identity, *, now: float) -> dict:
    """Klatka gossip beacona (json-ready): ttl jak T_MSG; dedup idzie z (wallet,bucket)."""
    bucket = int(now // BUCKET_S)
    return {"v": 1, "ttl": PRES_TTL, "e": pres_entry_full(identity, bucket)}


def parse_wire(raw: bytes | str) -> dict:
    import json
    try:
        p = json.loads(raw)
    except (ValueError, TypeError):
        raise PresenceError("wire: niepoprawny JSON") from None
    if not isinstance(p, dict) or p.get("v") != 1 or not isinstance(p.get("e"), dict):
        raise PresenceError("wire: brak v=1/e")
    ttl = p.get("ttl")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or not (0 <= ttl <= PRES_TTL):
        raise PresenceError(f"ttl poza 0..{PRES_TTL}")
    return p


class PresenceBook:
    """Książka dzwoneczków: wallet -> ostatni kubło. Estymacja ONLINE = wpisy
    z kubłem >= aktualne-1 (10 min świeżości). Nic poza RAM — amnezja jak reszta."""

    def __init__(self) -> None:
        self._last: dict[str, int] = {}

    def note(self, entry: dict, *, now: float) -> bool:
        """True gdy ŚWIEŻY (nowy wallet albo nowszy kubło tego walleta; fałsz czasem
        lub podpisem = False) — dispatch używa do decyzji o dalszym gossipie (dedup)."""
        bucket_now = int(now // BUCKET_S)
        # core źródła prawdy o kube (beacon niesie bucket W PODPISIE — odtwarzamy z e)
        b = _entry_bucket(entry)
        if b is None:
            return False
        if b > bucket_now + 1 or b < bucket_now - FRESH_BUCKETS - 8:
            return False                            # z przyszłości albo przedpotopowy
        core = pres_core_from_entry(entry, b)
        if core is None:
            return False
        w = verify_pres(entry, core)
        if w is None:
            return False
        if len(self._last) >= MAX_BOOK and w not in self._last:
            return False                            # pełna książka: nowych nie wmawiamy
        if self._last.get(w, -1) >= b:
            return False                            # dedup: znany albo starszy
        self._last[w] = b
        return True

    def online(self, *, now: float) -> int:
        cur = int(now // BUCKET_S)
        return sum(1 for b in self._last.values() if b >= cur - FRESH_BUCKETS + 1)

    def containers(self, *, now: float) -> dict:
        cur = int(now // BUCKET_S)
        return {"online_estimate": self.online(now=now),
                "known_total": len(self._last),
                "fresh_buckets": FRESH_BUCKETS, "bucket_s": BUCKET_S,
                "method": "presence-gossip (estymacja lokalna, nie cenzus)"}


def _entry_bucket(entry: dict) -> int | None:
    b = entry.get("bucket")
    if isinstance(b, int) and not isinstance(b, bool) and b >= 0:
        return b
    return None


def pres_core_from_entry(entry: dict, b: int | None = None, **_kw) -> dict | None:
    """Core podpisu = {v,op,wallet,bucket} odtworzone z entry (bucket = część
    podpisywana; entry NIESIE ją obok kluczy jak witness_entry z pou)."""
    sp = entry.get("sig_pub")
    xp = entry.get("x_pub")
    bb = b if b is not None else _entry_bucket(entry)
    if bb is None or not isinstance(sp, str) or not isinstance(xp, str):
        return None
    try:
        w = wallet_address(bytes.fromhex(sp), bytes.fromhex(xp))
    except Exception:
        return None
    return pres_core(w, bb)


def pres_entry_full(identity, bucket: int) -> dict:
    """Entry z kubełem obok (beacon musi nauczyć weryfikatora swojego kubła)."""
    e = pres_entry(identity, bucket)
    e["bucket"] = bucket
    return e


# ---------------------------------------------------------------- selftest
if __name__ == "__main__":
    import time

    print("net/presence.py — selftest: licznik sieci D61 (estymator gossip)\n")
    from core.identity import Identity

    now = time.time()
    b_now = int(now // BUCKET_S)
    ids = [Identity.generate(f"pres_c{i}") for i in range(5)]

    # 1) beacon: podpis wiąże (wallet,kubło); fałsz/podmianka = None
    e1 = pres_entry_full(ids[0], b_now)
    c1 = pres_core_from_entry(e1)
    assert c1 is not None and verify_pres(e1, c1) == ids[0].wallet
    zly = dict(e1, sig=ids[1].sign(canon(pres_core(ids[0].wallet, b_now))))
    assert verify_pres(zly, c1) is None, "podpis cudzym kluczem przeszedł!"
    e_old = pres_entry_full(ids[0], b_now) | {"bucket": b_now - 1}
    # podmianka kubła: sygnał mówi „starszy czas", ale sygnatura była pod (nowy kubło)
    # → core odtworzone Z PODMIENIONEGO kubła już nie pasuje do sygnatury = fałsz
    assert verify_pres(e_old, pres_core_from_entry(e_old)) is None, \
        "podmianka kubła bez przepisania sig!"
    e2b = pres_entry_full(ids[0], b_now - 1)
    assert verify_pres(e2b, pres_core_from_entry(e2b)) == ids[0].wallet
    print("  [OK] 1. beacon: sygnał podpisany pod (wallet,kubło); fałsz/podmianka = martwy")

    # 2) książka: online rośnie sygnałami, dedup po kubłe, gwałt licznika odmówiony
    bk = PresenceBook()
    for i, w in enumerate(ids):
        assert bk.note(pres_entry_full(w, b_now), now=now), f"sygnał {i} odrzucony"
    assert bk.online(now=now) == 5, bk.containers(now=now)
    assert not bk.note(pres_entry_full(ids[0], b_now), now=now), "dedup kubła padł"
    assert bk.online(now=now) == 5
    # nowszy kubło tego samego walleta = świeży update (node żyje dalej)
    assert bk.note(pres_entry_full(ids[0], b_now + 1), now=now + BUCKET_S)
    print("  [OK] 2. książka: 5 dzwoneczków = 5 online; dedup anty-echo; update = żywy")

    # 3) offline: po 10 min ciszy spadasz z licznika (zmiana online/offline płynie sama)
    later = now + 2 * BUCKET_S + 1
    got = bk.containers(now=later)
    assert got["online_estimate"] == 1, got       # tylko id0 odświeżył się (krok 2)
    assert "estymacja" in got["method"]
    print("  [OK] 3. przechodzenie online↔offline: cisza 10 min = znikasz z licznika")

    # 4) anty-spam książki: sufit walletów pilnowany; ~zły kształt entry = cicho False
    assert not bk.note({"sig_pub": "zz", "x_pub": "aa", "sig": "bb", "bucket": b_now},
                       now=now)
    assert not bk.note(pres_entry_full(ids[1], b_now + 7), now=now), "z przyszłości!"
    assert not bk.note(pres_entry_full(ids[1], b_now - 60), now=now), "przedpotopowy!"
    bk2 = PresenceBook()
    bk2._last = {f"FNX1f{i:031d}": b_now for i in range(MAX_BOOK)}
    assert not bk2.note(pres_entry_full(ids[2], b_now), now=now), "sufit nie trzyma"
    print("  [OK] 4. anty-DoS: sufit książki + brudne wejścia = bezpieczne False")

    print("\nSELFTEST: PASS ✅  net/presence.py — licznik online (D61):\n"
          "sygnały podpisane i uględniane co 5 min; cisza 10 min = offline; dedup\n"
          "anty-echo; kubło częścią podpisu; szacunek z etykietą ESTYMACJA, nie cenzus.")
