# chain/pow.py — Proof-of-Work FNX: kandydaci + weryfikacja (fnx_spec, D7)
"""
Decyzja D7: PoW CPU-friendly (RandomX-like). fnx_spec każe wybrać w M4/M5
spośród kandydatów — tu są DWAJ za wspólnym interfejsem:

  ALGO 1: argon2-lite — Argon2id (memory-hard; ASIC-resistant przez kosz RAM).
          To ten sam algorytm, który strzeże keystora (jedna biblioteka, zero
          nowych zależności). Parametry KONSENSUSU: 1024 KiB / t=1 / p=1
          (zamrożone w kodzie — zmiana = nowa wersja algorytmu, nie parametr).
  ALGO 2: sha256d     — baseline diagnostyczny (NIE do mainnetu: ASIC-able).

Target = "zbits": liczba początkowych bitów zera w 256-bitowym digescie.
  target(z) = 2^(256-z) - 1;   blok OK gdy int(digest) <= target(z).
Retarget co 144 bloków, clamp ×4/÷4 (log2) — patrz chain/ledger.py.
"""
from __future__ import annotations

import hashlib
import time

from core.keystore import KDFParams, _argon2id  # single source Argon2id w projekcie

ALGO_ARGON_LITE = 1
ALGO_SHA256D = 2
ALGO_NAMES = {ALGO_ARGON_LITE: "argon2-lite", ALGO_SHA256D: "sha256d"}
DEFAULT_ALGO = ALGO_ARGON_LITE

# KONSENSUS: parametry Argon2-lite są częścią protokołu (jak zbits).
ARGON_LITE_PARAMS = KDFParams(m_kib=1024, t=1, p=1)
_ARGON_SALT_DOM = b"fnx-pow-salt/v1"          # separacja domen (keystore ma swoją)


def digest(algo: int, preimage: bytes) -> bytes:
    """32B digest kandydata z pre-image nagłówka (header||nonce)."""
    if algo == ALGO_ARGON_LITE:
        # salt deterministyczny z preimage — PoW musi być odtwarzalny przez każdego
        salt = (_ARGON_SALT_DOM + preimage[:16])[:32].ljust(32, b"\x00")
        return _argon2id(preimage, salt, ARGON_LITE_PARAMS)
    if algo == ALGO_SHA256D:
        return hashlib.sha256(hashlib.sha256(preimage).digest()).digest()
    raise ValueError(f"nieznany PoW algo: {algo}")


def target_from_zbits(zbits: int) -> int:
    if not 0 <= zbits <= 256:
        raise ValueError("zbits poza 0..256")
    return (1 << (256 - zbits)) - 1


def verify(algo: int, preimage: bytes, zbits: int) -> bool:
    return int.from_bytes(digest(algo, preimage), "big") <= target_from_zbits(zbits)


def benchmark(seconds: float = 1.5) -> dict:
    """Ile hashy/s daje ten CPU per kandydat — dane pod decyzję spec (D7/M5)."""
    out = {}
    pre = b"fnx-bench" + bytes(32)
    for algo in (ALGO_ARGON_LITE, ALGO_SHA256D):
        n, t0 = 0, time.time()
        while time.time() - t0 < seconds:
            digest(algo, pre + n.to_bytes(8, "big"))
            n += 1
        out[ALGO_NAMES[algo]] = round(n / (time.time() - t0), 1)
    return out


if __name__ == "__main__":
    print("chain/pow.py — selftest\n")
    # verify: zbits=0 zawsze przechodzi; zbits=8 zwykle nie
    pre0 = b"test-preimage" + (0).to_bytes(8, "big")
    assert verify(ALGO_ARGON_LITE, pre0, 0) is True
    assert digest(ALGO_ARGON_LITE, pre0) != digest(ALGO_SHA256D, pre0), "domenty rozdzielone"
    print("  [OK] verify zbits=0; kandydaci daja rozne digesty (separacja domen)")

    # znajdz nonce dla zbits=6 i udowodnij verify/sztuczka
    n = 0
    while not verify(ALGO_ARGON_LITE, pre0 + n.to_bytes(4, "big"), 6):
        n += 1
    assert verify(ALGO_ARGON_LITE, pre0 + n.to_bytes(4, "big"), 6)
    print(f"  [OK] znaleziono PoW zbits=6 po {n} probach; verify potwierdza")

    rates = benchmark(1.0)
    print(f"  [OK] benchmark (1 s): {rates['argon2-lite']} h/s argon2-lite · "
          f"{rates['sha256d']} h/s sha256d (dane pod D7/M5)")
    print("\nSELFTEST: PASS ✅")
