# chain/miner.py — pętla kopania PoW (M5 MVP)
"""
Szuka nonce, dla którego digest nagłówka bloku ≤ target(zbits).
Czysta funkcja — stan sieciowy trzyma chain/ledger.py, wątek node net/fenix_node.py.
"""
from __future__ import annotations

import chain.pow as fpow


def mine(block, *, stop=None, max_tries: int | None = None, on_try=None):
    """Zwraca block z ustawionym block.nonce (Znalezione) albo None.

    block musi mieć: algo, zbits, pow_preimage(nonce)->bytes, nonce (nadpisze).
    stop() -> True przerywa natychmiast (node: nowa głowa łańcucha = szablon do kosza).
    max_tries: twarde ograniczenie prób (testy/dev).
    on_try(n): callback co próbę (GUI/hashrate).
    """
    n = 0
    while True:
        if stop and stop():
            return None
        if fpow.verify(block.algo, block.pow_preimage(n), block.zbits):
            block.nonce = n
            return block
        n += 1
        if on_try:
            on_try(n)
        if max_tries is not None and n >= max_tries:
            return None


if __name__ == "__main__":
    print("chain/miner.py — selftest\n")
    from chain.block import Block

    b = Block(prev="0" * 64, height=7, zbits=6, algo=fpow.DEFAULT_ALGO,
              miner="FNX1miner-test", timestamp=1760000000)
    tries = []
    won = mine(b, on_try=tries.append, max_tries=2_000_000)
    assert won is not None, "PoW zbits=6 powinien podejść szybko"
    assert fpow.verify(b.algo, b.pow_preimage(b.nonce), b.zbits)
    print(f"  [OK] wykopano blok (nonce={b.nonce}, prób={len(tries)}); digest <= target")

    # stop działa natychmiast
    b2 = Block(prev="0" * 64, height=8, zbits=64, algo=fpow.DEFAULT_ALGO,
               miner="x", timestamp=1760000000)
    assert mine(b2, stop=lambda: True) is None
    print("  [OK] stop=True → None (przerwanie pętli bez kopania)")

    print("\nSELFTEST: PASS ✅")
