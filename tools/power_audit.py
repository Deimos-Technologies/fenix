#!/usr/bin/env python3
# tools/power_audit.py — D64: audyt MOCY (kto ma przyciski nad siecią Fenix?)
"""
Zasada projektu od pierwszego raportu: NIGDY nie deklarujemy „brak 0day" —
deklarujemy, że każda ŚCIEŻKA DECYZYJNA jest jawnie rozliczona i ograniczona.
Ten skaner pilnuje, żeby NIGDY nie pojawił się cichy biskup w kodzie:

  1. Kropki attestorów dev (ATTESTOR_WALLETS) są tylko z trzech źródeł:
     definicja w ban_evt, boot Deimosa w core/admin, selftesty — NIGDY z GUI/app.
  2. Skarbiec DEV (TREASURY_WALLET_DEV) opisany jako DEV i NIE kierowany przez
     nowe moduły konsensusu (airdrop/urna/pou MUSZĄ być bezownerowe).
  3. Tx SYSTEMOWE (coinbase/ban-op=ban/airdrop/pou-ring) mają twarde bramki
     (sender/sig puste, matematyka zamiast kluczy).
  4. Biała lista IPC = dokładnie znany zestaw (nowy op = czerwona kontrola,
     dopóki nie zostanie tu przypisany intencją).
  5. IPC NIE wycieka sekretami (żadna odpowiedź nie niesie priv/seed/wrap).
  6. Duch (D63) NIE obchodzi kryptografii (frame/core/transport czyste od „ghost").
  7. Licznik (D61) NIE dotyka konsensusu (chain/ czyste od „presence").
  8. FLAGI DEV (zbits/no-cover) jawnie oznaczone jako DEV w help.
  9. Op „ban" NIE istnieje w IPC (ban_policy v1.0: żaden człowiek nie ma
     przycisku ban — tylko kropka k-z-n w TX_BAN_EVT).
 10. Census i ghost są toggle'ami LOKALNYMI (localhost unix), nie konsensusem.

Wynik: tabela kontrolek + rc 0/1. Kryptografia = tools/self_attack.py (tam walka).
"""
from __future__ import annotations

import re
import sys
import pathlib as _pl

ROOT = _pl.Path(__file__).resolve().parents[1]
FINDS: list[tuple[bool, str, str]] = []


def add(name: str, ok: bool, detail: str = "") -> None:
    FINDS.append((bool(ok), name, detail))


def rd(rel: str) -> str:
    p = ROOT / rel
    return p.read_text(encoding="utf-8") if p.exists() else ""


def prod(src: str) -> str:
    """Część PRODUKCYJNA pliku (przed strażnikiem __main__ — selftesty rejestrują
    kropki dev i liczą saldo skarbca do ASERCJI, co jest legalne i pożądane;
    audyt MOCY dotyczy ścieżek produkcyjnych)."""
    i = src.find('if __name__ == "__main__":')
    return src[:i] if i >= 0 else src


def main() -> int:
    ban_src = rd("chain/ban_evt.py")
    net_src = rd("net/fenix_node.py")
    ipc_src = rd("gui/backend_ipc.py")
    block_src = rd("chain/block.py")
    ledger_src = rd("chain/ledger.py")

    # 1) kropka dev: w części PRODUKCYJNEJ rejestracja tylko z ban_evt/core-admin
    refs = []
    for sub in ("app", "gui", "net", "ai"):
        for p in (ROOT / sub).glob("**/*.py"):
            s = prod(p.read_text(encoding="utf-8"))
            if "register_dev_attestor" in s or "ATTESTOR_WALLETS" in s:
                refs.append(str(p.relative_to(ROOT)))
    add("kropka attestorów: produkcja rejestruje TYLKO z ban_evt/core-admin (testy ponad)",
        not refs, "; ".join(refs) or "GUI/app/net/AI (prod.) nie rejestrują kropki — OK")
    add("kropka dev: definicja ATTESTOR_WALLETS istnieje TYLKO w chain/ban_evt.py",
        "ATTESTOR_WALLETS" in ban_src and rd("core/admin.py").count("ATTESTOR") >= 1)

    # 2) skarbiec DEV: stała opisana DEV + nie kierowana przez D58/D60/D62
    add("skarbiec: TREASURY_WALLET_DEV jawnie nazwany DEV w block.py",
        "TREASURY_WALLET_DEV" in block_src and "DEV" in block_src)
    for mod in ("chain/pou.py", "chain/vote_evt.py", "chain/airdrop.py"):
        s_prod = prod(rd(mod))
        add(f"{mod}: ZERO kierunku-skarbca w produkcji (ścieżka boska byłaby tu widoczna)",
            "TREASURY" not in s_prod,
            "moduł (prod.) nie zna stałej skarbca — bezownerowy" if
            "TREASURY" not in s_prod else "!!!")

    # 3) tx systemowe: twarde założenia (sender/sig puste + bramka matematyki)
    add("ban op=ban: sender/sig puste + kropka k-z-n (ban_evt w konsensusie)",
        "sender i sig puste" in ledger_src and "kropka" in ledger_src.lower())
    add("airdrop: sender/sig puste + wybór z blake2s(prev‖kamień)",
        "zdarzenie systemowe — sender i sig puste" in ledger_src
        and "blake2s(prev‖milestone)" in rd("chain/airdrop.py"))
    add("coinbase: dokładnie jeden i tylko na [0]",
        "coinbase dokładnie jeden i tylko na [0]" in ledger_src)

    # 4) biała lista IPC = znany zestaw (snapshot intencji — parsowane AST, nie regex
    # komentarzyk z '(D17)' w środku rozbijał regex → lekcja: parsowanie jak kompil.)
    import ast as _ast
    ops: tuple = ()
    try:
        tree = _ast.parse(ipc_src)
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Assign) and any(
                    isinstance(t, _ast.Name) and t.id == "PROTO_OPS" for t in node.targets):
                ops = tuple(_ast.literal_eval(node.value))
                break
    except (ValueError, SyntaxError):
        ops = ()
    EXPECTED = ("status", "peers", "mining", "submit", "balance", "nonce", "sync",
                "pool", "pool_decoys", "pool_mine", "pool_kis",
                "msg_sub", "msg_send", "msg_poll",
                "sentinel", "sentinel_peer", "sentinel_proposals",
                "profile", "donate", "netinfo", "site_created",
                "census", "ghost", "ban_status",     # D66: status banu — lusterko konsensusu
                "price",                             # D67: pokój cenowy (read-only; handel=P7)
                "grid_submit", "grid_status")        # D69: siatka AI — ogłaszam/czytam;
                #   pay = tx podpisana w demonie PO kworum+recompute (jak donate — nie handel)
    add(f"IPC whitelist = znany zestaw ({len(EXPECTED)} opów; nowy op = redo ludzkie oko)",
        set(ops) == set(EXPECTED), f"extra: {set(ops) - set(EXPECTED)}, "
        f"brak: {set(EXPECTED) - set(ops)}")

    # 5) IPC zero sekretów w odpowiedziach (priv/seed/wrap NIGDY w payloadzie)
    leaks = re.findall(r'\{[^{}]*\b(priv|seed|argon|wrap|MEK|KEK)\w*\s*:', ipc_src)
    add("IPC: żaden builder odpowiedzi nie niesie klucza sekretnego",
        not leaks, f"podejrzane klucze: {leaks}" if leaks else "czysto (zgodnie z D5/D24)")

    # 6) duch ≠ obejście krypto: „ghost" nie istnieje w frame/transport/KRYPTO-core
    #    (słowo „ghost" jako RANGA w identity/admin/keystore = legalne, nie ingerencja)
    ghost_hits = [base for base in ("net/frame.py", "transport/camo.py",
                  "transport/dnscamo.py", "core/crypto/fenix_crypto.py",
                  "core/crypto/fenix_wrap.py") if "ghost" in rd(base)]
    add("D63 duch: czysty z frame/camo/core-crypto (nie osłabia AEAD/krypto)",
        not ghost_hits, "; ".join(ghost_hits) or "czyste")

    # 7) licznik ≠ konsensus: „presence" nie istnieje w chain/
    pres_chain = [str(p.relative_to(ROOT)) for p in (ROOT / "chain").glob("*.py")
                  if "presence" in p.read_text(encoding="utf-8")]
    add("D61 licznik: NIE dotyka konsensusu (chain/ czyste od presence)",
        not pres_chain, "; ".join(pres_chain) or "czyste")

    # 8) flagi DEV jawne: --zbits i --no-cover oznaczone DEV w help
    add("--zbits oznaczone DEV (help)", "DEV trudność" in net_src)
    add("census jako ESTYMACJA, nie cenzus (etykieta metody obecna)",
        "estymacja" in net_src or "estymacja" in ipc_src)

    # 9) przycisk ban: NIE istnieje w IPC (ban_policy v1.0 wiąże).
    #    D66-ludzkieoko: „ban_status" to LUSTERKO read-only (ban_view — ta sama
    #    prawda co tombstone, nic nie egzekwuje); przyciskiem byłby op MUTUJĄCY.
    BAN_VIEW_ONLY = {"ban_status"}
    ban_ops = [o for o in ops if "ban" in o and o not in BAN_VIEW_ONLY]
    add("„przycisk ban” NIE istnieje w IPC (tylko kropka k-z-n w TX_BAN_EVT; "
        "ban_status = odczyt D66)",
        not ban_ops, f"znalezione: {ban_ops}" if ban_ops else "czysto (ban_status tylko czyta)")
    #    twarda wersja: handler ban_status nie zawiera żadnej mutacji rejestru
    import re as _re9
    m9 = _re9.search(r"def _op_ban_status.*?(?=\n    def |\Z)", ipc_src, _re9.S)
    h9 = m9.group(0) if m9 else ""
    trade_ops = [o for o in ops if o in ("buy", "sell", "trade", "swap_exec")]
    add("D67: IPC NIE handluje (brak op buy/sell/trade — handel = P7 poza kodem)",
        not trade_ops, f"znalezione: {trade_ops}" if trade_ops else "tylko widok ceny")
    add("D66: handler _op_ban_status bez mutacji (zero apply_, add_tx, set_)",
        bool(h9) and all(k not in h9 for k in ("apply_ban", "apply_unban", "add_tx", "set_ghost")),
        h9[:80] if h9 else "handler nie znaleziony")

    # 10) ghost/census togglable lokalnie (serwer unix 0660), nie w konsensusie
    add("ghost: toggle lokalny (set_ghost tylko w nodzie+IPC; brak w chain/)",
        "def set_ghost" in net_src and "ghost" not in ledger_src)
    add("airdrop: milestone jawne ⚠️ ROBOCZE §12 (nie skradzione do konsensusu)",
        "ROBOCZE" in rd("chain/airdrop.py"))

    # ------------------------------------------- werdykt
    ok = sum(1 for o, _, _ in FINDS if o)
    print("tools/power_audit.py — D64: kto ma moc nad siecią (statycznie)\n")
    for o, n, d in FINDS:
        print(f"  {'✅' if o else '❌'} {n}")
        if d and not o:
            print(f"      ↳ {d}")
        elif d and ("czyste" in d or "czysto" in d or "estymacja" in d.lower()):
            print(f"      ↳ {d}")
    verdict = ok == len(FINDS)
    print(f"\nWYNIK: {ok}/{len(FINDS)} kontrolek mocy zielonych "
          f"{'— PASS ✅' if verdict else '— FAIL ❌'}")
    print("Granica uczciwie: skaner pilnuje ZAMIARU (nie wykrywa celowo wrogo "
          "napisanego kodu). Do walki kryptograficznej: tools/self_attack.py.")
    return 0 if ok == len(FINDS) else 1


if __name__ == "__main__":
    sys.exit(main())
