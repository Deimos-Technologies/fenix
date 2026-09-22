# tools/full_audit.py — pełny audyt V.001-beta: wszystkie selftesty + kontrole bezpieczeństwa plików
# Wynik: /tmp/fenix_audit.json (czyta go tools/make_report.py → raport PDF)
"""Uruchamia KAŻDY selftest w repo (subprocess, timeout), sprawdza statyczne reguły
bezpieczeństwa (sekrety, exec-bity, gitignore, obecność doków) i liczy statystyki TODO.
Nie ocenia łaskawie: rc!=0 albo brak 'PASS' = FAIL z ogonem logu."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = Path("/tmp/fenix_audit.json")

TESTS = [
    # (obszar, nazwa, komenda, timeout_s)
    ("CORE", "identity.py", ["python3", "-m", "core.identity"], 120),
    ("CORE", "keystore.py (KS1/panic/backoff)", ["python3", "-m", "core.keystore"], 300),
    ("CORE", "crypto/fenix_crypto.py (E2E+Shamir)", ["python3", "-m", "core.crypto.fenix_crypto"], 300),
    ("CORE", "crypto/fenix_wrap.py", ["python3", "-m", "core.crypto.fenix_wrap"], 120),
    ("CORE", "crypto/fnx64.py (D70: tetracja do 10, strumień, dyfuzja, tempo)", ["python3", "core/crypto/fnx64.py"], 300),
    ("CHAIN", "pow.py (PoW argon-lite)", ["python3", "-m", "chain.pow"], 300),
    ("CHAIN", "battery: stealth/ring/amount (M5b 1-3)", ["python3", "chain/stealth.py"], 300),
    ("CHAIN", "ring_sig.py (nadawca)", ["python3", "chain/ring_sig.py"], 300),
    ("CHAIN", "amount_hide.py (kwoty)", ["python3", "chain/amount_hide.py"], 300),
    ("CHAIN", "miner.py", ["python3", "-m", "chain.miner"], 300),
    ("CHAIN", "ledger.py (konsensus)", ["python3", "-m", "chain.ledger"], 300),
    ("CHAIN", "tx_ring.py (pool prywatny E2E)", ["python3", "chain/tx_ring.py"], 600),
    ("CHAIN", "usernames.py (D28 on-chain)", ["python3", "chain/usernames.py"], 300),
    ("NET", "frame.py (AEAD v2/glina)", ["python3", "-m", "net.frame"], 300),
    ("NET", "fenix_node.py (mesh+mining+drut+sentinel P26+discovery D54)", ["python3", "-m", "net.fenix_node"], 900),
    ("TRANSPORT", "camo.py (padding/cover)", ["python3", "-m", "transport.camo"], 300),
    ("TRANSPORT", "dnscamo.py (D33 loopback)", ["python3", "-m", "transport.dnscamo"], 300),
    ("TRANSPORT", "mullvad.py (kill switch)", ["python3", "transport/mullvad.py"], 120),
    ("OS", "spoof.sh --selftest", ["bash", "os/spoof.sh", "--selftest"], 120),
    ("OS", "fenix_panicd.py (D27)", ["python3", "os/fenix_panicd.py"], 300),
    ("OS", "fenix_boot.py (bariera D24)", ["python3", "os/fenix_boot.py"], 300),
    ("OS", "fenix_payload.py (sealed)", ["python3", "os/fenix_payload.py"], 300),
    ("OS", "build_iso.sh --selftest (57)", ["bash", "os/build_iso.sh", "--selftest"], 300),
    ("GUI", "fenix_gui.py (D28/D29 + panic + vpn.env + IPC + Pool + czat E2E)", ["python3", "gui/fenix_gui.py"], 300),
    ("GUI", "panic_button.py (D27 w GUI, hold-2s)", ["python3", "gui/panic_button.py"], 120),
    ("GUI", "backend_ipc.py (most GUI↔demon, E2E + P20: żywe 2 procesy D56)", ["python3", "gui/backend_ipc.py"], 300),
    ("GUI", "pool_panel.py (M7c: TX_RING z GUI, E2E)", ["python3", "gui/pool_panel.py"], 600),
    ("APP", "messenger.py (M4: E2E+TOFU+impersonacja)", ["python3", "-m", "app.messenger"], 120),
    ("CHAIN", "clsag.py (3b rdzeń: ukryte kwoty MLSAG)", ["python3", "chain/clsag.py"], 300),
    ("CHAIN", "tx_hidden.py (konsensus v2 D38: mgła+bramka+migracja)", ["python3", "chain/tx_hidden.py"], 900),
    ("CHAIN", "contact_ref.py (P21/D45: nick→wallet→kontakt on-chain)", ["python3", "chain/contact_ref.py"], 600),
    ("CHAIN", "ranks.py (D46: ranga z konsensusu + D51 wygasanie 30d/renew)", ["python3", "chain/ranks.py"], 600),
    ("CHAIN", "ban_evt.py (D47: tombstone k-z-n 0x06, wykup D30)", ["python3", "chain/ban_evt.py"], 600),
    ("CHAIN", "donate.py (D50: datek skarbcowi 0x14, kwota użytkownika)", ["python3", "chain/donate.py"], 600),
    ("CHAIN", "pou.py (D58: PoU on-chain, TX_POU_ATTEST 0x04, VOTER 30d; D59: ring świadków z chain)", ["python3", "chain/pou.py"], 600),
    ("CHAIN", "vote_evt.py (D60: VOTE_EVT 0x07 — urna tylko dla VOTER)", ["python3", "chain/vote_evt.py"], 600),
    ("CHAIN", "airdrop.py (D62: TX_AIRDROP 0x15, kamień milowy 1M)", ["python3", "chain/airdrop.py"], 600),
    ("NET", "presence.py (D61: licznik online gossip-estymacja)", ["python3", "net/presence.py"], 300),
    ("TOOLS", "power_audit.py (D64: kto ma moc nad siecią)", ["python3", "tools/power_audit.py"], 300),
    ("CHAIN", "badges.py (D52: odznaki chain+local, panel, grafiki)", ["python3", "chain/badges.py"], 900),
    ("CORE", "admin.py (D53: konto Deimos, hasło fabryczne, attestor; D55 boot+wizytówka)", ["python3", "core/admin.py"], 300),
    ("GUI", "settings_admin.py (D55: ONB Deimosa — wymuszona zmiana hasła fabrycznego)", ["python3", "gui/settings_admin.py"], 300),
    ("AI", "ai_sentinel.py (M6: radar fail-open, wniosek→ban E2E)", ["python3", "ai/ai_sentinel.py"], 600),
    ("AI", "fnx_ai.py (D69: siatka obliczeniowa — koperty, kworum, recompute, rate-limit)", ["python3", "ai/fnx_ai.py"], 300),
    ("APP", "exchange.py (giełda+PSC D32)", ["python3", "-m", "app.exchange"], 300),
    ("APP", "fnx_coin.py (D65: FNX-COIN — cena z podaży/aktywności łańcucha, kupno+sprzedaż)", ["python3", "app/fnx_coin.py"], 600),
    ("APP", "xmr_swap.py (D34)", ["python3", "-m", "app.xmr_swap"], 600),
    ("TOOLS", "self_attack.py (red team)", ["python3", "tools/self_attack.py"], 300),
    ("E2E", "real_e2e.py (D68: 3 ŻYWE demony — mesh/kopanie/donate do iskry/"
     "AI-GRID z płatnością/restart z dysku)", ["python3", "tools/real_e2e.py"], 300),
]


def run_one(cmd: list[str], timeout: int) -> tuple[int, float, str]:
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        out = p.stdout + p.stderr
        return p.returncode, time.time() - t0, out
    except subprocess.TimeoutExpired:
        return 124, float(timeout), "TIMEOUT"


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True).stdout.strip()


def static_checks() -> list[dict]:
    checks = []

    def add(name, ok, detail=""):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    p = subprocess.run(["grep", "-rIlE", "^-----BEGIN [A-Z ]*PRIVATE KEY-----", "."],
                       cwd=ROOT, capture_output=True, text=True)
    leaked = [l for l in p.stdout.splitlines() if l and "/.git/" not in l]
    add("zero sekretów PEM w repo", not leaked, "; ".join(leaked))

    gi = (ROOT / ".gitignore").read_text()
    for pat in ("*.key", "secrets/", "*.iso", "__pycache__", "build/"):
        add(f".gitignore: {pat}", pat in gi)

    for f in ("os/spoof.sh", "os/build_iso.sh", "os/verify_iso.sh",
              "os/includes.chroot/usr/local/bin/fenix-vpn",
              "os/includes.chroot/usr/local/bin/fenix-netup",
              "os/includes.chroot/usr/local/bin/fenix-gui",
              "os/live-build/auto/config",
              "os/live-build/config/hooks/live/0100-fenix-hardening.hook.chroot",
              "os/live-build/config/hooks/live/0200-fenix-install.hook.chroot"):
        add(f"exec bit: {f}", os.access(ROOT / f, os.X_OK))

    for d in ("docs/decyzje_architektury.md", "docs/threat_model.md", "docs/ToS.md",
              "docs/fnx_spec.md", "docs/legal/FENIX_Dokument_PL.md",
              "docs/legal/FENIX_Dokument_EN.md", "docs/legal/FENIX_Dokument_RU.md"):
        add(f"docs: {d}", (ROOT / d).exists())

    gui_files = [x for x in (ROOT / "gui").iterdir() if x.name != ".gitkeep"] if (ROOT / "gui").exists() else []
    add("GUI zaimplementowane (M7)", len(gui_files) > 0, "gui/ puste — DOKUMENTOWANE jako luka")

    ai_files = [x for x in (ROOT / "ai").iterdir() if x.name not in (".gitkeep", "__pycache__")] \
        if (ROOT / "ai").exists() else []
    add("AI-Sentry zaimplementowane (M6)", len(ai_files) > 0, "ai/ puste — DOKUMENTOWANE jako luka")

    badge_dir = ROOT / "gui" / "assets" / "badges"
    badge_png = sorted(badge_dir.glob("*.png")) if badge_dir.exists() else []
    add("grafiki odznak (D52): 8×png w gui/assets/badges", len(badge_png) == 8,
        f"{len(badge_png)}×png — brakujące odznaki nie będą miały ikony")

    # D55/P27: oba końce kontraktu ONB+attest muszą być zapięte (statycznie)
    node_src = (ROOT / "net" / "fenix_node.py").read_text(encoding="utf-8")
    add("D55: demon wpina attest Deimosa przy starcie (register_admin_attestor_boot)",
        "register_admin_attestor_boot" in node_src and "_parse_seeds" in node_src,
        "fenix_node.py bez boot-attesta albo bez _parse_seeds — P0/P27 wraca")
    msg_src = (ROOT / "app" / "messenger.py").read_text(encoding="utf-8") if (ROOT / "app" / "messenger.py").exists() else ""
    add("D57/P24: ratchet = kanon mniejszego x_pub + kanały cand (concurrent-init)",
        "_rk_cand_put" in msg_src and "_RK_CAP_CAND" in msg_src,
        "messenger.py bez D57 — cross-first znowu nadpisuje sesje (P24 wraca)")
    block_src = (ROOT / "chain" / "block.py").read_text(encoding="utf-8")
    led_src = (ROOT / "chain" / "ledger.py").read_text(encoding="utf-8")
    add("D58/P25: TX_POU_ATTEST w KNOWN_TX + rejestr ledger.pou spięty wszędzie",
        "TX_POU_ATTEST" in block_src and "self.pou" in led_src and "pou_reg" in led_src
        and (ROOT / "chain" / "pou.py").exists(),
        "pou.py bez integracji (KNOWN_TX/ledger.pou) — PoU byłby martwym kodem")
    ad_src_n = (ROOT / "net" / "fenix_node.py").read_text(encoding="utf-8")
    add("D61-D64: licznik (T_PRES w TYPES+dispatch), airdrop (0x15+rejestr), duch (flag+IPC)",
        "T_PRES" in ad_src_n and "TX_AIRDROP" in block_src and "self.airdrops" in led_src
        and "self.ghost" in ad_src_n and (ROOT / "tools" / "power_audit.py").exists(),
        "D61-64 bez integracji (frame/ledger/node/ghost) — martwe pliki")
    add("D59+D60/P25: ring świadków z chain + VOTE_EVT gated VOTER",
        "draw_witnesses" in led_src and "TX_VOTE_EVT" in block_src and "self.votes" in led_src
        and (ROOT / "chain" / "vote_evt.py").exists(),
        "ring D59/VOTE_EVT D60 bez integracji — sybil-hack albo urna-wszyscy wraca")
    fx_src = (ROOT / "app" / "fnx_coin.py").read_text(encoding="utf-8") \
        if (ROOT / "app" / "fnx_coin.py").exists() else ""
    add("D65: FNX-COIN — cena wyłącznie z łańcucha (przycisk kursu ownera zdjęty)",
        "curve_price_cents" in fx_src and "supply_stats" in fx_src
        and "oracle" not in fx_src.lower() and "RateOracle" not in fx_src
        and "## 7b. CENA FNX Z ŁAŃCUCHA" in (ROOT / "docs" / "fnx_spec.md").read_text(encoding="utf-8")
        and "GIEŁDA FNX-COIN (D65)" in (ROOT / "TODO.md").read_text(encoding="utf-8"),
        "fnx_coin bez krzywej / ślad oracle / brak pinów spec+TODO — D65 niezintegrowany")
    bev_s = (ROOT / "chain" / "ban_evt.py").read_text(encoding="utf-8")
    ipc_s = (ROOT / "gui" / "backend_ipc.py").read_text(encoding="utf-8")
    gui_s = (ROOT / "gui" / "fenix_gui.py").read_text(encoding="utf-8")
    add("D66: status banu WIDOCZNY (ban_view + IPC ban_status read-only + bramka GUI)",
        "def ban_view" in bev_s and "ban_banner_pl" in bev_s
        and '"ban_status"' in ipc_s and "_op_ban_status" in ipc_s
        and "ban_status_info" in (ROOT / "net" / "fenix_node.py").read_text(encoding="utf-8")
        and "is_banned(self.ledger.bans, self.identity.wallet)" in gui_s
        and "WIDOK BANU (D66" in (ROOT / "docs" / "fnx_spec.md").read_text(encoding="utf-8"),
        "widok banu bez pinów (chain/IPC/node/GUI/spec) — D66 niezintegrowany")
    add("D67: pokój cenowy+karty Sieci (op price read-only; ghost toggle; census/kurs/ban w widoku)",
        "price_board_info" in (ROOT / "net" / "fenix_node.py").read_text(encoding="utf-8")
        and '"price"' in ipc_s and "_op_price" in ipc_s
        and "def exchange_card" in gui_s and "set_ghost_gui" in gui_s
        and "Kurs FNX-COIN" in gui_s and "Duch:" in gui_s
        and "plan_do_konca.md" in {x.name for x in (ROOT / "docs").iterdir()},
        "D67 bez pinów (node/IPC/ctl/view/docs) — pokój cenowy niezintegrowany")
    add("D68/D69: AI-GRID na drucie + dowód na żywych procesach (T_JOB+opty+pliki)",
        "T_JOB_RES" in (ROOT / "net" / "frame.py").read_text(encoding="utf-8")
        and "_accept_grid_job" in node_src and "--ai-grid" in node_src
        and '"grid_submit"' in ipc_s and "grid_status_info" in node_src
        and (ROOT / "ai" / "fnx_ai.py").exists()
        and (ROOT / "tools" / "real_e2e.py").exists(),
        "piny siatki/dowodu niekompletne (frame/node/ipc/tools) — D69 niezintegrowany")
    fx64 = (ROOT / "core" / "crypto" / "fnx64.py").read_text(encoding="utf-8")
    add("D72: FNX64 C 1:1 (fnx64_accel.c, złote porównanie zanim strumień pójdzie w C)",
        (ROOT / "core" / "crypto" / "fnx64_accel.c").is_file()
        and "fnx64_tower_batch" in fx64 and "def _accel_matches" in fx64
        and "def _stream_py" in fx64,
        "brak źródła C albo brak bramki złotych wektorów — peleryna znowu tylko w pętli Pythona")
    add("D70/D71: peleryna FNX64 na drucie (negocjacja+negacja) + trwałość chain.dat",
        "enable_fx" in (ROOT / "net" / "frame.py").read_text(encoding="utf-8")
        and "fx_pair" in (ROOT / "net" / "frame.py").read_text(encoding="utf-8")
        and "_flush_chain" in node_src and "load_chain" in node_src
        and (ROOT / "core" / "crypto" / "fnx64.py").exists()
        and "TcpSniffer" in (ROOT / "tools" / "real_e2e.py").read_text(encoding="utf-8"),
        "piny D70/D71 niekompletne (frame/node/tools) — peleryna lub trwałość niezintegrowana")
    svc = ROOT / "os" / "includes.chroot" / "etc" / "systemd" / "system" / "fenix-node.service"
    add("D55/P0: fenix-node.service podaje PLIK seeds; parser to akceptuje",
        svc.exists() and "--seeds /etc/fenix/seeds.list" in svc.read_text(encoding="utf-8")
        and "os.path.isfile" in node_src,
        "kontrakt seeds rozerwany (service↔parser) — demon na ISO by nie wstał")

    dirty = [l[2:].strip() for l in git("status", "--porcelain").splitlines() if l]
    tolerated = {"docs/crypto_attack_report.md"}       # regenerowany PRZEZ ten audyt
    unexpected = [d for d in dirty if d not in tolerated]
    add("git: drzewo czyste (poza regenerowanym raportem ataków)",
        not unexpected, "; ".join(unexpected[:5]))
    return checks


def todo_stats() -> dict:
    t = (ROOT / "TODO.md").read_text()
    return {"x": t.count("- [x]"), "tilde": t.count("- [~]"), "empty": t.count("- [ ]")}


def main() -> int:
    audit: dict = {
        "meta": {
            "date": time.strftime("%Y-%m-%d %H:%M"),
            "commit": git("log", "--oneline", "-1"),
            "python": sys.version.split()[0],
            "sandbox": "uid=%d, bez roota, bez qemu (Linux kontener)" % os.getuid(),
        },
        "tests": [], "static": [], "todo": todo_stats(),
    }
    n_pass = 0
    for area, name, cmd, tout in TESTS:
        rc, dur, tail = run_one(cmd, tout)
        ok = rc == 0 and ("PASS" in tail or "KONIEC:" in tail)
        audit["tests"].append({"area": area, "name": name, "cmd": " ".join(cmd),
                               "ok": ok, "rc": rc, "dur": round(dur, 1), "tail": tail})
        print(f"{'✅' if ok else '❌'} [{area}] {name}  ({dur:.0f}s, rc={rc})", flush=True)
        n_pass += ok
    audit["static"] = static_checks()
    n_sta = sum(1 for c in audit["static"] if c["ok"])
    audit["summary"] = {"tests_pass": n_pass, "tests_total": len(TESTS),
                        "static_pass": n_sta, "static_total": len(audit["static"])}
    OUT.write_text(json.dumps(audit, ensure_ascii=False, indent=1))
    print(f"\nWYNIK: {n_pass}/{len(TESTS)} testów · {n_sta}/{len(audit['static'])} kontroli → {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
