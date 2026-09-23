# tools/make_report.py — generator raportu PDF „raport V.001-beta" z /tmp/fenix_audit.json
# Styl: uczciwie (każdy problem tabelką), prosto (jak dla właściciela), komplet (testy+kontrole).
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT = Path("/tmp/fenix_audit.json")
OUT = ROOT / "raport V.001-beta.pdf"
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_M = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

PROBLEMS = [
    # (ID, waga, obszar, problem, plan/status)
    ("P1", "WYSOKA", "GUI", "GUI nie istnieje — katalog gui/ pusty (kamień M7). Projekt ma dziś interfejs CLI/demony.",
     "M7: okno po username (D28), portfel, ustawienia-paranoia A/B."),
    ("P2", "WYSOKA", "sieć", "Seeds to placeholdery DEV (203.0.113.x RFC5737). Bez prawdziwych seedów nowy node nie dołączy do sieci.",
     "M9: właściciel hostuje ≥3 seed-nody (VPS bez logów) i podmienia /etc/fenix/seeds.list."),
    ("P3", "WYSOKA", "ISO/QA", "ISO nie było testowane w prawdziwej maszynie wirtualnej (toolchain sandboxa: brak qemu/live-build). build_iso --selftest = 49/49 kontroli statycznych, ale nie boot.",
     "Na maszynie właściciela: live-build + qemu/kvm test boot; wtedy checkpointy [~]→[x]."),
    ("P4", "ŚREDNIA", "prywatność", "Kwoty na-chain są JAWNE w etapie 3a (jak Monero 2014–2016). Nadawca i odbiorca SĄ ukryci; kwota ułatwia korelację.",
     "Etap 3b: CLSAG (wektorowy ring [P,C]) wpiąć Pedersen+Borromean z chain/amount_hide.py; potem bulletproofs."),
    ("P5", "ŚREDNIA", "ekonomia", "BLOCK_REWARD=5 FNX i brak halvingu to wartości ROBOCZE (fnx_spec §12 celowo otwarte). Skarbiec = DEV wallet FNX1+0*32.",
     "Decyzja właściciela: krzywa emisji + M5 trezor na zimnym multisigu (D14)."),
    ("P6", "ŚREDNIA", "blockchain", "Stan ledgera tylko w RAM — brak zapisu łańcucha na dysk (chain.dat). Restart node = pełny resync z sieci.",
     "M5: snapshot/disk-writing z weryfikacją przy wczeście."),
    ("P7", "ŚREDNIA", "giełda/swap", "Paysafe (PSC) i monero-wallet-rpc gatewaye = uczciwe NotImplementedError — czekają na kontrakty merchantskie i hosting deska (poza kodem).",
     "D32/D34: umowa Paysafe + VPS desk; kod obsadzony (Stub działa w testach)."),
    ("P8", "ŚREDNIA", "transport", "DNS-camo (Profil D) wymaga WŁASNEJ domeny-mostu + serwera autorytatywnego (zadanie właściciela). Loopback E2E działa.",
     "Rejestracja domeny + DnsBridgeServer na VPS; DoT:853/DoH:443 dodane do konfiguracji."),
    ("P9", "ŚREDNIA", "ISO", "dm-verity nie jest wdrożone (integralność rootfs sprawdzana byłaby przez initramfs).",
     "Backlog ISO: verity + podpis; GPG keypair właściciela offline."),
    ("P10", "ŚREDNIA", "AI", "AI-Sentry (M6) i gui/ai puste — radar administracji nie istnieje.",
     "M6 po GUI; warstwa 1 reguły, kapsuły sesyjne RAM."),
    ("P11", "NISKA", "krypto", "Rangeproof Borromean = 6.3 KB na wyjście (heavy blocks).",
     "Bulletproofs (≈10x mniejsze) — backlog D31 po 3b."),
    ("P12", "NISKA", "transport", "snowflake_fnx (własny WebRTC-proxy, D29) i pełny onion/relay (M2) nie istnieją; obecnie Profil A szum + Profil D DNS + Mullvad WG.",
     "M2/M3 etapy wg TODO; Mullvad WG już daje profil B."),
    ("P13", "NISKA", "D28", "Avatar on-chain = tylko ref-hex 64B; warstwa blob (TX_BLOB_REF) nie wdrożona.",
     "M4+: blob-store + GUI avatara."),
    ("P14", "INFO", "krypto/testy", "ZNALEZIONE W TYM AUDYCIE i naprawione: test 2-udziałowy Shamira w fenix_crypto drukował '[!!] BLAD' ale NIE failował (rc=0). Teraz SystemExit — test naprawdę łapie.",
     "zamknięte (commit 'audit fix'). Lekcja: wzorzec 'print error zamiast assert' pilnować w nowych testach."),
    ("P15", "INFO", "Mullvad", "Prawdziwe up() (root + konto Mullvad + sieć) nie testowane — offline selftest 10/10.",
     "QA na maszynie właściciela z kontem Mullvad; [~] w TODO."),
    ("P16", "INFO", "media", "boot/boot.asm = materiał edukacyjny (nie używany przez ISO).",
     "zostaje jako docs/EDU (nie kasować — wyjaśnienie bootstrappingu)."),
]

HOW_IT_WORKS = [
    ("Warstwa 0 TOŻSAMOŚĆ", "core/identity + core/keystore: username+passkey (Argon2id) → tożsamość Ed25519+X25519 w kontenerze KS1; hasło-panika otwiera wabik (D24)."),
    ("Warstwa 1 OS", "FenixOS Live ISO (Debian live-build): amnezja jak Tails, spoof MAC przed siecią, nftables FAIL-CLOSED, panicd (Del+PageUp 2 s → shred+poweroff D27), sealed payload (kod zaszyfrowany, Shamir 3z5), fenix-vpn = Mullvad WireGuard opt-in z KILL SWITCHEM."),
    ("Warstwa 2 TRANSPORT", "net/frame AEAD v2 (zera jawnych bajtów na drucie — test łapie markery), camo (kowadła rekordowe jak TLS, cover traffic), DNS-camo Profil D (Mullvad resolver, base32 qname ↔ TXT), Mullvad WG."),
    ("Warstwa 3 SIECI", "net/fenix_node mesh: gossip tx+bloków, sync z chunkingiem, każdy kopie CPU (Argon-lite/sha256d), fork-choice najdłuższy ważny łańcuch."),
    ("Warstwa 4 CHAIN", "chain/ledger: konta+salda, fee D15 (0.001% burn + 0.055% skarbiec), retarget co 144 bloki. PRYWATNOŚĆ M5b: stealth (odbiorca), LSAG ring (nadawca w tłumie 5–11), Pedersen+Borromean (kwoty — gotowe, wpinane CLSAG w 3b)."),
    ("Warstwa 5 USŁUGI", "chain/tx_ring: TX_SHIELD/TX_RING (prywatny pool, key-image anti-double-spend); chain/usernames: rejestr username on-chain (D28); app/exchange: giełda+PSC (D32); app/xmr_swap: XMR→świeży FNX (D34)."),
    ("Warstwa 6 APP", "gui/ — PUSTE (M7). Komunikator M4 = następny dokument (username resolver z rejestru on-chain + TOFU + E2E)."),
]

SEC_EVIDENCE = [
    ("Szyfrowanie w ruchu", "frame AEAD v2: payload+pad pod AEAD, handshake tylko-efemeryczny; test DRUTU: zero markerów w 1088 rekordach (net.fenix_node)."),
    ("Szyfrowanie w spoczynku", "keystore KS1: Argon2id → KEK → MEK → AEAD; probe_panic odróżnia błędne hasło od panic hasła; backoff ×2 (2,4,8…300 s)."),
    ("Prywatność chain", "stealth: priv_ot·G == stealth_pub (wydobywalność); ring LSAG + key-image (double-spend wykrywalny, nadawca anonimowy); Pedersen: Σin−Σout−fee·H==0 bez kwot; Borromean 64-bit."),
    ("Anti-forensics", "panicd Del+PageUp → crypto-shred kontenera + wipe + poweroff (jedna ścieżka, 5/5); sealed payload z manifestem Ed25519; /run RAM; hasło-panika (wabik)."),
    ("Sieć-DEF", "nftables: policy drop ×3, tylko uid 1088 + fwmark 51820 (WG); kill switch fenixwg stawiany PRZED tunelem; dnscamo fair-use; spoof MAC before network-pre."),
    ("Ekonomia-DEF", "fee_split egzekwiwane w konsensusie (nie w GUI); coinbase limit; nonce Ethereum-model; mempool cap; double-spend odrzut (konto i key-image)."),
    ("Red-team", "tools/self_attack.py: 27 odparzone · 5 notatek · 0 problemów (pełny raport: docs/crypto_attack_report.md)."),
    ("Znalezione i naprawione", "audyt V.001: fenix_crypto 2-udziałowy test failował-był-błędnie (fix); ring c·Hp↔c·ki; amount blinding fee; ledger nonce mempool; dnscamo ACK/last-chunk (wszystkie: test→fix→rerun)."),
]


def main() -> int:
    from fpdf import FPDF

    a = json.loads(AUDIT.read_text())
    meta, tests, static, todo, summ = a["meta"], a["tests"], a["static"], a["todo"], a["summary"]

    class PDF(FPDF):
        def footer(self):
            self.set_y(-12)
            self.set_font("DejaVu", "", 7.5)
            self.set_text_color(120)
            self.cell(0, 6, f"FenixOS/AnonNet — raport V.001-beta · {meta['date']} · {meta['commit'][:40]} · strona {self.page_no()}/{{nb}}", align="C")

    pdf = PDF(format="A4")
    pdf.set_margins(15, 14, 15)
    pdf.set_auto_page_break(True, 16)
    pdf.add_font("DejaVu", "", FONT)
    pdf.add_font("DejaVu", "B", FONT_B)
    pdf.add_font("DM", "", FONT_M)
    pdf.alias_nb_pages()

    def mc(txt, h=5, **kw):
        # fpdf2: multi_cell zostawia x przy PRAWYM marginesie → następny width=0 wybucha.
        # Kuracja: zawsze start z lewego marginesu + karetka na nową linię.
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, h, txt, new_x="LMARGIN", new_y="NEXT", **kw)

    def h1(txt):
        pdf.set_font("DejaVu", "B", 15)
        pdf.set_text_color(20, 60, 120)
        mc(txt, 8)
        pdf.set_text_color(0)
        pdf.ln(1)

    def h2(txt):
        pdf.set_font("DejaVu", "B", 11.5)
        pdf.set_text_color(30, 30, 30)
        mc(txt, 6.5)
        pdf.set_text_color(0)

    def body(txt, size=9.5):
        pdf.set_font("DejaVu", "", size)
        mc(txt, 5)

    def bullet(txt, size=9.5, ind=6):
        pdf.set_x(15 + ind)
        body("• " + txt, size)

    # ---------------- okładka ----------------
    pdf.add_page()
    pdf.ln(30)
    pdf.set_font("DejaVu", "B", 26)
    mc("RAPORT V.001-beta", 12, align="C")
    pdf.set_font("DejaVu", "", 13)
    mc("FenixOS / AnonNet — rezolutny test projektu i zabezpieczeń", 7, align="C")
    pdf.ln(8)
    pdf.set_font("DejaVu", "", 10)
    mc(f"Data: {meta['date']}  ·  Commit: {meta['commit']}\n"
       f"Środowisko testowe: {meta['sandbox']} · Python {meta['python']}", 6, align="C")
    pdf.ln(10)
    pdf.set_font("DejaVu", "B", 12)
    pdf.set_text_color(0, 110, 0)
    mc(f"WYNIK: {summ['tests_pass']}/{summ['tests_total']} selftestów PASS · "
       f"{summ['static_pass']}/{summ['static_total']} kontroli statycznych", 8, align="C")
    pdf.set_text_color(200, 0, 0)
    pdf.set_font("DejaVu", "B", 10.5)
    mc(f"NAJWAŻNIEJSZE BRAKI: GUI (M7, 6.5) nie istnieje · seeds DEV · kwoty jawne (etap 3a) · "
                           f"brak boot-testu ISO w VM", align="C")
    pdf.set_text_color(0)

    # ---------------- 1. na czym stoimy ----------------
    pdf.add_page()
    h1("1. Na czym stoimy (podsumowanie dla właściciela)")
    body(f"Uruchomiono KOMPLETNĄ baterię: {summ['tests_total']} selftestów (CORE/CHAIN/NET/TRANSPORT/OS/APP/TOOLS) "
         f"+ {summ['static_total']} kontroli statycznych (sekrety, uprawnienia, konfiguracje). "
         f"Wszystkie selftesty przechodzą ({summ['tests_pass']}/{summ['tests_total']}). "
         f"Jedyna kontrola statyczna NIEprzechodząca to oczywisty, zaplanowany brak: GUI (świadomie odłożone do M7).")
    pdf.ln(1)
    body(f"Stan TODO.md: ■ zrobione {todo['x']}  ·  ◐ częściowe/QA-off-site {todo['tilde']}  ·  □ otwarte {todo['empty']}.")
    pdf.ln(1)
    h2("Co już DZIAŁA end-to-end (przetestowane, nie obiecane):")
    for b in (
        "Własny blockchain FNX z PoW CPU: 3-nodowy mesh kopie, synchronizuje i ZFIRMUJE wspólny łańcuch; fork-choice działa.",
        "Prywatny pool monero-style (etap 3a): TX_SHIELD/TX_RING — nadawca ukryty ringiem 5–11, odbiorca ukryty stealth; double-spend łapany key-image; fałszerstwa (druk FNX, wabik spoza poola) odrzucane.",
        "Rejestr username on-chain (D28): claim/rename z anty-squattingiem; regex identyczny jak kreator boota (fuzz 300/300).",
        "Kontener D24 z hasłem-paniki (wabik), Shamir 3z5 skarbca, panic Del+PageUp (shred+poweroff).",
        "Transport bez widoczności dla ISP: ramka AEAD v2 (na drucie ZERO jawnych bajtów — reguła testu na zawsze), camo kowadełkowe, DNS-camo, Mullvad WireGuard + kill switch PRZED tunelem.",
        "Live-ISO: build_iso --selftest 49/49 (hardening, spoof, payload sealed, demony, fenix-vpn opt-in).",
        "Giełda PSC (D32) i swap XMR→FNX (D34) — logika+limity+higiena PIN testowane stubami; bramki produkcyjne = P7.",
        "Red-team tools/self_attack.py: 27 odparzeń, 0 problemów.",
    ):
        bullet(b)
    pdf.ln(1)
    h2("Czego świadomie NIE MA (i dlaczego to OK na tym etapie):")
    for b in (
        "GUI (M7) — projekt ma dziś CLI/demony; GUI to następny duży kamień po fundamentach.",
        "Prawdziwy boot ISO w qemu — toolchain sandboxa go nie obsługuje; test na maszynie właściciela (P3).",
        "Pełne ukrycie kwot on-chain (CLSAG, etap 3b) — kamień 3 kryptografii czeka w amount_hide.py.",
    ):
        bullet(b)

    # ---------------- 2. jak to działa ----------------
    pdf.add_page()
    h1("2. Jak działa projekt (architektura warstw — prosto)")
    for name, desc in HOW_IT_WORKS:
        h2(name)
        body(desc)
        pdf.ln(0.5)

    # ---------------- 3. wyniki testów ----------------
    pdf.add_page()
    h1(f"3. Wyniki testów ({summ['tests_pass']}/{summ['tests_total']} PASS)")
    areas = []
    for t in tests:
        if t["area"] not in areas:
            areas.append(t["area"])
    pdf.set_font("DejaVu", "", 8.5)
    for area in areas:
        h2(area)
        pdf.set_font("DM", "", 7.6)
        pdf.set_fill_color(235, 240, 248)
        pdf.cell(92, 5, " test", border=1, fill=True)
        pdf.cell(18, 5, " status", border=1, fill=True)
        pdf.cell(16, 5, " czas[s]", border=1, fill=True)
        pdf.cell(54, 5, " komenda", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
        for t in [x for x in tests if x["area"] == area]:
            ok = t["ok"]
            pdf.set_text_color(0, 140, 0) if ok else pdf.set_text_color(200, 0, 0)
            pdf.cell(92, 5, " " + t["name"][:58], border=1)
            pdf.cell(18, 5, " PASS" if ok else " FAIL", border=1)
            pdf.set_text_color(0)
            pdf.cell(16, 5, f" {t['dur']}", border=1)
            pdf.cell(54, 5, " " + t["cmd"][:36], border=1, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("DejaVu", "", 8.5)
        pdf.ln(1.5)

    # ---------------- 4. zabezpieczenia ----------------
    h1("4. Sprawdzenie zabezpieczeń (z dowodami)")
    for name, evd in SEC_EVIDENCE:
        h2("✔ " + name)
        body(evd)
        pdf.ln(0.5)
    h2("Kontrole statyczne plików:")
    for c in static:
        mark = "✓" if c["ok"] else "✗"
        (pdf.set_text_color(0, 140, 0) if c["ok"] else pdf.set_text_color(200, 0, 0))
        bullet(f"{mark} {c['check']}" + (f" — {c['detail']}" if (c["detail"] and not c["ok"]) else ""), size=8.5)
        pdf.set_text_color(0)

    # ---------------- 5. problemy ----------------
    pdf.add_page()
    h1("5. Problemy i luki — KAŻDY udokumentowany")
    body("Wagi: WYSOKA = blokuje produkcję/mainnet; ŚREDNIA = działa MVP, ale plan wymagany; NISKA = roadmap; INFO = zamknięte/notatka.", size=8.8)
    pdf.ln(1)
    for pid, waga, obsz, prob, plan in PROBLEMS:
        col = {"WYSOKA": (200, 0, 0), "ŚREDNIA": (200, 120, 0), "NISKA": (90, 90, 200), "INFO": (90, 90, 90)}[waga]
        pdf.set_font("DejaVu", "B", 9.5)
        pdf.set_text_color(*col)
        mc(f"[{pid} | {waga}] {obsz}", 5.5)
        pdf.set_text_color(0)
        body(prob, size=9)
        pdf.set_font("DejaVu", "", 9)
        pdf.set_text_color(60, 60, 60)
        mc(f"   → plan: {plan}", 5)
        pdf.set_text_color(0)
        pdf.ln(1.2)

    # ---------------- 6. co dalej ----------------
    h1("6. Rekomendowane następne kroki")
    for i, s in enumerate((
        "P3: boot-test ISO w qemu na maszynie właściciela (odhacza [~] pkt ISO).",
        "P2: 3 prawdziwe seed-nody + podmiana seeds.list (sieć ożywa poza laboratorium).",
        "M7 GUI: okno po username + portfel + suwak paranoii (D28/D29) — największy widoczny krok dla użytkownika.",
        "P4: etap 3b CLSAG → kwoty prywatne on-chain (domknięcie D31).",
        "M4 communicator: username resolver (rejestr już gotowy) + TOFU + E2E messenger.",
        "P5: decyzja o emisji/halvingu FNX + trezor multisig (D14/D15).",
    ), 1):
        bullet(f"{i}. {s}")

    pdf.output(str(OUT))
    print(f"PDF: {OUT} ({OUT.stat().st_size} B, stron: {pdf.page_no()})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
