# tools/make_docs_pdf.py
# ============================================================
#  Generator PDF: FENIX — Rangi & Benefity + Polityka Banów + ToS
#  Uruchom: python3 tools/make_docs_pdf.py  (z katalogu FenixOS/)
#  Wymaga: pip install fpdf2
# ============================================================
import os, re, unicodedata
from fpdf import FPDF

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT  = os.path.join(ROOT, "docs", "FENIX_Rangi_Bany_ToS.pdf")
TOS  = os.path.join(ROOT, "docs", "ToS.md")

FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    "C:/Windows/Fonts/DejaVuSans.ttf",
]
FONT_BOLD_CANDIDATES = [p.replace("DejaVuSans.ttf", "DejaVuSans-Bold.ttf")
                        for p in FONT_CANDIDATES]

def find_font(cands):
    for p in cands:
        if os.path.exists(p):
            return p
    return None

F_REG  = find_font(FONT_CANDIDATES)
F_BOLD = find_font(FONT_BOLD_CANDIDATES)

def ascii_fold(s):
    return unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()

E = (lambda s: s) if F_REG else ascii_fold   # bez fontu TTF -> bez ogonkow

# ------------------------------------------------------------
#  TRESC: RANGI (z TODO.md, sekcja RANGI)
# ------------------------------------------------------------
RANGI = [
    ("ghost — startowa (0 FNX)", [
        "Hosting: 1 strona (Web Builder)",
        "Generowany avatar (identicon z walleta)",
        "Ciemny motyw GUI, 1 grupa (25 osob)",
        "Bufor offline 7 dni, tier 0 (standard)",
        "Pelne PoU/glos po 30 dniach uptime",
    ]),
    ("Donor — 0.000001 FNX", [
        "Wlasny avatar (upload, szyfrowany)",
        "Odznaka Donor + nick w kolorze braz",
        "Hosting: 3 strony",
        "Rezerwacja username (name protection)",
        "Bufor 30 dni, tier 1",
    ]),
    ("VIP — 0.000002 FNX", [
        "Animowany avatar, baner profilu",
        "Hosting: 5 stron + motywy premium stron",
        "2 zmiany username rocznie",
        "Grupy 3x100 osob, wlasne motywy GUI",
        "Tier 2 + priorytet laczenia z seedami",
    ]),
    ("VIP+ — 0.000003 FNX", [
        "Ramka avatara z poswiata, odznaka wspierajacego",
        "Hosting: 10 stron + vanity path /nick/strona",
        "Dostep do funkcji beta",
        "Grupy 5x250, podpisane raporty bezpieczenstwa konta",
        "Tier 3",
    ]),
    ("SVIP — 0.00001 FNX", [
        "Hosting: 25 stron + panel (agregaty, ZERO logow gosci)",
        "Interaktywna ramka avatara, storage x2",
        "Grupy 10x500, feed ogloszen na wlasnych stronach",
        "Bufor 180 dni",
        "Tier 4",
    ]),
    ("ELITE — 0.0001 FNX", [
        "Hosting: 100 stron + wlasne szablony Web Buildera (CSS sandbox)",
        "Fast-lane E2E gwarantowana",
        "Buildy RC + ankiety doradcze (niewiazace)",
        "Grupy bez limitu liczby (2k os./grupa)",
        "Vanity wallet (mielenie prefiksu), aura odznaki, tier 5",
    ]),
    ("SELITE — 0.01 FNX", [
        "Hosting: 500 stron + white-label (bez stopki Fenix)",
        "Kanal ogloszen sieciowych (moderacja admina)",
        "Wpis na stronie (opt-in), test builds + kanal do dev",
        "Vanity premium (dluzszy prefiks), sub-kanaly, grupy 5k",
        "LIMIT: 10 kont rocznie (ekskluzywnosc), tier 6",
    ]),
    ("FENIX — 100.1 FNX", [
        "LIFETIME. Hosting: bez twardego limitu (fair-use)",
        "Dedykowany priorytetowy relay E2E",
        "Fotel w radzie doradczej (kwartalnie, BEZ wladzy nad protokolem)",
        "Wspolprojekt 1 funkcji kosmetycznej z adminem",
        "Unikalna odznaka shard + Sciana Legend (opt-in)",
        "LIMIT: 21 kont w calej historii sieci (jak 21M BTC)",
    ]),
]

ZASADY_RANG = [
    "Ranga = perk sieciowy. NIGDY nie daje: glosu (tylko PoU >=30 dni), dostepu do AI",
    "bezpieczenstwa (wylacznie owner/admin), danych innych, unbana, wladzy nad protokolem.",
    "Ranga zapisana ON-CHAIN (tx RANK_UP, 6 potwierdzen); upgrade = doplata roznicy.",
    "Do czasu stealth addresses kupno rangi jest publiczne — tip: swiezy wallet.",
]

BANY = [
    "Auto-ban = konsens AI (narzedzie admina) -> wpis ON-CHAIN:",
    "   kod powodu + wyjasnienie PL/EN + hash dowodow (bez tresci!).",
    "Kody: ROUTE_LEAKAGE (routing przez niezabezpieczone proxy — wyciaganie danych",
    "poza Fenix!), PROTO_FLOOD, INVALIDTAG_STORM, SYBIL_RING, STORAGE_FRAUD,",
    "MSG_SPAM (meta, nie tresc), CAMO_VIOLATION.",
    "UNBAN: jedyna droga = 1 000 000 USD w XMR, JEDNORAZOWO (escrow multisig 2z3).",
    "Admin ma 30 dni: akcept -> skarbiec + unban on-chain; odmowa/timeout -> zwrot 99%",
    "(1% oplata anti-spam). Decyzja admina ostateczna.",
    "Unban: PoU/reputacja/VOTER od zera, ranga nie wraca.",
    "Jeden wykup na wallet w historii; ponowny ban = PERMANENTNY.",
    "Rejestr banow z wyjasnieniami jest publiczny (GUI + eksplorator).",
]

# ------------------------------------------------------------
class Doc(FPDF):
    def header(self):
        if F_BOLD: self.set_font("DV", "B", 9)
        else: self.set_font("helvetica", "B", 9)
        self.set_text_color(180, 60, 40)
        self.cell(0, 6, E("FENIX / AnonNet — Dokument projektu v1.0 (2026-07-19)"), align="R")
        self.ln(8)
    def footer(self):
        self.set_y(-12)
        self.set_font("DV" if F_REG else "helvetica", "", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 6, f"str. {self.page_no()}", align="C")

    def h1(self, t):
        self.set_font("DV" if F_BOLD else "helvetica", "B", 16)
        self.set_text_color(30, 30, 30); self.ln(2)
        self.multi_cell(0, 8, E(t)); self.ln(2)
    def h2(self, t):
        self.set_font("DV" if F_BOLD else "helvetica", "B", 12)
        self.set_text_color(180, 60, 40); self.ln(2)
        self.multi_cell(0, 6, E(t)); self.ln(1)
    def p(self, t, size=10, indent=0):
        self.set_font("DV" if F_REG else "helvetica", "", size)
        self.set_text_color(40, 40, 40)
        if indent: self.set_x(self.l_margin + indent)
        self.multi_cell(0, 5, E(t)); self.ln(1)
    def bullet(self, t, indent=6):
        self.set_font("DV" if F_REG else "helvetica", "", 10)
        self.set_text_color(40, 40, 40)
        self.set_x(self.l_margin + indent)
        cw = self.w - self.l_margin - self.r_margin - indent
        self.multi_cell(cw, 5, E("•  " + t)); self.ln(0.5)

pdf = Doc(orientation="P", unit="mm", format="A4")
pdf.set_auto_page_break(True, margin=18)
if F_REG:
    pdf.add_font("DV", "", F_REG)
if F_BOLD:
    pdf.add_font("DV", "B", F_BOLD)
pdf.add_page()

# --- STRONA TYTULOWA / SEKCJA 1 ------------------------------
pdf.h1("FENIX / AnonNet")
pdf.p("Rangi i Benefity  •  Polityka Banow  •  Warunki Korzystania (ToS)", 11)
pdf.p("Dokument projektu w wersji 1.0 z dnia 2026-07-19. ToS jest wersja ROBOCZA", 9)
pdf.p("i nie stanowi porady prawnej — przed publikacja wymagana konsultacja prawna.", 9)
pdf.ln(4)

pdf.h2("1. RANGI I BENEFITY (cenik wlasciciela)")
for name, perks in RANGI:
    pdf.set_font("DV" if F_BOLD else "helvetica", "B", 11)
    pdf.set_text_color(20, 20, 60)
    pdf.multi_cell(0, 6, E(name)); pdf.ln(0.5)
    for perk in perks:
        pdf.bullet(perk)
    pdf.ln(2)
pdf.h2("   Zasady nadrzedne rang")
for z in ZASADY_RANG:
    pdf.bullet(z)
pdf.ln(3)

pdf.h2("2. POLITYKA BANOW I WYKUPU (UNBAN)")
for b in BANY:
    pdf.bullet(b)
pdf.ln(3)

# --- SEKCJA 3: ToS z pliku md --------------------------------
pdf.h2("3. WARUNKI KORZYSTANIA (ToS)")
with open(TOS, encoding="utf-8") as f:
    for raw in f.read().splitlines():
        line = raw.rstrip()
        if not line.strip():
            pdf.ln(1); continue
        if line.startswith("## "):
            pdf.h2(line[3:])
        elif line.startswith("# "):
            pdf.set_font("DV" if F_BOLD else "helvetica", "B", 12)
            pdf.set_text_color(20, 20, 60)
            pdf.multi_cell(0, 6, E(line[2:])); pdf.ln(1)
        elif line.startswith("> "):
            pdf.p("[nota] " + line[2:], 8)
        elif re.match(r"^\d+\. ", line) or line.startswith("- "):
            txt = re.sub(r"^(\d+\. |- )\s*", "", line)
            pdf.bullet(txt)
        elif line.startswith("**") and line.endswith("**"):
            pdf.p(line.strip("*"), 9)
        else:
            pdf.p(line, 9)

os.makedirs(os.path.dirname(OUT), exist_ok=True)
pdf.output(OUT)
print(f"[OK] PDF zapisany: {OUT} ({os.path.getsize(OUT)//1024} KB)")
