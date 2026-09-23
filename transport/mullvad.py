# transport/mullvad.py — podłączenie Mullvad VPN (WireGuard) + kill switch (D29 profil B, D33)
"""
Po co: profil B paranoii = cały ruch FNX wychodzi przez tunel Mullvada (WireGuard).
ISP widzi tylko szyfrowaną rurkę do jednego IP Mullvada — nie widzi peerów FNX ani
struktury mesh. Mullvad nie wymaga maila/konta osobistego — konto = 16-cyfrowy
NUMER kupiony za gotówkę/XMR (pasuje do naszego modelu anonimowości).

Trzy filary modułu:
  1) WIREGUARD: własny keypair (X25519), rejestracja pubkey w API Mullvada
     (POST /wg/, auth: Token <numer-konta>), config wg-quick renderowany do RAM
     (/run/fenix/mullvad — nigdy na dysk; anti-forensic jak D24/D27).
  2) KILL SWITCH (to jest „bariera odstraszająca" dla wycieków!): reguły nftables
     ustawiane PRZED podniesieniem tunelu: policy=drop, puszczamy tylko (a) lo,
     (b) UDP do endpointu Mullvada, (c) interfejs fnxwg0. Padnie tunel → NIC
     nie wycieknie gołym łączem. Zero okna między up a regułami.
  3) HIGIENA TOKENA: numer konta z ENV (FENIX_MULLVAD_ACCOUNT) lub parametru,
     trzymany w bytearray, kasowany zerami przy down()/close(); NIGDY w plikach.

Sandbox: selftest jest OFFLINE (stub HTTP + stub runner) — prawdziwe `up()` wymaga
root + konto Mullvad + sieć → oznaczone w TODO jako [~] do QA na maszynie właściciela.
DNS: w configu domyślnie 193.138.218.74 (DNS Mullvada); dnscamo (Profil D, D33)
może jechać W TUNELU dla podwójnej warstwy.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import pathlib as _pl
import subprocess
from dataclasses import dataclass, field
from typing import Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

MULLVAD_API = "https://api.mullvad.net"
RELAYS_PATH = "/public/relays/wireguard/v1/"
WGKEY_PATH = "/wg/"
ENV_ACCOUNT = "FENIX_MULLVAD_ACCOUNT"
IFACE = "fnxwg0"
MULLVAD_DNS = "193.138.218.74"
NFT_TABLE = "fenixwg"
_DEFAULT_RUN_DIR = _pl.Path("/run/fenix/mullvad")


class MullvadError(Exception):
    """Wszystko, co może pójść nie tak z VPNem — jeden typ."""


# -------------------------------------------------------------------------- klucze WireGuard
def gen_wg_keypair() -> tuple[str, str]:
    """(priv_b64, pub_b64) — WireGuard = X25519; format base64 jak `wg genkey`."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    priv = X25519PrivateKey.generate()
    priv_b = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_b = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(priv_b).decode(), base64.b64encode(pub_b).decode()


def pubkey_of(priv_b64: str) -> str:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    try:
        raw = base64.b64decode(priv_b64, validate=True)
    except Exception:
        raise MullvadError("privkey: zły base64") from None
    if len(raw) != 32:
        raise MullvadError("privkey: 32 bajty")
    priv = X25519PrivateKey.from_private_bytes(raw)
    pub_b = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(pub_b).decode()


# -------------------------------------------------------------------------- HTTP (wstrzykiwalne)
class HttpClient:
    def get_json(self, url: str, headers: dict | None = None) -> dict: ...
    def post_json(self, url: str, headers: dict, body: dict) -> dict: ...


class UrllibHttpClient(HttpClient):
    """Prawdziwe HTTP (używane TYLKO na maszynie właściciela; selftest go nie dotyka)."""
    def get_json(self, url: str, headers: dict | None = None) -> dict:
        import urllib.request
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())

    def post_json(self, url: str, headers: dict, body: dict) -> dict:
        import urllib.request
        req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json", **headers})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return json.loads(r.read().decode())
        except Exception as e:
            code = getattr(e, "code", None)
            if code is not None:
                raise MullvadError(f"Mullvad API HTTP {code}") from None
            raise MullvadError(f"Mullvad API: {e}") from None


class StubHttpClient(HttpClient):
    """Selftest: skryptowane odpowiedzi + nagrywanie wywołań."""
    def __init__(self, relays: dict | None = None, wg_response: dict | Exception | None = None):
        self.relays = relays if relays is not None else _sample_relays()
        self.wg_response = wg_response if wg_response is not None else {
            "id": "deadbeef", "ipv4_address": "10.64.12.34/32", "ipv6_address": "fc00:bbbb:bbbb:bb01::c22/128"}
        self.calls: list[tuple[str, str, dict, dict]] = []

    def get_json(self, url: str, headers: dict | None = None) -> dict:
        self.calls.append(("GET", url, headers or {}, {}))
        if not url.endswith(RELAYS_PATH):
            raise MullvadError(f"stub: nieznany GET {url}")
        return self.relays

    def post_json(self, url: str, headers: dict, body: dict) -> dict:
        self.calls.append(("POST", url, headers, dict(body)))
        if not url.endswith(WGKEY_PATH):
            raise MullvadError(f"stub: nieznany POST {url}")
        if isinstance(self.wg_response, Exception):
            raise self.wg_response
        return self.wg_response


def _sample_relays() -> dict:
    return {"countries": [
        {"name": "Poland", "code": "pl", "cities": [{"name": "Warsaw", "code": "waw", "relays": [
            {"hostname": "pl-waw-wg-001", "public_key": base64.b64encode(b"\x11" * 32).decode(),
             "ipv4_addr_in": "185.65.134.83", "multihop_port": 3001},
            {"hostname": "pl-waw-wg-002", "public_key": base64.b64encode(b"\x22" * 32).decode(),
             "ipv4_addr_in": "185.65.134.84", "multihop_port": 3002}]}]},
        {"name": "Netherlands", "code": "nl", "cities": [{"name": "Amsterdam", "code": "ams", "relays": [
            {"hostname": "nl-ams-wg-001", "public_key": base64.b64encode(b"\x33" * 32).decode(),
             "ipv4_addr_in": "146.70.99.3", "multihop_port": 3001}]}]}]}


# -------------------------------------------------------------------------- runner (wstrzykiwalny)
class CmdRunner:
    def run(self, argv: list[str]) -> tuple[int, str]: ...


class RealRunner(CmdRunner):
    """Prawdziwe wywołania (root na maszynie właściciela)."""
    def run(self, argv: list[str]) -> tuple[int, str]:
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=60)
            return p.returncode, p.stdout + p.stderr
        except (OSError, subprocess.SubprocessError) as e:
            return 127, f"komenda nie wstała ({argv[0]}): {e}"


class StubRunner(CmdRunner):
    """Selftest: nagrywa sekwencję komend; `wg show …` → skryptowane wyjście."""
    def __init__(self):
        self.calls: list[list[str]] = []
        self.wg_show = f"interface: {IFACE}\n  public key: stub\n  latest handshake: 42 seconds ago\n"

    def run(self, argv: list[str]) -> tuple[int, str]:
        self.calls.append(list(argv))
        if argv[:2] == ["wg", "show"]:
            return 0, self.wg_show
        return 0, "ok"


# -------------------------------------------------------------------------- config / kill switch
@dataclass
class WgSession:
    priv_b64: str
    pub_b64: str
    addr_v4: str
    addr_v6: str
    peer_pub_b64: str
    endpoint: str            # "ip:port"
    dns: str = MULLVAD_DNS

    def render_conf(self) -> str:
        return (f"[Interface]\n"
                f"PrivateKey = {self.priv_b64}\n"
                f"Address = {self.addr_v4}, {self.addr_v6}\n"
                f"DNS = {self.dns}\n\n"
                f"[Peer]\n"
                f"PublicKey = {self.peer_pub_b64}\n"
                f"AllowedIPs = 0.0.0.0/0, ::0/0\n"
                f"Endpoint = {self.endpoint}\n"
                f"PersistentKeepalive = 25\n")


def validate_wg_conf(text: str) -> None:
    """Minimalny parser INI wg-quick (Interface: PrivateKey+Address; Peer: PublicKey+Endpoint)."""
    cur = None
    got = {"Interface": set(), "Peer": set()}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1]
            if cur not in got:
                raise MullvadError(f"config: nieznana sekcja [{cur}]")
            continue
        if cur is None or "=" not in line:
            raise MullvadError("config: linia poza sekcją / bez '='")
        k = line.split("=", 1)[0].strip()
        got[cur].add(k)
    if "PrivateKey" not in got["Interface"] or "Address" not in got["Interface"]:
        raise MullvadError("config: [Interface] bez PrivateKey/Address")
    if "PublicKey" not in got["Peer"] or "Endpoint" not in got["Peer"]:
        raise MullvadError("config: [Peer] bez PublicKey/Endpoint")


def render_killswitch(endpoint_ip: str, endpoint_port: int, iface: str = IFACE) -> str:
    """nftables: domyślnie DROP; przepuszczamy TYLKO lo, UDP→endpoint, sam tunel.
    Wooow — to jest mur przy bramie: padnie tunel, nic nie wyjdzie obok."""
    return f"""# KILL SWITCH FenixOS/Mullvad — stosuj PRZED wg-quick up (zero okna wycieku)
table inet {NFT_TABLE} {{
  chain output {{
    type filter hook output priority 0; policy drop;
    oif "lo" counter accept comment "localhost zawsze"
    ip daddr {endpoint_ip} udp dport {endpoint_port} counter accept comment "handshake WG do endpointu"
    oifname "{iface}" counter accept comment "ruch TYLKO tunelem"
    counter drop comment "wszystko inne = wyciek → DROP"
  }}
}}
"""


# -------------------------------------------------------------------------- menedżer
class MullvadVPN:
    """Sterowanie tunel: fetch_relay → register_key → up/down/status. RAM-only + zeroize."""

    def __init__(self, account_token: str | None, run_dir: _pl.Path | None = None,
                 http: HttpClient | None = None, runner: CmdRunner | None = None,
                 allow_no_token: bool = False):
        token = account_token or os.environ.get(ENV_ACCOUNT, "")
        if not token.strip() and allow_no_token:
            # tylko dla down(): sprzątanie nie wymaga API; token to same zera
            self._token = bytearray(b"\x00" * 16)
        elif not token or not token.strip().isdigit():
            raise MullvadError(f"numer konta Mullvad: podaj (param/{ENV_ACCOUNT}); 16 cyfr, nie email")
        else:
            self._token = bytearray(token.strip().encode())      # bytearray = wipeable
        self.run_dir = _pl.Path(run_dir) if run_dir else _DEFAULT_RUN_DIR
        self.http = http or UrllibHttpClient()
        self.runner = runner or RealRunner()
        self.session: Optional[WgSession] = None
        self._up = False

    # --- bezpieczne kasowanie (schemat D27: 2× nadpis + usunięcie) ---
    def _wipe_file(self, p: _pl.Path) -> None:
        try:
            size = p.stat().st_size
            with open(p, "r+b", buffering=0) as f:
                for pat in (b"\x55", b"\xAA"):
                    f.write(pat * size)
                    f.flush()
                    os.fsync(f.fileno())
            p.unlink()
        except FileNotFoundError:
            pass

    def zeroize(self) -> None:
        for i in range(len(self._token)):
            self._token[i] = 0

    # --- API ---
    def _auth(self) -> dict:
        return {"Authorization": "Token " + self._token.decode()}

    def pick_relay(self, relay_filter: dict | None = None) -> tuple[str, str, int]:
        """Zwraca (pubkey_b64, ipv4, port); filter: {"country": "pl", "hostname": "-waw-"}."""
        f = relay_filter or {}
        data = self.http.get_json(MULLVAD_API + RELAYS_PATH)
        for c in data.get("countries", []):
            if f.get("country") and c.get("code") != f["country"]:
                continue
            for city in c.get("cities", []):
                for r in city.get("relays", []):
                    if f.get("hostname") and f["hostname"] not in r.get("hostname", ""):
                        continue
                    if r.get("public_key") and r.get("ipv4_addr_in"):
                        return r["public_key"], r["ipv4_addr_in"], int(r.get("multihop_port", 51820))
        raise MullvadError(f"brak relayu pasującego do filtra {f!r}")

    def build_session(self, relay_filter: dict | None = None) -> WgSession:
        pubkey, ip, port = self.pick_relay(relay_filter)
        priv_b64, pub_b64 = gen_wg_keypair()
        resp = self.http.post_json(MULLVAD_API + WGKEY_PATH, self._auth(), {"pubkey": pub_b64})
        if not resp.get("ipv4_address"):
            raise MullvadError(f"Mullvad API: brak adresu w odpowiedzi ({resp!r})")
        self.session = WgSession(priv_b64=priv_b64, pub_b64=pub_b64,
                                 addr_v4=resp["ipv4_address"], addr_v6=resp.get("ipv6_address", ""),
                                 peer_pub_b64=pubkey, endpoint=f"{ip}:{port}")
        return self.session

    # --- sterowanie ---
    @property
    def conf_path(self) -> _pl.Path:
        return self.run_dir / f"{IFACE}.conf"

    def up(self, relay_filter: dict | None = None) -> _pl.Path:
        if self._up:
            raise MullvadError("tunel już podniesiony (najpierw down())")
        sess = self.build_session(relay_filter)                      # API: relays + /wg/
        conf = sess.render_conf()
        validate_wg_conf(conf)
        ip, port = sess.endpoint.rsplit(":", 1)
        ks = render_killswitch(ip, int(port), IFACE)
        if sess.priv_b64 in ks or self._token.decode() in ks or self._token.decode() in conf:
            raise MullvadError("PANIC: sekret wyciekł do artefaktu — przerwano")
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.conf_path.write_text(conf)
        os.chmod(self.conf_path, 0o600)
        ks_path = self.run_dir / "killswitch.nft"
        ks_path.write_text(ks)
        os.chmod(ks_path, 0o600)
        rc, out = self.runner.run(["nft", "-f", str(ks_path)])      # 1) mur NAJPIERW
        if rc != 0:
            raise MullvadError(f"kill switch nie wszedł: {out}")
        rc, out = self.runner.run(["wg-quick", "up", str(self.conf_path)])  # 2) dopiero tunel
        if rc != 0:
            self.runner.run(["nft", "delete", "table", "inet", NFT_TABLE])
            raise MullvadError(f"wg-quick up: {out}")
        self._up = True
        return self.conf_path

    def status(self) -> str:
        rc, out = self.runner.run(["wg", "show", IFACE])
        return out if rc == 0 else ""

    def down(self) -> None:
        # tolerancyjne down: sprząta nawet gdy _up nie ustawione w TYM procesie
        # (np. restart demona/usługi mid-run; rc komend ignorujemy celowo)
        self.runner.run(["wg-quick", "down", str(self.conf_path)])
        self.runner.run(["nft", "delete", "table", "inet", NFT_TABLE])
        self._up = False
        self._wipe_file(self.conf_path)
        self._wipe_file(self.run_dir / "killswitch.nft")
        self.zeroize()
        self.session = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.down()


# -------------------------------------------------------------------------- CLI (ISO: fenix-vpn)
def _cli() -> None:
    """`python3 -m transport.mullvad up|down|status` — wołane przez /usr/local/bin/fenix-vpn
    na Live-ISO. Token z FENIX_MULLVAD_ACCOUNT (nigdy z argv — argv widzi `ps`!)."""
    import argparse
    ap = argparse.ArgumentParser(prog="python3 -m transport.mullvad",
                                 description="Mullvad WireGuard dla FNX: mur najpierw, potem tunel.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ap_up = sub.add_parser("up", help="kill switch → tunel (RAM-only config)")
    ap_up.add_argument("--country", default="pl", help="kod kraju relayu (domyślnie pl)")
    ap_up.add_argument("--hostname", default="", help="fragment hostname relayu (np. waw)")
    sub.add_parser("down", help="tunel w dół + shred configu + zeroize tokena")
    sub.add_parser("status", help="wg show fnxwg0")
    args = ap.parse_args()
    if args.cmd == "status":
        rc, out = RealRunner().run(["wg", "show", IFACE])
        print(out if rc == 0 else "tunel nieaktywny")
        raise SystemExit(0 if rc == 0 else 1)
    if args.cmd == "down":
        MullvadVPN(None, allow_no_token=True).down()
        print("tunel zdjęty, artefakty shred, token zeroizowany")
        return
    vpn = MullvadVPN(None)                     # token z ENV; brak → MullvadError
    try:
        path = vpn.up({"country": args.country,
                       **({"hostname": args.hostname} if args.hostname else {})})
        print(f"tunel UP: {vpn.session.endpoint} (kill switch aktywny; config RAM: {path})")
    except MullvadError as e:
        print(f"BŁĄD: {e}")
        try:
            vpn.down()
        finally:
            raise SystemExit(1)


# -------------------------------------------------------------------------- selftest (OFFLINE)
if __name__ == "__main__" and len(sys.argv) > 1:
    _cli()

if __name__ == "__main__":
    import tempfile

    print("transport/mullvad.py — selftest (offline: stub-HTTP + stub-runner)\n")

    # 1) keypair + pubkey spójny
    priv_b64, pub_b64 = gen_wg_keypair()
    assert pubkey_of(priv_b64) == pub_b64
    assert len(base64.b64decode(priv_b64)) == 32 and len(base64.b64decode(pub_b64)) == 32
    try:
        pubkey_of("nie-base64!!!")
        raise SystemExit("zły base64 przeszedł!")
    except MullvadError:
        pass
    print("  [OK] 1. keypair X25519/base64 jak wg genkey; zły klucz odrzucony")

    # 2) filtr relayów
    http = StubHttpClient()
    vpn = MullvadVPN("1234567812345678", run_dir=_pl.Path(tempfile.mkdtemp(prefix="mv-test-")),
                     http=http, runner=StubRunner())
    pub, ip, port = vpn.pick_relay({"country": "pl", "hostname": "waw"})
    assert (ip, port) == ("185.65.134.83", 3001)
    pub2, ip2, port2 = vpn.pick_relay({})
    assert ip2 == "185.65.134.83"  # pierwszy z listy
    try:
        vpn.pick_relay({"country": "xx"})
        raise SystemExit("pusty filtr przeszedł!")
    except MullvadError:
        pass
    print("  [OK] 2. wybór relayu: filtr pl/waw trafia; pusty → pierwszy; zły kraj → błąd")

    # 3) rejestracja klucza w API (stub nagrywa request)
    sess = vpn.build_session({"country": "pl"})
    posts = [c for c in http.calls if c[0] == "POST"]
    assert len(posts) == 1 and posts[0][1] == MULLVAD_API + WGKEY_PATH
    assert posts[0][2]["Authorization"] == "Token 1234567812345678"
    assert posts[0][3] == {"pubkey": pubkey_of(sess.priv_b64)}
    assert sess.addr_v4 == "10.64.12.34/32" and sess.endpoint == "185.65.134.83:3001"
    print("  [OK] 3. POST /wg/ z Token auth; konto NIGDY w body, tylko nagłówek")

    # 3b) 401 → błąd, bez configu
    http401 = StubHttpClient(wg_response=MullvadError("Mullvad API HTTP 401"))
    vpn_bad = MullvadVPN("0000000000000000", run_dir=_pl.Path(tempfile.mkdtemp(prefix="mv-bad-")),
                         http=http401, runner=StubRunner())
    try:
        vpn_bad.build_session({})
        raise SystemExit("401 przeszło!")
    except MullvadError:
        pass
    assert not (vpn_bad.run_dir / f"{IFACE}.conf").exists()
    print("  [OK] 3b. HTTP 401 → MullvadError; żadnego configu na dysku")

    # 4) render conf: klucze są, tokena NIE MA, perms 0600
    vpn2 = MullvadVPN("1234567812345678", run_dir=_pl.Path(tempfile.mkdtemp(prefix="mv-up-")),
                      http=StubHttpClient(), runner=StubRunner())
    conf_path = vpn2.up({"country": "pl"})
    text = conf_path.read_text()
    validate_wg_conf(text)
    assert sess.priv_b64 not in text and "1234567812345678" not in text
    assert "[Peer]" in text and "AllowedIPs = 0.0.0.0/0, ::0/0" in text
    assert oct(conf_path.stat().st_mode & 0o777) == "0o600"
    print("  [OK] 4. config wg-quick ważny; token NIE w configu; chmod 0600")

    # 5) kill switch: policy drop + tylko endpoint UDP + iface
    ks = (vpn2.run_dir / "killswitch.nft").read_text()
    assert "policy drop" in ks and 'oifname "fnxwg0"' in ks
    assert "185.65.134.83" in ks and "dport 3001" in ks and 'oif "lo"' in ks
    assert vpn2.session.priv_b64 not in ks
    print("  [OK] 5. kill switch: mur przy bramie (policy drop; tylko tunel+endpoint)")

    # 6) up: kolejność komend — NAJPIERW nft, POTEM wg-quick (zero okna wycieku)
    cmds = [c[:2] for c in vpn2.runner.calls]
    assert cmds == [["nft", "-f"], ["wg-quick", "up"]], cmds
    st = vpn2.status()
    assert "latest handshake" in st
    try:
        vpn2.up({})
        raise SystemExit("podwójne up przeszło!")
    except MullvadError:
        pass
    print("  [OK] 6. up(): mur → tunel (w tej kolejności); podwójne up odrzucone")

    # 7) down: odwrotna kolejność + shred configu + token wyzerowany
    tok_before = bytes(vpn2._token)
    vpn2.down()
    cmds_down = [c[:3] for c in vpn2.runner.calls[3:]]     # [0..2] = nft -f, wg-quick up, wg show
    assert cmds_down[0][:2] == ["wg-quick", "down"] and cmds_down[1] == ["nft", "delete", "table"], cmds_down
    assert not conf_path.exists() and not (vpn2.run_dir / "killswitch.nft").exists()
    assert bytes(vpn2._token) == b"\x00" * len(tok_before) and tok_before != bytes(vpn2._token)
    print("  [OK] 7. down(): tunel → mur zdjęty, config shred 2×, token wyzerowany w RAM")

    # 8) brak/wadliwy konta
    for bad in ("", "abcd1234", "  "):
        try:
            MullvadVPN(bad, run_dir=_pl.Path("/tmp/x"), http=StubHttpClient(), runner=StubRunner())
            raise SystemExit(f"konto {bad!r} przeszło!")
        except MullvadError:
            pass
    print("  [OK] 8. numer konta: pusty/nie-cyfry odrzucone (Mullvad = 16 cyfr, nie email)")

    # 9) up po down działa znowu (świeża sesja)
    vpn3 = MullvadVPN("1234567812345678", run_dir=_pl.Path(tempfile.mkdtemp(prefix="mv-re-")),
                      http=StubHttpClient(), runner=StubRunner())
    vpn3.up({"country": "nl"})
    assert vpn3.session.endpoint.startswith("146.70.99.3")
    vpn3.down()
    vpn3.up({})
    assert vpn3.session is not None
    vpn3.down()
    print("  [OK] 9. cykl up→down→up (inny kraj): sesje świeże, stany czyste")

    print("\nSELFTEST: PASS ✅  Mullvad/WireGuard: klucze, API, kill switch, higiena tokena")
    print("NOTE: prawdziwe up() (root + konto + sieć) = QA na maszynie właściciela [TODO ~]")
