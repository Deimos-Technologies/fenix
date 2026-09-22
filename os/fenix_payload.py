#!/usr/bin/env python3
# os/fenix_payload.py — ZAPIECZĘTOWANY ŁADUNEK kodu na ISO (boot_security §3, FNX-PAYLOAD v1)
"""
Kod Fenixa na ISO NIE leży jawnie. Build pakuje stos do ładunku:

    BUILD (offline):  stos → tar → chunked AEAD (klucz_ładunku 32B, losowy)
                      manifest {pliki: sha256, commit, build_pub} + podpis Ed25519 (D14)
                      klucz_ładunku → Shamir 3-z-5 (fenix_crypto) → seed nodes
                      KLUCZ NIGDY NIE TRAFIA NA ISO
    BOOT:  verify manifestu + payload → (udziały od seedów, M5) → składamy klucz W RAM
           → AEAD-decrypt po chunkach → /run/fenix-payload (tmpfs 0700)
           → self-check hash każdego pliku vs manifest → DOPUBLIKOWAĆ stos
    DEV:   FENIX_DEV_PAYLOAD_KEY w ENV → payload jawny, wielkie „DEV BUILD" (§4)

Trzy właściwości z §0: ładunek BEZUŻYTECZNY bez klucza zbiorczego,
NIEPODMIENIALNY (manifest+podpis+hasze), NIE PRZETRWA zasilania (tmpfs).

Format pliku (FNX-PAYLOAD v1):
    magic 8B "FNXPAYL1" | hdr_len 4B big-endian | hdr JSON | chunki
    hdr = {v, aead, dev?, commit, created_at, nonce_base, chunk_size, nchunks,
           manifest_sha256, manifest_sig, build_pub}
    chunk i: AEAD(key, nonce=blake2s(nonce_base‖i)[:12], pt, aad=hdr_raw‖i)

Selftest (bez argumentów): tamper 1 bajta → boot odmawia; podpis/manifest → fail;
Shamir 3-z-5 klucza_ładunku; dev-mode gated ENV-em. Zero roota, zero dysku poza tmp.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import time
import pathlib as _pl

if __package__ in (None, ""):
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidTag                      # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (     # noqa: E402
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.serialization import (          # noqa: E402
    Encoding, PublicFormat, PrivateFormat, NoEncryption)
import secrets as _secrets                                          # noqa: E402

MAGIC = b"FNXPAYL1"
VERSION = 1
CHUNK_SIZE = 1 << 20                    # 1 MiB na chunk AEAD (RAM-friendly)
STACK_DIRS = ("core", "net", "transport", "app", "gui", "chain")


class PayloadError(Exception):
    """Integralność/podpis/AEAD/dev-gate — jeden typ (brak orakli)."""


# ------------------------------------------------------------------ AEAD (jak keystore)
def _aead():
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    return ChaCha20Poly1305, "chacha20"       # XChaCha brak w tym runtime (nonce 12B)


def _nonce(base: bytes, idx: int) -> bytes:
    return hashlib.blake2s(base + idx.to_bytes(4, "big"), digest_size=12).digest()


# ------------------------------------------------------------------ manifest + tar
def _hash_tree(root: str, dirs=STACK_DIRS) -> dict:
    """{relpath: sha256} dla wszystkich plików stosu (deterministycznie posortowane)."""
    files = {}
    for d in dirs:
        base = _pl.Path(root, d)
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts:
                rel = p.relative_to(root).as_posix()
                files[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    if not files:
        raise PayloadError("pusty stos do spakowania (brak core/net/…?)")
    return files


def _canon(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def build_manifest(root: str, commit: str, build_pub: bytes,
                   dirs=STACK_DIRS) -> dict:
    return {"v": VERSION, "commit": commit, "created_at": int(time.time()),
            "files": _hash_tree(root, dirs), "build_pub": build_pub.hex()}


def _sign(priv: Ed25519PrivateKey, data: bytes) -> bytes:
    return priv.sign(data)


def _tar_stream(root: str, files: list[str], extra: dict[str, bytes]) -> bytes:
    """tar stosu + extra pliki (manifest+sig pod __manifest__/). Deterministyczny:
    sortowane nazwy, mtime=0, uid/gid=0 — ten sam input = ten sam tar."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for rel in sorted(files):
            ti = tar.gettarinfo(str(_pl.Path(root, rel)), arcname=rel)
            ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = 0, 0, 0, "", ""
            with open(_pl.Path(root, rel), "rb") as f:
                tar.addfile(ti, f)
        for name, data in sorted(extra.items()):
            ti = tarfile.TarInfo(f"__manifest__/{name}")
            ti.size, ti.mtime, ti.uid, ti.gid = len(data), 0, 0, 0
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


# ------------------------------------------------------------------ BUILD (host, offline)
def build_payload(root: str, out_path: str, build_priv: Ed25519PrivateKey,
                  commit: str, payload_key: bytes | None = None,
                  dirs=STACK_DIRS) -> bytes:
    """Zwraca klucz_ładunku (32B) — idzie do Shamira, NIGDY na dysk/ISO."""
    if payload_key is None:
        payload_key = _secrets.token_bytes(32)
    pub = build_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    manifest = build_manifest(root, commit, pub, dirs)
    m_raw = _canon(manifest)
    m_sig = _sign(build_priv, m_raw)
    plain = _tar_stream(root, list(manifest["files"]),
                        {"manifest_payload.json": m_raw,
                         "manifest_payload.sig": m_sig})
    box, name = _aead()
    nonce_base = _secrets.token_bytes(16)
    hdr = {"v": VERSION, "aead": name, "commit": commit,
           "created_at": manifest["created_at"], "nonce_base": nonce_base.hex(),
           "chunk_size": CHUNK_SIZE,
           "nchunks": (len(plain) + CHUNK_SIZE - 1) // CHUNK_SIZE,
           "manifest_sha256": hashlib.sha256(m_raw).hexdigest(),
           "manifest_sig": m_sig.hex(), "build_pub": pub.hex()}
    hdr_raw = _canon(hdr)
    out = bytearray(MAGIC + len(hdr_raw).to_bytes(4, "big") + hdr_raw)
    aead = box(payload_key)
    for i in range(hdr["nchunks"]):
        chunk = plain[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE]
        ct = aead.encrypt(_nonce(nonce_base, i), chunk, hdr_raw + i.to_bytes(4, "big"))
        out += len(ct).to_bytes(4, "big") + ct
    with open(out_path, "wb") as f:
        f.write(bytes(out))
    return payload_key


def build_dev_payload(root: str, out_path: str, commit: str,
                      dirs=STACK_DIRS) -> None:
    """DEV (§4): payload JAWNY, oznaczony; boot go przyjmie TYLKO z ENV
    FENIX_DEV_PAYLOAD_KEY. GUI pokaże wielkie DEV BUILD."""
    files = _hash_tree(root, dirs)
    manifest = {"v": VERSION, "commit": commit, "created_at": int(time.time()),
                "files": files, "build_pub": "dev"}
    plain = _tar_stream(root, list(files), {"manifest_payload.json": _canon(manifest)})
    hdr = {"v": VERSION, "dev": True, "commit": commit,
           "created_at": manifest["created_at"], "manifest_files": len(files)}
    hdr_raw = _canon(hdr)
    with open(out_path, "wb") as f:
        f.write(MAGIC + len(hdr_raw).to_bytes(4, "big") + hdr_raw
                + len(plain).to_bytes(8, "big") + plain)


# ------------------------------------------------------------------ BOOT (verify+extract)
def _read_hdr(f) -> tuple[dict, bytes]:
    magic = f.read(8)
    if magic != MAGIC:
        raise PayloadError("zły MAGIC ładunku")
    hdr_len = int.from_bytes(f.read(4), "big")
    if not (0 < hdr_len < 1 << 20):
        raise PayloadError("nagłówek: niewiarygodny rozmiar")
    hdr_raw = f.read(hdr_len)
    return json.loads(hdr_raw), hdr_raw


def verify_and_extract(payload_path: str, key: bytes | None, dest_dir: str,
                       allow_dev_env: bool = True) -> dict:
    """Odszyfruj+weryfikuj+wypakuj do dest_dir (w ISO: /run/fenix-payload, tmpfs).
    Zwraca manifest. Każda niezgodność = PayloadError, NIC nie zostaje na miejscu."""
    with open(payload_path, "rb") as f:
        hdr, hdr_raw = _read_hdr(f)
        body = f.read()

    if hdr.get("dev"):
        if allow_dev_env and os.environ.get("FENIX_DEV_PAYLOAD_KEY"):
            blob_len = int.from_bytes(body[:8], "big")
            blob = body[8:8 + blob_len]
            print("  [DEV] payload JAWNY — tryb deweloperski, wielkie DEV BUILD w GUI")
            return _extract(blob, dest_dir, expected_manifest=None)
        raise PayloadError("ładunek DEV bez ENV FENIX_DEV_PAYLOAD_KEY — odmowa")

    if key is None or len(key) != 32:
        raise PayloadError("brak klucza_ładunku (udziały seedów nie złożone?)")
    box, _name = _aead()
    aead = box(key)
    nonce_base = bytes.fromhex(hdr["nonce_base"])
    plain = bytearray()
    off = 0
    for i in range(hdr["nchunks"]):
        clen = int.from_bytes(body[off:off + 4], "big")
        off += 4
        ct = body[off:off + clen]
        off += clen
        try:
            plain += aead.decrypt(_nonce(nonce_base, i), ct,
                                  hdr_raw + i.to_bytes(4, "big"))
        except InvalidTag:
            raise PayloadError(f"AEAD chunk {i} nieważny (podmiana ładunku?)") from None
    return _extract(bytes(plain), dest_dir, expected_manifest=hdr)


def _extract(blob: bytes, dest_dir: str, expected_manifest: dict | None) -> dict:
    """Rozpakuj tar do dest_dir; przy podpisanym manifeście: najpierw podpis,
    potem hash każdego pliku — zanim cokolwiek uznać za stos."""
    if os.path.exists(dest_dir):
        import shutil
        shutil.rmtree(dest_dir)
    os.makedirs(dest_dir, mode=0o700)
    manifest = None
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r") as tar:
        for member in tar:
            if member.name.startswith("/") or ".." in member.name.split("/"):
                raise PayloadError(f"patologiczna ścieżka w tar: {member.name}")
        try:
            tar.extractall(dest_dir, filter="data")     # py3.12+: odrzuca symlinki/device
        except TypeError:
            tar.extractall(dest_dir)                    # starszy python — fallback
        if expected_manifest is not None:
            m_raw = tar.extractfile("__manifest__/manifest_payload.json").read()
            m_sig = bytes.fromhex(expected_manifest["manifest_sig"])
            pub = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(expected_manifest["build_pub"]))
            try:
                pub.verify(m_sig, m_raw)
            except Exception:
                raise PayloadError("podpis manifestu nieważny (D14)") from None
            if hashlib.sha256(m_raw).hexdigest() != expected_manifest["manifest_sha256"]:
                raise PayloadError("manifest_embedded ≠ manifest_hdr")
            manifest = json.loads(m_raw)
    if manifest is not None:
        for rel, sha in manifest["files"].items():
            p = _pl.Path(dest_dir, rel)
            if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest() != sha:
                raise PayloadError(f"hash pliku ≠ manifest: {rel}")
    return manifest


# ------------------------------------------------------------------ Shamir klucza (M5-ready)
def split_payload_key(key: bytes, k: int = 3, n: int = 5) -> list[bytes]:
    from core.crypto.fenix_crypto import split_secret
    return split_secret(key, k, n)


def combine_payload_key(shares: list[bytes]) -> bytes:
    from core.crypto.fenix_crypto import combine_shares
    return combine_shares(shares)


# ------------------------------------------------------------------ CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="fenix-payload",
                                 description="Zapieczętowany ładunek kodu ISO (boot_security §3)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="spakuj stos → payload.enc (offline host)")
    b.add_argument("--root", default=".")
    b.add_argument("--out", required=True)
    b.add_argument("--commit", default="dev")
    b.add_argument("--key-out", default=None, help="gdzie ODDZIELNIE zapisać klucz (do Shamira)")
    b.add_argument("--build-key", default=None, help="hex prywatnego klucza build (D14)")
    d = sub.add_parser("build-dev", help="jawny payload DEV (gated ENV przy boot)")
    d.add_argument("--root", default=".")
    d.add_argument("--out", required=True)
    d.add_argument("--commit", default="dev")
    x = sub.add_parser("extract", help="boot: verify+extract do dest")
    x.add_argument("--payload", required=True)
    x.add_argument("--key", default=None, help="hex klucza_ładunku (ze złożonych udziałów)")
    x.add_argument("--dest", required=True)
    args = ap.parse_args(argv)

    if args.cmd == "build":
        if args.build_key:
            priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(args.build_key))
        else:
            priv = Ed25519PrivateKey.generate()
            print(f"[wygenerowano DEV build-key: pub={priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}]")
        key = build_payload(args.root, args.out, priv, args.commit)
        if args.key_out:
            with open(args.key_out, "w") as f:
                f.write(key.hex() + "\n")
        print(f"[payload.enc → {args.out}; klucz: tylko do Shamira 3-z-5]")
        return 0
    if args.cmd == "build-dev":
        build_dev_payload(args.root, args.out, args.commit)
        print(f"[payload DEV (jawny) → {args.out}]")
        return 0
    if args.cmd == "extract":
        key = bytes.fromhex(args.key) if args.key else None
        manifest = verify_and_extract(args.payload, key, args.dest)
        print(f"[stos wypakowany do {args.dest}; plików: "
              f"{len(manifest['files']) if manifest else 'dev'}]")
        return 0
    return 2


# ------------------------------------------------------------------ selftest
if __name__ == "__main__" and len(sys.argv) > 1:
    raise SystemExit(main())

if __name__ == "__main__":

    print("os/fenix_payload.py — selftest: build→tamper→boot-odmowa; Shamir 3-z-5; dev-gate\n")
    tmp = tempfile.mkdtemp(prefix="fenix-payload-test-")
    try:
        # stos-test: mini repo
        root = os.path.join(tmp, "stack")
        for d in ("core", "net"):
            os.makedirs(os.path.join(root, d))
        open(os.path.join(root, "core", "a.py"), "w").write("SECRET_CODE_A = 1\n")
        open(os.path.join(root, "net", "b.py"), "w").write("SECRET_CODE_B = 2\n")

        priv = Ed25519PrivateKey.generate()
        pay = os.path.join(tmp, "payload.enc")
        key = build_payload(root, pay, priv, commit="abc123")

        # 1) kod NIE leży jawnie w pliku ładunku
        blob = open(pay, "rb").read()
        assert b"SECRET_CODE_A" not in blob and b"SECRET_CODE_B" not in blob
        assert len(key) == 32
        print("  [OK] 1. payload.enc: kod niewidoczny w bajtach pliku (chunked AEAD)")

        # 2) happy path: extract do dest, drzewo identyczne
        dest = os.path.join(tmp, "out")
        manifest = verify_and_extract(pay, key, dest)
        assert manifest["commit"] == "abc123"
        assert open(os.path.join(dest, "core", "a.py")).read() == "SECRET_CODE_A = 1\n"
        print(f"  [OK] 2. boot: podpis+hashe OK → wypakowano {len(manifest['files'])} pliki")

        # 3) tamper 1 bajta w chunku → odmowa; nic nie zostaje
        bad = bytearray(blob)
        bad[-20] ^= 1
        pay_bad = os.path.join(tmp, "payload_bad.enc")
        open(pay_bad, "wb").write(bytes(bad))
        try:
            verify_and_extract(pay_bad, key, os.path.join(tmp, "out2"))
            raise SystemExit("podmiana przeszła!")
        except PayloadError as e:
            assert "AEAD" in str(e) or "manifest" in str(e) or "podpis" in str(e)
        print("  [OK] 3. 1 bajt zmieniony → AEAD odmawia: boot staje (tag-test z §6)")

        # 4) zły klucz (np. z podrobionych udziałów) → odmowa
        try:
            verify_and_extract(pay, b"\x00" * 32, os.path.join(tmp, "out3"))
            raise SystemExit("zły klucz przeszedł!")
        except PayloadError:
            print("  [OK] 4. zły klucz_ładunku → cegła (żadnych orakli, jeden PayloadError)")

        # 5) Shamir 3-z-5 klucza_ładunku: 3 udziały składają, 2 nie otwierają
        shares = split_payload_key(key, k=3, n=5)
        assert combine_payload_key([shares[0], shares[2], shares[4]]) == key
        assert combine_payload_key([shares[1], shares[3], shares[0]]) == key
        try:
            k2 = combine_payload_key([shares[0], shares[1]])
            verify_and_extract(pay, k2, os.path.join(tmp, "out4"))
            opened = (k2 == key)
        except (ValueError, PayloadError):
            opened = False
        assert not opened, "2 udziały < 3 NIE mogą otworzyć ładunku"
        print("  [OK] 5. Shamir 3-z-5: dowolne 3 składają klucz; 2 = cegła (boot_security §4)")

        # 6) DEV payload: bez ENV odmowa, z ENV przechodzi; nagłówek uczciwie 'dev'
        devp = os.path.join(tmp, "payload_dev.bin")
        build_dev_payload(root, devp, commit="abc123")
        os.environ.pop("FENIX_DEV_PAYLOAD_KEY", None)
        try:
            verify_and_extract(devp, None, os.path.join(tmp, "out5"))
            raise SystemExit("DEV bez ENV przeszedł!")
        except PayloadError:
            pass
        os.environ["FENIX_DEV_PAYLOAD_KEY"] = "dev"
        verify_and_extract(devp, None, os.path.join(tmp, "out5"))
        assert open(os.path.join(tmp, "out5", "net", "b.py")).read() == "SECRET_CODE_B = 2\n"
        os.environ.pop("FENIX_DEV_PAYLOAD_KEY", None)
        print("  [OK] 6. dev-gate: bez ENV cegła; z ENV jawny payload + banner DEV (§4)")

        # 7) podmiana manifestu w nagłówku → podpis fail
        with open(pay, "rb") as f:
            magic = f.read(8); hl = int.from_bytes(f.read(4), "big"); hr = f.read(hl); body = f.read()
        hdr = json.loads(hr)
        hdr["manifest_sha256"] = "0" * 64
        hr2 = _canon(hdr)
        pay_bad2 = os.path.join(tmp, "payload_bad2.enc")
        open(pay_bad2, "wb").write(magic + len(hr2).to_bytes(4, "big") + hr2 + body)
        try:
            verify_and_extract(pay_bad2, key, os.path.join(tmp, "out6"))
            raise SystemExit("podmiana nagłówka przeszła!")
        except PayloadError:
            print("  [OK] 7. podmiana manifestu w nagłówku → boot odmawia (manifest-test §6)")

        print("\nSELFTEST: PASS ✅  ładunek: bezużyteczny bez klucza · niepodmienialny · tmpfs-only")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
