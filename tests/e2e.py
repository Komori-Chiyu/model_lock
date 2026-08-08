#!/usr/bin/env python3
"""Offline end-to-end: artist issues code -> packs signed licensed .vkit -> buyer verifies locally."""
import base64
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from packager.ledger import Ledger
from packager.vkit import (
    make_vreq,
    pack_model,
    read_header,
    unpack_model,
    verify_author,
    verify_license,
)


def main():
    tmp = Path(tempfile.mkdtemp(prefix="modelock-offline-e2e-"))
    print("workdir:", tmp)

    # 1) buyer device key + vreq
    buyer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    vreq = make_vreq(buyer.public_key())
    (tmp / "buyer.vreq").write_text(json.dumps(vreq))

    # 2) artist key + ledger code bound to buyer key
    author = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ledger = Ledger(tmp / "license_records.db")
    code = ledger.gen_codes("小樱", vreq["key_id"], note="阿花")[0]
    print("activation code:", code)

    # 3) pack with license (code + expiry), signed by author
    model_dir = tmp / "model"
    (model_dir / "expressions").mkdir(parents=True)
    (model_dir / "model.model3.json").write_text(
        json.dumps({"Version": 3, "FileReferences": {"Moc": "model.moc3"}})
    )
    (model_dir / "model.moc3").write_bytes(os.urandom(4096))
    (model_dir / "textures" / "skin.png").parent.mkdir(parents=True)
    (model_dir / "textures" / "skin.png").write_bytes(os.urandom(65536))
    pkg = tmp / "小樱-阿花.vkit"
    pack_model(
        model_dir, [vreq], model_id="小樱", output=pkg,
        author_private_key=author, code=code, expires_at="2099-12-31",
        ledger_path=tmp / "license_records.db",
    )
    header, _ = read_header(pkg)
    print("packed:", len(header.files), "files; license bound to", header.license["key_id"][:8])

    # 4) buyer local verification (this is what the client does offline)
    spki = author.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    verify_author(header, spki)
    lic = verify_license(header, vreq["key_id"], code)
    print("author signature OK; license OK; expires:", lic["expires_at"])

    # wrong code must fail
    try:
        verify_license(header, vreq["key_id"], "ML-WRONG")
        raise SystemExit("FAIL: wrong code accepted")
    except Exception:
        print("wrong code correctly rejected")

    # 5) decrypt roundtrip on buyer device
    outdir = tmp / "unpacked"
    unpack_model(pkg, buyer, outdir)
    for rel in ["model.model3.json", "model.moc3", "textures/skin.png"]:
        assert (outdir / rel).read_bytes() == (model_dir / rel).read_bytes(), rel
    print("roundtrip OK")

    # 6) code cannot be reused for a different buyer (ledger binding)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    vreq2 = make_vreq(other.public_key())
    try:
        pack_model(
            model_dir, [vreq2], model_id="小樱", output=tmp / "x.vkit",
            code=code, ledger_path=tmp / "license_records.db",
        )
        raise SystemExit("FAIL: same code reused for another buyer")
    except Exception:
        print("code reuse for another buyer correctly rejected")

    shutil.rmtree(tmp, ignore_errors=True)
    print("OFFLINE E2E PASS")


if __name__ == "__main__":
    main()
