#!/usr/bin/env python3
"""End-to-end: server issues code -> buyer activates -> artist packs -> buyer unpacks."""
import base64
import json
import os
import shutil
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from packager.vkit import make_vreq, pack_model, unpack_model, read_header
from server.server import Store, ModelLockServer, make_handler


def post(port, path, body):
    import urllib.request
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


def main():
    tmp = Path(tempfile.mkdtemp(prefix="modelock-e2e-"))
    print("workdir:", tmp)

    # 1) buyer key + vreq
    buyer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    vreq = make_vreq(buyer.public_key())
    (tmp / "buyer.vreq").write_text(json.dumps(vreq))

    # 2) server + activation code
    db = tmp / "e2e.db"
    admin = "e2e-admin"
    store = Store(str(db))
    api = ModelLockServer(store, admin, b"e2e-secret", token_ttl=3600)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(api))
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        codes = post(port, "/api/admin/codes", {
            "admin_key": admin, "model_id": "小樱", "count": 1, "max_devices": 1,
        })["codes"]
        code = codes[0]
        print("activation code:", code)

        # 3) buyer activates from device A
        spki_b64 = base64.b64encode(
            buyer.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode()
        act = post(port, "/api/activate", {
            "code": code, "device_id": "device-A",
            "pubkey_spki": spki_b64,
            "hwids": {"machine_guid": "fake-guid"},
        })
        token = act["token"]
        print("activated model:", act["model_id"])

        # 4) device B must be rejected (one code one device)
        try:
            post(port, "/api/activate", {
                "code": code, "device_id": "device-B",
                "pubkey_spki": spki_b64,
            })
            raise SystemExit("FAIL: device B should have been rejected")
        except Exception as exc:
            assert "403" in str(exc) or "DEVICE_MISMATCH" in str(exc), exc
            print("device B correctly rejected")

        # 5) artist packs the model for this buyer
        model_dir = tmp / "model"
        (model_dir / "expressions").mkdir(parents=True)
        (model_dir / "model.model3.json").write_text(
            json.dumps({"Version": 3, "FileReferences": {"Moc": "model.moc3"}})
        )
        (model_dir / "model.moc3").write_bytes(os.urandom(4096))
        (model_dir / "textures" / "skin.png").parent.mkdir(parents=True)
        (model_dir / "textures" / "skin.png").write_bytes(os.urandom(65536))
        author = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pkg = tmp / "小樱-买家.vkit"
        pack_model(model_dir, [vreq], model_id="小樱", output=pkg, author_private_key=author)
        header, _ = read_header(pkg)
        print(f"packed: {len(header.files)} files, recipients={len(header.recipients)}")

        # 6) buyer decrypts on this device
        outdir = tmp / "unpacked"
        unpack_model(pkg, buyer, outdir)
        for rel in ["model.model3.json", "model.moc3", "textures/skin.png"]:
            assert (outdir / rel).read_bytes() == (model_dir / rel).read_bytes(), rel
        print("roundtrip OK")

        # 7) token refresh
        refreshed = post(port, "/api/refresh", {"token": token})["token"]
        assert refreshed != token
        print("token refresh OK")
    finally:
        httpd.shutdown()
        httpd.server_close()
        shutil.rmtree(tmp, ignore_errors=True)
    print("E2E PASS")


if __name__ == "__main__":
    main()
