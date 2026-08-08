import io
import json
import os
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from packager.vkit import (
    BLOCK_SIZE,
    IntegrityError,
    RecipientMismatch,
    VkitError,
    key_id_of_spki,
    load_vreq,
    make_vreq,
    pack_model,
    read_header,
    unpack_model,
    validate_relative_path,
    verify_author,
)


def make_model_dir(root: Path, nfiles: int = 3, big: bool = False):
    d = root / "model"
    (d / "expressions").mkdir(parents=True, exist_ok=True)
    (d / "model.model3.json").write_text(
        json.dumps({"Version": 3, "FileReferences": {"Moc": "model.moc3"}})
    )
    (d / "model.moc3").write_bytes(os.urandom(64 * 1024))
    (d / "textures" / "tex.png").parent.mkdir(exist_ok=True)
    (d / "textures" / "tex.png").write_bytes(os.urandom(256 * 1024))
    (d / "expressions" / "angry.json").write_text('{"type":"Live2D Expression"}')
    if big:
        with open(d / "big.bin", "wb") as fh:
            for _ in range(3):
                fh.write(os.urandom(BLOCK_SIZE))
    return d


class VkitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vkit-test-")
        self.root = Path(self.tmp)
        self.buyer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.vreq = make_vreq(self.buyer_key.public_key())
        self.model = make_model_dir(self.root)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _pack(self, **kw):
        out = self.root / "out.vkit"
        pack_model(
            self.model, [self.vreq], model_id="test", output=out,
            block_size=BLOCK_SIZE, **kw,
        )
        return out

    def test_roundtrip(self):
        pkg = self._pack()
        outdir = self.root / "unpacked"
        unpack_model(pkg, self.buyer_key, outdir)
        for rel in ["model.model3.json", "model.moc3", "textures/tex.png",
                    "expressions/angry.json"]:
            self.assertEqual(
                (self.model / rel).read_bytes(), (outdir / rel).read_bytes(),
                rel,
            )

    def test_big_multiblock_roundtrip(self):
        self.model = make_model_dir(self.root, big=True)
        pkg = self._pack()
        outdir = self.root / "unpacked"
        unpack_model(pkg, self.buyer_key, outdir)
        self.assertEqual((self.model / "big.bin").read_bytes(),
                         (outdir / "big.bin").read_bytes())

    def test_wrong_key_rejected(self):
        pkg = self._pack()
        with self.assertRaises(RecipientMismatch):
            unpack_model(pkg, self.other_key, self.root / "x")

    def test_tamper_detected(self):
        pkg = self._pack()
        data = bytearray(pkg.read_bytes())
        # Flip a byte in the data region (after prefix + header).
        prefix = struct.unpack("<4sIQQ", bytes(data[:24]))
        header_len, data_len = prefix[2], prefix[3]
        data[24 + header_len + 10] ^= 0xFF
        tampered = self.root / "tampered.vkit"
        tampered.write_bytes(data)
        with self.assertRaises(IntegrityError):
            unpack_model(tampered, self.buyer_key, self.root / "y")

    def test_multiple_recipients(self):
        vreq2 = make_vreq(self.other_key.public_key())
        out = self.root / "multi.vkit"
        pack_model(self.model, [self.vreq, vreq2], model_id="m", output=out)
        for key in (self.buyer_key, self.other_key):
            unpack_model(out, key, self.root / f"out-{key is self.buyer_key}")

    def test_author_signature_verify(self):
        author = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pkg = self._pack(author_private_key=author)
        header, _ = read_header(pkg)
        spki = author.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        verify_author(header, spki)  # must not raise
        with self.assertRaises(IntegrityError):
            verify_author(header, key_id_of_spki(spki).encode())  # wrong pin

    def test_path_rules_reject_evil(self):
        for bad in [
            "../escape.txt",
            "a/b/../../c",
            "bad\\name",
            "bad:name",
            "bad?name",
            "a//b",
            "/abs",
            "a/" + "x" * 300,
            "ctrl\x00char",
        ]:
            with self.assertRaises(VkitError, msg=bad):
                validate_relative_path(bad)
        self.assertEqual(validate_relative_path("a/b/c.json"), "a/b/c.json")
        self.assertEqual(validate_relative_path("模型/贴图.png"), "模型/贴图.png")
    def test_case_insensitive_collision(self):
        evil = self.root / "case"
        (evil / "A.txt").parent.mkdir(parents=True)
        (evil / "A.txt").write_text("a")
        (evil / "a.txt").write_text("b")
        with self.assertRaises(VkitError):
            pack_model(evil, [self.vreq], model_id="c", output=self.root / "c.vkit")

    def test_vreq_validation(self):
        (self.root / "r.vreq").write_text(json.dumps(self.vreq))
        self.assertEqual(load_vreq(self.root / "r.vreq")["key_id"], self.vreq["key_id"])


if __name__ == "__main__":
    unittest.main()
