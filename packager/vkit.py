"""VKIT: per-recipient encrypted Live2D model package format.

Format (v1)
-----------
All integers are little-endian.

  prefix (24 bytes):
    u32  magic         = b"VKIT"
    u32  version       = 1
    u64  header_len
    u64  data_len
  header (header_len bytes): UTF-8 JSON (see build_header)
  data (data_len bytes):
    for each file in header["files"] order:
      for each block in file["blocks"]:
        ciphertext(block_len)  -- AES-256-GCM, nonce+tag live in header

Security properties:
  * Content key (CEK, 32 random bytes) is wrapped for every recipient with
    RSA-OAEP(SHA-256).  A package contains no key material that a non-recipient
    can derive, so forwarding the file to another machine is useless.
  * Each 1 MiB block is independently authenticated with AAD =
    "VKIT1" || file_path || block_index, preventing block swapping/tampering.
  * The artist may sign the header (RSASSA-PSS).  The client verifies the
    signature when an author public key is pinned.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import tempfile
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from shutil import copyfileobj
from typing import Dict, Iterable, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"VKIT"
VERSION = 1
BLOCK_SIZE = 1024 * 1024  # 1 MiB
PREFIX = struct.Struct("<4sIQQ")  # magic, version, header_len, data_len
KEY_ID_BYTES = 16

FORBIDDEN_WIN_CHARS = set('\\/:*?"<>|')
MAX_COMPONENT_UTF16 = 255
MAX_PATH_UTF16 = 4096


class VkitError(Exception):
    """Base class for package errors."""


class FormatError(VkitError):
    """Malformed package / request file."""


class RecipientMismatch(VkitError):
    """Package is not encrypted for the supplied key."""


class IntegrityError(VkitError):
    """Authentication failed (tampered or wrong key)."""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str, what: str = "base64") -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:  # pragma: no cover - trivial
        raise FormatError(f"invalid {what}") from exc


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def key_id_of_spki(spki_der: bytes) -> str:
    """First KEY_ID_BYTES of SHA-256(spki) as 32 hex chars."""
    return hashlib.sha256(spki_der).hexdigest()[: KEY_ID_BYTES * 2]


def load_vreq(path: Path) -> Dict:
    """Load and validate a buyer request file (.vreq)."""
    raw = path.read_bytes()
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FormatError("vreq is not valid UTF-8 JSON") from exc
    if not isinstance(doc, dict) or doc.get("magic") != "VREQ":
        raise FormatError("vreq magic mismatch")
    if doc.get("version") != 1:
        raise FormatError("vreq version not supported")
    spki = _b64d(doc.get("spki", ""), "vreq spki")
    try:
        pub = serialization.load_der_public_key(spki)
    except ValueError as exc:
        raise FormatError("vreq spki is not a valid public key") from exc
    if not isinstance(pub, rsa.RSAPublicKey) or pub.key_size < 2040:
        raise FormatError("vreq must contain an RSA-2048 public key")
    if doc.get("algorithm") != "RSA-2048":
        raise FormatError("vreq algorithm must be RSA-2048")
    expected = key_id_of_spki(spki)
    if doc.get("key_id", "").lower() != expected:
        raise FormatError("vreq key_id does not match embedded public key")
    return {"key_id": expected, "spki_der": spki, "public_key": pub}


def make_vreq(public_key: rsa.RSAPublicKey, created_at: Optional[str] = None) -> Dict:
    """Serialize a request file (used by tests and the artist-side demo)."""
    spki = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "magic": "VREQ",
        "version": 1,
        "algorithm": "RSA-2048",
        "key_id": key_id_of_spki(spki),
        "spki": _b64(spki),
        "created_at": created_at or now_iso(),
    }


def validate_relative_path(path: str) -> str:
    """Validate one package-relative POSIX path against protocol rules."""
    if not path or path.startswith("/") or path.startswith("\\"):
        raise FormatError(f"path must be relative: {path!r}")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in path):
        raise FormatError(f"path contains control character: {path!r}")
    raw_parts = path.split("/")
    if any(not p for p in raw_parts):
        raise FormatError(f"path contains empty component: {path!r}")
    parts = raw_parts
    if not parts:
        raise FormatError(f"empty path: {path!r}")
    for part in parts:
        if part in (".", ".."):
            raise FormatError(f"path contains '.' or '..': {path!r}")
        if any(ch in FORBIDDEN_WIN_CHARS for ch in part):
            raise FormatError(f"path component contains forbidden character: {part!r}")
        if len(part.encode("utf-16-le")) // 2 > MAX_COMPONENT_UTF16:
            raise FormatError(f"path component too long: {part!r}")
    if len(path.encode("utf-16-le")) // 2 > MAX_PATH_UTF16:
        raise FormatError(f"path too long: {path!r}")
    return "/".join(parts)


def collect_files(root: Path) -> List[Tuple[str, Path]]:
    """Walk a model directory into validated relative paths (sorted, unique)."""
    found: List[Tuple[str, Path]] = []
    seen: Dict[str, str] = {}
    for base, dirs, files in os.walk(root):
        dirs.sort()
        files.sort()
        for name in files:
            rel = os.path.relpath(os.path.join(base, name), root).replace("\\", "/")
            rel = validate_relative_path(rel)
            lower = rel.lower()
            if lower in seen:
                raise FormatError(
                    f"case-insensitive name collision: {seen[lower]!r} vs {rel!r}"
                )
            seen[lower] = rel
            found.append((rel, Path(base) / name))
    # Prefix conflicts: "a" (file) vs "a/b" (file under dir named "a").
    prefixes = set()
    for rel, _ in found:
        parts = rel.split("/")
        for i in range(1, len(parts)):
            prefixes.add("/".join(parts[:i]))
    for rel, _ in found:
        if rel in prefixes:
            raise FormatError(f"file/directory prefix conflict: {rel!r}")
    found.sort(key=lambda item: item[0])
    return found


def _aad(path: str, block_index: int) -> bytes:
    return b"VKIT1" + path.encode("utf-8") + struct.pack("<Q", block_index)


@dataclass
class BlockMeta:
    index: int
    nonce: bytes
    tag: bytes
    length: int  # plaintext/ciphertext length

    def to_json(self) -> Dict:
        return {"i": self.index, "n": _b64(self.nonce), "t": _b64(self.tag), "l": self.length}

    @classmethod
    def from_json(cls, doc: Dict) -> "BlockMeta":
        return cls(
            index=int(doc["i"]),
            nonce=_b64d(doc["n"], "block nonce"),
            tag=_b64d(doc["t"], "block tag"),
            length=int(doc["l"]),
        )


@dataclass
class FileMeta:
    path: str
    size: int
    data_offset: int
    blocks: List[BlockMeta] = field(default_factory=list)

    def to_json(self) -> Dict:
        return {
            "path": self.path,
            "size": self.size,
            "offset": self.data_offset,
            "blocks": [b.to_json() for b in self.blocks],
        }

    @classmethod
    def from_json(cls, doc: Dict) -> "FileMeta":
        return cls(
            path=str(doc["path"]),
            size=int(doc["size"]),
            data_offset=int(doc["offset"]),
            blocks=[BlockMeta.from_json(b) for b in doc["blocks"]],
        )


@dataclass
class PackageHeader:
    model_id: str
    created_at: str
    block_size: int
    recipients: List[Dict]
    files: List[FileMeta]
    author_public_key: Optional[bytes] = None
    author_signature: Optional[bytes] = None
    note: str = ""

    def to_json(self, with_signature: bool = True) -> Dict:
        doc: Dict = {
            "magic": "VKIT",
            "version": VERSION,
            "model_id": self.model_id,
            "created_at": self.created_at,
            "block_size": self.block_size,
            "recipients": self.recipients,
            "files": [f.to_json() for f in self.files],
            "note": self.note,
        }
        if self.author_public_key is not None:
            doc["author_public_key"] = _b64(self.author_public_key)
        if with_signature and self.author_signature is not None:
            doc["author_signature"] = _b64(self.author_signature)
        return doc

    def canonical_bytes(self) -> bytes:
        """Header bytes used for the author signature (signature field omitted)."""
        doc = self.to_json(with_signature=False)
        return json.dumps(doc, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_json(cls, doc: Dict) -> "PackageHeader":
        if doc.get("magic") != "VKIT" or doc.get("version") != VERSION:
            raise FormatError("not a VKIT v1 package")
        header = cls(
            model_id=str(doc["model_id"]),
            created_at=str(doc["created_at"]),
            block_size=int(doc["block_size"]),
            recipients=list(doc["recipients"]),
            files=[FileMeta.from_json(f) for f in doc["files"]],
            note=str(doc.get("note", "")),
        )
        if "author_public_key" in doc:
            header.author_public_key = _b64d(doc["author_public_key"], "author key")
        if "author_signature" in doc:
            header.author_signature = _b64d(doc["author_signature"], "author signature")
        return header


def _wrap_cek(cek: bytes, spki_der: bytes) -> Dict:
    pub = serialization.load_der_public_key(spki_der)
    wrapped = pub.encrypt(
        cek,
        padding.PKCS1v15(),
    )
    return {
        "key_id": key_id_of_spki(spki_der),
        "algorithm": "RSA-PKCS1v15",
        "wrapped_cek": _b64(wrapped),
    }


def _unwrap_cek(recipients: List[Dict], private_key: rsa.RSAPrivateKey) -> bytes:
    my_id = key_id_of_spki(
        private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    for entry in recipients:
        if entry.get("key_id", "").lower() == my_id:
            try:
                return private_key.decrypt(
                    _b64d(entry.get("wrapped_cek", ""), "wrapped_cek"),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
            except ValueError as exc:
                raise IntegrityError("failed to unwrap CEK") from exc
    raise RecipientMismatch("package recipient key_id does not match this key")


def pack_model(
    model_dir: Path,
    vreqs: Iterable[Dict],
    model_id: str,
    output: Path,
    note: str = "",
    author_private_key: Optional[rsa.RSAPrivateKey] = None,
    block_size: int = BLOCK_SIZE,
    created_at: Optional[str] = None,
) -> PackageHeader:
    """Encrypt a model directory into a .vkit file for one or more buyers."""
    if block_size <= 0 or block_size > 16 * 1024 * 1024:
        raise VkitError("block_size must be in (0, 16 MiB]")
    reqs = list(vreqs)
    if not reqs:
        raise VkitError("at least one recipient vreq is required")
    reqs = [_normalize_vreq(r) for r in reqs]
    files = collect_files(model_dir)
    cek = AESGCM.generate_key(bit_length=256)
    recipients = [_wrap_cek(cek, r["spki_der"]) for r in reqs]

    file_metas: List[FileMeta] = []
    data_len = 0
    with tempfile.TemporaryFile() as data_fh:
        aes = AESGCM(cek)
        for rel, src in files:
            meta = FileMeta(path=rel, size=src.stat().st_size, data_offset=data_fh.tell())
            idx = 0
            with open(src, "rb") as fh:
                while True:
                    chunk = fh.read(block_size)
                    if not chunk:
                        break
                    nonce = os.urandom(12)
                    ct = aes.encrypt(nonce, chunk, _aad(rel, idx))
                    data_fh.write(ct)
                    meta.blocks.append(BlockMeta(idx, nonce, ct[-16:], len(chunk)))
                    idx += 1
                    data_len += len(ct)
            if idx == 0:
                # Empty file: still authenticate one empty block.
                nonce = os.urandom(12)
                ct = aes.encrypt(nonce, b"", _aad(rel, 0))
                data_fh.write(ct)
                meta.blocks.append(BlockMeta(0, nonce, ct[-16:], 0))
                data_len += len(ct)
            file_metas.append(meta)

        header = PackageHeader(
            model_id=model_id,
            created_at=created_at or now_iso(),
            block_size=block_size,
            recipients=recipients,
            files=file_metas,
            note=note,
        )
        if author_private_key is not None:
            header.author_public_key = author_private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            header.author_signature = author_private_key.sign(
                header.canonical_bytes(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        header_bytes = json.dumps(
            header.to_json(), ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        with open(output, "wb") as out:
            out.write(PREFIX.pack(MAGIC, VERSION, len(header_bytes), data_len))
            out.write(header_bytes)
            data_fh.seek(0)
            copyfileobj(data_fh, out)
    return header

def _normalize_vreq(vreq: Dict) -> Dict:
    """Accept either a loaded vreq (with spki_der) or a raw serialized vreq."""
    if "spki_der" in vreq and vreq["spki_der"]:
        return vreq
    if "spki" in vreq:
        spki = _b64d(vreq["spki"], "vreq spki")
        expected = key_id_of_spki(spki)
        if vreq.get("key_id", "").lower() != expected:
            raise FormatError("vreq key_id does not match embedded public key")
        return {"key_id": expected, "spki_der": spki}
    raise FormatError("vreq is missing spki/spki_der")


def read_header(path: Path) -> Tuple[PackageHeader, int]:
    """Read the package header; returns (header, data_start_offset)."""
    with open(path, "rb") as fh:
        prefix = fh.read(PREFIX.size)
        if len(prefix) != PREFIX.size:
            raise FormatError("file too small")
        magic, version, header_len, data_len = PREFIX.unpack(prefix)
        if magic != MAGIC or version != VERSION:
            raise FormatError("not a VKIT v1 package")
        if header_len > 64 * 1024 * 1024:
            raise FormatError("header too large")
        raw = fh.read(header_len)
        if len(raw) != header_len:
            raise FormatError("truncated header")
        try:
            header = PackageHeader.from_json(json.loads(raw.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FormatError("invalid header JSON") from exc
        data_start = fh.tell()
        fh.seek(0, os.SEEK_END)
        if data_start + data_len != fh.tell():
            raise FormatError("data length mismatch")
        return header, data_start


def verify_author(header: PackageHeader, expected_author_spki: Optional[bytes] = None) -> None:
    """Verify the artist signature if present (or if a pinned key is expected)."""
    if header.author_public_key is None or header.author_signature is None:
        if expected_author_spki is not None:
            raise IntegrityError("package is not signed, but an author key is pinned")
        return
    if expected_author_spki is not None and header.author_public_key != expected_author_spki:
        raise IntegrityError("package signed by an unexpected author")
    pub = serialization.load_der_public_key(header.author_public_key)
    try:
        pub.verify(
            header.author_signature,
            header.canonical_bytes(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise IntegrityError("author signature invalid") from exc


def open_cek(header: PackageHeader, private_key: rsa.RSAPrivateKey) -> bytes:
    """Unwrap the content key for a recipient private key."""
    return _unwrap_cek(header.recipients, private_key)


class PackageReader:
    """Random-access reader that decrypts one block at a time."""

    def __init__(self, path: Path, header: PackageHeader, cek: bytes):
        self.path = path
        self.header = header
        self.aes = AESGCM(cek)
        self._fh = open(path, "rb")
        self._data_start = 0
        # Locate data region by re-reading the prefix.
        self._fh.seek(0)
        magic, version, header_len, data_len = PREFIX.unpack(self._fh.read(PREFIX.size))
        self._data_start = PREFIX.size + header_len

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "PackageReader":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _read_block(self, meta: FileMeta, block: BlockMeta) -> bytes:
        offset = self._data_start + meta.data_offset
        for prev in meta.blocks:
            if prev.index == block.index:
                break
            offset += len(prev.tag) + prev.length  # ciphertext = plaintext len + 16 tag
        else:
            raise FormatError("block index not found")
        ct_len = block.length + 16
        self._fh.seek(offset)
        ct = self._fh.read(ct_len)
        if len(ct) != ct_len:
            raise FormatError("truncated block data")
        try:
            return self.aes.decrypt(block.nonce, ct, _aad(meta.path, block.index))
        except Exception as exc:
            raise IntegrityError(f"block {block.index} authentication failed") from exc

    def read_file(self, meta: FileMeta) -> bytes:
        out = io.BytesIO()
        for block in meta.blocks:
            out.write(self._read_block(meta, block))
        return out.getvalue()

    def read_all(self) -> Dict[str, bytes]:
        return {f.path: self.read_file(f) for f in self.header.files}


def unpack_model(
    package: Path,
    private_key: rsa.RSAPrivateKey,
    output_dir: Path,
    expected_author_spki: Optional[bytes] = None,
) -> Dict[str, bytes]:
    """Decrypt a package for the supplied private key (test/verification path)."""
    header, _ = read_header(package)
    verify_author(header, expected_author_spki)
    cek = open_cek(header, private_key)
    output_dir.mkdir(parents=True, exist_ok=True)
    with PackageReader(package, header, cek) as reader:
        for meta in header.files:
            data = reader.read_file(meta)
            target = output_dir.joinpath(*meta.path.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        return reader.read_all()


def find_model_json(files: Iterable[FileMeta]) -> Optional[str]:
    """Locate the .model3.json entry (VTS entry point)."""
    for f in files:
        if f.path.lower().endswith(".model3.json"):
            return f.path
    return None
