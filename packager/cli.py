"""Command line interface for the artist-side packager (and Linux test tools).

Commands:
  gen-key     --output key.pem            generate an RSA-2048 key pair
  make-vreq   --key key.pem --output req.vreq
  vreq-info   --vreq req.vreq
  pack        --model-dir DIR --vreq r1.vreq [--vreq r2.vreq ...]
              --output out.vkit [--model-id ID] [--note NOTE]
              [--author-key author.pem]
  unpack      --vkit out.vkit --key key.pem --output DIR
  verify      --vkit out.vkit [--author-key author.pem]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .vkit import (
    VkitError,
    find_model_json,
    load_vreq,
    make_vreq,
    pack_model,
    read_header,
    unpack_model,
    verify_author,
)


def _load_private_key(path: Path) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _save_private_key(key: rsa.RSAPrivateKey, path: Path) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def cmd_gen_key(args) -> int:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _save_private_key(key, args.output)
    print(f"wrote RSA-2048 key to {args.output}")
    return 0


def cmd_make_vreq(args) -> int:
    key = _load_private_key(args.key)
    doc = make_vreq(key.public_key())
    args.output.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote vreq key_id={doc['key_id']} -> {args.output}")
    return 0


def cmd_vreq_info(args) -> int:
    vreq = load_vreq(args.vreq)
    print(json.dumps(
        {"key_id": vreq["key_id"], "algorithm": "RSA-2048", "spki_sha256": vreq["key_id"]},
        indent=2,
    ))
    return 0


def cmd_pack(args) -> int:
    vreqs = [load_vreq(p) for p in args.vreq]
    author_key = _load_private_key(args.author_key) if args.author_key else None
    header = pack_model(
        model_dir=args.model_dir,
        vreqs=vreqs,
        model_id=args.model_id or args.model_dir.name,
        output=args.output,
        note=args.note or "",
        author_private_key=author_key,
    )
    entry = find_model_json(header.files)
    print(f"packed {len(header.files)} files -> {args.output}")
    print(f"  recipients: {[r['key_id'] for r in header.recipients]}")
    print(f"  model3.json: {entry}")
    return 0


def cmd_unpack(args) -> int:
    key = _load_private_key(args.key)
    unpack_model(args.vkit, key, args.output)
    print(f"unpacked -> {args.output}")
    return 0


def cmd_verify(args) -> int:
    header, _ = read_header(args.vkit)
    expected = None
    if args.author_key:
        pub = _load_private_key(args.author_key).public_key()
        expected = pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    verify_author(header, expected)
    print(f"OK model_id={header.model_id} files={len(header.files)} "
          f"signed={header.author_signature is not None}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="vkit", description="VKIT model packager")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("gen-key")
    p.add_argument("--output", type=Path, required=True)
    p.set_defaults(func=cmd_gen_key)

    p = sub.add_parser("make-vreq")
    p.add_argument("--key", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.set_defaults(func=cmd_make_vreq)

    p = sub.add_parser("vreq-info")
    p.add_argument("--vreq", type=Path, required=True)
    p.set_defaults(func=cmd_vreq_info)

    p = sub.add_parser("pack")
    p.add_argument("--model-dir", type=Path, required=True)
    p.add_argument("--vreq", type=Path, action="append", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--model-id", default=None)
    p.add_argument("--note", default=None)
    p.add_argument("--author-key", type=Path, default=None)
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser("unpack")
    p.add_argument("--vkit", type=Path, required=True)
    p.add_argument("--key", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser("verify")
    p.add_argument("--vkit", type=Path, required=True)
    p.add_argument("--author-key", type=Path, default=None)
    p.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except VkitError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
