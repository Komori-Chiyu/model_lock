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
  gen-code    --model-id M --key-id <买家key_id> [--note 备注] [--count N] [--db ledger.db]
  list-codes  [--model-id M] [--db ledger.db]
  export-author-key --key author.pem --output author.spki
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .ledger import Ledger
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
        code=args.code,
        expires_at=args.expires,
        ledger_path=args.db,
    )
    entry = find_model_json(header.files)
    print(f"packed {len(header.files)} files -> {args.output}")
    print(f"  recipients: {[r['key_id'] for r in header.recipients]}")
    if header.license:
        print(f"  license: key_id={header.license['key_id']} expires={header.license.get('expires_at')}")
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



def cmd_gen_code(args) -> int:
    ledger = Ledger(args.db)
    codes = ledger.gen_codes(args.model_id, args.key_id, note=args.note or "", count=args.count)
    for c in codes:
        print(c)
    return 0


def cmd_list_codes(args) -> int:
    ledger = Ledger(args.db)
    for row in ledger.list_codes(args.model_id):
        print(f"{row['code']} | {row['model_id']} | {row['key_id']} | {row['status']} | {row['note']}")
    return 0


def cmd_export_author_key(args) -> int:
    import base64
    key = _load_private_key(args.key)
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    args.output.write_text(base64.b64encode(spki).decode("ascii") + "\n")
    print(f"wrote author SPKI (base64) -> {args.output}")
    return 0


def _add_ledger_args(p):
    p.add_argument("--model-id", required=True)
    p.add_argument("--key-id", required=True)
    p.add_argument("--note", default=None)
    p.add_argument("--db", type=Path, default=Path("license_records.db"))

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
    p.add_argument("--code", default=None, help="offline activation code (from gen-code)")
    p.add_argument("--expires", default=None, help="license expiry date YYYY-MM-DD (optional)")
    p.add_argument("--db", type=Path, default=None, help="path to license ledger db")
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

    p = sub.add_parser("gen-code")
    p.add_argument("--model-id", required=True)
    p.add_argument("--key-id", required=True)
    p.add_argument("--note", default=None)
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--db", type=Path, default=Path("license_records.db"))
    p.set_defaults(func=cmd_gen_code)

    p = sub.add_parser("list-codes")
    p.add_argument("--model-id", default=None)
    p.add_argument("--db", type=Path, default=Path("license_records.db"))
    p.set_defaults(func=cmd_list_codes)

    p = sub.add_parser("export-author-key")
    p.add_argument("--key", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.set_defaults(func=cmd_export_author_key)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except VkitError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
