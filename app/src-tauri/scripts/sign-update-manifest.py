#!/usr/bin/env python3
"""Sign exact existing JSON bytes; NEVER generate/find keys or rewrite the manifest.

Issuer-only dependency: Python 3 + cryptography (no automatic installation).
Example (all paths selected explicitly by the caller):
  sign-update-manifest.py --kind core --manifest /issuer/kat-client-core-update.json \
    --private-key /explicit/issuer-key --signature /issuer/kat-client-core-update.json.sig
  sign-update-manifest.py --kind package --manifest /issuer/kat-package-auth.json \
    --private-key /explicit/issuer-key --signature /issuer/kat-package-auth.json.sig

PEM/DER Ed25519 or raw 32-byte seed / 64-byte seed+public / 64-char hex seed accepted.
Encrypted keys are unsupported: no prompts, passwords, private-key output, or key temp files.
This validates issuer schema, NOT live GitHub metadata, installed sequence floors, PE bytes,
GUI VersionReq semantics, or runtime capabilities. The Rust verifier remains authoritative.
"""
import argparse
import hashlib
import json
import os
import re
import stat
import sys
import unicodedata

KEY_ID = "0afa646ee76f17d8"
PUBLIC_KEY = bytes([41, 70, 129, 235, 51, 84, 134, 28, 155, 40, 162, 162, 46, 247, 214, 86,
                    86, 96, 103, 249, 12, 185, 146, 22, 47, 101, 58, 253, 135, 229, 40, 63])
MAX_JSON = 64 * 1024
ROLES = {"kat-desktop.exe", "kat-install-helper.exe", "kat-network-service.exe", "kat-client-core.exe"}
U64 = 2**64 - 1


class Invalid(Exception):
    pass


def need(ok):
    if not ok:
        raise Invalid("invalid input")


def exact(obj, fields):
    need(type(obj) is dict and set(obj) == set(fields.split()))


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result


def text(value, maximum):
    return type(value) is str and 0 < len(value.encode("utf-8")) <= maximum and all(unicodedata.category(c) != "Cc" for c in value)


def sha(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def number(value, minimum=1, maximum=U64):
    return type(value) is int and minimum <= value <= maximum


def atom(value, maximum):
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1," + str(maximum) + r"}", value) is not None and value not in (".", "..")


def version(value):
    if type(value) is not str or len(value) > 128:
        return False
    m = re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", value)
    return m is not None and all(int(n) <= U64 for n in m.groups())


def validate(data, kind):
    obj = json.loads(data.decode("utf-8"), object_pairs_hook=unique,
                     parse_constant=lambda _: (_ for _ in ()).throw(Invalid("invalid number")))
    if kind == "package":
        exact(obj, "schema product key_id os arch app_version stdio_protocol service_protocol record_schema workspace_schema source_revision components")
        need(obj["product"] == "kat-client-package" and version(obj["app_version"]))
        need(type(obj["workspace_schema"]) is int and obj["workspace_schema"] == 1)
        components = obj["components"]
        need(type(components) is dict and ROLES <= set(components) <= ROLES | {"kat-proxy-watchdog.exe"})
        need(all(sha(value) for value in components.values()))
    else:
        exact(obj, "schema product owner repo release version sequence os arch asset gui_compatibility stdio_protocol required_capabilities service_protocol record_schema workspace_read_compatibility workspace_write_compatibility source_revision key_id")
        product, repo = ("kat-client", "Kat-Client") if kind == "client" else ("kat-client-core", "Kat-Server")
        need(obj["product"] == product and obj["owner"] == "shui1iao" and obj["repo"] == repo)
        exact(obj["release"], "id tag")
        need(number(obj["release"]["id"]) and text(obj["release"]["tag"], 256))
        exact(obj["asset"], "name id bytes sha256")
        asset = obj["asset"]
        need(atom(asset["name"], 240) and asset["name"].endswith(".exe") and number(asset["id"]) and sha(asset["sha256"]))
        need(number(asset["bytes"], 64, 1024**3 if kind == "client" else 256 * 1024**2))
        need(("setup" in asset["name"].lower()) if kind == "client" else
             (asset["name"].startswith("kat-client-core") and "windows-amd64" in asset["name"]))
        need(version(obj["version"]) and number(obj["sequence"]) and text(obj["gui_compatibility"], 256))
        caps = obj["required_capabilities"]
        need(type(caps) is list and len(caps) <= 64 and all(atom(c, 80) for c in caps) and len(caps) == len(set(caps)))
        need(all(type(obj[k]) is int and obj[k] == 1 for k in ("workspace_read_compatibility", "workspace_write_compatibility")))
    need(type(obj["schema"]) is int and obj["schema"] == 1 and obj["key_id"] == KEY_ID)
    need(obj["os"] == "windows" and obj["arch"] == "amd64")
    need(type(obj["stdio_protocol"]) is int and obj["stdio_protocol"] == 1)
    need(type(obj["service_protocol"]) is int and obj["service_protocol"] == 1)
    need(type(obj["record_schema"]) is int and obj["record_schema"] == 2)
    need(type(obj["source_revision"]) is str and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", obj["source_revision"]) is not None)


def read_explicit(path, limit, private=False):
    need(os.path.isabs(path))
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit)
        if private and os.name == "posix":
            need(info.st_mode & 0o077 == 0)
        data = source.read(limit + 1)
        need(0 < len(data) <= limit)
        return data


def load_key(data):
    # Imports happen only in issuer execution; this file is never imported by the application.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if data.startswith(b"-----BEGIN"):
        key = serialization.load_pem_private_key(data, password=None)
    elif len(data) == 32:
        key = Ed25519PrivateKey.from_private_bytes(data)
    elif len(data) == 64 and data[32:] == PUBLIC_KEY:
        key = Ed25519PrivateKey.from_private_bytes(data[:32])
    elif re.fullmatch(rb"[0-9a-fA-F]{64}(?:\r?\n)?", data):
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data.decode("ascii").strip()))
    else:
        key = serialization.load_der_private_key(data, password=None)
    need(isinstance(key, Ed25519PrivateKey))
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    need(public == PUBLIC_KEY)
    return key


class QuietParser(argparse.ArgumentParser):
    def error(self, _message):
        # Do not echo caller arguments (especially the explicit private key path).
        self.print_usage(sys.stderr)
        self.exit(2, "error: invalid arguments; use --help\n")


def main():
    parser = QuietParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kind", choices=("client", "core", "package"), required=True)
    parser.add_argument("--manifest", required=True, help="absolute path to exact existing JSON bytes")
    parser.add_argument("--private-key", required=True, help="explicit absolute Ed25519 key path; never searched or generated")
    parser.add_argument("--signature", required=True, help="absolute NEW detached signature path; never overwritten")
    args = parser.parse_args()
    created = False
    try:
        data = read_explicit(args.manifest, MAX_JSON)
        validate(data, args.kind)
        need(os.path.isabs(args.signature) and os.path.abspath(args.signature) not in
             (os.path.abspath(args.manifest), os.path.abspath(args.private_key)))
        key = load_key(read_explicit(args.private_key, 16 * 1024, private=True))
        signature = key.sign(data)
        need(len(signature) == 64)
        key.public_key().verify(signature, data)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(args.signature, flags, 0o600)
        created = True
        with os.fdopen(fd, "wb") as output:
            output.write(signature.hex().encode("ascii") + b"\n")
            output.flush()
            os.fsync(output.fileno())
        # Only public material; no input paths or private key details.
        print("signed exact JSON bytes; key_id=" + KEY_ID + "; sha256=" + hashlib.sha256(data).hexdigest())
        return 0
    except Exception:
        if created:
            try:
                os.unlink(args.signature)
            except OSError:
                pass
        print("signing failed: invalid schema/key/path, missing cryptography, or output already exists; no private material logged", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
