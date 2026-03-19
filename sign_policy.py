#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from hashlib import sha256

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEFAULT_POLICY_DIR = Path("src/diverify/policies")
DEFAULT_METADATA_DIR = Path("metadata/policies")
DEFAULT_PRIVKEY_PATH = Path("keys/policy_priv.pem")
DEFAULT_PUBKEY_PATH = DEFAULT_METADATA_DIR / "policy_pub.pem"


def canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def load_priv(path: Path) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def write_priv(path: Path, key: Ed25519PrivateKey) -> None:
    ensure_parent(path)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def write_pub(path: Path, key: Ed25519PrivateKey) -> None:
    ensure_parent(path)
    path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def ensure_keypair(priv_path: Path, pub_path: Path) -> Ed25519PrivateKey:
    if priv_path.exists():
        key = load_priv(priv_path)
        if not pub_path.exists():
            write_pub(pub_path, key)
        return key
    if pub_path.exists():
        raise FileNotFoundError(f"Public key exists at {pub_path}, but private key is missing at {priv_path}")
    key = Ed25519PrivateKey.generate()
    write_priv(priv_path, key)
    write_pub(pub_path, key)
    return key


def sign_one(policy_path: Path, key: Ed25519PrivateKey, version: int, epoch: int, out_path: Path) -> None:
    metadata = {
        "policy_id": policy_path.stem,
        "version": version,
        "epoch": epoch,
        "policy_hash": sha256(policy_path.read_bytes()).hexdigest(),
    }
    metadata["signature"] = key.sign(canonical_json_bytes(metadata)).hex()
    ensure_parent(out_path)
    out_path.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Wrote {out_path}")


def main() -> None:
    p = argparse.ArgumentParser(description="Generate/reuse a DiVerify policy keypair and sign policy metadata.")
    p.add_argument("--policy", help="Path to one policy JSON; omit to sign all policies")
    p.add_argument("--version", required=True, type=int, help="Policy semantic version")
    p.add_argument("--epoch", required=True, type=int, help="Policy freshness epoch")
    p.add_argument("--out", help="Output metadata path (only valid with --policy)")
    p.add_argument("--policy-dir", default=str(DEFAULT_POLICY_DIR))
    p.add_argument("--metadata-dir", default=str(DEFAULT_METADATA_DIR))
    p.add_argument("--private-key", default=str(DEFAULT_PRIVKEY_PATH))
    p.add_argument("--public-key", default=str(DEFAULT_PUBKEY_PATH))
    args = p.parse_args()

    policy_dir = Path(args.policy_dir)
    metadata_dir = Path(args.metadata_dir)
    priv_path = Path(args.private_key)
    pub_path = Path(args.public_key)

    policies = [Path(args.policy)] if args.policy else sorted(policy_dir.glob("*.json"))
    if not policies:
        raise FileNotFoundError(f"No policy files found in {policy_dir}")
    if args.out and len(policies) > 1:
        raise ValueError("--out can only be used with --policy")

    key = ensure_keypair(priv_path, pub_path)

    for policy_path in policies:
        if not policy_path.exists():
            raise FileNotFoundError(f"Policy file not found: {policy_path}")
        out_path = Path(args.out) if args.out else metadata_dir / f"{policy_path.stem}.meta.json"
        sign_one(policy_path, key, args.version, args.epoch, out_path)


if __name__ == "__main__":
    main()