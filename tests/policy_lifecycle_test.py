from pathlib import Path
import json
import shutil
import tempfile

from securesystemslib.exceptions import VerificationError
from diverify.policy import PolicyEvaluator


def read_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_policy_once(
    policy_path: Path,
    meta_path: Path,
    pubkey_path: Path,
    state_path: Path,
) -> None:
    PolicyEvaluator(
        policy_file=str(policy_path),
        policy_meta_file=str(meta_path),
        policy_pubkey_file=str(pubkey_path),
        state_file=str(state_path),
    )


def main():
    policy_dir = Path("src/diverify/policies")
    metadata_dir = Path("metadata/policies")

    source_policy = policy_dir / "policy_a1.json"
    meta_v1 = metadata_dir / "policy_a1_v1.meta.json"
    meta_v2 = metadata_dir / "policy_a1_v2.meta.json"
    source_pubkey = metadata_dir / "policy_pub.pem"

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)

        policy_path = tmpdir / "policy_a1.json"
        meta_path = tmpdir / "policy_a1.meta.json"
        pubkey_path = tmpdir / "policy_pub.pem"
        state_path = tmpdir / ".policy_state.json"

        shutil.copy(source_policy, policy_path)
        shutil.copy(source_pubkey, pubkey_path)

        print("=== Case 1: Initial load (v1) ===")
        shutil.copy(meta_v1, meta_path)
        load_policy_once(policy_path, meta_path, pubkey_path, state_path)
        print("Accepted initial policy bundle.")
        print(f"State after v1: {read_json(state_path)}")

        print("\n=== Case 2: Update (v2) ===")
        shutil.copy(meta_v2, meta_path)
        load_policy_once(policy_path, meta_path, pubkey_path, state_path)
        print("Accepted updated policy bundle.")
        print(f"State after v2: {read_json(state_path)}")

        print("\n=== Case 3: Rollback attempt (back to v1) ===")
        shutil.copy(meta_v1, meta_path)
        try:
            load_policy_once(policy_path, meta_path, pubkey_path, state_path)
            print("ERROR: rollback was accepted unexpectedly")
        except VerificationError as e:
            print(f"Rollback correctly rejected: {e}")


if __name__ == "__main__":
    from pathlib import Path
import sys

metadata_dir = Path("metadata/policies")

meta_v1 = metadata_dir / "policy_a1_v1.meta.json"
meta_v2 = metadata_dir / "policy_a1_v2.meta.json"

if not (meta_v1.exists() and meta_v2.exists()):
    print("\nMissing required policy metadata files.\n")
    print("Run the following commands first:\n")
    print("python sign_policy.py \\")
    print("  --policy src/diverify/policies/policy_a1.json \\")
    print("  --policy-id policy_a1 \\")
    print("  --version 1 \\")
    print("  --epoch 1 \\")
    print("  --out metadata/policies/policy_a1_v1.meta.json\n")
    print("python sign_policy.py \\")
    print("  --policy src/diverify/policies/policy_a1.json \\")
    print("  --policy-id policy_a1 \\")
    print("  --version 2 \\")
    print("  --epoch 1 \\")
    print("  --out metadata/policies/policy_a1_v2.meta.json\n")
    sys.exit(1)
main()