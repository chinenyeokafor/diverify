import json

def prompt_yes_no(question):
    while True:
        answer = input(f"{question} (y/n): ").strip().lower()
        if answer in ['y', 'yes']:
            return True
        elif answer in ['n', 'no']:
            return False
        else:
            print("Please enter 'y' or 'n'.")

def generate_policy():
    print("=== Software Signature Trust Policy Generator ===\n")

    identity = input("Enter the identity (e.g. maintainer@example.com): ").strip()
    provider = input("Enter the provider (e.g. https://token.actions.githubusercontent.com): ").strip()
    device_fingerprint = input("Enter the device fingerprint: ").strip()

    slot9a_public_key = input("Enter the slot9a public key for your security key device: ").strip()
    slotf9_attestation_cert = input("Enter the pem for security key slotf9_attestation_cert: ").strip()

    signer_measurement = input("Enter the signer measurement (e.g. hash or measurement string): ").strip()

    rule = input("Enter logical trust rule (e.g. (identity AND provider)): ").strip()

    policy = {
        "identity": identity,
        "provider": provider,
        "device_fingerprint": device_fingerprint,
        "security_key": {
            "slot9a_public_key": slot9a_public_key,
            "slotf9_attestation_cert": slotf9_attestation_cert,
        },
        "signer_measurement": signer_measurement,
        "rule": rule
    }

    print("\nGenerated Policy:\n")
    print(json.dumps(policy, indent=2))

    save = prompt_yes_no("Would you like to save this policy to a file?")
    if save:
        filename = f"{input('Software name (e.g. django): ').strip()}-policy.json"
        with open(filename, "w") as f:
            json.dump(policy, f, indent=2)
        print(f"Policy saved to {filename}")

if __name__ == "__main__":
    generate_policy()
