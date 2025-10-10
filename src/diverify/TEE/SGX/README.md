# DiVerify SGX Support with Gramine

This directory provides configuration and setup for running the DiVerify daemon in Intel SGX enclaves using Gramine.

## Prerequisites

- Intel CPU with SGX support (SGX enabled in BIOS/UEFI)
- At least 4GB EPC memory recommended

## Setup Steps

1. [Install Gramine](https://gramine.readthedocs.io/en/stable/installation.html)
2. Prepare host environment, attestation infrastructure, and signing key ([setup guide](https://gist.github.com/chinenyeokafor/af1401c38b177dd1a889f32d286964a6#file-intel_sgx_remote_attestation_setup-md))
3. Provide DiVerify configuration file (`diverify.manifest.template`)
4. Build and sign the manifest:
    ```bash
    cd /home/diverify/src/diverify/TEE/SGX
    make clean
    make
    ```
    This generates:
    - `diverify.manifest`
    - `diverify.manifest.sgx`
    - `diverify.sig`
    and updates the `signer_measurement` values in the policies.

5. Set up Python virtual environment and dependencies:
    ```bash
    cd /home/diverify/src/diverify/TEE/SGX
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirement-daemon.txt
    pip install -e /home/diverify
    ```

6. Launch the daemon:
    ```bash
    gramine-sgx ./diverify
    ```
    For debug mode:
    ```bash
    DEBUG=1 gramine-sgx ./diverify
    ```

The daemon will start at `http://0.0.0.0:8001` inside the SGX enclave.
