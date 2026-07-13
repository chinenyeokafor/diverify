# DiVerify Evaluation Guide

This guide provides instructions for me to set up and evaluate the DiVerify project, Sigstore's local infrastructure (Fulcio CA, Rekor, and CTLog).

The experiment is run on a host with **SGX capability**.

## Platform Requirements

- Intel CPU with SGX support enabled in BIOS/UEFI.
- A Linux host with Docker and Docker Compose installed.
- SGX runtime support configured in the containers used for DiVerify and Fulcio.
- No GPU is required.

---

## Components Needed
2. Fulcio Certificate Authority for certificate issuance
3. CTLog for certificate logging
4. Rekor for signature logging

---

## Steps

### 1. Clone Repositories
Clone the following repositories to home directory:

- **[diverify](https://github.com/chinenyeokafor/diverify)**
- **[containerized_sigstore](https://github.com/chinenyeokafor/sigstore_containerized)**


### 2. SGX & Enclave Requirements
`diverify` and `fulcio` require enclaves for trusted signing and quote/QVL verification.  
**SGX must be properly configured** in the container.  
Either follow this GitHub Gist [link](https://gist.github.com/chinenyeokafor/af1401c38b177dd1a889f32d286964a6#file-intel_sgx_remote_attestation_setup-md) for setup or use a custom base image I've pre-configured for SGX, such as the one in my Docker Compose file.

---

### 3. Deploy Infrastructure
- Deploy **Sigstore infra** and **diverify** using the `docker-compose-deverify.yml` file in the `containerized_sigstore` directory.

---

### 4. Start PCCS Services
Inside the `diverify` and `fulcio` containers, start the PCCS service:

```bash
cd /opt/intel/sgx-dcap-pccs/
node pccs_server.js &
```

---

### 5. Start Fulcio Service
Inside the `fulcio` container, start fulcio service:

```bash
cd /home/fulcio-Div
./run.sh
```

---

### 6. Generate Local Root of Trust
We use `diverify` for the client and verifier.  
To generate the local Sigstore infra root of trust, run:

```bash
python /diverify/util/generate_trusted_root.py
```

---

### 7. Start DiVerify Daemon and Run Tests
**Inside the `diverify` container:**

- **Terminal 1**: Follow ../src/diverify/TEE/SGX/README.md to start the DiVerify daemon

- **Terminal 2**: Run the test scripts:
  ```bash
  cd /home/diverify
  tests/run.sh
  ```

This runs tests across **three modes** and **three levels**.

---

### 9. Evaluate performance and storage cost
The previous step generates client and daemon logs for signing and verification latency: `perf_log.jsonl` and `src/diverify/TEE/SGX/daemon_perf_log.jsonl`. It also generates `sig_data_eval/sig_bundles.csv` for storage cost evaluation.

- Run these scripts to merge logs and compute averages (output: `sig_data_eval/avg_perf.csv`):
  ```bash
  python tests/combine_perf_logs.py
  python tests/avg_perf.py
  ```

- Run this script to compute storage overhead:
  ```bash
  python tests/sig_overhead.py
  ```

- Run this script to generate LaTeX tables from the evaluation results:
  ```bash
  python tests/generate_latex_tables.py
  ```

- Run this to compute integration effort:
``` bash
  cloc src/diverify/daemon/ src/diverify/scope_providers/ src/diverify/util src/diverify/sigstore/ sign_policy.py src/diverify/policy.py --exclude-dir=.venv,venv,__pycache__
```
## Errors / Issues

### Error: Failed to download target policy*.json
**Cause**: Policy not authenticating  
**Fix**: Need to sign policy following on step 7 and retry.