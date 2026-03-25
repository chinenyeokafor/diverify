# DiVerify Evaluation Guide

This guide provides instructions for me to set up and evaluate the DiVerify project using `securesystemslib`, Sigstore's local infrastructure (Fulcio CA, Rekor, and CTLog).

The experiment is run on a host with **SGX capability**.

---

## Components Needed
1. `securesystemslib` for signing and verification
2. Fulcio Certificate Authority for certificate issuance
3. CTLog for certificate logging
4. Rekor for signature logging
5. RSTUF for distribution of DiVerify policy

---

## Steps

### 1. Clone Repositories
I need to clone the following repositories to my home directory:

- **[securesystemslib](https://github.com/chinenyeokafor/securesystemslib/tree/DiVerify)**
- **[rstuf](https://github.com/chinenyeokafor/rstuf)**
- **[containerized_sigstore](https://github.com/chinenyeokafor/sigstore_containerized)**

---

### 2. Set Up RSTUF
Follow [link](https://repository-service-tuf.readthedocs.io/en/stable/guide/deployment/setup.html#service-setup) to set up RSTUF for the key ceremony.  
Then, add policy delegation and sign accordingly.

---

### 3. SGX & Enclave Requirements
`securesystemslib` and `fulcio` require enclaves for trusted signing and quote/QVL verification.  
**SGX must be properly configured** in the container.  
I can either follow this GitHub Gist [link](https://gist.github.com/chinenyeokafor/af1401c38b177dd1a889f32d286964a6#file-intel_sgx_remote_attestation_setup-md) for setup or use a custom base image I've pre-configured for SGX, such as the one in my Docker Compose file.

---

### 4. Deploy Infrastructure
- Deploy **Sigstore infra** and **securesystemslib** using the `docker-compose-deverify.yml` file in the `containerized_sigstore` directory.
- Deploy **rstuf** using `docker-compose.yml` in the `rstuf` directory.

---

### 5. Start PCCS Services
Inside the `securesystemslib` and `fulcio` containers, start the PCCS service:

```bash
cd /opt/intel/sgx-dcap-pccs/
node pccs_server.js &
```

---

### 6. Start Fulcio Service
Inside the `fulcio` container, start fulcio service:

```bash
cd /home/fulio-Div
./run.sh
```

---

### 7. Generate Local Root of Trust
We use `securesystemslib` for the client and verifier.  
To generate the local Sigstore infra root of trust, run:

```bash
python /diverify/util/generate_trusted_root.py
```

---

### 8. Start DiVerify Daemon and Run Tests
**Inside the `securesystemslib` container:**

- **Terminal 1**: Follow ../src/diverify/TEE/SGX/README.md to start the DiVerify daemon

- **Terminal 2**: Run the test scripts:
  ```bash
  cd /home/securesystemslib
  tests/run.sh
  ```

This runs tests across **three modes** and **three levels**.

---

### 9. Evaluate performance
The above generates client and daemon data `perf_log.jsonl` and `src/diverify/TEE/SGX/daemon_perf_log.jsonl`
Run the scripts to combine data and average the result:
  ```bash
  python tests/combine_perf_logs.py 
  python tests/avg_perf.py 

  ```
Signing and verification overhead data is then saved to `sig_data_eval/avg_perf.csv`

## Errors / Issues

### Error: Failed to download target policy*.json
**Cause**: Policy not found or TUF policies expired.  
**Fix**: Need to re-sign and retry.