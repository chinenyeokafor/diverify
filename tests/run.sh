#!/bin/bash

for mode in a b c; do
  for level in 1 2 3 ; do
    for i in $(seq 1 1); do
      echo "Running $i time: mode=$mode, level=$level"
      # PERF_MODE=true python tests/sign_verify_with_sslib.py --mode "$mode" --level "$level"
      python tests/sign_with_sigstore.py --mode "$mode" --level "$level"
    done
  done
done
