#!/bin/bash

for mode in a b c; do
  for level in 1 2 3 ; do
    for i in $(seq 1 10); do
      echo "Running iteration=$i mode=$mode level=$level"
      #  python tests/sign_with_sigstore.py --mode "$mode" --level "$level"
      PERF_MODE=true PERF_ITER=$i python tests/sign_with_sigstore.py --mode "$mode" --level "$level" --iter "$i"
    done
  done
done
