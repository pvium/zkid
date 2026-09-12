#!/bin/sh
# Adversarial circuit tests: signs decoy payloads with the fixture key and checks the circuit
# rejects prover offsets that point at them. Requires nargo and node on PATH.
set -e
cd "$(dirname "$0")/.."
python3 test/adversarial.py
